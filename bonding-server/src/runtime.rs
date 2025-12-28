use anyhow::{Context, Result};
use base64::Engine;
use bonding_core::control::ServerConfig;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use bonding_core::proto::control::{self, ControlMessage};
use bonding_core::proto::Packet;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use bonding_core::reorder::ReorderBuffer;
use bonding_core::transport::{EncryptionKey, PacketCrypto};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;

pub type LogFn = Box<dyn Fn(String) + Send + Sync + 'static>;

const NONCE_DOMAIN_CLIENT_TO_SERVER: u32 = 0x43325300; // "C2S\0"
const NONCE_DOMAIN_SERVER_TO_CLIENT: u32 = 0x53324300; // "S2C\0"

const UDP_RECV_BUF_SIZE: usize = 2048;

fn decode_key_b64(s: &str) -> Result<EncryptionKey> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("failed to decode encryption_key_b64 as base64")?;

    if raw.len() != 32 {
        anyhow::bail!(
            "encryption_key_b64 must decode to exactly 32 bytes, got {}",
            raw.len()
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(key)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn ipv4_src_dst(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    // Minimal IPv4 parser for routing: src/dst are always at fixed offsets.
    // Returns None if the packet doesn't look like IPv4.
    if packet.len() < 20 {
        return None;
    }

    let ver = packet[0] >> 4;
    if ver != 4 {
        return None;
    }

    let ihl = packet[0] & 0x0f;
    if ihl < 5 {
        return None;
    }

    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    ipv4_src_dst(packet).map(|(_, dst)| dst)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Debug, Clone)]
struct SessionState {
    peers: std::collections::HashMap<SocketAddr, Instant>,
    assigned_vip: Option<Ipv4Addr>,
    last_seen: Instant,
    reorder: ReorderBuffer,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl SessionState {
    fn new(peer: SocketAddr, now: Instant) -> Self {
        let mut peers = std::collections::HashMap::new();
        peers.insert(peer, now);
        Self {
            peers,
            assigned_vip: None,
            last_seen: now,
            reorder: ReorderBuffer::new(),
        }
    }

    fn update(&mut self, peer: SocketAddr, now: Instant) {
        self.peers.insert(peer, now);
        self.last_seen = now;
    }

    fn prune_peers(&mut self, ttl: Duration, now: Instant) {
        self.peers.retain(|_, last_seen| now.duration_since(*last_seen) < ttl);
    }

    fn best_peer(&self) -> Option<SocketAddr> {
        // Simple strategy: use the most recently seen peer
        self.peers
            .iter()
            .max_by_key(|(_, last_seen)| *last_seen)
            .map(|(peer, _)| *peer)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Debug, Clone)]
struct Ipv4Pool {
    net: u32,
    mask: u32,
    first: u32,
    last: u32,
    server_ip: u32,
    next: u32,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Ipv4Pool {
    fn new(server_ip: Ipv4Addr, prefix: u8) -> Result<Self> {
        anyhow::ensure!(prefix <= 32, "invalid IPv4 prefix length: {prefix}");

        let ip_u32 = u32::from_be_bytes(server_ip.octets());
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let net = ip_u32 & mask;
        let broadcast = net | (!mask);

        // Reserve network + broadcast; for small prefixes there may be no usable hosts.
        let first = net.saturating_add(1);
        let last = broadcast.saturating_sub(1);
        anyhow::ensure!(
            first <= last,
            "subnet /{prefix} has no usable host addresses"
        );

        Ok(Self {
            net,
            mask,
            first,
            last,
            server_ip: ip_u32,
            next: first,
        })
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        (ip_u32 & self.mask) == self.net
    }

    fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        ip_u32 == self.server_ip || ip_u32 < self.first || ip_u32 > self.last
    }

    fn allocate_next(
        &mut self,
        assigned: &std::collections::HashSet<Ipv4Addr>,
    ) -> Option<Ipv4Addr> {
        let mut cur = self.next;
        for _ in 0..=((self.last - self.first) as usize) {
            if cur == self.server_ip {
                cur = if cur >= self.last {
                    self.first
                } else {
                    cur + 1
                };
                continue;
            }

            let ip = Ipv4Addr::from(cur.to_be_bytes());
            if !assigned.contains(&ip) {
                self.next = if cur >= self.last {
                    self.first
                } else {
                    cur + 1
                };
                return Some(ip);
            }
            cur = if cur >= self.last {
                self.first
            } else {
                cur + 1
            };
        }
        None
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    mut stop: watch::Receiver<bool>,
    log: LogFn,
) -> Result<()> {
    let log = Arc::new(log);

    if cfg.enable_tun {
        #[cfg(target_os = "linux")]
        {
            return run_server_tun_mode(cfg, stop, log).await;
        }

        #[cfg(target_os = "windows")]
        {
            return run_server_tun_mode_windows(cfg, stop, log).await;
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = stop; // silence unused warning
            anyhow::bail!(
                "enable_tun=true is currently only supported for Linux and Windows servers"
            );
        }
    }

    let bind_addr: SocketAddr = format!("{}:{}", cfg.listen_addr, cfg.listen_port)
        .parse()
        .with_context(|| "listen_addr/listen_port is not a valid socket address")?;

    (log.as_ref())(format!(
        "Server config: bind={bind_addr} encryption={} health_interval={:?}",
        cfg.enable_encryption, cfg.health_interval
    ));

    let crypto = if cfg.enable_encryption {
        let key_b64 = cfg
            .encryption_key_b64
            .as_deref()
            .context("enable_encryption=true but encryption_key_b64 is missing")?;
        let key = decode_key_b64(key_b64)?;
        Some(PacketCrypto::new(&key))
    } else {
        None
    };

    let sock = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket to {bind_addr}"))?;
    (log.as_ref())(format!("UDP socket bound: {}", sock.local_addr()?));

    let mut buf = [0u8; UDP_RECV_BUF_SIZE];
    let mut received: u64 = 0;
    let mut tick = tokio::time::interval(cfg.health_interval);
    let mut tx_seq: u64 = 1;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                (log.as_ref())(format!("Health tick: received_packets={received}"));
            }
            recv = sock.recv_from(&mut buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                received += 1;

                let pkt = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        (log.as_ref())(format!("Recv {n} bytes from {peer}: invalid protocol packet: {e}"));
                        continue;
                    }
                };

                let payload = if let Some(ref crypto) = crypto {
                    match crypto.open_packet(NONCE_DOMAIN_CLIENT_TO_SERVER, &pkt) {
                        Ok(p) => p,
                        Err(e) => {
                            (log.as_ref())(format!("Recv pkt from {peer}: decrypt failed: {e}"));
                            continue;
                        }
                    }
                } else {
                    pkt.payload
                };

                let msg = String::from_utf8_lossy(&payload);
                (log.as_ref())(format!(
                    "Recv pkt session={} seq={} from {peer}: {msg}",
                    pkt.header.session_id,
                    pkt.header.sequence
                ));

                let plaintext = b"bonding-server:ack";
                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet(
                            NONCE_DOMAIN_SERVER_TO_CLIENT,
                            pkt.header.session_id,
                            tx_seq,
                            plaintext,
                        )
                        .context("failed to seal packet")?
                        .encode()
                } else {
                    Packet::new(pkt.header.session_id, tx_seq, plaintext.to_vec()).encode()
                };

                tx_seq = tx_seq.wrapping_add(1);
                let _ = sock.send_to(&wire, peer).await;
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    (log.as_ref())("Stop requested".to_string());
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                (log.as_ref())("Ctrl+C received".to_string());
                break;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
async fn run_server_tun_mode_windows(
    cfg: ServerConfig,
    mut stop: watch::Receiver<bool>,
    log: Arc<LogFn>,
) -> Result<()> {
    use bonding_core::proto::PacketFlags;
    use bonding_core::tun::{TunDevice, WintunDevice};
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    let bind_addr: SocketAddr = format!("{}:{}", cfg.listen_addr, cfg.listen_port)
        .parse()
        .with_context(|| "listen_addr/listen_port is not a valid socket address")?;

    (log.as_ref())(format!(
        "Server starting Windows TUN mode: bind={bind_addr} adapter='{}' tun_mtu={} encryption={}",
        cfg.tun_device_name, cfg.tun_mtu, cfg.enable_encryption
    ));

    // Ensure wintun.dll is present.
    match crate::wintun_loader::ensure_wintun_dll() {
        Ok(p) => (log.as_ref())(format!("Wintun DLL available at: {}", p.display())),
        Err(e) => {
            (log.as_ref())(format!("Failed to ensure wintun.dll: {e}"));
            return Err(e.into());
        }
    }

    let crypto = if cfg.enable_encryption {
        let key_b64 = cfg
            .encryption_key_b64
            .as_deref()
            .context("enable_encryption=true but encryption_key_b64 is missing")?;
        let key = decode_key_b64(key_b64)?;
        Some(PacketCrypto::new(&key))
    } else {
        None
    };

    let sock = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket to {bind_addr}"))?;
    (log.as_ref())(format!("UDP socket bound: {}", sock.local_addr()?));

    // Create/open the Wintun adapter.
    let tun = WintunDevice::new(&cfg.tun_device_name).with_context(|| {
        format!(
            "failed to create/open Wintun adapter '{}'",
            cfg.tun_device_name
        )
    })?;

    (log.as_ref())(format!(
        "Wintun ready: name='{}' mtu={} (cfg tun_mtu={})",
        tun.name(),
        tun.mtu(),
        cfg.tun_mtu
    ));

    let effective_mtu = cfg.tun_mtu.min(tun.mtu());
    if effective_mtu != cfg.tun_mtu {
        (log.as_ref())(format!(
            "Warning: cfg.tun_mtu={} exceeds Wintun MTU={}; using effective_mtu={} for buffers/config",
            cfg.tun_mtu,
            tun.mtu(),
            effective_mtu
        ));
    }

    if cfg.auto_config_tun {
        if let Some(ip) = cfg.tun_ipv4_addr {
            crate::windows_tun_config::configure_windows_tun(
                tun.name(),
                effective_mtu,
                ip,
                cfg.tun_ipv4_prefix,
                &cfg.tun_routes,
                &|m| (log.as_ref())(m),
            )?;
        } else {
            (log.as_ref())(
                "auto_config_tun=true but tun_ipv4_addr is not set; skipping auto config"
                    .to_string(),
            );
        }
    }

    // Optional: enable forwarding + NAT using NetNat.
    if cfg.enable_ipv4_forwarding || cfg.windows_enable_netnat {
        if let Some(tun_ip) = cfg.tun_ipv4_addr {
            crate::windows_nat_config::configure_windows_forwarding_and_netnat(
                crate::windows_nat_config::WindowsNetNatOptions {
                    tun_interface_alias: tun.name(),
                    tun_ipv4: tun_ip,
                    tun_prefix: cfg.tun_ipv4_prefix,
                    enable_forwarding: cfg.enable_ipv4_forwarding,
                    enable_netnat: cfg.windows_enable_netnat,
                    netnat_name: &cfg.windows_netnat_name,
                    internal_prefix_override: cfg.windows_netnat_internal_prefix.as_deref(),
                },
                &|m| (log.as_ref())(m),
            )?;
        } else {
            (log.as_ref())(
                "Windows forwarding/NetNat requested but tun_ipv4_addr is not set; skipping"
                    .to_string(),
            );
        }
    }

    const NET_TO_TUN_QUEUE: usize = 1024;

    // net -> tun (bounded; drop on overflow)
    let (net_to_tun_tx, mut net_to_tun_rx) = mpsc::channel::<Vec<u8>>(NET_TO_TUN_QUEUE);
    // tun -> net (tokio)
    let (tun_to_net_tx, mut tun_to_net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_thread = Arc::clone(&stop_flag);
    let log_thread = Arc::clone(&log);
    let mtu = effective_mtu;

    let tun_thread = thread::spawn(move || {
        let mut tun = tun;
        let mut buf = vec![0u8; mtu.clamp(1500, 65535)];

        while !stop_flag_thread.load(Ordering::Relaxed) {
            // Drain queued packets from UDP to TUN.
            loop {
                match net_to_tun_rx.try_recv() {
                    Ok(pkt) => {
                        if let Err(e) = tun.write_packet(&pkt) {
                            (log_thread.as_ref())(format!("TUN write error: {e}"));
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
                }
            }

            match tun.read_packet(&mut buf) {
                Ok(n) => {
                    if n > 0 && tun_to_net_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No packet ready.
                }
                Err(e) => {
                    (log_thread.as_ref())(format!("TUN read error: {e}"));
                }
            }

            thread::sleep(Duration::from_millis(1));
        }
    });

    let mut udp_buf = [0u8; UDP_RECV_BUF_SIZE];
    let mut received: u64 = 0;
    let mut tx_seq: u64 = 1;

    // Multi-client support with explicit per-session VIP assignment
    let mut sessions: HashMap<u64, SessionState> = HashMap::new();
    let mut assigned_set: HashSet<Ipv4Addr> = HashSet::new();
    let mut vip_to_session: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut dropped_net_to_tun: u64 = 0;
    let mut dropped_net_to_tun_last: u64 = 0;

    const SESSION_TTL: Duration = Duration::from_secs(30);

    let mut pool = cfg
        .tun_ipv4_addr
        .map(|ip| Ipv4Pool::new(ip, cfg.tun_ipv4_prefix))
        .transpose()
        .context("failed to initialize IPv4 pool")?;

    let mut health_tick = tokio::time::interval(cfg.health_interval);
    let mut keepalive_tick = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = health_tick.tick() => {
                let now = Instant::now();

                // Prune peers within sessions
                for state in sessions.values_mut() {
                    state.prune_peers(SESSION_TTL, now);
                }

                // Prune empty/expired sessions
                let expired: Vec<u64> = sessions
                    .iter()
                    .filter_map(|(sid, state)| {
                        if state.peers.is_empty() || now.duration_since(state.last_seen) >= SESSION_TTL {
                            Some(*sid)
                        } else {
                            None
                        }
                    })
                    .collect();

                for sid in expired {
                    if let Some(state) = sessions.remove(&sid) {
                        if let Some(ip) = state.assigned_vip {
                            assigned_set.remove(&ip);
                            vip_to_session.remove(&ip);
                        }
                    }
                }

                let dropped_delta = dropped_net_to_tun.saturating_sub(dropped_net_to_tun_last);
                dropped_net_to_tun_last = dropped_net_to_tun;

                (log.as_ref())(format!(
                    "Health tick: received_packets={received} sessions={} clients={} dropped_udp_to_tun={} (+{})",
                    sessions.len(),
                    vip_to_session.len(),
                    dropped_net_to_tun,
                    dropped_delta
                ));
            }

            _ = keepalive_tick.tick() => {
                let flags_raw = PacketFlags::ACK_ONLY;
                
                for (sid, state) in &sessions {
                    // Send keepalive to ALL active peers to maintain NAT mappings
                    for (peer, _) in &state.peers {
                        let wire = if let Some(ref crypto) = crypto {
                            crypto
                                .seal_packet_with_flags(
                                    NONCE_DOMAIN_SERVER_TO_CLIENT,
                                    *sid,
                                    tx_seq,
                                    flags_raw,
                                    &[],
                                )
                                .context("failed to seal ACK_ONLY keepalive")?
                                .encode()
                        } else {
                            let mut pkt = Packet::new(*sid, tx_seq, Vec::new());
                            pkt.header.flags = PacketFlags::from_raw(flags_raw);
                            pkt.encode()
                        };
                        
                        let _ = sock.send_to(&wire, *peer).await;
                    }
                    tx_seq = tx_seq.wrapping_add(1);
                }
            }

            recv = sock.recv_from(&mut udp_buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                received += 1;

                let pkt = match Packet::decode(&udp_buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        (log.as_ref())(format!("Recv {n} bytes from {peer}: invalid protocol packet: {e}"));
                        continue;
                    }
                };

                let payload = if let Some(ref crypto) = crypto {
                    match crypto.open_packet(NONCE_DOMAIN_CLIENT_TO_SERVER, &pkt) {
                        Ok(p) => p,
                        Err(e) => {
                            (log.as_ref())(format!("Recv pkt from {peer}: decrypt failed: {e}"));
                            continue;
                        }
                    }
                } else {
                    pkt.payload
                };

                let now = Instant::now();
                let session_id = pkt.header.session_id;
                
                sessions.entry(session_id)
                    .and_modify(|s| s.update(peer, now))
                    .or_insert_with(|| SessionState::new(peer, now));

                if pkt.header.flags.is_set(PacketFlags::ACK_ONLY) || payload.is_empty() {
                    continue;
                }

                // Control handshake messages are handled here and never forwarded to TUN.
                if let Some(ctrl) = control::decode(&payload) {
                    match ctrl {
                        ControlMessage::Hello { requested_ipv4 } => {
                            let mut assigned_ip = None;
                            if let Some(state) = sessions.get(&session_id) {
                                assigned_ip = state.assigned_vip;
                            }

                            let assigned = if let Some(ip) = assigned_ip {
                                Ok(ip)
                            } else {
                                let candidate = match requested_ipv4 {
                                    Some(ip) => {
                                        if assigned_set.contains(&ip) {
                                            Err(ControlMessage::Nack { code: 3, message: "requested_ip_in_use".to_string() })
                                        } else if let Some(ref p) = pool {
                                            if !p.contains(ip) || p.is_reserved(ip) {
                                                Err(ControlMessage::Nack { code: 2, message: "requested_ip_out_of_range".to_string() })
                                            } else {
                                                Ok(ip)
                                            }
                                        } else {
                                            Ok(ip)
                                        }
                                    }
                                    None => {
                                        if let Some(ref mut p) = pool {
                                            match p.allocate_next(&assigned_set) {
                                                Some(ip) => Ok(ip),
                                                None => Err(ControlMessage::Nack { code: 4, message: "no_free_ips".to_string() }),
                                            }
                                        } else {
                                            Err(ControlMessage::Nack { code: 1, message: "server_has_no_ip_pool".to_string() })
                                        }
                                    }
                                };

                                match candidate {
                                    Ok(ip) => {
                                        if let Some(state) = sessions.get_mut(&session_id) {
                                            state.assigned_vip = Some(ip);
                                        }
                                        assigned_set.insert(ip);
                                        vip_to_session.insert(ip, session_id);
                                        Ok(ip)
                                    }
                                    Err(nack) => Err(nack),
                                }
                            };

                            let resp = match assigned {
                                Ok(ip) => ControlMessage::Assign { ipv4: ip, prefix: cfg.tun_ipv4_prefix },
                                Err(nack) => nack,
                            };

                            let resp_payload = control::encode(&resp);
                            let flags_raw: u8 = 0;
                            let wire = if let Some(ref crypto) = crypto {
                                crypto
                                    .seal_packet_with_flags(
                                        NONCE_DOMAIN_SERVER_TO_CLIENT,
                                        session_id,
                                        tx_seq,
                                        flags_raw,
                                        &resp_payload,
                                    )
                                    .context("failed to seal control response")?
                                    .encode()
                            } else {
                                let mut out = Packet::new(session_id, tx_seq, resp_payload);
                                out.header.flags = PacketFlags::from_raw(flags_raw);
                                out.encode()
                            };

                            tx_seq = tx_seq.wrapping_add(1);
                            let _ = sock.send_to(&wire, peer).await;
                        }
                        ControlMessage::Assign { .. } | ControlMessage::Nack { .. } => {
                            // Server ignores these.
                        }
                    }

                    continue;
                }

                // Implicit assignment fallback
                let mut assigned_ip = None;
                if let Some(state) = sessions.get(&session_id) {
                    assigned_ip = state.assigned_vip;
                }

                if assigned_ip.is_none() {
                    if let Some((src, _dst)) = ipv4_src_dst(&payload) {
                        let ok = if let Some(ref p) = pool {
                            p.contains(src) && !p.is_reserved(src)
                        } else {
                            true
                        };

                        if ok && !assigned_set.contains(&src) {
                            if let Some(state) = sessions.get_mut(&session_id) {
                                state.assigned_vip = Some(src);
                            }
                            assigned_set.insert(src);
                            vip_to_session.insert(src, session_id);
                            assigned_ip = Some(src);
                        }
                    }
                }

                let Some(assigned) = assigned_ip else {
                    continue;
                };

                // Anti-spoof
                let Some((src, _dst)) = ipv4_src_dst(&payload) else {
                    continue;
                };
                if src != assigned {
                    continue;
                }

                if let Some(state) = sessions.get_mut(&session_id) {
                    if let Err(_e) = state.reorder.insert(pkt.header.sequence, payload) {
                        continue;
                    }
                    
                    for (_seq, data) in state.reorder.retrieve() {
                        if let Err(_e) = net_to_tun_tx.try_send(data) {
                            dropped_net_to_tun = dropped_net_to_tun.wrapping_add(1);
                        }
                    }
                }
            }

            maybe_pkt = tun_to_net_rx.recv() => {
                let Some(ip_packet) = maybe_pkt else {
                    break;
                };

                if let (Some(server_ip), Some(dst)) = (cfg.tun_ipv4_addr, ipv4_dst(&ip_packet)) {
                    if dst == server_ip {
                        continue;
                    }
                }

                let mut target_session: Option<u64> = None;
                if let Some(dst) = ipv4_dst(&ip_packet) {
                    if let Some(sid) = vip_to_session.get(&dst) {
                        target_session = Some(*sid);
                    }
                }

                let Some(session_id) = target_session else { continue; };
                
                let mut target_peer = None;
                if let Some(state) = sessions.get(&session_id) {
                    target_peer = state.best_peer();
                }
                
                let Some(peer) = target_peer else { continue; };

                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet(
                            NONCE_DOMAIN_SERVER_TO_CLIENT,
                            session_id,
                            tx_seq,
                            &ip_packet,
                        )
                        .context("failed to seal data packet")?
                        .encode()
                } else {
                    Packet::new(session_id, tx_seq, ip_packet).encode()
                };

                tx_seq = tx_seq.wrapping_add(1);
                let _ = sock.send_to(&wire, peer).await;
            }

            _ = stop.changed() => {
                if *stop.borrow() {
                    (log.as_ref())("Stop requested".to_string());
                    break;
                }
            }

            _ = tokio::signal::ctrl_c() => {
                (log.as_ref())("Ctrl+C received".to_string());
                break;
            }
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    drop(net_to_tun_tx);
    drop(tun_to_net_rx);
    let _ = tun_thread.join();

    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_server_tun_mode(
    cfg: ServerConfig,
    mut stop: watch::Receiver<bool>,
    log: Arc<LogFn>,
) -> Result<()> {
    use bonding_core::proto::PacketFlags;
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};
    use tun_rs::DeviceBuilder;

    let bind_addr: SocketAddr = format!("{}:{}", cfg.listen_addr, cfg.listen_port)
        .parse()
        .with_context(|| "listen_addr/listen_port is not a valid socket address")?;

    (log.as_ref())(format!(
        "Server starting TUN mode: bind={bind_addr} tun_device={} tun_mtu={} encryption={}",
        cfg.tun_device_name, cfg.tun_mtu, cfg.enable_encryption
    ));

    let crypto = if cfg.enable_encryption {
        let key_b64 = cfg
            .encryption_key_b64
            .as_deref()
            .context("enable_encryption=true but encryption_key_b64 is missing")?;
        let key = decode_key_b64(key_b64)?;
        Some(PacketCrypto::new(&key))
    } else {
        None
    };

    let sock = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket to {bind_addr}"))?;
    (log.as_ref())(format!("UDP socket bound: {}", sock.local_addr()?));

    let mtu_u16 = u16::try_from(cfg.tun_mtu).context("tun_mtu must fit in u16")?;
    let dev = DeviceBuilder::new()
        .name(&cfg.tun_device_name)
        .mtu(mtu_u16)
        .build_async()
        .context("failed to create TUN device")?;

    let ifname = dev.name().unwrap_or_else(|_| cfg.tun_device_name.clone());

    (log.as_ref())(format!(
        "Linux TUN device created: name='{}' mtu={}",
        ifname, cfg.tun_mtu
    ));

    if cfg.auto_config_tun {
        if let Some(ip) = cfg.tun_ipv4_addr {
            crate::linux_tun_config::configure_linux_tun(
                &ifname,
                cfg.tun_mtu,
                ip,
                cfg.tun_ipv4_prefix,
                &cfg.tun_routes,
                &|m| (log.as_ref())(m),
            )?;
        } else {
            (log.as_ref())(
                "auto_config_tun=true but tun_ipv4_addr is not set; skipping auto config"
                    .to_string(),
            );
        }
    }

    // Optional: enable forwarding + NAT (MASQUERADE) so tunnel clients can reach
    // resources via the server (e.g. tailnet via tailscale0).
    if cfg.enable_ipv4_forwarding || !cfg.nat_masquerade_out_ifaces.is_empty() {
        if let Some(tun_ip) = cfg.tun_ipv4_addr {
            crate::linux_nat_config::configure_linux_forwarding_and_nat(
                &ifname,
                tun_ip,
                cfg.tun_ipv4_prefix,
                &cfg.nat_masquerade_out_ifaces,
                cfg.enable_ipv4_forwarding,
                &|m| (log.as_ref())(m),
            )?;
        } else {
            (log.as_ref())(
                "NAT/forwarding requested but tun_ipv4_addr is not set; skipping NAT/forwarding"
                    .to_string(),
            );
        }
    }

    let mut udp_buf = [0u8; UDP_RECV_BUF_SIZE];
    let mut tun_buf = vec![0u8; cfg.tun_mtu.clamp(1500, 65535)];

    let mut received: u64 = 0;
    let mut tx_seq: u64 = 1;

    let mut sessions: HashMap<u64, SessionState> = HashMap::new();
    let mut assigned_set: HashSet<Ipv4Addr> = HashSet::new();
    let mut vip_to_session: HashMap<Ipv4Addr, u64> = HashMap::new();

    const SESSION_TTL: Duration = Duration::from_secs(30);

    let mut pool = cfg
        .tun_ipv4_addr
        .map(|ip| Ipv4Pool::new(ip, cfg.tun_ipv4_prefix))
        .transpose()
        .context("failed to initialize IPv4 pool")?;

    let mut health_tick = tokio::time::interval(cfg.health_interval);
    let mut keepalive_tick = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = health_tick.tick() => {
                let now = Instant::now();

                // Prune peers within sessions
                for state in sessions.values_mut() {
                    state.prune_peers(SESSION_TTL, now);
                }

                // Prune empty/expired sessions
                let expired: Vec<u64> = sessions
                    .iter()
                    .filter_map(|(sid, state)| {
                        if state.peers.is_empty() || now.duration_since(state.last_seen) >= SESSION_TTL {
                            Some(*sid)
                        } else {
                            None
                        }
                    })
                    .collect();

                for sid in expired {
                    if let Some(state) = sessions.remove(&sid) {
                        if let Some(ip) = state.assigned_vip {
                            assigned_set.remove(&ip);
                            vip_to_session.remove(&ip);
                        }
                    }
                }

                (log.as_ref())(format!(
                    "Health tick: received_packets={received} sessions={} clients={}",
                    sessions.len(),
                    vip_to_session.len()
                ));
            }

            _ = keepalive_tick.tick() => {
                let flags_raw = PacketFlags::ACK_ONLY;
                
                for (sid, state) in &sessions {
                    // Send keepalive to ALL active peers to maintain NAT mappings
                    for (peer, _) in &state.peers {
                        let wire = if let Some(ref crypto) = crypto {
                            crypto
                                .seal_packet_with_flags(
                                    NONCE_DOMAIN_SERVER_TO_CLIENT,
                                    *sid,
                                    tx_seq,
                                    flags_raw,
                                    &[],
                                )
                                .context("failed to seal ACK_ONLY keepalive")?
                                .encode()
                        } else {
                            let mut pkt = Packet::new(*sid, tx_seq, Vec::new());
                            pkt.header.flags = PacketFlags::from_raw(flags_raw);
                            pkt.encode()
                        };
                        
                        let _ = sock.send_to(&wire, *peer).await;
                    }
                    tx_seq = tx_seq.wrapping_add(1);
                }
            }

            recv = sock.recv_from(&mut udp_buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                received += 1;

                let pkt = match Packet::decode(&udp_buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        (log.as_ref())(format!("Recv {n} bytes from {peer}: invalid protocol packet: {e}"));
                        continue;
                    }
                };

                let payload = if let Some(ref crypto) = crypto {
                    match crypto.open_packet(NONCE_DOMAIN_CLIENT_TO_SERVER, &pkt) {
                        Ok(p) => p,
                        Err(e) => {
                            (log.as_ref())(format!("Recv pkt from {peer}: decrypt failed: {e}"));
                            continue;
                        }
                    }
                } else {
                    pkt.payload
                };

                let now = Instant::now();
                let session_id = pkt.header.session_id;
                
                sessions.entry(session_id)
                    .and_modify(|s| s.update(peer, now))
                    .or_insert_with(|| SessionState::new(peer, now));

                if pkt.header.flags.is_set(PacketFlags::ACK_ONLY) || payload.is_empty() {
                    continue;
                }

                // Control handshake messages are handled here and never forwarded to TUN.
                if let Some(ctrl) = control::decode(&payload) {
                    match ctrl {
                        ControlMessage::Hello { requested_ipv4 } => {
                            let mut assigned_ip = None;
                            if let Some(state) = sessions.get(&session_id) {
                                assigned_ip = state.assigned_vip;
                            }

                            let assigned = if let Some(ip) = assigned_ip {
                                Ok(ip)
                            } else {
                                let candidate = match requested_ipv4 {
                                    Some(ip) => {
                                        if assigned_set.contains(&ip) {
                                            Err(ControlMessage::Nack { code: 3, message: "requested_ip_in_use".to_string() })
                                        } else if let Some(ref p) = pool {
                                            if !p.contains(ip) || p.is_reserved(ip) {
                                                Err(ControlMessage::Nack { code: 2, message: "requested_ip_out_of_range".to_string() })
                                            } else {
                                                Ok(ip)
                                            }
                                        } else {
                                            Ok(ip)
                                        }
                                    }
                                    None => {
                                        if let Some(ref mut p) = pool {
                                            match p.allocate_next(&assigned_set) {
                                                Some(ip) => Ok(ip),
                                                None => Err(ControlMessage::Nack { code: 4, message: "no_free_ips".to_string() }),
                                            }
                                        } else {
                                            Err(ControlMessage::Nack { code: 1, message: "server_has_no_ip_pool".to_string() })
                                        }
                                    }
                                };

                                match candidate {
                                    Ok(ip) => {
                                        if let Some(state) = sessions.get_mut(&session_id) {
                                            state.assigned_vip = Some(ip);
                                        }
                                        assigned_set.insert(ip);
                                        vip_to_session.insert(ip, session_id);
                                        Ok(ip)
                                    }
                                    Err(nack) => Err(nack),
                                }
                            };

                            let resp = match assigned {
                                Ok(ip) => ControlMessage::Assign { ipv4: ip, prefix: cfg.tun_ipv4_prefix },
                                Err(nack) => nack,
                            };

                            let resp_payload = control::encode(&resp);
                            let flags_raw: u8 = 0;
                            let wire = if let Some(ref crypto) = crypto {
                                crypto
                                    .seal_packet_with_flags(
                                        NONCE_DOMAIN_SERVER_TO_CLIENT,
                                        session_id,
                                        tx_seq,
                                        flags_raw,
                                        &resp_payload,
                                    )
                                    .context("failed to seal control response")?
                                    .encode()
                            } else {
                                let mut out = Packet::new(session_id, tx_seq, resp_payload);
                                out.header.flags = PacketFlags::from_raw(flags_raw);
                                out.encode()
                            };

                            tx_seq = tx_seq.wrapping_add(1);
                            let _ = sock.send_to(&wire, peer).await;
                        }
                        ControlMessage::Assign { .. } | ControlMessage::Nack { .. } => {
                            // Server ignores these.
                        }
                    }

                    continue;
                }

                // Implicit assignment fallback
                let mut assigned_ip = None;
                if let Some(state) = sessions.get(&session_id) {
                    assigned_ip = state.assigned_vip;
                }

                if assigned_ip.is_none() {
                    if let Some((src, _dst)) = ipv4_src_dst(&payload) {
                        let ok = if let Some(ref p) = pool {
                            p.contains(src) && !p.is_reserved(src)
                        } else {
                            true
                        };

                        if ok && !assigned_set.contains(&src) {
                            if let Some(state) = sessions.get_mut(&session_id) {
                                state.assigned_vip = Some(src);
                            }
                            assigned_set.insert(src);
                            vip_to_session.insert(src, session_id);
                            assigned_ip = Some(src);
                        }
                    }
                }

                let Some(assigned) = assigned_ip else {
                    continue;
                };

                // Anti-spoof: require IPv4 and correct source address.
                let Some((src, _dst)) = ipv4_src_dst(&payload) else {
                    continue;
                };
                if src != assigned {
                    continue;
                }

                // vip_to_session is already set during assignment

                if let Some(state) = sessions.get_mut(&session_id) {
                    if let Err(_e) = state.reorder.insert(pkt.header.sequence, payload) {
                        continue;
                    }
                    
                    for (_seq, data) in state.reorder.retrieve() {
                        dev.send(&data).await.context("failed to write packet to TUN")?;
                    }
                }
            }

            tun_len = dev.recv(&mut tun_buf) => {
                let n = tun_len.context("failed to read packet from TUN")?;
                if n == 0 {
                    continue;
                }

                let plaintext = &tun_buf[..n];

                if let (Some(server_ip), Some(dst)) = (cfg.tun_ipv4_addr, ipv4_dst(plaintext)) {
                    if dst == server_ip {
                        continue;
                    }
                }

                let mut target_session: Option<u64> = None;
                if let Some(dst) = ipv4_dst(plaintext) {
                    if let Some(sid) = vip_to_session.get(&dst) {
                        target_session = Some(*sid);
                    }
                }

                let Some(session_id) = target_session else { continue; };
                
                let mut target_peer = None;
                if let Some(state) = sessions.get(&session_id) {
                    target_peer = state.best_peer();
                }
                
                let Some(peer) = target_peer else { continue; };

                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet(
                            NONCE_DOMAIN_SERVER_TO_CLIENT,
                            session_id,
                            tx_seq,
                            plaintext,
                        )
                        .context("failed to seal data packet")?
                        .encode()
                } else {
                    Packet::new(session_id, tx_seq, plaintext.to_vec()).encode()
                };

                tx_seq = tx_seq.wrapping_add(1);
                let _ = sock.send_to(&wire, peer).await;
            }

            _ = stop.changed() => {
                if *stop.borrow() {
                    (log.as_ref())("Stop requested".to_string());
                    break;
                }
            }

            _ = tokio::signal::ctrl_c() => {
                (log.as_ref())("Ctrl+C received".to_string());
                break;
            }
        }
    }

    Ok(())
}
