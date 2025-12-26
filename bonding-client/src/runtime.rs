use anyhow::{Context, Result};
use base64::Engine;
use bonding_core::control::BondingConfig;
use bonding_core::proto::Packet;
#[cfg(target_os = "windows")]
use bonding_core::proto::PacketFlags;
use bonding_core::transport::{EncryptionKey, PacketCrypto};
use std::net::SocketAddr;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::watch;

#[cfg(target_os = "windows")]
use crate::wintun_loader;

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

pub async fn run_client(
    cfg: BondingConfig,
    mut stop: watch::Receiver<bool>,
    log: LogFn,
) -> Result<()> {
    let log = Arc::new(log);

    (log.as_ref())(format!(
        "Client config: server={}:{} mode={} mtu={} encryption={}",
        cfg.server_addr, cfg.server_port, cfg.bonding_mode, cfg.mtu, cfg.enable_encryption
    ));

    if cfg.enable_tun {
        #[cfg(target_os = "windows")]
        {
            return run_client_tun_mode(cfg, stop, log).await;
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = stop; // silence unused warning on non-windows
            anyhow::bail!("enable_tun=true is currently only supported for Windows clients");
        }
    }

    #[cfg(target_os = "windows")]
    {
        match wintun_loader::ensure_wintun_dll() {
            Ok(dll_path) => {
                (log.as_ref())(format!("Wintun DLL available at: {}", dll_path.display()))
            }
            Err(e) => {
                (log.as_ref())(format!("Failed to ensure wintun.dll: {e}"));
                return Err(e.into());
            }
        }
    }

    let server: SocketAddr = format!("{}:{}", cfg.server_addr, cfg.server_port)
        .parse()
        .with_context(|| "server_addr/server_port is not a valid socket address")?;

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

    let session_id: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut tx_seq: u64 = 1;

    // Bind an ephemeral UDP socket.
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind UDP socket")?;
    (log.as_ref())(format!("UDP socket bound: {}", sock.local_addr()?));

    // Periodic keepalive packet (now framed using the protocol).
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut buf = [0u8; UDP_RECV_BUF_SIZE];
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let plaintext = b"bonding-client:hello";

                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet(NONCE_DOMAIN_CLIENT_TO_SERVER, session_id, tx_seq, plaintext)
                        .context("failed to seal packet")?
                        .encode()
                } else {
                    Packet::new(session_id, tx_seq, plaintext.to_vec()).encode()
                };

                let _ = sock.send_to(&wire, server).await;
                (log.as_ref())(format!("Sent keepalive seq={tx_seq} to {server}"));
                tx_seq = tx_seq.wrapping_add(1);
            }
            recv = sock.recv_from(&mut buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                let pkt = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        (log.as_ref())(format!("Recv {n} bytes from {peer}: invalid protocol packet: {e}"));
                        continue;
                    }
                };

                let payload = if let Some(ref crypto) = crypto {
                    match crypto.open_packet(NONCE_DOMAIN_SERVER_TO_CLIENT, &pkt) {
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
                (log.as_ref())(format!("Recv pkt seq={} from {peer}: {msg}", pkt.header.sequence));
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
async fn run_client_tun_mode(
    cfg: BondingConfig,
    mut stop: watch::Receiver<bool>,
    log: Arc<LogFn>,
) -> Result<()> {
    use bonding_core::tun::{TunDevice, WintunDevice};
    use std::io;
    use std::thread;
    use tokio::sync::mpsc;

    (log.as_ref())(format!(
        "Client starting TUN mode: adapter='{}' mtu={} server={}:{}",
        cfg.adapter_name, cfg.mtu, cfg.server_addr, cfg.server_port
    ));

    // Ensure wintun.dll is present (required for adapter creation).
    match wintun_loader::ensure_wintun_dll() {
        Ok(dll_path) => (log.as_ref())(format!("Wintun DLL available at: {}", dll_path.display())),
        Err(e) => {
            (log.as_ref())(format!("Failed to ensure wintun.dll: {e}"));
            return Err(e.into());
        }
    }

    let server: SocketAddr = format!("{}:{}", cfg.server_addr, cfg.server_port)
        .parse()
        .with_context(|| "server_addr/server_port is not a valid socket address")?;

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

    let session_id: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut tx_seq: u64 = 1;

    const NET_TO_TUN_QUEUE: usize = 1024;
    let mut dropped_net_to_tun: u64 = 0;
    let mut dropped_net_to_tun_last: u64 = 0;

    // Bind an ephemeral UDP socket.
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind UDP socket")?;
    (log.as_ref())(format!("UDP socket bound: {}", sock.local_addr()?));

    // Create/open the adapter up-front so we can auto-configure it before pumping.
    let tun = WintunDevice::new(&cfg.adapter_name).with_context(|| {
        format!(
            "failed to create/open Wintun adapter '{}'",
            cfg.adapter_name
        )
    })?;

    (log.as_ref())(format!(
        "Wintun ready: name='{}' mtu={} (cfg mtu={})",
        tun.name(),
        tun.mtu(),
        cfg.mtu
    ));

    if cfg.auto_config_tun {
        if let Some(ip) = cfg.tun_ipv4_addr {
            crate::windows_tun_config::configure_windows_tun(
                tun.name(),
                cfg.mtu,
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

    // Channel: UDP -> TUN (bounded; drop on overflow).
    let (net_to_tun_tx, mut net_to_tun_rx) = mpsc::channel::<Vec<u8>>(NET_TO_TUN_QUEUE);

    // Channel: TUN -> UDP (tokio, bounded).
    let (tun_to_net_tx, mut tun_to_net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_thread = Arc::clone(&stop_flag);
    let log_thread = Arc::clone(&log);
    let mtu = cfg.mtu;

    let tun_thread = thread::spawn(move || {
        let mut tun = tun;
        let mut buf = vec![0u8; mtu.clamp(1500, 65535)];

        while !stop_flag_thread.load(Ordering::Relaxed) {
            // Drain outbound packets to the TUN adapter.
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
                    // No packet ready right now.
                }
                Err(e) => {
                    (log_thread.as_ref())(format!("TUN read error: {e}"));
                }
            }

            thread::sleep(Duration::from_millis(1));
        }
    });

    let mut udp_buf = [0u8; UDP_RECV_BUF_SIZE];
    let mut tick = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                // ACK_ONLY keepalive (empty payload) so the server can learn our peer/port.
                let flags_raw = PacketFlags::ACK_ONLY;
                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet_with_flags(
                            NONCE_DOMAIN_CLIENT_TO_SERVER,
                            session_id,
                            tx_seq,
                            flags_raw,
                            &[],
                        )
                        .context("failed to seal ACK_ONLY keepalive")?
                        .encode()
                } else {
                    let mut pkt = Packet::new(session_id, tx_seq, Vec::new());
                    pkt.header.flags = PacketFlags::from_raw(flags_raw);
                    pkt.encode()
                };

                let _ = sock.send_to(&wire, server).await;
                tx_seq = tx_seq.wrapping_add(1);

                let dropped_delta = dropped_net_to_tun.saturating_sub(dropped_net_to_tun_last);
                dropped_net_to_tun_last = dropped_net_to_tun;
                if dropped_delta > 0 {
                    (log.as_ref())(format!(
                        "Warning: dropped {dropped_delta} UDP->TUN packets due to full queue (total dropped={dropped_net_to_tun})"
                    ));
                }
            }

            maybe_pkt = tun_to_net_rx.recv() => {
                let Some(ip_packet) = maybe_pkt else {
                    break;
                };

                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet(
                            NONCE_DOMAIN_CLIENT_TO_SERVER,
                            session_id,
                            tx_seq,
                            &ip_packet,
                        )
                        .context("failed to seal data packet")?
                        .encode()
                } else {
                    Packet::new(session_id, tx_seq, ip_packet).encode()
                };

                let _ = sock.send_to(&wire, server).await;
                tx_seq = tx_seq.wrapping_add(1);
            }

            recv = sock.recv_from(&mut udp_buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                if peer != server {
                    // Ignore unexpected peers for now.
                    continue;
                }

                let pkt = match Packet::decode(&udp_buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        (log.as_ref())(format!("Recv {n} bytes from {peer}: invalid protocol packet: {e}"));
                        continue;
                    }
                };

                let payload = if let Some(ref crypto) = crypto {
                    match crypto.open_packet(NONCE_DOMAIN_SERVER_TO_CLIENT, &pkt) {
                        Ok(p) => p,
                        Err(e) => {
                            (log.as_ref())(format!("Recv pkt from {peer}: decrypt failed: {e}"));
                            continue;
                        }
                    }
                } else {
                    pkt.payload
                };

                if pkt.header.flags.is_set(PacketFlags::ACK_ONLY) || payload.is_empty() {
                    // Keepalive/control packet.
                    continue;
                }

                if let Err(_e) = net_to_tun_tx.try_send(payload) {
                    dropped_net_to_tun = dropped_net_to_tun.wrapping_add(1);
                }
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
