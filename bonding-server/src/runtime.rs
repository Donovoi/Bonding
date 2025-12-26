use anyhow::{Context, Result};
use base64::Engine;
use bonding_core::control::ServerConfig;
use bonding_core::proto::Packet;
use bonding_core::transport::{EncryptionKey, PacketCrypto};
use std::net::SocketAddr;
use std::sync::Arc;
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

        #[cfg(not(target_os = "linux"))]
        {
            let _ = stop; // silence unused warning
            anyhow::bail!("enable_tun=true is currently only supported for Linux servers");
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

#[cfg(target_os = "linux")]
async fn run_server_tun_mode(
    cfg: ServerConfig,
    mut stop: watch::Receiver<bool>,
    log: Arc<LogFn>,
) -> Result<()> {
    use bonding_core::proto::PacketFlags;
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
    let mut tun_buf = vec![0u8; cfg.tun_mtu.max(1500).min(65535)];

    let mut received: u64 = 0;
    let mut tx_seq: u64 = 1;

    let mut last_peer: Option<SocketAddr> = None;
    let mut last_session_id: Option<u64> = None;

    let mut health_tick = tokio::time::interval(cfg.health_interval);
    let mut keepalive_tick = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = health_tick.tick() => {
                (log.as_ref())(format!("Health tick: received_packets={received} peer_known={}", last_peer.is_some()));
            }

            _ = keepalive_tick.tick() => {
                let Some(peer) = last_peer else { continue; };
                let Some(session_id) = last_session_id else { continue; };

                let flags_raw = PacketFlags::ACK_ONLY;
                let wire = if let Some(ref crypto) = crypto {
                    crypto
                        .seal_packet_with_flags(
                            NONCE_DOMAIN_SERVER_TO_CLIENT,
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

                tx_seq = tx_seq.wrapping_add(1);
                let _ = sock.send_to(&wire, peer).await;
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

                last_peer = Some(peer);
                last_session_id = Some(pkt.header.session_id);

                if pkt.header.flags.is_set(PacketFlags::ACK_ONLY) || payload.is_empty() {
                    continue;
                }

                dev.send(&payload).await.context("failed to write packet to TUN")?;
            }

            tun_len = dev.recv(&mut tun_buf) => {
                let n = tun_len.context("failed to read packet from TUN")?;
                if n == 0 {
                    continue;
                }

                let Some(peer) = last_peer else { continue; };
                let Some(session_id) = last_session_id else { continue; };

                let plaintext = &tun_buf[..n];
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
