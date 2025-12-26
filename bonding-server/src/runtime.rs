use anyhow::{Context, Result};
use bonding_core::control::ServerConfig;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::watch;

pub type LogFn = Box<dyn Fn(String) + Send + Sync + 'static>;

pub async fn run_server(
    cfg: ServerConfig,
    mut stop: watch::Receiver<bool>,
    log: LogFn,
) -> Result<()> {
    let bind_addr: SocketAddr = format!("{}:{}", cfg.listen_addr, cfg.listen_port)
        .parse()
        .with_context(|| "listen_addr/listen_port is not a valid socket address")?;

    log(format!(
        "Server config: bind={bind_addr} encryption={} health_interval={:?}",
        cfg.enable_encryption, cfg.health_interval
    ));

    let sock = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket to {bind_addr}"))?;
    log(format!("UDP socket bound: {}", sock.local_addr()?));

    let mut buf = [0u8; 2048];
    let mut received: u64 = 0;
    let mut tick = tokio::time::interval(cfg.health_interval);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                log(format!("Health tick: received_packets={received}"));
            }
            recv = sock.recv_from(&mut buf) => {
                let (n, peer) = recv.context("failed to receive UDP packet")?;
                received += 1;
                let msg = String::from_utf8_lossy(&buf[..n]);
                log(format!("Recv {n} bytes from {peer}: {msg}"));

                // Placeholder response.
                let _ = sock.send_to(b"bonding-server:ack", peer).await;
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    log("Stop requested".to_string());
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log("Ctrl+C received".to_string());
                break;
            }
        }
    }

    Ok(())
}
