use anyhow::{Context, Result};
use bonding_core::control::BondingConfig;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;

#[cfg(target_os = "windows")]
use crate::wintun_loader;

pub type LogFn = Box<dyn Fn(String) + Send + Sync + 'static>;

pub async fn run_client(
    cfg: BondingConfig,
    mut stop: watch::Receiver<bool>,
    log: LogFn,
) -> Result<()> {
    log(format!(
        "Client config: server={}:{} mode={} mtu={} encryption={}",
        cfg.server_addr, cfg.server_port, cfg.bonding_mode, cfg.mtu, cfg.enable_encryption
    ));

    #[cfg(target_os = "windows")]
    {
        match wintun_loader::ensure_wintun_dll() {
            Ok(dll_path) => log(format!("Wintun DLL available at: {}", dll_path.display())),
            Err(e) => {
                log(format!("Failed to ensure wintun.dll: {e}"));
                return Err(e.into());
            }
        }
    }

    let server: SocketAddr = format!("{}:{}", cfg.server_addr, cfg.server_port)
        .parse()
        .with_context(|| "server_addr/server_port is not a valid socket address")?;

    // Bind an ephemeral UDP socket.
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind UDP socket")?;
    log(format!("UDP socket bound: {}", sock.local_addr()?));

    // Periodic keepalive packet (placeholder).
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let msg = b"bonding-client:hello";
                let _ = sock.send_to(msg, server).await;
                log(format!("Sent keepalive to {server}"));
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
