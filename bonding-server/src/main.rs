use anyhow::Result;
use base64::Engine;
use bonding_core::transport::PacketCrypto;

mod cli;
mod config;
mod runtime;
mod ui;

#[cfg(target_os = "linux")]
mod linux_tun_config;

#[cfg(target_os = "linux")]
mod linux_nat_config;

#[cfg(target_os = "windows")]
mod wintun_loader;

#[cfg(target_os = "windows")]
mod windows_tun_config;

#[cfg(target_os = "windows")]
mod windows_nat_config;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Attempt to elevate early (keeps behavior consistent with the client on Windows).
        if bonding_core::windows_admin::relaunch_as_admin_if_needed()? {
            return Ok(());
        }
    }

    tracing_subscriber::fmt::init();

    let cli = <cli::Cli as clap::Parser>::parse();
    let config_path = match cli.config {
        Some(p) => p,
        None => config::default_config_path()?,
    };

    match cli.command.unwrap_or(cli::Command::Ui) {
        cli::Command::PrintConfigPath => {
            println!("{}", config_path.display());
            Ok(())
        }
        cli::Command::InitConfig { force } => {
            let mut cfg = bonding_core::control::ServerConfig::default();
            if cfg.enable_encryption {
                let key = PacketCrypto::generate_key();
                cfg.encryption_key_b64 =
                    Some(base64::engine::general_purpose::STANDARD.encode(key));
            }
            config::save(&config_path, &cfg, force)?;
            println!("Wrote default config to {}", config_path.display());
            Ok(())
        }
        cli::Command::Run => {
            let cfg = config::load(&config_path)?;
            let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            runtime::run_server(cfg, stop_rx, Box::new(|m| tracing::info!("{m}"))).await
        }
        cli::Command::Ui => {
            let cfg = config::load(&config_path)?;
            ui::run(config_path, cfg).await
        }
    }
}
