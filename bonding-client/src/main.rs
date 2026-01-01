use anyhow::Result;
use base64::Engine;
use bonding_client::{cli, config, runtime, ui};
use bonding_core::transport::PacketCrypto;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Attempt to elevate early (Wintun adapter creation requires admin).
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
            let mut cfg = bonding_core::control::BondingConfig::default();
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
            runtime::run_client(cfg, stop_rx, Box::new(|m| tracing::info!("{m}"))).await
        }
        cli::Command::Ui => {
            let cfg = config::load(&config_path)?;
            ui::run(config_path, cfg).await
        }
    }
}
