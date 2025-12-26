use anyhow::Result;

mod cli;
mod config;
mod runtime;
mod ui;

#[cfg(target_os = "windows")]
mod wintun_loader;

#[tokio::main]
async fn main() -> Result<()> {
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
            let cfg = bonding_core::control::BondingConfig::default();
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
