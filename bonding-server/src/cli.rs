use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "bonding-server",
    version,
    about = "Bonding server (with optional terminal UI)"
)]
pub struct Cli {
    /// Path to config file (TOML)
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launch the interactive terminal UI
    Ui,

    /// Run the server in the foreground (no UI)
    Run,

    /// Write a default config file (does not overwrite unless --force)
    InitConfig {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,
    },

    /// Print the resolved config file path
    PrintConfigPath,
}
