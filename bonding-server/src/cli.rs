use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser, PartialEq, Eq)]
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

#[derive(Debug, Subcommand, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run_with_config_override() {
        let cli = Cli::try_parse_from(["bonding-server", "--config", "/tmp/server.toml", "run"])
            .expect("run command should parse");

        assert_eq!(
            cli,
            Cli {
                config: Some(PathBuf::from("/tmp/server.toml")),
                command: Some(Command::Run),
            }
        );
    }

    #[test]
    fn parses_init_config_force() {
        let cli = Cli::try_parse_from(["bonding-server", "init-config", "--force"])
            .expect("init-config should parse");

        assert_eq!(
            cli,
            Cli {
                config: None,
                command: Some(Command::InitConfig { force: true }),
            }
        );
    }

    #[test]
    fn defaults_to_no_subcommand() {
        let cli = Cli::try_parse_from(["bonding-server"]).expect("default invocation should parse");

        assert_eq!(
            cli,
            Cli {
                config: None,
                command: None,
            }
        );
    }
}
