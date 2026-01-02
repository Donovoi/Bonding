//! Combined Bonding client/server binary with TUI mode selection.

use anyhow::Result;
use base64::Engine;
use bonding_core::transport::PacketCrypto;
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::io::stdout;
use std::path::PathBuf;

/// Bonding - Multi-path network bonding
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Override config file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Run as client (headless)
    Client {
        #[command(subcommand)]
        subcommand: Option<ClientCommand>,
    },
    /// Run as server (headless)
    Server {
        #[command(subcommand)]
        subcommand: Option<ServerCommand>,
    },
    /// Launch interactive mode selector (default)
    Ui,
}

#[derive(Subcommand, Debug, Clone)]
enum ClientCommand {
    /// Print the config file path
    PrintConfigPath,
    /// Initialize a default config file
    InitConfig {
        /// Overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
    /// Run the client directly (no TUI)
    Run,
    /// Run the client TUI
    Ui,
}

#[derive(Subcommand, Debug, Clone)]
enum ServerCommand {
    /// Print the config file path
    PrintConfigPath,
    /// Initialize a default config file
    InitConfig {
        /// Overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
    /// Run the server directly (no TUI)
    Run,
    /// Run the server TUI
    Ui,
}

/// Mode selection for the TUI menu
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Client,
    Server,
}

impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::Client => "Client",
            Mode::Server => "Server",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Mode::Client => "Connect to a Bonding server and bond multiple network paths",
            Mode::Server => "Run a Bonding server to accept client connections",
        }
    }
}

struct ModeSelector {
    modes: Vec<Mode>,
    state: ListState,
}

impl ModeSelector {
    fn new() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            modes: vec![Mode::Client, Mode::Server],
            state,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.modes.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.modes.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn selected(&self) -> Option<Mode> {
        self.state.selected().map(|i| self.modes[i])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Attempt to elevate early (Wintun adapter creation requires admin).
        if bonding_core::windows_admin::relaunch_as_admin_if_needed()? {
            return Ok(());
        }
    }

    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Ui) {
        Command::Client { subcommand } => run_client_mode(cli.config, subcommand).await,
        Command::Server { subcommand } => run_server_mode(cli.config, subcommand).await,
        Command::Ui => run_mode_selector().await,
    }
}

async fn run_client_mode(
    config_override: Option<PathBuf>,
    subcommand: Option<ClientCommand>,
) -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = match config_override {
        Some(p) => p,
        None => bonding_client::config::default_config_path()?,
    };

    match subcommand.unwrap_or(ClientCommand::Ui) {
        ClientCommand::PrintConfigPath => {
            println!("{}", config_path.display());
            Ok(())
        }
        ClientCommand::InitConfig { force } => {
            let mut cfg = bonding_core::control::BondingConfig::default();
            if cfg.enable_encryption {
                let key = PacketCrypto::generate_key();
                cfg.encryption_key_b64 =
                    Some(base64::engine::general_purpose::STANDARD.encode(key));
            }
            bonding_client::config::save(&config_path, &cfg, force)?;
            println!("Wrote default config to {}", config_path.display());
            Ok(())
        }
        ClientCommand::Run => {
            let cfg = bonding_client::config::load(&config_path)?;
            let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            bonding_client::runtime::run_client(cfg, stop_rx, Box::new(|m| tracing::info!("{m}")))
                .await
        }
        ClientCommand::Ui => {
            let cfg = bonding_client::config::load(&config_path)?;
            bonding_client::ui::run(config_path, cfg).await
        }
    }
}

async fn run_server_mode(
    config_override: Option<PathBuf>,
    subcommand: Option<ServerCommand>,
) -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = match config_override {
        Some(p) => p,
        None => bonding_server::config::default_config_path()?,
    };

    match subcommand.unwrap_or(ServerCommand::Ui) {
        ServerCommand::PrintConfigPath => {
            println!("{}", config_path.display());
            Ok(())
        }
        ServerCommand::InitConfig { force } => {
            let mut cfg = bonding_core::control::ServerConfig::default();
            if cfg.enable_encryption {
                let key = PacketCrypto::generate_key();
                cfg.encryption_key_b64 =
                    Some(base64::engine::general_purpose::STANDARD.encode(key));
            }
            bonding_server::config::save(&config_path, &cfg, force)?;
            println!("Wrote default config to {}", config_path.display());
            Ok(())
        }
        ServerCommand::Run => {
            let cfg = bonding_server::config::load(&config_path)?;
            let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            bonding_server::runtime::run_server(cfg, stop_rx, Box::new(|m| tracing::info!("{m}")))
                .await
        }
        ServerCommand::Ui => {
            let cfg = bonding_server::config::load(&config_path)?;
            bonding_server::ui::run(config_path, cfg).await
        }
    }
}

async fn run_mode_selector() -> Result<()> {
    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selector = ModeSelector::new();

    loop {
        terminal.draw(|f| draw_mode_selector(f, &mut selector))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        // Clean up terminal
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        return Ok(());
                    }
                    KeyCode::Up | KeyCode::Char('k') => selector.previous(),
                    KeyCode::Down | KeyCode::Char('j') => selector.next(),
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if let Some(mode) = selector.selected() {
                            // Clean up terminal before launching mode
                            disable_raw_mode()?;
                            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

                            return match mode {
                                Mode::Client => {
                                    run_client_mode(None, Some(ClientCommand::Ui)).await
                                }
                                Mode::Server => {
                                    run_server_mode(None, Some(ServerCommand::Ui)).await
                                }
                            };
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_mode_selector(f: &mut Frame, selector: &mut ModeSelector) {
    let size = f.area();

    // Create centered layout
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Min(15),
            Constraint::Percentage(25),
        ])
        .split(size);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Min(50),
            Constraint::Percentage(20),
        ])
        .split(vertical[1]);

    let center = horizontal[1];

    // Main block
    let block = Block::default()
        .title(" Bonding ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(center);
    f.render_widget(block, center);

    // Split inner area
    let inner_layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(1), // Spacer
            Constraint::Min(5),    // Menu
            Constraint::Length(1), // Spacer
            Constraint::Length(3), // Description
            Constraint::Length(2), // Help
        ])
        .split(inner);

    // Title
    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Multi-Path ", Style::default().fg(Color::White)),
            Span::styled(
                "Network Bonding",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Select Mode:",
            Style::default().fg(Color::Yellow),
        )),
    ])
    .alignment(Alignment::Center);
    f.render_widget(title, inner_layout[0]);

    // Mode list
    let items: Vec<ListItem> = selector
        .modes
        .iter()
        .map(|mode| {
            let icon = match mode {
                Mode::Client => "󰒍 ",
                Mode::Server => "󰒋 ",
            };
            ListItem::new(Line::from(vec![Span::raw(icon), Span::raw(mode.name())]))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, inner_layout[2], &mut selector.state);

    // Description of selected mode
    if let Some(mode) = selector.selected() {
        let desc = Paragraph::new(mode.description())
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);
        f.render_widget(desc, inner_layout[4]);
    }

    // Help text
    let help = Paragraph::new(Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" Navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" Select  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" Quit"),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(help, inner_layout[5]);
}
