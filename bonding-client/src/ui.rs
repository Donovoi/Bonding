use crate::config as cfg_io;
use crate::runtime;
use anyhow::{anyhow, Context, Result};
use bonding_core::control::BondingConfig;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::watch;

struct UiState {
    config_path: PathBuf,
    config: BondingConfig,
    running: bool,
    logs: VecDeque<String>,
}

impl UiState {
    fn push_log(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.logs.push_back(msg);
        while self.logs.len() > 200 {
            self.logs.pop_front();
        }
    }
}

pub async fn run(config_path: PathBuf, config: BondingConfig) -> Result<()> {
    let handle = Handle::current();

    let state = Arc::new(Mutex::new(UiState {
        config_path,
        config: config.clone(),
        running: false,
        logs: VecDeque::new(),
    }));

    {
        let mut s = state.lock().unwrap();
        s.push_log("Press 's' to start/stop, 'r' reload config, 'q' quit");
    }

    // Runner control
    let (stop_tx, stop_rx) = watch::channel(false);
    let runner = Arc::new(Mutex::new((
        stop_tx,
        Option::<tokio::task::JoinHandle<()>>::None,
    )));

    // Run the UI on a blocking thread. Make sure we restore the terminal even if the UI panics.
    tokio::task::spawn_blocking(move || run_ui_blocking(handle, state, runner, stop_rx, config))
        .await
        .context("UI task join failed")??;

    Ok(())
}

fn run_ui_blocking(
    handle: Handle,
    state: Arc<Mutex<UiState>>,
    runner: Arc<Mutex<(watch::Sender<bool>, Option<tokio::task::JoinHandle<()>>)>>,
    stop_rx: watch::Receiver<bool>,
    initial_config: BondingConfig,
) -> Result<()> {
    // Prevent the default panic hook from spewing output while the terminal is in raw/alt-screen.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ui_loop(handle, state, runner, stop_rx, initial_config)
    }));

    std::panic::set_hook(prev_hook);

    match res {
        Ok(r) => r,
        Err(_) => Err(anyhow!(
            "UI panicked (terminal restored). Try `bonding-client run` if the UI keeps failing."
        )),
    }
}

fn ui_loop(
    handle: Handle,
    state: Arc<Mutex<UiState>>,
    runner: Arc<Mutex<(watch::Sender<bool>, Option<tokio::task::JoinHandle<()>>)>>,
    stop_rx: watch::Receiver<bool>,
    _initial_config: BondingConfig,
) -> Result<()> {
    let (mut terminal, _cleanup) = setup_terminal()?;

    let mut tick = std::time::Instant::now();

    loop {
        // Snapshot state outside the draw closure so we can handle errors here.
        let (running, config_path, cfg, logs_snapshot) = {
            let s = state
                .lock()
                .map_err(|_| anyhow!("UI state lock poisoned"))?;
            (
                s.running,
                s.config_path.clone(),
                s.config.clone(),
                s.logs.clone(),
            )
        };

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(8),
                    Constraint::Min(10),
                    Constraint::Length(2),
                ])
                .split(f.area());

            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    "Bonding Client",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  |  "),
                Span::styled(
                    if running { "RUNNING" } else { "STOPPED" },
                    Style::default()
                        .fg(if running { Color::Green } else { Color::Yellow })
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let cfg_text = Text::from(vec![
                Line::from(format!("Config: {}", config_path.display())),
                Line::from(format!("Server: {}:{}", cfg.server_addr, cfg.server_port)),
                Line::from(format!("Mode: {}", cfg.bonding_mode)),
                Line::from(format!("MTU: {}", cfg.mtu)),
                Line::from(format!(
                    "Encryption: {} | Health interval: {:?}",
                    cfg.enable_encryption, cfg.health_check_interval
                )),
            ]);

            let cfg_widget = Paragraph::new(cfg_text)
                .block(
                    Block::default()
                        .title("Configuration")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: true });
            f.render_widget(cfg_widget, chunks[1]);

            let log_lines: Vec<Line> = logs_snapshot
                .iter()
                .rev()
                .take(200)
                .rev()
                .map(|l| Line::from(l.as_str()))
                .collect();

            let logs = Paragraph::new(Text::from(log_lines))
                .block(Block::default().title("Logs").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            f.render_widget(logs, chunks[2]);

            let help = Paragraph::new("s start/stop  r reload config  q quit")
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(help, chunks[3]);
        })?;

        // Input handling
        let timeout = Duration::from_millis(200);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('r') => {
                        let (path, cfg) = {
                            let s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            (s.config_path.clone(), s.config.clone())
                        };
                        match cfg_io::load(&path) {
                            Ok(new_cfg) => {
                                let mut s = state
                                    .lock()
                                    .map_err(|_| anyhow!("UI state lock poisoned"))?;
                                s.config = new_cfg;
                                s.push_log("Config reloaded".to_string());
                            }
                            Err(e) => {
                                let mut s = state
                                    .lock()
                                    .map_err(|_| anyhow!("UI state lock poisoned"))?;
                                s.push_log(format!("Failed to reload config: {e}"));
                                s.config = cfg; // keep current
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        let mut runner_guard = runner
                            .lock()
                            .map_err(|_| anyhow!("UI runner lock poisoned"))?;
                        let (ref stop_tx, ref mut handle_opt) = *runner_guard;

                        if handle_opt.is_some() {
                            // request stop
                            let _ = stop_tx.send(true);
                            let mut s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            s.running = false;
                            s.push_log("Stopping...".to_string());
                            // join in background
                            if let Some(h) = handle_opt.take() {
                                let _ = handle.block_on(async { h.await });
                            }
                            // reset stop channel to false for next run
                            let _ = stop_tx.send(false);
                            let mut s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            s.push_log("Stopped".to_string());
                        } else {
                            // start
                            let cfg = {
                                state
                                    .lock()
                                    .map_err(|_| anyhow!("UI state lock poisoned"))?
                                    .config
                                    .clone()
                            };
                            let state2 = state.clone();
                            let stop_rx2 = stop_rx.clone();
                            let task = handle.spawn(async move {
                                let state_for_log = state2.clone();
                                let log = Box::new(move |msg: String| {
                                    if let Ok(mut s) = state_for_log.lock() {
                                        s.push_log(msg);
                                    }
                                });
                                if let Err(e) = runtime::run_client(cfg, stop_rx2, log).await {
                                    if let Ok(mut s) = state2.lock() {
                                        s.push_log(format!("Client error: {e}"));
                                        s.running = false;
                                    }
                                }
                            });
                            *handle_opt = Some(task);

                            let mut s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            s.running = true;
                            s.push_log("Started".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // lightweight tick
        if tick.elapsed() > Duration::from_secs(60) {
            tick = std::time::Instant::now();
        }
    }

    Ok(())
}

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        // Best-effort terminal restoration.
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, Show);
    }
}

fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, TerminalCleanup)> {
    enable_raw_mode().context("enable_raw_mode")?;
    let cleanup = TerminalCleanup;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, Hide).context("EnterAlternateScreen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create Terminal")?;
    terminal.clear().ok();
    Ok((terminal, cleanup))
}
