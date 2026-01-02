use crate::config as cfg_io;
use crate::runtime;
use anyhow::{anyhow, Context, Result};
use bonding_core::control::BondingConfig;
use chrono::Local;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Terminal,
};
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::watch;

type RunnerJoinHandle = tokio::task::JoinHandle<()>;
type RunnerState = (watch::Sender<bool>, Option<RunnerJoinHandle>);
type SharedRunner = Arc<Mutex<RunnerState>>;

/// Log entry with timestamp and severity level
#[derive(Clone)]
struct LogEntry {
    timestamp: String,
    message: String,
    level: LogLevel,
}

#[derive(Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl LogLevel {
    fn color(&self) -> Color {
        match self {
            LogLevel::Info => Color::White,
            LogLevel::Success => Color::Green,
            LogLevel::Warning => Color::Yellow,
            LogLevel::Error => Color::Red,
        }
    }

    fn prefix(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Success => " OK ",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERR ",
        }
    }
}

struct UiState {
    config_path: PathBuf,
    config: BondingConfig,
    running: bool,
    logs: VecDeque<LogEntry>,
    log_scroll: usize,
    start_time: Option<Instant>,
}

impl UiState {
    fn push_log(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        let level = Self::detect_level(&msg);
        let entry = LogEntry {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            message: msg,
            level,
        };
        self.logs.push_back(entry);
        while self.logs.len() > 500 {
            self.logs.pop_front();
        }
        // Auto-scroll to bottom on new message
        self.log_scroll = self.logs.len().saturating_sub(1);
    }

    fn detect_level(msg: &str) -> LogLevel {
        let lower = msg.to_lowercase();
        if lower.contains("error") || lower.contains("failed") || lower.contains("fatal") {
            LogLevel::Error
        } else if lower.contains("warning") || lower.contains("warn") {
            LogLevel::Warning
        } else if lower.contains("success")
            || lower.contains("connected")
            || lower.contains("started")
        {
            LogLevel::Success
        } else {
            LogLevel::Info
        }
    }

    fn uptime(&self) -> Option<String> {
        self.start_time.map(|t| {
            let secs = t.elapsed().as_secs();
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            let secs = secs % 60;
            if hours > 0 {
                format!("{:02}:{:02}:{:02}", hours, mins, secs)
            } else {
                format!("{:02}:{:02}", mins, secs)
            }
        })
    }
}

pub async fn run(config_path: PathBuf, config: BondingConfig) -> Result<()> {
    let handle = Handle::current();

    let state = Arc::new(Mutex::new(UiState {
        config_path,
        config: config.clone(),
        running: false,
        logs: VecDeque::new(),
        log_scroll: 0,
        start_time: None,
    }));

    {
        let mut s = state.lock().unwrap();
        s.push_log("Welcome to Bonding Client");
        s.push_log("Press 's' to start/stop, 'r' to reload config, 'q' to quit");
        s.push_log("Use ↑/↓ or Page Up/Down to scroll logs");
    }

    // Runner control
    let (stop_tx, stop_rx) = watch::channel(false);
    let runner: SharedRunner = Arc::new(Mutex::new((stop_tx, None)));

    // Run the UI on a blocking thread. Make sure we restore the terminal even if the UI panics.
    tokio::task::spawn_blocking(move || run_ui_blocking(handle, state, runner, stop_rx, config))
        .await
        .context("UI task join failed")??;

    Ok(())
}

fn run_ui_blocking(
    handle: Handle,
    state: Arc<Mutex<UiState>>,
    runner: SharedRunner,
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
    runner: SharedRunner,
    stop_rx: watch::Receiver<bool>,
    _initial_config: BondingConfig,
) -> Result<()> {
    let (mut terminal, _cleanup) = setup_terminal()?;

    let mut tick = std::time::Instant::now();

    loop {
        // Snapshot state outside the draw closure so we can handle errors here.
        let (running, config_path, cfg, logs_snapshot, log_scroll, uptime) = {
            let s = state
                .lock()
                .map_err(|_| anyhow!("UI state lock poisoned"))?;
            (
                s.running,
                s.config_path.clone(),
                s.config.clone(),
                s.logs.clone(),
                s.log_scroll,
                s.uptime(),
            )
        };

        terminal.draw(|f| {
            let area = f.area();

            // Main layout with header, config, logs, and footer
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header
                    Constraint::Length(9), // Config panel
                    Constraint::Min(8),    // Logs
                    Constraint::Length(3), // Help bar
                ])
                .split(area);

            // ═══════════════════════════════════════════════════════════════
            // HEADER
            // ═══════════════════════════════════════════════════════════════
            let status_icon = if running { "●" } else { "○" };
            let status_text = if running { "RUNNING" } else { "STOPPED" };
            let status_color = if running {
                Color::Green
            } else {
                Color::DarkGray
            };

            let uptime_text = uptime.map(|u| format!("  ⏱ {}", u)).unwrap_or_default();

            let header = Paragraph::new(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    "BONDING CLIENT",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} {}", status_icon, status_text),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(uptime_text, Style::default().fg(Color::DarkGray)),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            f.render_widget(header, chunks[0]);

            // ═══════════════════════════════════════════════════════════════
            // CONFIGURATION PANEL
            // ═══════════════════════════════════════════════════════════════
            let key_style = Style::default().fg(Color::DarkGray);
            let val_style = Style::default().fg(Color::White);
            let path_style = Style::default().fg(Color::Blue);

            let enc_status = if cfg.enable_encryption {
                if cfg
                    .encryption_key_b64
                    .as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    Span::styled("✓ Enabled", Style::default().fg(Color::Green))
                } else {
                    Span::styled("⚠ No Key", Style::default().fg(Color::Yellow))
                }
            } else {
                Span::styled("✗ Disabled", Style::default().fg(Color::DarkGray))
            };

            let cfg_lines = vec![
                Line::from(vec![
                    Span::styled("  Config    ", key_style),
                    Span::styled(config_path.display().to_string(), path_style),
                ]),
                Line::from(vec![
                    Span::styled("  Server    ", key_style),
                    Span::styled(
                        format!("{}:{}", cfg.server_addr, cfg.server_port),
                        val_style,
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Mode      ", key_style),
                    Span::styled(
                        cfg.bonding_mode.to_string(),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::styled("    MTU ", key_style),
                    Span::styled(cfg.mtu.to_string(), val_style),
                ]),
                Line::from(vec![
                    Span::styled("  TUN       ", key_style),
                    if cfg.enable_tun {
                        Span::styled("✓ Enabled", Style::default().fg(Color::Green))
                    } else {
                        Span::styled("✗ Disabled", Style::default().fg(Color::DarkGray))
                    },
                ]),
                Line::from(vec![Span::styled("  Encrypt   ", key_style), enc_status]),
                Line::from(vec![
                    Span::styled("  Health    ", key_style),
                    Span::styled(format!("{:?}", cfg.health_check_interval), val_style),
                ]),
            ];

            let cfg_widget = Paragraph::new(Text::from(cfg_lines)).block(
                Block::default()
                    .title(Span::styled(
                        " Configuration ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(cfg_widget, chunks[1]);

            // ═══════════════════════════════════════════════════════════════
            // LOGS PANEL
            // ═══════════════════════════════════════════════════════════════
            let logs_area = chunks[2];
            let inner_height = logs_area.height.saturating_sub(2) as usize;
            let total_logs = logs_snapshot.len();

            // Calculate visible window
            let start_idx = log_scroll.saturating_sub(inner_height.saturating_sub(1));
            let end_idx = (start_idx + inner_height).min(total_logs);

            let log_lines: Vec<Line> = logs_snapshot
                .iter()
                .skip(start_idx)
                .take(end_idx - start_idx)
                .map(|entry| {
                    Line::from(vec![
                        Span::styled(
                            format!(" {} ", entry.timestamp),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("[{}] ", entry.level.prefix()),
                            Style::default()
                                .fg(entry.level.color())
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(&entry.message, Style::default().fg(entry.level.color())),
                    ])
                })
                .collect();

            let scroll_info = if total_logs > inner_height {
                format!(" {}/{} ", end_idx, total_logs)
            } else {
                String::new()
            };

            let logs = Paragraph::new(Text::from(log_lines)).block(
                Block::default()
                    .title(Span::styled(
                        " Logs ",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .title_bottom(Line::from(scroll_info).alignment(Alignment::Right))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(logs, logs_area);

            // Scrollbar
            if total_logs > inner_height {
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(Some("▲"))
                    .end_symbol(Some("▼"))
                    .track_symbol(Some("│"))
                    .thumb_symbol("█");
                let mut scrollbar_state = ScrollbarState::new(total_logs).position(log_scroll);
                let scrollbar_area = Rect {
                    x: logs_area.x + logs_area.width - 1,
                    y: logs_area.y + 1,
                    width: 1,
                    height: logs_area.height.saturating_sub(2),
                };
                f.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
            }

            // ═══════════════════════════════════════════════════════════════
            // HELP BAR
            // ═══════════════════════════════════════════════════════════════
            let help_items = [
                ("s", if running { "Stop" } else { "Start" }),
                ("r", "Reload"),
                ("↑↓", "Scroll"),
                ("q", "Quit"),
            ];

            let help_spans: Vec<Span> = help_items
                .iter()
                .enumerate()
                .flat_map(|(i, (key, desc))| {
                    let mut spans = vec![
                        Span::styled(
                            format!(" {} ", key),
                            Style::default().fg(Color::Black).bg(Color::DarkGray),
                        ),
                        Span::styled(format!(" {} ", desc), Style::default().fg(Color::White)),
                    ];
                    if i < help_items.len() - 1 {
                        spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
                    }
                    spans
                })
                .collect();

            let help = Paragraph::new(Line::from(help_spans))
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(help, chunks[3]);
        })?;

        // Input handling
        let timeout = Duration::from_millis(100);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        s.log_scroll = s.log_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        let max_scroll = s.logs.len().saturating_sub(1);
                        s.log_scroll = (s.log_scroll + 1).min(max_scroll);
                    }
                    KeyCode::PageUp => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        s.log_scroll = s.log_scroll.saturating_sub(10);
                    }
                    KeyCode::PageDown => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        let max_scroll = s.logs.len().saturating_sub(1);
                        s.log_scroll = (s.log_scroll + 10).min(max_scroll);
                    }
                    KeyCode::Home => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        s.log_scroll = 0;
                    }
                    KeyCode::End => {
                        let mut s = state
                            .lock()
                            .map_err(|_| anyhow!("UI state lock poisoned"))?;
                        s.log_scroll = s.logs.len().saturating_sub(1);
                    }
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
                            s.start_time = None;
                            s.push_log("Stopping...");
                            // join in background
                            if let Some(h) = handle_opt.take() {
                                let _ = handle.block_on(h);
                            }
                            // reset stop channel to false for next run
                            let _ = stop_tx.send(false);
                            let mut s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            s.push_log("Stopped");
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
                                        s.start_time = None;
                                    }
                                }
                            });
                            *handle_opt = Some(task);

                            let mut s = state
                                .lock()
                                .map_err(|_| anyhow!("UI state lock poisoned"))?;
                            s.running = true;
                            s.start_time = Some(Instant::now());
                            s.push_log("Started");
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
