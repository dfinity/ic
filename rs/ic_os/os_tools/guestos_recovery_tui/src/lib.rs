mod ui;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend};
use std::io::{self, BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

// ============================================================================
// Constants
// ============================================================================

// Field length constants
const VERSION_LENGTH: usize = 40; // Git commit hash length (hex characters)
const HASH_LENGTH: usize = 64; // SHA256 hash length (hex characters)

// Process monitoring constants
const MAX_ERROR_LINES: usize = 30; // Maximum number of error lines to display
const PROCESS_POLL_INTERVAL_MS: u64 = 100; // Polling interval for process monitoring

// ============================================================================
// Terminal Management
// ============================================================================

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode().context("Failed to enable raw mode")?;

    let mut stdout = io::stdout();
    // Try to enter alternate screen mode, but don't fail if it doesn't work
    let _ = execute!(stdout, EnterAlternateScreen);

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;
    terminal.clear().context("Failed to clear terminal")?;

    Ok(terminal)
}

fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().context("Failed to disable raw mode")?;
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    terminal.show_cursor().context("Failed to show cursor")?;
    Ok(())
}

/// Guard struct to ensure terminal cleanup on panic
struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
}

impl TerminalGuard {
    fn new(terminal: Terminal<CrosstermBackend<io::Stdout>>) -> Self {
        Self {
            terminal: Some(terminal),
        }
    }

    fn get_mut(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        self.terminal.as_mut().unwrap()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(ref mut terminal) = self.terminal {
            let _ = teardown_terminal(terminal);
        }
    }
}

// ============================================================================
// Command Building
// ============================================================================

fn build_upgrader_command(params: &RecoveryParams) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg("/opt/ic/bin/guestos-recovery-upgrader.sh")
        .arg(format!("version={}", params.version))
        .arg(format!("version-hash={}", params.version_hash))
        .arg(format!("recovery-hash={}", params.recovery_hash));
    cmd
}

// ============================================================================
// Types and Data Structures
// ============================================================================

enum InputResult {
    Continue,
    Exit,
    Proceed,
}

#[derive(Default, Clone)]
pub struct RecoveryParams {
    /// The commit ID of the recovery-GuestOS update image (40 hex characters)
    pub version: String,
    /// The SHA256 sum of the recovery-GuestOS update image (64 hex characters)
    pub version_hash: String,
    /// The SHA256 sum of the recovery.tar.zst (64 hex characters)
    pub recovery_hash: String,
}

impl RecoveryParams {
    pub fn validate(&self) -> Result<()> {
        if let Some(len) = Field::Version.required_length() {
            Self::validate_hex_field(&self.version, len, "VERSION", "Git commit hash")?;
        }
        if let Some(len) = Field::VersionHash.required_length() {
            Self::validate_hex_field(&self.version_hash, len, "VERSION-HASH", "SHA256")?;
        }
        if let Some(len) = Field::RecoveryHash.required_length() {
            Self::validate_hex_field(&self.recovery_hash, len, "RECOVERY-HASH", "SHA256")?;
        }
        Ok(())
    }

    fn validate_hex_field(value: &str, len: usize, name: &str, description: &str) -> Result<()> {
        if value.is_empty() {
            anyhow::bail!("{} is required", name);
        }
        if value.len() != len || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "{} must be exactly {} hexadecimal characters ({})",
                name,
                len,
                description
            );
        }
        Ok(())
    }
}

#[derive(PartialEq, Copy, Clone)]
pub(crate) enum Field {
    Version,
    VersionHash,
    RecoveryHash,
    CheckArtifactsButton,
    ExitButton,
}

impl Field {
    const ALL: &'static [Field] = &[
        Field::Version,
        Field::VersionHash,
        Field::RecoveryHash,
        Field::CheckArtifactsButton,
        Field::ExitButton,
    ];

    const INPUT_FIELDS: &'static [Field] =
        &[Field::Version, Field::VersionHash, Field::RecoveryHash];

    fn next(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + 1) % Self::ALL.len()]
    }

    fn previous(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn is_input_field(&self) -> bool {
        Self::INPUT_FIELDS.contains(self)
    }

    /// Returns the required length for this field
    fn required_length(&self) -> Option<usize> {
        match self {
            Field::Version => Some(VERSION_LENGTH),
            Field::VersionHash | Field::RecoveryHash => Some(HASH_LENGTH),
            _ => None,
        }
    }

    fn get_value_mut<'a>(&self, params: &'a mut RecoveryParams) -> Option<&'a mut String> {
        match self {
            Field::Version => Some(&mut params.version),
            Field::VersionHash => Some(&mut params.version_hash),
            Field::RecoveryHash => Some(&mut params.recovery_hash),
            _ => None,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Field::Version => "VERSION:",
            Field::VersionHash => "VERSION-HASH:",
            Field::RecoveryHash => "RECOVERY-HASH:",
            _ => "",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Field::Version => {
                "Mandatory. The commit ID of the recovery-GuestOS update image (40 hex characters)."
            }
            Field::VersionHash => {
                "Mandatory. The SHA256 sum of the recovery-GuestOS update image (64 hex characters)."
            }
            Field::RecoveryHash => {
                "Mandatory. The SHA256 sum of the recovery.tar.zst (64 hex characters)."
            }
            _ => "",
        }
    }

    fn get_value<'a>(&self, params: &'a RecoveryParams) -> &'a str {
        match self {
            Field::Version => &params.version,
            Field::VersionHash => &params.version_hash,
            Field::RecoveryHash => &params.recovery_hash,
            _ => "",
        }
    }
}

pub struct App {
    current_field: Field,
    params: RecoveryParams,
    error_message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            current_field: Field::Version,
            params: RecoveryParams::default(),
            error_message: None,
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    fn clear_error(&mut self) {
        self.error_message = None;
    }

    fn continue_without_error(&mut self) -> InputResult {
        self.clear_error();
        InputResult::Continue
    }

    fn teardown_and_error(
        mut terminal_guard: TerminalGuard,
        e: impl Into<anyhow::Error>,
        context: impl FnOnce() -> String,
    ) -> Result<Option<RecoveryParams>> {
        let mut term = terminal_guard.terminal.take().unwrap();
        teardown_terminal(&mut term)?;
        Err(e.into()).with_context(context)
    }

    fn handle_input_char(&mut self, c: char) {
        match (
            self.current_field.required_length(),
            self.current_field.get_value_mut(&mut self.params),
        ) {
            (Some(max_len), Some(field_value))
                if field_value.len() < max_len && c.is_ascii_hexdigit() =>
            {
                field_value.push(c);
                self.clear_error();
            }
            _ => {}
        }
    }

    fn handle_backspace(&mut self) {
        if let Some(field_value) = self.current_field.get_value_mut(&mut self.params) {
            field_value.pop();
            self.clear_error();
        }
    }

    /// Runs the interactive TUI and returns the recovery parameters if the user proceeds.
    /// Returns `None` if the user exits without proceeding.
    pub fn run(&mut self) -> Result<Option<RecoveryParams>> {
        if !atty::is(atty::Stream::Stdout) || !atty::is(atty::Stream::Stdin) {
            anyhow::bail!(
                "This program requires an interactive terminal.\n\
                VS Code terminal and regular terminals should work.\n\
                Make sure you're not piping or redirecting output."
            );
        }

        let terminal = setup_terminal()?;
        let mut terminal_guard = TerminalGuard::new(terminal);

        let test_size = terminal_guard.get_mut().size()?;
        if let Err(e) = ui::validate_terminal_size(test_size) {
            return Self::teardown_and_error(terminal_guard, e, || {
                "Terminal size validation failed".to_string()
            });
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        terminal_guard
            .get_mut()
            .draw(|f: &mut Frame| ui::render_app_ui(self, f))?;

        let result = loop {
            match event::read() {
                Ok(Event::Key(key)) => {
                    if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            break Ok(None);
                        }

                        let needs_redraw = match self.handle_input(key)? {
                            InputResult::Continue => true,
                            InputResult::Exit => break Ok(None),
                            InputResult::Proceed => match self.params.validate() {
                                Ok(_) => break Ok(Some(self.params.clone())),
                                Err(e) => {
                                    self.error_message = Some(e.to_string());
                                    true
                                }
                            },
                        };

                        if needs_redraw
                            && let Err(e) = terminal_guard
                                .get_mut()
                                .draw(|f: &mut Frame| ui::render_app_ui(self, f))
                        {
                            return Self::teardown_and_error(terminal_guard, e, || {
                                "Failed to render TUI - terminal may not support required features"
                                    .to_string()
                            });
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    return Self::teardown_and_error(terminal_guard, e, || {
                        "Failed to read terminal events - terminal may not support required features".to_string()
                    });
                }
            }
        };

        execute!(terminal_guard.get_mut().backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;
        result
    }

    fn handle_input(&mut self, key: KeyEvent) -> Result<InputResult> {
        match key.code {
            KeyCode::Esc => Ok(InputResult::Exit),

            KeyCode::Enter => {
                if self.current_field.is_input_field() {
                    self.current_field = self.current_field.next();
                    Ok(self.continue_without_error())
                } else {
                    Ok(match self.current_field {
                        Field::ExitButton => InputResult::Exit,
                        Field::CheckArtifactsButton => InputResult::Proceed,
                        _ => InputResult::Continue,
                    })
                }
            }

            KeyCode::Tab | KeyCode::Down => {
                self.current_field = self.current_field.next();
                Ok(self.continue_without_error())
            }

            KeyCode::Up => {
                self.current_field = self.current_field.previous();
                Ok(self.continue_without_error())
            }

            KeyCode::Left | KeyCode::Right => {
                if matches!(
                    self.current_field,
                    Field::CheckArtifactsButton | Field::ExitButton
                ) {
                    self.current_field = match self.current_field {
                        Field::CheckArtifactsButton => Field::ExitButton,
                        Field::ExitButton => Field::CheckArtifactsButton,
                        _ => unreachable!(),
                    };
                    self.clear_error();
                }
                Ok(InputResult::Continue)
            }

            KeyCode::Char(c) if self.current_field.is_input_field() => {
                self.handle_input_char(c);
                Ok(InputResult::Continue)
            }

            KeyCode::Backspace if self.current_field.is_input_field() => {
                self.handle_backspace();
                Ok(InputResult::Continue)
            }

            _ => Ok(InputResult::Continue),
        }
    }
}

// ============================================================================
// Process and Log Monitoring
// ============================================================================

/// Parses log lines from bytes, filtering out empty lines
fn parse_log_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .collect()
}

/// Spawns a thread to read lines from a stream and append them to a shared log buffer
fn spawn_log_reader_thread<R>(
    stream: R,
    log_lines: Arc<Mutex<Vec<String>>>,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let mut logs = log_lines.lock().unwrap();
                    logs.push(line);
                }
                Err(_) => break,
            }
        }
    })
}

/// Detects success message in stdout
fn detect_success_message(stdout_lines: &[String]) -> Option<String> {
    const SUCCESS_INDICATOR: &str = "Recovery Upgrader completed successfully";
    stdout_lines
        .iter()
        .find(|line| line.contains(SUCCESS_INDICATOR))
        .map(|_| SUCCESS_INDICATOR.to_string())
}

/// Monitors a child process, displaying real-time logs in the terminal.
/// Returns the process exit status and all collected logs.
fn monitor_process_with_logs(
    mut child: std::process::Child,
    stdout_handle: thread::JoinHandle<()>,
    stderr_handle: thread::JoinHandle<()>,
    log_lines: Arc<Mutex<Vec<String>>>,
    terminal_guard: &mut TerminalGuard,
    params: &RecoveryParams,
) -> Result<(std::process::ExitStatus, Vec<String>)> {
    let mut last_log_count = 0;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                stdout_handle.join().ok();
                stderr_handle.join().ok();
                break status;
            }
            Ok(None) => {
                let logs = log_lines.lock().unwrap();
                let current_count = logs.len();
                // Only redraw if we have new logs
                if current_count > last_log_count {
                    let current_logs: Vec<String> = logs.clone();
                    drop(logs);

                    terminal_guard
                        .get_mut()
                        .draw(|f| ui::draw_logs_screen(f, params, &current_logs))
                        .ok();

                    last_log_count = current_count;
                } else {
                    drop(logs);
                }

                thread::sleep(std::time::Duration::from_millis(PROCESS_POLL_INTERVAL_MS));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Error waiting for process: {}", e));
            }
        }
    };

    let logs = log_lines.lock().unwrap();
    let all_logs: Vec<String> = logs.clone();
    drop(logs);

    Ok((status, all_logs))
}

/// Extracts errors from stdout/stderr
fn extract_errors_from_logs(stdout_lines: &[String], stderr_lines: &[String]) -> Vec<String> {
    if !stderr_lines.is_empty() {
        let start = stderr_lines.len().saturating_sub(MAX_ERROR_LINES);
        stderr_lines[start..].to_vec()
    } else if !stdout_lines.is_empty() {
        let start = stdout_lines.len().saturating_sub(MAX_ERROR_LINES);
        stdout_lines[start..].to_vec()
    } else {
        Vec::new()
    }
}

// ============================================================================
// Main Execution
// ============================================================================

/// Displays a status screen and runs the recovery upgrader script with the given parameters.
/// Shows real-time logs and a completion screen with results.
pub fn show_status_and_run_upgrader(params: &RecoveryParams) -> Result<()> {
    let terminal = setup_terminal()?;
    let mut terminal_guard = TerminalGuard::new(terminal);

    terminal_guard
        .get_mut()
        .draw(|f| ui::draw_status_screen(f, params))?;

    if params.version.is_empty() || params.version_hash.is_empty() {
        anyhow::bail!("Invalid parameters: version and version-hash must be non-empty");
    }

    let mut cmd = build_upgrader_command(params);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn recovery upgrader")?;

    let log_lines = Arc::new(Mutex::new(Vec::<String>::new()));

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdout handle"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stderr handle"))?;

    let stdout_handle = spawn_log_reader_thread(stdout, Arc::clone(&log_lines));
    let stderr_handle = spawn_log_reader_thread(stderr, Arc::clone(&log_lines));

    let (status, all_logs) = monitor_process_with_logs(
        child,
        stdout_handle,
        stderr_handle,
        log_lines,
        &mut terminal_guard,
        params,
    )?;

    let output = std::process::Output {
        status,
        stdout: all_logs.join("\n").into_bytes(),
        stderr: vec![],
    };

    let stdout_lines = parse_log_lines(&output.stdout);
    let stderr_lines = parse_log_lines(&output.stderr);

    let success_message = detect_success_message(&stdout_lines);
    let error_messages = if output.status.success() {
        Vec::new()
    } else {
        extract_errors_from_logs(&stdout_lines, &stderr_lines)
    };

    let success = output.status.success();
    terminal_guard.get_mut().draw(|f| {
        ui::draw_completion_screen(
            f,
            success,
            &success_message,
            &output,
            &stdout_lines,
            &stderr_lines,
            &error_messages,
            params,
        );
    })?;

    if let Event::Key(_) = event::read()? {}

    let mut terminal = terminal_guard.terminal.take().unwrap();
    let _ = terminal.clear();
    teardown_terminal(&mut terminal)?;

    if !output.status.success() {
        anyhow::bail!(
            "Recovery upgrader failed with exit code: {:?}",
            output.status.code()
        );
    }

    if let Some(ref msg) = success_message {
        eprintln!("{}", msg);
    } else if output.status.success() {
        eprintln!("Recovery completed successfully!");
    }

    Ok(())
}
