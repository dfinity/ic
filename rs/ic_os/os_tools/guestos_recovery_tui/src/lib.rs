mod ui;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode, size,
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend, layout::Rect};
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
        self.terminal
            .as_mut()
            .expect("TerminalGuard: terminal was already taken.")
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

/// Represents the action to take after processing user input
enum Action {
    /// Continue the event loop and redraw the UI
    Redraw,
    /// Exit the application without proceeding
    Exit,
    /// Proceed with recovery (after validation)
    Proceed,
    /// No action needed (no redraw required)
    NoOp,
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
            Self::validate_hex_field(
                &self.version_hash,
                len,
                "VERSION-HASH",
                "Recovery-GuestOS SHA256",
            )?;
        }
        if let Some(len) = Field::RecoveryHash.required_length() {
            Self::validate_hex_field(
                &self.recovery_hash,
                len,
                "RECOVERY-HASH",
                "Recovery archive SHA256",
            )?;
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

struct FieldMetadata {
    label: &'static str,
    description: &'static str,
    required_len: Option<usize>,
    is_input: bool,
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

    fn metadata(&self) -> FieldMetadata {
        match self {
            Field::Version => FieldMetadata {
                label: "VERSION:",
                description: "Mandatory. The commit ID of the recovery-GuestOS update image (40 hex characters).",
                required_len: Some(VERSION_LENGTH),
                is_input: true,
            },
            Field::VersionHash => FieldMetadata {
                label: "VERSION-HASH:",
                description: "Mandatory. The SHA256 sum of the recovery-GuestOS update image (64 hex characters).",
                required_len: Some(HASH_LENGTH),
                is_input: true,
            },
            Field::RecoveryHash => FieldMetadata {
                label: "RECOVERY-HASH:",
                description: "Mandatory. The SHA256 sum of the recovery.tar.zst (64 hex characters).",
                required_len: Some(HASH_LENGTH),
                is_input: true,
            },
            _ => FieldMetadata {
                label: "",
                description: "",
                required_len: None,
                is_input: false,
            },
        }
    }

    fn next(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + 1) % Self::ALL.len()]
    }

    fn previous(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn is_input_field(&self) -> bool {
        self.metadata().is_input
    }

    /// Returns the required length for this field
    fn required_length(&self) -> Option<usize> {
        self.metadata().required_len
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
        self.metadata().label
    }

    fn description(&self) -> &'static str {
        self.metadata().description
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
    exit_message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            current_field: Field::Version,
            params: RecoveryParams::default(),
            error_message: None,
            exit_message: None,
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

    /// Redraws the UI, handling any errors
    fn redraw(&self, terminal_guard: &mut TerminalGuard) -> Result<()> {
        let _ = terminal_guard
            .get_mut()
            .draw(|f: &mut Frame| ui::render_app_ui(self, f))
            .map_err(|e| {
                anyhow::anyhow!("Failed to render TUI - terminal may not support required features")
                    .context(e)
            })?;
        Ok(())
    }

    fn teardown_and_error(
        mut terminal_guard: TerminalGuard,
        e: impl Into<anyhow::Error>,
        context: impl FnOnce() -> String,
    ) -> Result<Option<RecoveryParams>> {
        let mut term = terminal_guard
            .terminal
            .take()
            .expect("TerminalGuard: terminal was already taken.");
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

        let terminal_size = terminal_guard.get_mut().size()?;
        let test_size = Rect::new(0, 0, terminal_size.width, terminal_size.height);
        if let Err(e) = ui::validate_terminal_size(test_size) {
            return Self::teardown_and_error(terminal_guard, e, || {
                "Terminal size validation failed".to_string()
            });
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        self.redraw(&mut terminal_guard)?;

        let result = loop {
            // Read event with error handling
            let event = match event::read() {
                Ok(event) => event,
                Err(e) => {
                    return Self::teardown_and_error(terminal_guard, e, || {
                        "Failed to read terminal events - terminal may not support required features"
                            .to_string()
                    });
                }
            };

            // Early continue for non-key events or non-press events
            let key = match event {
                Event::Key(key)
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    key
                }
                _ => continue,
            };

            // Handle Ctrl+C first (special case)
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                break Ok(None);
            }

            // Process input and get action
            let action = self.process_input(key)?;

            // Handle action
            match action {
                Action::Exit => {
                    self.exit_message = Some("Recovery cancelled by user".to_string());
                    self.redraw(&mut terminal_guard)?;
                    break Ok(None);
                }
                Action::Proceed => match self.params.validate() {
                    Ok(_) => break Ok(Some(self.params.clone())),
                    Err(e) => {
                        self.error_message = Some(e.to_string());
                        self.redraw(&mut terminal_guard)?;
                    }
                },
                Action::Redraw => {
                    self.redraw(&mut terminal_guard)?;
                }
                Action::NoOp => {}
            }
        };

        execute!(terminal_guard.get_mut().backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;
        result
    }

    /// Processes a key event and returns the action to take
    fn process_input(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Esc => Ok(Action::Exit),

            KeyCode::Enter => {
                if self.current_field.is_input_field() {
                    self.current_field = self.current_field.next();
                    self.clear_error();
                    Ok(Action::Redraw)
                } else {
                    Ok(match self.current_field {
                        Field::ExitButton => Action::Exit,
                        Field::CheckArtifactsButton => Action::Proceed,
                        _ => Action::NoOp,
                    })
                }
            }

            KeyCode::Tab | KeyCode::Down => {
                self.current_field = self.current_field.next();
                self.clear_error();
                Ok(Action::Redraw)
            }

            KeyCode::Up => {
                self.current_field = self.current_field.previous();
                self.clear_error();
                Ok(Action::Redraw)
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
                    Ok(Action::Redraw)
                } else {
                    Ok(Action::NoOp)
                }
            }

            KeyCode::Char(c) if self.current_field.is_input_field() => {
                self.handle_input_char(c);
                Ok(Action::Redraw)
            }

            KeyCode::Backspace if self.current_field.is_input_field() => {
                self.handle_backspace();
                Ok(Action::Redraw)
            }

            _ => Ok(Action::NoOp),
        }
    }
}

// ============================================================================
// Process and Log Monitoring
// ============================================================================

/// Spawns a thread to read lines from stdout and append them to a shared log buffer
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

/// Monitors a child process, displaying real-time logs in the terminal.
/// Returns the process exit status and all collected logs.
fn monitor_process_with_logs(
    mut child: std::process::Child,
    stdout_handle: thread::JoinHandle<()>,
    log_lines: Arc<Mutex<Vec<String>>>,
    terminal_guard: &mut TerminalGuard,
    params: &RecoveryParams,
) -> Result<(std::process::ExitStatus, Vec<String>)> {
    let mut last_log_count = 0;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                stdout_handle.join().ok();
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

/// Extracts the last N error lines from log output
fn extract_errors_from_logs(log_lines: &[String]) -> Vec<String> {
    if log_lines.is_empty() {
        return Vec::new();
    }
    let start = log_lines.len().saturating_sub(MAX_ERROR_LINES);
    log_lines[start..].to_vec()
}

// ============================================================================
// Success Message Printing
// ============================================================================

/// Prints a prominent success message to stderr (outside the TUI).
/// This message is designed to be highly visible and will appear in the normal
/// terminal after the TUI exits, before any subsequent service logs.
/// The message uses prominent formatting with borders and colors to stand out.
fn print_prominent_success_message(message: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    // ANSI color codes
    const GREEN: &str = "\x1b[32m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";
    const SEPARATOR_CHAR: &str = "═";

    // Get terminal width, defaulting to 80 if unavailable
    let width = size().map(|(w, _)| w as usize).unwrap_or(80).min(100); // Cap at 100 for readability

    let separator = SEPARATOR_CHAR.repeat(width);

    // Print prominent success message with borders, styling, and extra spacing
    // The extra blank lines help separate it from subsequent service logs
    let _ = writeln!(
        handle,
        "\n\n{}{}{}\n{}{}✓ {}{}{}\n{}{}{}\n\n",
        GREEN, separator, RESET, GREEN, BOLD, message, RESET, RESET, GREEN, separator, RESET
    );
    let _ = handle.flush();
}

// ============================================================================
// Main Execution
// ============================================================================

/// Displays a status screen and runs the recovery upgrader script with the given parameters.
/// Shows real-time logs and a completion screen with results.
pub fn show_status_and_run_upgrader(params: &RecoveryParams) -> Result<()> {
    if params.version.is_empty() || params.version_hash.is_empty() {
        anyhow::bail!("Invalid parameters: version and version-hash must be non-empty");
    }

    let status = {
        let terminal = setup_terminal()?;
        let mut terminal_guard = TerminalGuard::new(terminal);

        terminal_guard
            .get_mut()
            .draw(|f| ui::draw_status_screen(f, params))?;

        let mut cmd = build_upgrader_command(params);
        cmd.stdout(Stdio::piped());
        // Explicitly discard stderr - dd's status=progress output to stderr would clutter the display
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().context("Failed to spawn recovery upgrader")?;

        let log_lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout handle"))?;

        let stdout_handle = spawn_log_reader_thread(stdout, Arc::clone(&log_lines));

        let (status, all_logs) = monitor_process_with_logs(
            child,
            stdout_handle,
            log_lines,
            &mut terminal_guard,
            params,
        )?;

        if !status.success() {
            let error_messages = extract_errors_from_logs(&all_logs);

            // For failure: show completion screen and wait for user to press any key
            terminal_guard.get_mut().draw(|f| {
                ui::draw_failure_screen(f, status.code(), &all_logs, &error_messages, params);
            })?;

            // Wait for user to press any key before exiting
            if let Event::Key(_) = event::read()? {}
        }

        status
    }; // terminal_guard is dropped here, safely restoring the terminal

    if status.success() {
        // Print success message after terminal is teared down
        print_prominent_success_message("Recovery completed successfully!");
        Ok(())
    } else {
        anyhow::bail!(
            "Recovery upgrader failed with exit code: {:?}",
            status.code()
        );
    }
}
