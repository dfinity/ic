mod ui;

use anyhow::{Context, Result};
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
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
use std::time::Duration;

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
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;

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

#[derive(Clone)]
pub(crate) struct InputState {
    pub current_field: Field,
    pub params: RecoveryParams,
    pub error_message: Option<String>,
    pub exit_message: Option<String>,
}

impl Default for InputState {
    fn default() -> Self {
        Self {
            current_field: Field::Version,
            params: RecoveryParams::default(),
            error_message: None,
            exit_message: None,
        }
    }
}

pub(crate) struct RunningState {
    pub child: std::process::Child,
    pub stdout_handle: Option<thread::JoinHandle<()>>,
    pub log_lines: Arc<Mutex<Vec<String>>>,
    pub params: RecoveryParams,
}

#[derive(Clone)]
pub(crate) struct DoneState {
    pub params: RecoveryParams,
    pub logs: Vec<String>,
    pub exit_status: std::process::ExitStatus,
    pub error_messages: Vec<String>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum AppState {
    Input(InputState),
    Running(RunningState),
    Done(DoneState),
}

impl Default for AppState {
    fn default() -> Self {
        AppState::Input(InputState::default())
    }
}

pub struct App {
    state: Option<AppState>,
    should_quit: bool,
    result: Option<Result<()>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            state: Some(AppState::default()),
            should_quit: false,
            result: None,
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    fn clear_error(&mut self) {
        if let Some(AppState::Input(state)) = &mut self.state {
            state.error_message = None;
        }
    }

    fn redraw(&self, terminal_guard: &mut TerminalGuard) -> Result<()> {
        if let Some(state) = &self.state {
            let _ = terminal_guard
                .get_mut()
                .draw(|f: &mut Frame| ui::render(f, state))
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to render TUI - terminal may not support required features"
                    )
                    .context(e)
                })?;
        }
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

    /// Runs the interactive TUI application.
    pub fn run(&mut self) -> Result<()> {
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
            let _ = Self::teardown_and_error(terminal_guard, e, || {
                "Terminal size validation failed".to_string()
            });
            return Err(anyhow::anyhow!("Terminal size validation failed"));
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        // Main Loop
        loop {
            if self.should_quit {
                break;
            }

            self.redraw(&mut terminal_guard)?;

            // Event polling
            if crossterm::event::poll(Duration::from_millis(PROCESS_POLL_INTERVAL_MS))? {
                let event = crossterm::event::read()
                    .map_err(|e| anyhow::anyhow!("Failed to read terminal events").context(e))?;
                self.handle_event(event)?;
            }

            // State tick
            self.tick()?;
        }

        execute!(terminal_guard.get_mut().backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;

        // If we finished successfully, print the message after cleanup
        if let Some(Ok(())) = self.result {
            // Drop guard to cleanup terminal before printing
            drop(terminal_guard);
            print_prominent_success_message("Recovery completed successfully!");
        } else if let Some(Err(ref _e)) = self.result {
            // If we failed with an error (not just a cancelled operation)
            // The guard will drop and we can print error if needed, but caller handles it.
        }

        if let Some(result) = self.result.take() {
            result
        } else {
            Ok(()) // Default to Ok if exited cleanly (e.g. Ctrl+C)
        }
    }

    fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key)
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat =>
            {
                // Global Ctrl+C handler
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    self.should_quit = true;
                    self.result = None; // Cancelled
                    return Ok(());
                }
                self.handle_key_event(key)
            }
            _ => Ok(()),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        let state = self.state.take();

        match state {
            Some(AppState::Input(mut input_state)) => {
                match self.handle_input_key_event(&mut input_state, key) {
                    Ok(true) => Ok(()), // Transition occurred, self.state is already set
                    Ok(false) => {
                        self.state = Some(AppState::Input(input_state));
                        Ok(())
                    }
                    Err(e) => {
                        self.state = Some(AppState::Input(input_state));
                        Err(e)
                    }
                }
            }
            Some(AppState::Running(s)) => {
                self.state = Some(AppState::Running(s));
                Ok(())
            }
            Some(AppState::Done(s)) => {
                // Any key exits
                self.should_quit = true;
                self.state = Some(AppState::Done(s));
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn handle_input_key_event(
        &mut self,
        input_state: &mut InputState,
        key: KeyEvent,
    ) -> Result<bool> {
        match key.code {
            KeyCode::Esc => {
                input_state.exit_message = Some("Recovery cancelled by user".to_string());
                self.should_quit = true;
            }

            KeyCode::Enter => {
                if input_state.current_field.is_input_field() {
                    input_state.current_field = input_state.current_field.next();
                    self.clear_error();
                } else {
                    match input_state.current_field {
                        Field::ExitButton => {
                            input_state.exit_message =
                                Some("Recovery cancelled by user".to_string());
                            self.should_quit = true;
                        }
                        Field::CheckArtifactsButton => {
                            // Validate and transition to running
                            if let Err(e) = input_state.params.validate() {
                                input_state.error_message = Some(e.to_string());
                            } else {
                                self.transition_to_running(input_state.params.clone())?;
                                return Ok(true);
                            }
                        }
                        _ => {}
                    }
                }
            }

            KeyCode::Tab | KeyCode::Down => {
                input_state.current_field = input_state.current_field.next();
                self.clear_error();
            }

            KeyCode::Up => {
                input_state.current_field = input_state.current_field.previous();
                self.clear_error();
            }

            KeyCode::Left | KeyCode::Right => {
                if matches!(
                    input_state.current_field,
                    Field::CheckArtifactsButton | Field::ExitButton
                ) {
                    input_state.current_field = match input_state.current_field {
                        Field::CheckArtifactsButton => Field::ExitButton,
                        Field::ExitButton => Field::CheckArtifactsButton,
                        _ => unreachable!(),
                    };
                    self.clear_error();
                }
            }

            KeyCode::Char(c) if input_state.current_field.is_input_field() => {
                match (
                    input_state.current_field.required_length(),
                    input_state
                        .current_field
                        .get_value_mut(&mut input_state.params),
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

            KeyCode::Backspace if input_state.current_field.is_input_field() => {
                if let Some(field_value) = input_state
                    .current_field
                    .get_value_mut(&mut input_state.params)
                {
                    field_value.pop();
                    self.clear_error();
                }
            }

            _ => {}
        }
        Ok(false)
    }

    fn transition_to_running(&mut self, params: RecoveryParams) -> Result<()> {
        let mut cmd = build_upgrader_command(&params);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().context("Failed to spawn recovery upgrader")?;

        let log_lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout handle"))?;

        let stdout_handle = spawn_log_reader_thread(stdout, Arc::clone(&log_lines));

        self.state = Some(AppState::Running(RunningState {
            child,
            stdout_handle: Some(stdout_handle),
            log_lines,
            params,
        }));

        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        let finished_state = if let Some(AppState::Running(running_state)) = &mut self.state {
            match running_state.child.try_wait() {
                Ok(Some(status)) => {
                    // Process finished
                    if let Some(handle) = running_state.stdout_handle.take() {
                        handle.join().ok();
                    }

                    // Collect logs
                    let logs = running_state.log_lines.lock().unwrap().clone();

                    if status.success() {
                        self.result = Some(Ok(()));
                        self.should_quit = true;
                        None
                    } else {
                        // Failure -> Transition to Done
                        let error_messages = extract_errors_from_logs(&logs);
                        Some(DoneState {
                            params: running_state.params.clone(),
                            logs,
                            exit_status: status,
                            error_messages,
                        })
                    }
                }
                Ok(None) => None, // Still running
                Err(e) => return Err(anyhow::anyhow!("Error waiting for process: {}", e)),
            }
        } else {
            None
        };

        if let Some(done_state) = finished_state {
            self.result = Some(Err(anyhow::anyhow!("Recovery failed")));
            self.state = Some(AppState::Done(done_state));
        }

        Ok(())
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

    let width = size().map(|(w, _)| w as usize).unwrap_or(80).min(100);

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
