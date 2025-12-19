pub mod recovery_utils;
mod ui;

use anyhow::{Context, Result};
use ratatui::crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::size;
use ratatui::{DefaultTerminal, Frame, restore};
use recovery_utils::{
    RecoveryUpgraderCommand, build_recovery_upgrader_install_command,
    build_recovery_upgrader_prep_command,
};
use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tui_textarea::TextArea;

// ============================================================================
// Constants
// ============================================================================

// Field length constants
const VERSION_LENGTH: usize = 40; // Git commit hash length (hex characters)
const PREFIX_HASH_LENGTH: usize = 6; // Recovery hash prefix length (hex characters)
const PREP_METADATA_PATH: &str = "/run/guestos-recovery/stage/prep-info";

// Process monitoring constants
const MAX_ERROR_LINES: usize = 30; // Maximum number of error lines to display
const PROCESS_POLL_INTERVAL_MS: u64 = 100; // Polling interval for process monitoring

// ============================================================================
// Types and Data Structures
// ============================================================================

#[derive(Default, Clone)]
pub struct RecoveryParams {
    /// The commit ID of the recovery-GuestOS update image (40 hex characters)
    pub version: String,
    /// The recovery hash prefix provided by the user (6 hex characters)
    pub recovery_hash_prefix: String,
    /// Calculated full hash of the downloaded recovery-GuestOS upgrade tarball
    pub version_hash_full: Option<String>,
    /// Calculated full hash of the downloaded recovery artifact
    pub recovery_hash_full: Option<String>,
}

fn is_lowercase_hex(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f')
}

impl RecoveryParams {
    pub fn validate_inputs(&self) -> Result<()> {
        Self::validate_hex_field(&self.version, VERSION_LENGTH, "VERSION")?;
        Self::validate_hex_field(
            &self.recovery_hash_prefix,
            PREFIX_HASH_LENGTH,
            "RECOVERY-HASH-PREFIX",
        )?;
        Ok(())
    }

    fn validate_hex_field(value: &str, required_len: usize, name: &str) -> Result<()> {
        if value.is_empty() {
            anyhow::bail!("{} is required", name);
        }
        if value.len() != required_len {
            anyhow::bail!(
                "{} must be exactly {} hexadecimal characters; got {}",
                name,
                required_len,
                value.len()
            );
        }
        if !value.chars().all(is_lowercase_hex) {
            anyhow::bail!(
                "{} must contain only lowercase hexadecimal characters",
                name
            );
        }
        Ok(())
    }
}

#[derive(PartialEq, Copy, Clone)]
pub(crate) enum Field {
    Version,
    RecoveryHashPrefix,
    CheckArtifactsButton,
    ExitButton,
}

struct FieldMetadata {
    name: &'static str,
    required_len: Option<usize>,
    is_input: bool,
}

impl Field {
    const ALL: &'static [Field] = &[
        Field::Version,
        Field::RecoveryHashPrefix,
        Field::CheckArtifactsButton,
        Field::ExitButton,
    ];

    const INPUT_FIELDS: &'static [Field] = &[Field::Version, Field::RecoveryHashPrefix];

    fn metadata(&self) -> FieldMetadata {
        match self {
            Field::Version => FieldMetadata {
                name: "VERSION",
                required_len: Some(VERSION_LENGTH),
                is_input: true,
            },
            Field::RecoveryHashPrefix => FieldMetadata {
                name: "RECOVERY-HASH-PREFIX",
                required_len: Some(PREFIX_HASH_LENGTH),
                is_input: true,
            },
            _ => FieldMetadata {
                name: "",
                required_len: None,
                is_input: false,
            },
        }
    }

    fn is_input_field(&self) -> bool {
        self.metadata().is_input
    }

    /// Returns the required length for this field
    fn required_length(&self) -> Option<usize> {
        self.metadata().required_len
    }
}

#[derive(Clone)]
pub(crate) struct InputState {
    pub focused_index: usize,
    pub inputs: Vec<TextArea<'static>>,
    pub error_message: Option<String>,
    pub exit_message: Option<String>,
}

impl Default for InputState {
    fn default() -> Self {
        let inputs = Field::INPUT_FIELDS
            .iter()
            .map(|_| {
                let mut t = TextArea::default();
                t.set_cursor_line_style(ratatui::style::Style::default());
                t
            })
            .collect::<Vec<_>>();

        Self {
            focused_index: 0,
            inputs,
            error_message: None,
            exit_message: None,
        }
    }
}

impl InputState {
    pub fn current_field(&self) -> Field {
        Field::ALL[self.focused_index]
    }

    pub fn get_input_index(&self, field: Field) -> Option<usize> {
        Field::INPUT_FIELDS.iter().position(|&f| f == field)
    }
}

pub(crate) struct RunningState {
    pub task: RecoveryTask,
    pub params: RecoveryParams,
    pub phase: RecoveryPhase,
    pub previous_input_state: Option<InputState>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum RecoveryPhase {
    Prep,
    Install,
}

pub struct RecoveryTask {
    child: std::process::Child,
    stdout_handle: Option<thread::JoinHandle<()>>,
    log_lines: Arc<Mutex<Vec<String>>>,
}

impl RecoveryTask {
    pub fn start(command: RecoveryUpgraderCommand) -> Result<Self> {
        let mut cmd = command.to_command();

        cmd.stdout(Stdio::piped());
        // Redirect stderr to null to avoid cluttering the TUI output
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().context("Failed to spawn recovery upgrader")?;

        let log_lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout handle"))?;

        let stdout_handle = start_log_capture(stdout, Arc::clone(&log_lines));

        Ok(Self {
            child,
            stdout_handle: Some(stdout_handle),
            log_lines,
        })
    }

    pub fn get_logs(&self) -> Vec<String> {
        self.log_lines.lock().unwrap().clone()
    }

    pub fn check_status(&mut self) -> Result<Option<std::process::ExitStatus>> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                // Process finished
                if let Some(handle) = self.stdout_handle.take() {
                    handle.join().ok();
                }
                Ok(Some(status))
            }
            Ok(None) => Ok(None), // Still running
            Err(e) => Err(anyhow::anyhow!("Error waiting for process: {}", e)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct FailureState {
    pub params: RecoveryParams,
    pub logs: Vec<String>,
    pub exit_status: std::process::ExitStatus,
    pub error_messages: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct ConfirmationState {
    pub input_state: InputState,
    pub params: RecoveryParams,
    pub selected_option: ConfirmationOption,
}

#[derive(Clone, PartialEq)]
pub(crate) enum ConfirmationOption {
    Yes,
    No,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum AppState {
    Input(InputState),
    InputConfirmation(ConfirmationState),
    Running(RunningState),
    /// There is no "Success" state because on success, the TUI exits immediately
    /// to allow the GuestOSRecoveryApp to print a success message to stdout (outside the TUI),
    /// followed by the GuestOS startup logs.
    /// This state is only reached if the recovery process fails.
    Failure(FailureState),
}

impl Default for AppState {
    fn default() -> Self {
        AppState::Input(InputState::default())
    }
}

// ============================================================================
// Terminal Management
// ============================================================================

/// Prints a prominent success message to stderr (outside the TUI).
/// This message is designed to be highly visible and will appear in the normal
/// terminal after the TUI exits, before any subsequent service logs.
/// The message uses prominent formatting with borders and colors to stand out.
fn print_success_summary(message: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    // ANSI color codes
    const GREEN: &str = "\x1b[32m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";
    const SEPARATOR_CHAR: &str = "=";

    let width = size().map(|(w, _)| w as usize).unwrap_or(80).min(100);

    let separator = SEPARATOR_CHAR.repeat(width);

    // Print prominent success message with borders, styling, and extra spacing
    // The extra blank lines help separate it from subsequent service logs
    let _ = writeln!(
        handle,
        "\n\n{}{}{}\n{}{}SUCCESS: {}{}{}\n{}{}{}\n\n",
        GREEN, separator, RESET, GREEN, BOLD, message, RESET, RESET, GREEN, separator, RESET
    );
    let _ = handle.flush();
}

// ============================================================================
// Application Logic
// ============================================================================

pub struct GuestOSRecoveryApp {
    state: Option<AppState>,
    should_quit: bool,
    result: Option<Result<()>>,
}

impl Default for GuestOSRecoveryApp {
    fn default() -> Self {
        Self {
            state: Some(AppState::default()),
            should_quit: false,
            result: None,
        }
    }
}

impl GuestOSRecoveryApp {
    pub fn new() -> Self {
        Self::default()
    }

    fn redraw(&self, terminal: &mut DefaultTerminal) -> Result<()> {
        if let Some(state) = &self.state {
            terminal
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

    /// Runs the interactive TUI application.
    pub fn run(&mut self) -> Result<()> {
        if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
            anyhow::bail!("This tool requires an interactive terminal.");
        }

        let terminal = match ratatui::try_init() {
            Ok(t) => t,
            Err(e) => {
                println!("\nERROR: Manual Recovery TUI failed to start.\n{e:#}\n");
                return Err(e.into());
            }
        };
        // Wrap terminal in a guard that ensures restore on any exit
        let mut terminal = scopeguard::guard(terminal, |_| restore());
        terminal.clear().context("Failed to clear terminal")?;

        execute!(terminal.backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        // Main Loop
        loop {
            if self.should_quit {
                break;
            }

            self.redraw(&mut terminal)?;

            // Event polling
            if ratatui::crossterm::event::poll(Duration::from_millis(PROCESS_POLL_INTERVAL_MS))? {
                let event = ratatui::crossterm::event::read()
                    .map_err(|e| anyhow::anyhow!("Failed to read terminal events").context(e))?;
                self.handle_event(event)?;
            }

            // State tick
            self.tick()?;
        }

        execute!(terminal.backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;

        // Drop guard to cleanup terminal before printing any final messages
        drop(terminal);

        // If we finished successfully, print the message after cleanup
        if let Some(Ok(())) = self.result {
            print_success_summary("Recovery completed successfully!");
        } else if self.result.is_none() {
            println!("\nManual recovery has been canceled.");
        } else if let Some(Err(ref _e)) = self.result {
            // If we failed with an error (not just a cancelled operation)
            // The guard is dropped so we can print error if needed, but caller handles it.
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
            Some(AppState::InputConfirmation(mut confirmation_state)) => {
                if self.handle_confirmation_key_event(&mut confirmation_state, key)? {
                    // Transition occurred, state already updated
                    Ok(())
                } else {
                    self.state = Some(AppState::InputConfirmation(confirmation_state));
                    Ok(())
                }
            }
            Some(AppState::Running(s)) => {
                self.state = Some(AppState::Running(s));
                Ok(())
            }
            Some(AppState::Failure(s)) => {
                // Any key exits
                self.should_quit = true;
                self.state = Some(AppState::Failure(s));
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn handle_confirmation_key_event(
        &mut self,
        state: &mut ConfirmationState,
        key: KeyEvent,
    ) -> Result<bool> {
        match key.code {
            KeyCode::Esc => {
                self.state = Some(AppState::Input(state.input_state.clone()));
                Ok(true)
            }
            KeyCode::Left => {
                state.selected_option = ConfirmationOption::Yes;
                Ok(false)
            }
            KeyCode::Right => {
                state.selected_option = ConfirmationOption::No;
                Ok(false)
            }
            KeyCode::Tab => {
                state.selected_option = match state.selected_option {
                    ConfirmationOption::Yes => ConfirmationOption::No,
                    ConfirmationOption::No => ConfirmationOption::Yes,
                };
                Ok(false)
            }
            KeyCode::Enter => match state.selected_option {
                ConfirmationOption::Yes => {
                    self.start_install(state.params.clone())?;
                    Ok(true)
                }
                ConfirmationOption::No => {
                    self.state = Some(AppState::Input(state.input_state.clone()));
                    Ok(true)
                }
            },
            _ => Ok(false),
        }
    }

    fn handle_input_key_event(
        &mut self,
        input_state: &mut InputState,
        key: KeyEvent,
    ) -> Result<bool> {
        // Clear error on any user input
        input_state.error_message = None;

        match key.code {
            KeyCode::Esc => {
                input_state.exit_message = Some("Recovery cancelled by user".to_string());
                self.should_quit = true;
                return Ok(false);
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                self.handle_navigation(input_state, key.code);
                return Ok(false);
            }
            KeyCode::Enter => return self.handle_submission(input_state),
            _ => {}
        }

        let current = input_state.current_field();
        if let Some(idx) = input_state.get_input_index(current) {
            self.handle_text_input(input_state, idx, key, current);
        } else {
            // Button navigation
            if matches!(key.code, KeyCode::Left | KeyCode::Right) {
                self.handle_navigation(input_state, key.code);
            }
        }
        Ok(false)
    }

    fn handle_navigation(&mut self, input_state: &mut InputState, key_code: KeyCode) {
        let count = Field::ALL.len();
        match key_code {
            KeyCode::Tab | KeyCode::Down => {
                input_state.focused_index = (input_state.focused_index + 1) % count;
            }
            KeyCode::Up => {
                input_state.focused_index = (input_state.focused_index + count - 1) % count;
            }
            KeyCode::Left | KeyCode::Right => {
                let current = input_state.current_field();
                if matches!(current, Field::CheckArtifactsButton | Field::ExitButton) {
                    // Toggle between the last two fields (buttons)
                    if current == Field::CheckArtifactsButton {
                        if let Some(idx) = Field::ALL.iter().position(|&f| f == Field::ExitButton) {
                            input_state.focused_index = idx;
                        }
                    } else if let Some(idx) = Field::ALL
                        .iter()
                        .position(|&f| f == Field::CheckArtifactsButton)
                    {
                        input_state.focused_index = idx;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_submission(&mut self, input_state: &mut InputState) -> Result<bool> {
        let current = input_state.current_field();
        if current.is_input_field() {
            input_state.focused_index = (input_state.focused_index + 1) % Field::ALL.len();
            Ok(false)
        } else {
            match current {
                Field::ExitButton => {
                    input_state.exit_message = Some("Recovery cancelled by user".to_string());
                    self.should_quit = true;
                    Ok(false)
                }
                Field::CheckArtifactsButton => {
                    // Construct params from inputs
                    let get_field_text = |target_field: Field| {
                        if let Some(idx) = input_state.get_input_index(target_field) {
                            input_state.inputs[idx]
                                .lines()
                                .first()
                                .cloned()
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    };

                    let params = RecoveryParams {
                        version: get_field_text(Field::Version),
                        recovery_hash_prefix: get_field_text(Field::RecoveryHashPrefix),
                        version_hash_full: None,
                        recovery_hash_full: None,
                    };

                    // Validate and transition to running
                    if let Err(e) = params.validate_inputs() {
                        input_state.error_message = Some(e.to_string());
                        Ok(false)
                    } else {
                        self.start_prep(params, input_state.clone())?;
                        Ok(true)
                    }
                }
                _ => Ok(false),
            }
        }
    }

    fn handle_text_input(
        &self,
        input_state: &mut InputState,
        idx: usize,
        key: KeyEvent,
        field: Field,
    ) {
        // Pre-validation for character input (hex only, max length)
        if let KeyCode::Char(c) = key.code {
            if !is_lowercase_hex(c) {
                return;
            }

            if let Some(max_len) = field.required_length() {
                let current_len = input_state.inputs[idx]
                    .lines()
                    .first()
                    .map(|l| l.len())
                    .unwrap_or(0);
                if current_len >= max_len {
                    return;
                }
            }
        }

        // Pass input to the focused text area
        input_state.inputs[idx].input(key);
    }

    fn start_prep(&mut self, params: RecoveryParams, input_state: InputState) -> Result<()> {
        let command =
            build_recovery_upgrader_prep_command(&params.version, &params.recovery_hash_prefix);
        let task = RecoveryTask::start(command)?;

        self.state = Some(AppState::Running(RunningState {
            task,
            params,
            phase: RecoveryPhase::Prep,
            previous_input_state: Some(input_state),
        }));
        Ok(())
    }

    fn start_install(&mut self, params: RecoveryParams) -> Result<()> {
        let command = build_recovery_upgrader_install_command();
        let task = RecoveryTask::start(command)?;

        self.state = Some(AppState::Running(RunningState {
            task,
            params,
            phase: RecoveryPhase::Install,
            previous_input_state: None,
        }));

        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        if let Some(AppState::Running(running)) = &mut self.state
            && let Some(status) = running.task.check_status()?
        {
            let logs = running.task.get_logs();

            if !status.success() {
                let error_messages = extract_errors_from_logs(&logs);
                let failure_state = FailureState {
                    params: running.params.clone(),
                    logs,
                    exit_status: status,
                    error_messages,
                };
                self.result = Some(Err(anyhow::anyhow!("Recovery failed")));
                self.state = Some(AppState::Failure(failure_state));
                return Ok(());
            }

            match running.phase {
                RecoveryPhase::Prep => match read_prep_metadata() {
                    Ok(prep) => {
                        let mut params = running.params.clone();
                        params.version_hash_full = Some(prep.version_hash_full);
                        params.recovery_hash_full = Some(prep.recovery_hash_full);

                        let input_state = running.previous_input_state.clone().unwrap_or_default();

                        self.state = Some(AppState::InputConfirmation(ConfirmationState {
                            input_state,
                            params,
                            selected_option: ConfirmationOption::Yes,
                        }));
                    }
                    Err(e) => {
                        let failure_state = FailureState {
                            params: running.params.clone(),
                            logs,
                            exit_status: status,
                            error_messages: vec![e.to_string()],
                        };
                        self.result = Some(Err(anyhow::anyhow!("Recovery failed during prep")));
                        self.state = Some(AppState::Failure(failure_state));
                    }
                },
                RecoveryPhase::Install => {
                    self.result = Some(Ok(()));
                    self.should_quit = true;
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Process and Log Monitoring
// ============================================================================

/// Spawns a thread to read lines from stdout and append them to a shared log buffer
fn start_log_capture<R>(stream: R, log_lines: Arc<Mutex<Vec<String>>>) -> thread::JoinHandle<()>
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

struct PrepResults {
    version_hash_full: String,
    recovery_hash_full: String,
}

fn read_prep_metadata() -> Result<PrepResults> {
    let contents = fs::read_to_string(PREP_METADATA_PATH)
        .with_context(|| format!("Failed to read prep metadata at {}", PREP_METADATA_PATH))?;

    let mut version_hash_full: Option<String> = None;
    let mut recovery_hash_full: Option<String> = None;

    for line in contents.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "VERSION_HASH_FULL" | "version_hash_full" => {
                    version_hash_full = Some(value.to_string())
                }
                "RECOVERY_HASH_FULL" | "recovery_hash_full" => {
                    recovery_hash_full = Some(value.to_string())
                }
                _ => {}
            }
        }
    }

    let version_hash_full = version_hash_full
        .ok_or_else(|| anyhow::anyhow!("Prep metadata missing VERSION_HASH_FULL"))?;
    let recovery_hash_full = recovery_hash_full
        .ok_or_else(|| anyhow::anyhow!("Prep metadata missing RECOVERY_HASH_FULL"))?;

    Ok(PrepResults {
        version_hash_full,
        recovery_hash_full,
    })
}
