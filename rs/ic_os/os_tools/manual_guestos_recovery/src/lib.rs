//! Interactive TUI application for manual GuestOS recovery.
//! NNS mode prompts for a recovery version and recovery hash prefix.
//! TEE mode prompts for a recovery version and target boot alternative.

pub mod recovery_utils;
mod ui;

use anyhow::{Context, Result};
use clap::ValueEnum;
use grub::BootAlternative;
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
use tracing::error;
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

#[derive(Clone)]
pub struct RecoveryParams {
    /// The commit ID of the recovery-GuestOS update image (40 hex characters)
    pub version: String,
    /// The recovery hash prefix provided by the user (6 hex characters), if provided.
    pub recovery_hash_prefix: Option<String>,
    /// Calculated full hash of the downloaded recovery-GuestOS upgrade tarball
    pub version_hash_full: Option<String>,
    /// Calculated full hash of the downloaded recovery artifact, if enabled.
    pub recovery_hash_full: Option<String>,
    /// Whether recovery operates in NNS or TEE mode.
    pub mode: RecoveryMode,
    /// The currently configured GuestOS boot alternative when the TUI started.
    pub current_boot_alternative: BootAlternative,
    /// Whether the target should be the current or opposite boot alternative.
    pub target_boot_alternative_selection: TargetBootAlternativeSelection,
}

fn is_lowercase_hex(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f')
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum RecoveryMode {
    #[default]
    Nns,
    Tee,
}

impl RecoveryMode {
    fn requires_recovery_hash(self) -> bool {
        matches!(self, Self::Nns)
    }

    fn can_select_target_boot_alternative(self) -> bool {
        matches!(self, Self::Tee)
    }

    fn default_target_boot_alternative_selection(self) -> TargetBootAlternativeSelection {
        match self {
            Self::Nns => TargetBootAlternativeSelection::Opposite,
            Self::Tee => TargetBootAlternativeSelection::Current,
        }
    }
}

/// Where the GuestOS is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetBootAlternativeSelection {
    /// Replace the GuestOS on the current boot alternative.
    Current,
    /// Write to the opposite boot alternative.
    Opposite,
}

impl TargetBootAlternativeSelection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Opposite => "opposite",
        }
    }
}

fn create_text_area_with_text(text: &str) -> TextArea<'static> {
    let mut t = TextArea::default();
    t.set_cursor_line_style(ratatui::style::Style::default());
    if !text.is_empty() {
        t.insert_str(text);
    }
    t
}

impl RecoveryParams {
    pub fn validate_inputs(&self) -> Result<()> {
        Self::validate_hex_field(&self.version, VERSION_LENGTH, "VERSION")?;
        let recovery_hash_prefix = self.recovery_hash_prefix.as_deref().unwrap_or_default();
        if self.mode.requires_recovery_hash() {
            Self::validate_hex_field(
                recovery_hash_prefix,
                PREFIX_HASH_LENGTH,
                "RECOVERY-HASH-PREFIX",
            )?;
        } else if !recovery_hash_prefix.is_empty() {
            anyhow::bail!("RECOVERY-HASH-PREFIX must be empty in TEE mode");
        }
        Ok(())
    }

    fn effective_target_boot_alternative_selection(&self) -> TargetBootAlternativeSelection {
        if self.mode.can_select_target_boot_alternative() {
            self.target_boot_alternative_selection
        } else {
            self.mode.default_target_boot_alternative_selection()
        }
    }

    fn get_target_boot_alternative(&self) -> BootAlternative {
        match self.effective_target_boot_alternative_selection() {
            TargetBootAlternativeSelection::Current => self.current_boot_alternative,
            TargetBootAlternativeSelection::Opposite => {
                self.current_boot_alternative.get_opposite()
            }
        }
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
    TargetBootAlternative,
    CheckArtifactsButton,
    ExitButton,
}

struct FieldMetadata {
    name: &'static str,
    required_len: Option<usize>,
    is_input: bool,
}

impl Field {
    const ALL_NNS: &'static [Field] = &[
        Field::Version,
        Field::RecoveryHashPrefix,
        Field::CheckArtifactsButton,
        Field::ExitButton,
    ];

    const ALL_TEE: &'static [Field] = &[
        Field::Version,
        Field::TargetBootAlternative,
        Field::CheckArtifactsButton,
        Field::ExitButton,
    ];

    const INPUT_FIELDS_NNS: &'static [Field] = &[Field::Version, Field::RecoveryHashPrefix];

    const INPUT_FIELDS_TEE: &'static [Field] = &[Field::Version, Field::TargetBootAlternative];

    fn all_fields(mode: RecoveryMode) -> &'static [Field] {
        match mode {
            RecoveryMode::Nns => Self::ALL_NNS,
            RecoveryMode::Tee => Self::ALL_TEE,
        }
    }

    fn input_fields(mode: RecoveryMode) -> &'static [Field] {
        match mode {
            RecoveryMode::Nns => Self::INPUT_FIELDS_NNS,
            RecoveryMode::Tee => Self::INPUT_FIELDS_TEE,
        }
    }

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
            Field::TargetBootAlternative => FieldMetadata {
                name: "TARGET-BOOT-ALTERNATIVE",
                required_len: None,
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
    pub mode: RecoveryMode,
    pub current_boot_alternative: BootAlternative,
    pub target_boot_alternative_selection: TargetBootAlternativeSelection,
}

impl InputState {
    pub fn new(mode: RecoveryMode, current_boot_alternative: BootAlternative) -> Self {
        let target_boot_alternative_selection = mode.default_target_boot_alternative_selection();
        let inputs = vec![create_text_area_with_text(""); Field::input_fields(mode).len()];

        Self {
            focused_index: 0,
            inputs,
            error_message: None,
            exit_message: None,
            mode,
            current_boot_alternative,
            target_boot_alternative_selection,
        }
    }

    pub fn current_field(&self) -> Field {
        self.all_fields()[self.focused_index]
    }

    pub(crate) fn resolve_boot_alternative(
        &self,
        selection: TargetBootAlternativeSelection,
    ) -> BootAlternative {
        match selection {
            TargetBootAlternativeSelection::Current => self.current_boot_alternative,
            TargetBootAlternativeSelection::Opposite => {
                self.current_boot_alternative.get_opposite()
            }
        }
    }

    fn all_fields(&self) -> &'static [Field] {
        Field::all_fields(self.mode)
    }

    fn input_fields(&self) -> &'static [Field] {
        Field::input_fields(self.mode)
    }

    pub fn get_input_index(&self, field: Field) -> Option<usize> {
        self.input_fields().iter().position(|&f| f == field)
    }

    pub(crate) fn get_field_text(&self, field: Field) -> String {
        if let Some(idx) = self.get_input_index(field) {
            self.inputs[idx]
                .lines()
                .first()
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        }
    }

    fn set_target_boot_alternative_selection(&mut self, selection: TargetBootAlternativeSelection) {
        self.target_boot_alternative_selection = selection;
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

#[derive(Clone, PartialEq, Debug)]
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

impl GuestOSRecoveryApp {
    pub fn new(mode: RecoveryMode, current_boot_alternative: BootAlternative) -> Self {
        Self {
            state: Some(AppState::Input(InputState::new(
                mode,
                current_boot_alternative,
            ))),
            should_quit: false,
            result: None,
        }
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
                error!("Manual Recovery TUI failed to start: {e:#}");
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
        if current == Field::TargetBootAlternative {
            self.handle_target_boot_alternative_input(input_state, key);
            return Ok(false);
        }

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
        let all_fields = input_state.all_fields();
        let count = all_fields.len();
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
                        if let Some(idx) = all_fields.iter().position(|&f| f == Field::ExitButton) {
                            input_state.focused_index = idx;
                        }
                    } else if let Some(idx) = all_fields
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
            input_state.focused_index =
                (input_state.focused_index + 1) % input_state.all_fields().len();
            Ok(false)
        } else {
            match current {
                Field::ExitButton => {
                    input_state.exit_message = Some("Recovery cancelled by user".to_string());
                    self.should_quit = true;
                    Ok(false)
                }
                Field::CheckArtifactsButton => {
                    let recovery_hash_prefix =
                        Some(input_state.get_field_text(Field::RecoveryHashPrefix))
                            .filter(|prefix| !prefix.is_empty());
                    let params = RecoveryParams {
                        version: input_state.get_field_text(Field::Version),
                        current_boot_alternative: input_state.current_boot_alternative,
                        target_boot_alternative_selection: input_state
                            .target_boot_alternative_selection,
                        recovery_hash_prefix,
                        version_hash_full: None,
                        recovery_hash_full: None,
                        mode: input_state.mode,
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

    fn handle_target_boot_alternative_input(&self, input_state: &mut InputState, key: KeyEvent) {
        match key.code {
            KeyCode::Left | KeyCode::Char('c') | KeyCode::Char('C') => input_state
                .set_target_boot_alternative_selection(TargetBootAlternativeSelection::Current),
            KeyCode::Right | KeyCode::Char('o') | KeyCode::Char('O') => input_state
                .set_target_boot_alternative_selection(TargetBootAlternativeSelection::Opposite),
            KeyCode::Char(' ') => {
                let toggled = match input_state.target_boot_alternative_selection {
                    TargetBootAlternativeSelection::Current => {
                        TargetBootAlternativeSelection::Opposite
                    }
                    TargetBootAlternativeSelection::Opposite => {
                        TargetBootAlternativeSelection::Current
                    }
                };
                input_state.set_target_boot_alternative_selection(toggled);
            }
            _ => {}
        }
    }

    fn handle_text_input(
        &self,
        input_state: &mut InputState,
        idx: usize,
        key: KeyEvent,
        field: Field,
    ) {
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
        let command = build_recovery_upgrader_prep_command(
            &params.version,
            params.get_target_boot_alternative(),
            params.recovery_hash_prefix.as_deref().unwrap_or(""),
            params.mode.requires_recovery_hash(),
        );
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
        let command = build_recovery_upgrader_install_command(params.mode.requires_recovery_hash());
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
                        params.recovery_hash_full = prep.recovery_hash_full;

                        let input_state =
                            running.previous_input_state.clone().unwrap_or_else(|| {
                                InputState::new(
                                    running.params.mode,
                                    running.params.current_boot_alternative,
                                )
                            });

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

#[derive(Debug)]
struct PrepResults {
    version_hash_full: String,
    recovery_hash_full: Option<String>,
}

fn read_prep_metadata() -> Result<PrepResults> {
    let contents = fs::read_to_string(PREP_METADATA_PATH)
        .with_context(|| format!("Failed to read prep metadata at {}", PREP_METADATA_PATH))?;
    parse_prep_metadata(&contents)
}

/// Parses prep metadata from a key=value formatted string.
fn parse_prep_metadata(contents: &str) -> Result<PrepResults> {
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
    Ok(PrepResults {
        version_hash_full,
        recovery_hash_full,
    })
}

#[cfg(test)]
impl RecoveryTask {
    /// Creates a mock task for testing with predefined logs.
    /// Spawns a no-op process that exits immediately.
    pub(crate) fn mock_with_logs(logs: Vec<String>) -> Self {
        use std::process::Command;

        let child = Command::new("true")
            .spawn()
            .expect("Failed to spawn 'true' command for mock task");

        Self {
            child,
            stdout_handle: None,
            log_lines: Arc::new(Mutex::new(logs)),
        }
    }
}

#[cfg(test)]
impl GuestOSRecoveryApp {
    pub(crate) fn with_state(state: AppState) -> Self {
        Self {
            state: Some(state),
            should_quit: false,
            result: None,
        }
    }

    pub(crate) fn get_state(&self) -> Option<&AppState> {
        self.state.as_ref()
    }

    pub(crate) fn is_should_quit(&self) -> bool {
        self.should_quit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyEventKind, KeyEventState};

    const TEST_CURRENT_BOOT_ALTERNATIVE: BootAlternative = BootAlternative::A;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn key_event(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl_c_event() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn char_event(c: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn create_test_failure_state() -> FailureState {
        // Run a command that fails to get a real ExitStatus
        let status = std::process::Command::new("false")
            .status()
            .expect("Failed to run 'false' command");
        FailureState {
            params: default_recovery_params_for_test(),
            logs: vec!["test log".to_string()],
            exit_status: status,
            error_messages: vec!["test error".to_string()],
        }
    }

    fn default_recovery_params_for_test() -> RecoveryParams {
        RecoveryParams {
            version: String::new(),
            recovery_hash_prefix: None,
            version_hash_full: None,
            recovery_hash_full: None,
            mode: RecoveryMode::Nns,
            current_boot_alternative: BootAlternative::A,
            target_boot_alternative_selection: TargetBootAlternativeSelection::Opposite,
        }
    }

    fn create_test_input_state(mode: RecoveryMode) -> InputState {
        InputState::new(mode, TEST_CURRENT_BOOT_ALTERNATIVE)
    }

    fn create_test_app(mode: RecoveryMode) -> GuestOSRecoveryApp {
        GuestOSRecoveryApp::new(mode, TEST_CURRENT_BOOT_ALTERNATIVE)
    }

    fn set_field_text(state: &mut InputState, field: Field, text: &str) {
        if let Some(idx) = state.get_input_index(field) {
            state.inputs[idx] = create_text_area_with_text(text);
        }
    }

    fn create_valid_input_state() -> InputState {
        let mut state = create_test_input_state(RecoveryMode::Nns);
        set_field_text(&mut state, Field::Version, &"a".repeat(VERSION_LENGTH));
        set_field_text(
            &mut state,
            Field::RecoveryHashPrefix,
            &"b".repeat(PREFIX_HASH_LENGTH),
        );
        state
    }

    // ========================================================================
    // Unit Tests
    // ========================================================================

    mod validation {
        use super::*;

        #[test]
        fn is_lowercase_hex_accepts_valid() {
            assert!(is_lowercase_hex('0'));
            assert!(is_lowercase_hex('9'));
            assert!(is_lowercase_hex('a'));
            assert!(is_lowercase_hex('f'));
        }

        #[test]
        fn is_lowercase_hex_rejects_invalid() {
            assert!(!is_lowercase_hex('A'));
            assert!(!is_lowercase_hex('F'));
            assert!(!is_lowercase_hex('g'));
            assert!(!is_lowercase_hex(' '));
        }

        #[test]
        fn validate_inputs_accepts_valid_params() {
            let params = RecoveryParams {
                version: "0123456789abcdef0123456789abcdef01234567".to_string(),
                recovery_hash_prefix: Some("a1b2c3".to_string()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_ok());
        }

        #[test]
        fn validate_inputs_allows_missing_recovery_hash_in_tee_mode() {
            let params = RecoveryParams {
                version: "0123456789abcdef0123456789abcdef01234567".to_string(),
                recovery_hash_prefix: None,
                mode: RecoveryMode::Tee,
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_ok());
        }

        #[test]
        fn validate_inputs_allows_empty_recovery_hash_in_tee_mode() {
            let params = RecoveryParams {
                version: "0123456789abcdef0123456789abcdef01234567".to_string(),
                recovery_hash_prefix: Some(String::new()),
                mode: RecoveryMode::Tee,
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_ok());
        }

        #[test]
        fn validate_inputs_rejects_invalid_recovery_hash_in_tee_mode() {
            let params = RecoveryParams {
                version: "0123456789abcdef0123456789abcdef01234567".to_string(),
                recovery_hash_prefix: Some("ABCDEF".to_string()),
                mode: RecoveryMode::Tee,
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());
        }

        #[test]
        fn validate_inputs_rejects_invalid_version() {
            let valid_hash = "abc123".to_string();

            // Empty
            let params = RecoveryParams {
                version: String::new(),
                recovery_hash_prefix: Some(valid_hash.clone()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());

            // Wrong length
            let params = RecoveryParams {
                version: "abc".to_string(),
                recovery_hash_prefix: Some(valid_hash.clone()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());

            // Invalid chars (uppercase)
            let params = RecoveryParams {
                version: "A".repeat(VERSION_LENGTH),
                recovery_hash_prefix: Some(valid_hash),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());
        }

        #[test]
        fn validate_inputs_rejects_invalid_recovery_hash() {
            let valid_version = "a".repeat(VERSION_LENGTH);

            // Empty
            let params = RecoveryParams {
                version: valid_version.clone(),
                recovery_hash_prefix: Some(String::new()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());

            // Wrong length
            let params = RecoveryParams {
                version: valid_version.clone(),
                recovery_hash_prefix: Some("abc".to_string()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());

            // Invalid chars (uppercase)
            let params = RecoveryParams {
                version: valid_version,
                recovery_hash_prefix: Some("ABCDEF".to_string()),
                ..default_recovery_params_for_test()
            };
            assert!(params.validate_inputs().is_err());
        }

        #[test]
        fn get_target_boot_alternative_honors_selection_in_tee_mode() {
            let current = RecoveryParams {
                current_boot_alternative: BootAlternative::B,
                target_boot_alternative_selection: TargetBootAlternativeSelection::Current,
                mode: RecoveryMode::Tee,
                ..default_recovery_params_for_test()
            };
            assert_eq!(current.get_target_boot_alternative(), BootAlternative::B);

            let opposite = RecoveryParams {
                current_boot_alternative: BootAlternative::B,
                target_boot_alternative_selection: TargetBootAlternativeSelection::Opposite,
                mode: RecoveryMode::Tee,
                ..default_recovery_params_for_test()
            };
            assert_eq!(opposite.get_target_boot_alternative(), BootAlternative::A);
        }

        #[test]
        fn get_target_boot_alternative_uses_opposite_in_nns_mode() {
            let params = RecoveryParams {
                current_boot_alternative: BootAlternative::B,
                target_boot_alternative_selection: TargetBootAlternativeSelection::Current,
                mode: RecoveryMode::Nns,
                ..default_recovery_params_for_test()
            };
            assert_eq!(params.get_target_boot_alternative(), BootAlternative::A);
        }
    }

    mod prep_metadata {
        use super::*;

        #[test]
        fn parses_valid_metadata() {
            let contents = "VERSION_HASH_FULL=abc123def456\nRECOVERY_HASH_FULL=789xyz";
            let result = parse_prep_metadata(contents).unwrap();

            assert_eq!(result.version_hash_full, "abc123def456");
            assert_eq!(result.recovery_hash_full, Some("789xyz".to_string()));
        }

        #[test]
        fn parses_metadata_without_recovery_hash() {
            let contents = "VERSION_HASH_FULL=abc123def456";
            let result = parse_prep_metadata(contents).unwrap();

            assert_eq!(result.version_hash_full, "abc123def456");
            assert_eq!(result.recovery_hash_full, None);
        }

        #[test]
        fn rejects_empty_content() {
            let result = parse_prep_metadata("");
            assert!(result.is_err());
        }
    }

    mod log_extraction {
        use super::*;

        #[test]
        fn returns_all_when_under_limit() {
            assert!(extract_errors_from_logs(&[]).is_empty());

            let logs: Vec<String> = (0..10).map(|i| format!("line {}", i)).collect();
            let result = extract_errors_from_logs(&logs);
            assert_eq!(result.len(), 10);
        }

        #[test]
        fn truncates_to_last_n() {
            let total = MAX_ERROR_LINES + 20;
            let logs: Vec<String> = (0..total).map(|i| format!("line {}", i)).collect();
            let result = extract_errors_from_logs(&logs);

            assert_eq!(result.len(), MAX_ERROR_LINES);
            assert_eq!(result[0], format!("line {}", total - MAX_ERROR_LINES));
        }
    }

    // ========================================================================
    // State Machine Tests
    // ========================================================================

    mod global_behavior {
        use super::*;

        #[test]
        fn ctrl_c_quits_from_input_state() {
            let mut app = create_test_app(RecoveryMode::Nns);
            app.handle_event(Event::Key(ctrl_c_event())).unwrap();
            assert!(app.is_should_quit());
        }

        #[test]
        fn ctrl_c_quits_from_confirmation_state() {
            let confirmation = ConfirmationState {
                input_state: create_test_input_state(RecoveryMode::Nns),
                params: default_recovery_params_for_test(),
                selected_option: ConfirmationOption::Yes,
            };
            let mut app = GuestOSRecoveryApp::with_state(AppState::InputConfirmation(confirmation));
            app.handle_event(Event::Key(ctrl_c_event())).unwrap();
            assert!(app.is_should_quit());
        }

        #[test]
        fn ctrl_c_quits_from_failure_state() {
            let failure = create_test_failure_state();
            let mut app = GuestOSRecoveryApp::with_state(AppState::Failure(failure));
            app.handle_event(Event::Key(ctrl_c_event())).unwrap();
            assert!(app.is_should_quit());
        }

        #[test]
        fn non_press_events_are_ignored() {
            let mut app = create_test_app(RecoveryMode::Nns);

            let release_event = KeyEvent {
                code: KeyCode::Tab,
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Release,
                state: KeyEventState::empty(),
            };
            app.handle_event(Event::Key(release_event)).unwrap();

            assert!(matches!(
                app.get_state(),
                Some(AppState::Input(s)) if s.current_field() == Field::Version
            ));
        }

        #[test]
        fn repeat_events_are_handled() {
            let mut app = create_test_app(RecoveryMode::Nns);

            let repeat_event = KeyEvent {
                code: KeyCode::Tab,
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Repeat,
                state: KeyEventState::empty(),
            };
            app.handle_event(Event::Key(repeat_event)).unwrap();

            assert!(matches!(
                app.get_state(),
                Some(AppState::Input(s)) if s.current_field() == Field::RecoveryHashPrefix
            ));
        }

        #[test]
        fn new_in_tee_mode_hides_recovery_hash_field() {
            let app = create_test_app(RecoveryMode::Tee);
            assert!(matches!(
                app.get_state(),
                Some(AppState::Input(s)) if s.current_field() == Field::Version && s.mode == RecoveryMode::Tee
            ));
        }

        #[test]
        fn input_state_prefills_target_boot_alternative_from_current_boot_alternative() {
            let state = InputState::new(RecoveryMode::Nns, BootAlternative::B);
            assert_eq!(state.current_boot_alternative, BootAlternative::B);
            assert_eq!(
                state.target_boot_alternative_selection,
                TargetBootAlternativeSelection::Opposite
            );

            let alternative_state = InputState::new(RecoveryMode::Tee, BootAlternative::B);
            assert_eq!(
                alternative_state.target_boot_alternative_selection,
                TargetBootAlternativeSelection::Current
            );
        }
    }

    mod input_state {
        use super::*;

        mod navigation {
            use super::*;

            #[test]
            fn tab_navigates_forward_through_all_fields() {
                let mut app = create_test_app(RecoveryMode::Nns);

                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::RecoveryHashPrefix
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::CheckArtifactsButton
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::ExitButton
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));
            }

            #[test]
            fn up_arrow_navigates_backward() {
                let mut app = create_test_app(RecoveryMode::Nns);

                app.handle_event(Event::Key(key_event(KeyCode::Up)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::ExitButton
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Up)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::CheckArtifactsButton
                ));
            }

            #[test]
            fn left_right_toggles_buttons() {
                let input_state = InputState {
                    focused_index: 2, // CheckArtifactsButton
                    ..create_test_input_state(RecoveryMode::Nns)
                };
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Right)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::ExitButton
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Left)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::CheckArtifactsButton
                ));
            }

            #[test]
            fn tab_navigates_through_tee_mode_without_recovery_hash_field() {
                let mut app = create_test_app(RecoveryMode::Tee);
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));
                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::TargetBootAlternative
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::CheckArtifactsButton
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::ExitButton
                ));
                app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));
            }

            #[test]
            fn left_right_does_nothing_on_text_fields() {
                let mut app = create_test_app(RecoveryMode::Nns);

                app.handle_event(Event::Key(key_event(KeyCode::Left)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));

                app.handle_event(Event::Key(key_event(KeyCode::Right)))
                    .unwrap();
                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::Version
                ));
            }

            #[test]
            fn escape_quits_with_message() {
                let mut app = create_test_app(RecoveryMode::Nns);
                app.handle_event(Event::Key(key_event(KeyCode::Esc)))
                    .unwrap();

                assert!(app.is_should_quit());
                if let Some(AppState::Input(state)) = app.get_state() {
                    assert!(state.exit_message.as_ref().unwrap().contains("cancelled"));
                } else {
                    panic!("Expected Input state");
                }
            }
        }

        mod text_entry {
            use super::*;

            #[test]
            fn accepts_lowercase_hex() {
                let mut app = create_test_app(RecoveryMode::Nns);

                for c in ['0', '1', '9', 'a', 'b', 'f'] {
                    app.handle_event(Event::Key(char_event(c))).unwrap();
                }

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(state.get_field_text(Field::Version), "019abf");
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn rejects_invalid_characters() {
                let mut app = create_test_app(RecoveryMode::Nns);

                for c in ['A', 'G', 'z', ' ', '!'] {
                    app.handle_event(Event::Key(char_event(c))).unwrap();
                }

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(state.get_field_text(Field::Version), "");
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn respects_max_length() {
                let mut app = create_test_app(RecoveryMode::Nns);

                for _ in 0..(VERSION_LENGTH + 10) {
                    app.handle_event(Event::Key(char_event('a'))).unwrap();
                }

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(state.get_field_text(Field::Version).len(), VERSION_LENGTH);
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn enter_advances_focus() {
                let mut app = create_test_app(RecoveryMode::Nns);
                app.handle_event(Event::Key(key_event(KeyCode::Enter)))
                    .unwrap();

                assert!(matches!(
                    app.get_state(),
                    Some(AppState::Input(s)) if s.current_field() == Field::RecoveryHashPrefix
                ));
            }

            #[test]
            fn tee_target_boot_alternative_field_switches_between_current_and_opposite() {
                let mut input_state = create_test_input_state(RecoveryMode::Tee);
                input_state.focused_index = 1;
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Left)))
                    .unwrap();

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(
                        state.target_boot_alternative_selection,
                        TargetBootAlternativeSelection::Current
                    );
                } else {
                    panic!("Expected Input state");
                }

                app.handle_event(Event::Key(key_event(KeyCode::Right)))
                    .unwrap();

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(
                        state.target_boot_alternative_selection,
                        TargetBootAlternativeSelection::Opposite
                    );
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn typing_clears_error_message() {
                let input_state = InputState {
                    error_message: Some("Previous error".to_string()),
                    ..create_test_input_state(RecoveryMode::Nns)
                };
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(char_event('a'))).unwrap();

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert!(state.error_message.is_none());
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn backspace_deletes_characters() {
                let mut input_state = create_test_input_state(RecoveryMode::Nns);
                set_field_text(&mut input_state, Field::Version, "abc123");
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Backspace)))
                    .unwrap();

                if let Some(AppState::Input(state)) = app.get_state() {
                    assert_eq!(state.get_field_text(Field::Version), "abc12");
                } else {
                    panic!("Expected Input state");
                }
            }
        }

        mod submission {
            use super::*;

            #[test]
            fn exit_button_quits() {
                let input_state = InputState {
                    focused_index: 3, // ExitButton
                    ..create_test_input_state(RecoveryMode::Nns)
                };
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Enter)))
                    .unwrap();

                assert!(app.is_should_quit());
            }

            #[test]
            fn empty_inputs_shows_error() {
                let input_state = InputState {
                    focused_index: 2, // CheckArtifactsButton
                    ..create_test_input_state(RecoveryMode::Nns)
                };
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Enter)))
                    .unwrap();

                assert!(!app.is_should_quit());
                if let Some(AppState::Input(state)) = app.get_state() {
                    assert!(state.error_message.as_ref().unwrap().contains("VERSION"));
                } else {
                    panic!("Expected Input state");
                }
            }

            #[test]
            fn invalid_version_length_shows_error() {
                let mut input_state = create_test_input_state(RecoveryMode::Nns);
                set_field_text(&mut input_state, Field::Version, "abc"); // Too short
                set_field_text(&mut input_state, Field::RecoveryHashPrefix, "123456");
                input_state.focused_index = 2; // CheckArtifactsButton
                let mut app = GuestOSRecoveryApp::with_state(AppState::Input(input_state));

                app.handle_event(Event::Key(key_event(KeyCode::Enter)))
                    .unwrap();

                if let Some(AppState::Input(state)) = app.get_state() {
                    let error = state.error_message.as_ref().unwrap();
                    assert!(error.contains("40") || error.contains("VERSION"));
                } else {
                    panic!("Expected Input state");
                }
            }
        }
    }

    mod confirmation_state {
        use super::*;

        #[test]
        fn escape_returns_to_input() {
            let confirmation = ConfirmationState {
                input_state: create_test_input_state(RecoveryMode::Nns),
                params: default_recovery_params_for_test(),
                selected_option: ConfirmationOption::Yes,
            };
            let mut app = GuestOSRecoveryApp::with_state(AppState::InputConfirmation(confirmation));

            app.handle_event(Event::Key(key_event(KeyCode::Esc)))
                .unwrap();

            assert!(matches!(app.get_state(), Some(AppState::Input(_))));
            assert!(!app.is_should_quit());
        }

        #[test]
        fn tab_toggles_selection() {
            let confirmation = ConfirmationState {
                input_state: create_test_input_state(RecoveryMode::Nns),
                params: default_recovery_params_for_test(),
                selected_option: ConfirmationOption::Yes,
            };
            let mut app = GuestOSRecoveryApp::with_state(AppState::InputConfirmation(confirmation));

            let get_selection = |app: &GuestOSRecoveryApp| {
                if let Some(AppState::InputConfirmation(state)) = app.get_state() {
                    state.selected_option.clone()
                } else {
                    panic!("Expected InputConfirmation state");
                }
            };

            app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                .unwrap();
            assert_eq!(get_selection(&app), ConfirmationOption::No);

            app.handle_event(Event::Key(key_event(KeyCode::Tab)))
                .unwrap();
            assert_eq!(get_selection(&app), ConfirmationOption::Yes);
        }

        #[test]
        fn left_right_changes_selection() {
            let confirmation = ConfirmationState {
                input_state: create_test_input_state(RecoveryMode::Nns),
                params: default_recovery_params_for_test(),
                selected_option: ConfirmationOption::Yes,
            };
            let mut app = GuestOSRecoveryApp::with_state(AppState::InputConfirmation(confirmation));

            let get_selection = |app: &GuestOSRecoveryApp| {
                if let Some(AppState::InputConfirmation(state)) = app.get_state() {
                    state.selected_option.clone()
                } else {
                    panic!("Expected InputConfirmation state");
                }
            };

            app.handle_event(Event::Key(key_event(KeyCode::Right)))
                .unwrap();
            assert_eq!(get_selection(&app), ConfirmationOption::No);

            app.handle_event(Event::Key(key_event(KeyCode::Left)))
                .unwrap();
            assert_eq!(get_selection(&app), ConfirmationOption::Yes);
        }

        #[test]
        fn enter_no_returns_to_input() {
            let confirmation = ConfirmationState {
                input_state: create_valid_input_state(),
                params: default_recovery_params_for_test(),
                selected_option: ConfirmationOption::No,
            };
            let mut app = GuestOSRecoveryApp::with_state(AppState::InputConfirmation(confirmation));

            app.handle_event(Event::Key(key_event(KeyCode::Enter)))
                .unwrap();

            assert!(matches!(app.get_state(), Some(AppState::Input(_))));
            assert!(!app.is_should_quit());
        }
    }

    mod failure_state {
        use super::*;

        #[test]
        fn any_key_quits() {
            let failure = create_test_failure_state();
            let mut app = GuestOSRecoveryApp::with_state(AppState::Failure(failure));

            app.handle_event(Event::Key(char_event('x'))).unwrap();

            assert!(app.is_should_quit());
        }
    }
}
