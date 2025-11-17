use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::io::{self, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

// Terminal size constants
const MIN_TERMINAL_WIDTH: u16 = 10;
const MIN_TERMINAL_HEIGHT: u16 = 15;

/// Checks if the terminal size is too small for the UI
fn is_terminal_too_small(size: Rect) -> bool {
    size.width < MIN_TERMINAL_WIDTH || size.height < MIN_TERMINAL_HEIGHT
}

/// Validates terminal size and returns an error if too small
fn validate_terminal_size(size: Rect) -> Result<()> {
    if is_terminal_too_small(size) {
        anyhow::bail!(
            "Terminal too small: {}x{} (minimum: {}x{}). Please resize your terminal.",
            size.width,
            size.height,
            MIN_TERMINAL_WIDTH,
            MIN_TERMINAL_HEIGHT
        );
    }
    Ok(())
}

// Field length constants
const VERSION_LENGTH: usize = 40; // Git commit hash length (hex characters)
const HASH_LENGTH: usize = 64; // SHA256 hash length (hex characters)

// UI layout constants
const TEXT_PADDING: u16 = 4; // Padding for text display
const MAX_ERROR_LINES: usize = 30; // Maximum number of error lines to display
const PROCESS_POLL_INTERVAL_MS: u64 = 100; // Polling interval for process monitoring

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

// Guard struct to ensure terminal cleanup on panic
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

fn build_upgrader_command(params: &RecoveryParams) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg("/opt/ic/bin/guestos-recovery-upgrader.sh")
        .arg(format!("version={}", params.version))
        .arg(format!("version-hash={}", params.version_hash))
        .arg(format!("recovery-hash={}", params.recovery_hash));
    cmd
}

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
enum Field {
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
        if let Err(e) = validate_terminal_size(test_size) {
            let mut term = terminal_guard.terminal.take().unwrap();
            teardown_terminal(&mut term)?;
            return Err(e);
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))?;

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
                            && let Err(e) =
                                terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))
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
                    self.clear_error();
                    Ok(InputResult::Continue)
                } else {
                    match self.current_field {
                        Field::ExitButton => Ok(InputResult::Exit),
                        Field::CheckArtifactsButton => Ok(InputResult::Proceed),
                        _ => Ok(InputResult::Continue),
                    }
                }
            }

            KeyCode::Tab | KeyCode::Down => {
                self.current_field = self.current_field.next();
                self.clear_error();
                Ok(InputResult::Continue)
            }

            KeyCode::Up => {
                self.current_field = self.current_field.previous();
                self.clear_error();
                Ok(InputResult::Continue)
            }

            KeyCode::Left | KeyCode::Right => {
                if matches!(
                    self.current_field,
                    Field::CheckArtifactsButton | Field::ExitButton
                ) {
                    self.current_field = if self.current_field == Field::CheckArtifactsButton {
                        Field::ExitButton
                    } else {
                        Field::CheckArtifactsButton
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

    fn ui(&self, f: &mut Frame) {
        let size = f.size();

        if is_terminal_too_small(size) {
            let error_text = vec![
                Line::from("Terminal too small"),
                Line::from(format!(
                    "Minimum size: {}x{}, current: {}x{}",
                    MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT, size.width, size.height
                )),
                Line::from("Please resize your terminal"),
            ];
            let para = Paragraph::new(error_text)
                .block(Block::default().borders(Borders::ALL).title("Error"))
                .alignment(Alignment::Center);
            f.render_widget(para, size);
            return;
        }

        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Title area
                Constraint::Length(3), // Instructions area
                Constraint::Length(9), // Input fields area (3 fields × 3 rows each)
                Constraint::Length(1), // Button area
                Constraint::Min(0),    // Remaining space
            ])
            .split(size);

        let title = Paragraph::new("NNS recovery")
            .block(
                Block::default()
                    .borders(Borders::NONE)
                    .style(Style::default().bold()),
            )
            .alignment(Alignment::Center)
            .style(Style::default().bold());
        f.render_widget(title, main_layout[0]);

        let instructions = vec![
            Line::from("Enter the information supplied by the recovery coordinator."),
            Line::from("Use Up/Down arrows or TAB to move between fields."),
        ];
        let instructions_para = Paragraph::new(instructions)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        f.render_widget(instructions_para, main_layout[1]);

        let fields_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Version field
                Constraint::Length(3), // VersionHash field
                Constraint::Length(3), // RecoveryHash field
            ])
            .split(main_layout[2]);

        for (i, field) in Field::INPUT_FIELDS.iter().enumerate() {
            self.render_input_field(
                f,
                *field,
                field.label(),
                field.get_value(&self.params),
                field.description(),
                fields_layout[i],
            );
        }

        let check_text = "<Run recovery>";
        let exit_text = "<Exit>";
        let check_text_len = check_text.len() as u16;
        let exit_text_len = exit_text.len() as u16;
        let spacing = 5;
        let total_width = check_text_len + exit_text_len + spacing;

        let button_area = main_layout[3];
        let start_x = button_area.x + (button_area.width.saturating_sub(total_width)) / 2;

        self.render_button(
            f,
            check_text,
            Field::CheckArtifactsButton,
            Rect::new(start_x, button_area.y, check_text_len, 1),
        );
        self.render_button(
            f,
            exit_text,
            Field::ExitButton,
            Rect::new(
                start_x + check_text_len + spacing,
                button_area.y,
                exit_text_len,
                1,
            ),
        );

        if let Some(ref error) = self.error_message {
            const MIN_BOX_WIDTH: u16 = 60;
            const BOX_HEIGHT: u16 = 5;
            const BORDER_PADDING: u16 = 4;

            let max_width = (size.width * 80 / 100).max(MIN_BOX_WIDTH);
            let error_text_width = error.len().min(u16::MAX as usize) as u16;
            let box_width = error_text_width.clamp(MIN_BOX_WIDTH, max_width) + BORDER_PADDING;

            let vertical_area = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(BOX_HEIGHT),
                    Constraint::Percentage(50),
                ])
                .split(size)[1];

            let start_x = vertical_area.x + (vertical_area.width.saturating_sub(box_width)) / 2;
            let error_area = Rect::new(start_x, vertical_area.y, box_width, BOX_HEIGHT);

            let error_para = Paragraph::new(error.as_str())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .fg(Color::Red)
                        .bg(Color::Black)
                        .title("Error"),
                )
                .wrap(Wrap { trim: true });
            f.render_widget(Clear, error_area);
            f.render_widget(error_para, error_area);
        }
    }

    fn render_input_field(
        &self,
        f: &mut Frame,
        field: Field,
        label: &str,
        value: &str,
        description: &str,
        area: Rect,
    ) {
        let selected = self.current_field == field;
        let block = Block::default()
            .borders(Borders::ALL)
            .bg(if selected { Color::Blue } else { Color::Reset })
            .title(Span::styled(
                label,
                Style::default()
                    .bold()
                    .fg(if selected { Color::White } else { Color::Cyan }),
            ));
        let input = if selected {
            format!("{}█", value)
        } else {
            value.to_string()
        };
        let content = vec![Line::from(input), Line::from(""), Line::from(description)];
        let para = Paragraph::new(content).block(block).fg(Color::Cyan);
        f.render_widget(para, area);
    }

    fn render_button(&self, f: &mut Frame, text: &str, field: Field, area: Rect) {
        let selected = self.current_field == field;
        let para = Paragraph::new(text)
            .bg(if selected { Color::Blue } else { Color::Reset })
            .fg(if selected { Color::White } else { Color::Reset });
        f.render_widget(para, area);
    }
}

/// Parses log lines from bytes, filtering out empty lines
fn parse_log_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .collect()
}

fn calculate_log_viewport(total_lines: usize, available_height: usize) -> (usize, usize) {
    let lines_to_show = total_lines.min(available_height);
    let start_idx = total_lines.saturating_sub(lines_to_show);
    (start_idx, lines_to_show)
}

fn is_error_line(line: &str) -> bool {
    line.contains("ERROR:") || line.contains("error:") || line.contains("Error:")
}

/// Detects success message in stdout
fn detect_success_message(stdout_lines: &[String]) -> Option<String> {
    const SUCCESS_INDICATOR: &str = "Recovery Upgrader completed successfully";
    stdout_lines
        .iter()
        .find(|line| line.contains(SUCCESS_INDICATOR))
        .map(|_| SUCCESS_INDICATOR.to_string())
}

/// Extracts errors from stdout/stderr (tries explicit errors, then fallback to last N lines)
fn extract_errors_from_logs(stdout_lines: &[String], stderr_lines: &[String]) -> Vec<String> {
    // Try explicit errors first
    let explicit_errors: Vec<String> = stdout_lines
        .iter()
        .chain(stderr_lines.iter())
        .filter(|line| is_error_line(line))
        .cloned()
        .collect();

    if !explicit_errors.is_empty() {
        // Include debug context with explicit errors
        let mut messages: Vec<String> = stdout_lines
            .iter()
            .filter(|line| {
                (line.contains("Received") && line.contains("arguments"))
                    || line.contains("Parsed VERSION")
                    || line.contains("Parsed VERSION_HASH")
            })
            .cloned()
            .collect();
        messages.extend(explicit_errors);
        return messages;
    }

    // Fallback: last N lines from stderr or stdout
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

fn truncate_line(line: &str, max_width: usize) -> String {
    if line.len() > max_width {
        format!("{}...", &line[..max_width.saturating_sub(3)])
    } else {
        line.to_string()
    }
}

fn create_separator(width: u16) -> String {
    "─".repeat((width.saturating_sub(TEXT_PADDING)).max(10) as usize)
}

fn draw_completion_screen(
    f: &mut Frame,
    success: bool,
    success_message: &Option<String>,
    output: &std::process::Output,
    stdout_lines: &[String],
    stderr_lines: &[String],
    error_messages: &[String],
) {
    let size = f.size();
    if is_terminal_too_small(size) {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if success {
            "Recovery Completed"
        } else {
            "Recovery Failed"
        })
        .style(if success {
            Style::default().fg(Color::Green).bold()
        } else {
            Style::default().fg(Color::Red).bold()
        });

    let mut text = Vec::new();

    if success {
        text.push(Line::from(""));
        let success_msg = match success_message {
            Some(msg) => format!("✓ {}", msg),
            None => "✓ Recovery completed successfully!".to_string(),
        };
        text.push(Line::from(vec![Span::styled(
            success_msg,
            Style::default().fg(Color::Green).bold(),
        )]));
        text.push(Line::from(""));
        let separator = create_separator(size.width);
        text.push(Line::from(vec![Span::styled(
            separator,
            Style::default().fg(Color::DarkGray),
        )]));
        text.push(Line::from(""));
    } else {
        text.push(Line::from(""));
        text.push(Line::from(vec![Span::styled(
            format!(
                "✗ Recovery failed with exit code: {:?}",
                output.status.code()
            ),
            Style::default().fg(Color::Red).bold(),
        )]));
        text.push(Line::from(""));
        let separator = create_separator(size.width);
        text.push(Line::from(vec![Span::styled(
            separator,
            Style::default().fg(Color::DarkGray),
        )]));
        text.push(Line::from(""));

        let mut all_log_lines = Vec::new();

        for line in stdout_lines {
            all_log_lines.push(line.clone());
        }

        for line in stderr_lines {
            if !stdout_lines.contains(line) {
                all_log_lines.push(line.clone());
            }
        }

        if !all_log_lines.is_empty() {
            text.push(Line::from(vec![Span::styled(
                "Error logs:",
                Style::default().fg(Color::Red).bold(),
            )]));
            text.push(Line::from(""));

            let available_height = size.height.saturating_sub(11) as usize;
            let (start_idx, _) = calculate_log_viewport(all_log_lines.len(), available_height);

            let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
            for line in &all_log_lines[start_idx..] {
                text.push(Line::from(format!("  {}", truncate_line(line, max_width))));
            }
        } else if !error_messages.is_empty() {
            text.push(Line::from(vec![Span::styled(
                "Error details:",
                Style::default().fg(Color::Red).bold(),
            )]));
            text.push(Line::from(""));
            let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
            for error in error_messages {
                text.push(Line::from(format!("  {}", truncate_line(error, max_width))));
            }
        } else {
            text.push(Line::from(""));
            text.push(Line::from(
                "No error logs captured. Check system logs for details:",
            ));
            text.push(Line::from("  journalctl -t guestos-recovery-upgrader"));
        }
    }

    text.push(Line::from(""));
    text.push(Line::from("Press any key to continue..."));

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(para, size);
}

/// Displays a status screen and runs the recovery upgrader script with the given parameters.
/// Shows real-time logs and a completion screen with results.
pub fn show_status_and_run_upgrader(params: &RecoveryParams) -> Result<()> {
    let terminal = setup_terminal()?;
    let mut terminal_guard = TerminalGuard::new(terminal);

    let version_line = format!("  VERSION: {}", params.version);
    let version_hash_line = format!("  VERSION-HASH: {}", params.version_hash);
    let recovery_hash_line = format!("  RECOVERY-HASH: {}", params.recovery_hash);
    terminal_guard.get_mut().draw(|f| {
        let size = f.size();
        if is_terminal_too_small(size) {
            return;
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .title("GuestOS Recovery Upgrader")
            .style(Style::default().bold());

        let text = vec![
            Line::from("Parameters:"),
            Line::from(version_line.clone()),
            Line::from(version_hash_line.clone()),
            Line::from(recovery_hash_line.clone()),
            Line::from(""),
            Line::from("Starting recovery process..."),
            Line::from("This may take several minutes. Please wait..."),
        ];

        let para = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true });
        f.render_widget(para, size);
    })?;

    if params.version.is_empty() || params.version_hash.is_empty() {
        anyhow::bail!("Invalid parameters: version and version-hash must be non-empty");
    }

    let mut cmd = build_upgrader_command(params);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn recovery upgrader")?;

    let log_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_lines_stdout = Arc::clone(&log_lines);
    let log_lines_stderr = Arc::clone(&log_lines);

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdout handle"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stderr handle"))?;

    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let mut logs = log_lines_stdout.lock().unwrap();
                    logs.push(line);
                }
                Err(_) => break,
            }
        }
    });

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let mut logs = log_lines_stderr.lock().unwrap();
                    logs.push(line);
                }
                Err(_) => break,
            }
        }
    });

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
                        .draw(|f| {
                            let size = f.size();
                            if is_terminal_too_small(size) {
                                return;
                            }
                            let block = Block::default()
                                .borders(Borders::ALL)
                                .title("GuestOS Recovery Upgrader")
                                .style(Style::default().bold());

                            let mut text = vec![
                                Line::from("Parameters:"),
                                Line::from(version_line.clone()),
                                Line::from(version_hash_line.clone()),
                                Line::from(recovery_hash_line.clone()),
                                Line::from(""),
                                Line::from("Recovery process logs:"),
                                Line::from(""),
                            ];

                            let available_height = size.height.saturating_sub(10) as usize;
                            let (start_idx, lines_to_show) =
                                calculate_log_viewport(current_logs.len(), available_height);

                            let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
                            for line in &current_logs[start_idx..] {
                                text.push(Line::from(format!(
                                    "  {}",
                                    truncate_line(line, max_width)
                                )));
                            }

                            if current_logs.len() > lines_to_show {
                                text.push(Line::from(""));
                                text.push(Line::from(format!(
                                    "  ... (showing last {} of {} log lines)",
                                    lines_to_show,
                                    current_logs.len()
                                )));
                            }

                            let para = Paragraph::new(text)
                                .block(block)
                                .alignment(Alignment::Left)
                                .wrap(Wrap { trim: true });
                            f.render_widget(para, size);
                        })
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
        draw_completion_screen(
            f,
            success,
            &success_message,
            &output,
            &stdout_lines,
            &stderr_lines,
            &error_messages,
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
