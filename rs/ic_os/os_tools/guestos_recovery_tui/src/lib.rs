use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    Clear as TerminalClear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
    disable_raw_mode, enable_raw_mode,
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
    // Clear the normal screen after leaving alternate screen to prevent interference from background logs
    let _ = execute!(io::stdout(), TerminalClear(ClearType::All));
    let _ = io::stdout().flush();
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
            let _ = disable_raw_mode();
            let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            let _ = terminal.show_cursor();
            // Clear the normal screen after leaving alternate screen to prevent interference from background logs
            let _ = execute!(io::stdout(), TerminalClear(ClearType::All));
            let _ = io::stdout().flush();
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
        Self::validate_hex_field(&self.version, 40, "VERSION", "Git commit hash")?;
        Self::validate_hex_field(&self.version_hash, 64, "VERSION-HASH", "SHA256")?;
        Self::validate_hex_field(&self.recovery_hash, 64, "RECOVERY-HASH", "SHA256")?;
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

    fn next(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + 1) % Self::ALL.len()]
    }

    fn previous(&self) -> Self {
        let pos = Self::ALL.iter().position(|&f| f == *self).unwrap_or(0);
        Self::ALL[(pos + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn is_input_field(&self) -> bool {
        matches!(
            self,
            Field::Version | Field::VersionHash | Field::RecoveryHash
        )
    }

    fn max_length(&self) -> Option<usize> {
        match self {
            Field::Version => Some(40),
            Field::VersionHash | Field::RecoveryHash => Some(64),
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

    fn handle_input_char(&mut self, c: char) {
        if let (Some(max_len), Some(field_value)) = (
            self.current_field.max_length(),
            self.current_field.get_value_mut(&mut self.params),
        ) {
            if field_value.len() < max_len && c.is_ascii_hexdigit() {
                field_value.push(c);
                self.clear_error();
            }
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
        if test_size.width < 10 || test_size.height < 15 {
            let mut term = terminal_guard.terminal.take().unwrap();
            teardown_terminal(&mut term)?;
            anyhow::bail!(
                "Terminal too small: {}x{} (minimum: 10x15). Please resize your terminal.",
                test_size.width,
                test_size.height
            );
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))?;

        let result = loop {
            // Poll with periodic redraws to ensure the screen stays clean.
            if event::poll(Duration::from_millis(2000))? {
                match event::read()? {
                    Event::Key(key) => {
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

                            if needs_redraw {
                                if let Err(e) =
                                    terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))
                                {
                                    let mut term = terminal_guard.terminal.take().unwrap();
                                    teardown_terminal(&mut term)?;
                                    return Err(e).context("Failed to render TUI - terminal may not support required features");
                                }
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // No event yet, periodically redraw to prevent log interference
                // Redraw without clearing to avoid flashing - overwriting should be sufficient
                terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))?;
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

    fn ui(&self, f: &mut Frame) {
        let size = f.size();

        if size.width < 10 || size.height < 15 {
            let error_text = vec![
                Line::from("Terminal too small"),
                Line::from(format!(
                    "Minimum size: 10x15, current: {}x{}",
                    size.width, size.height
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
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(9),
                Constraint::Length(1),
                Constraint::Min(0),
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
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(main_layout[2]);

        let field_configs = [
            (
                Field::Version,
                "VERSION:",
                &self.params.version,
                "Mandatory. The commit ID of the recovery-GuestOS update image (40 hex characters).",
                fields_layout[0],
            ),
            (
                Field::VersionHash,
                "VERSION-HASH:",
                &self.params.version_hash,
                "Mandatory. The SHA256 sum of the recovery-GuestOS update image (64 hex characters).",
                fields_layout[1],
            ),
            (
                Field::RecoveryHash,
                "RECOVERY-HASH:",
                &self.params.recovery_hash,
                "Mandatory. The SHA256 sum of the recovery.tar.zst (64 hex characters).",
                fields_layout[2],
            ),
        ];

        for (field, label, value, description, area) in field_configs.iter() {
            self.render_input_field(f, *field, label, value, description, *area);
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
    if size.width < 10 || size.height < 5 {
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
        let separator = "─".repeat((size.width.saturating_sub(4)).max(10) as usize);
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
        let separator = "─".repeat((size.width.saturating_sub(4)).max(10) as usize);
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

            let available_height = size.height.saturating_sub(11);
            let lines_to_show = all_log_lines.len().min(available_height as usize);

            let start_idx = if all_log_lines.len() > lines_to_show {
                all_log_lines.len() - lines_to_show
            } else {
                0
            };

            for line in &all_log_lines[start_idx..] {
                let max_width = (size.width.saturating_sub(4)) as usize;
                let display_line = if line.len() > max_width {
                    format!("{}...", &line[..max_width.saturating_sub(3)])
                } else {
                    line.clone()
                };
                text.push(Line::from(format!("  {}", display_line)));
            }
        } else if !error_messages.is_empty() {
            text.push(Line::from(vec![Span::styled(
                "Error details:",
                Style::default().fg(Color::Red).bold(),
            )]));
            text.push(Line::from(""));
            for error in error_messages {
                let max_width = (size.width.saturating_sub(4)) as usize;
                let display_line = if error.len() > max_width {
                    format!("{}...", &error[..max_width.saturating_sub(3)])
                } else {
                    error.clone()
                };
                text.push(Line::from(format!("  {}", display_line)));
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
        if size.width < 10 || size.height < 5 {
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

    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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
        for line in reader.lines().filter_map(Result::ok) {
            let mut logs = log_lines_stdout.lock().unwrap();
            logs.push(line);
        }
    });

    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().filter_map(Result::ok) {
            let mut logs = log_lines_stderr.lock().unwrap();
            logs.push(line);
        }
    });

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                stdout_handle.join().ok();
                stderr_handle.join().ok();
                break status;
            }
            Ok(None) => {
                let logs = log_lines.lock().unwrap();
                let current_logs: Vec<String> = logs.clone();
                drop(logs);

                // Always redraw periodically to prevent background log interference
                // Redraw without clearing to avoid flashing - overwriting should be sufficient
                terminal_guard
                    .get_mut()
                    .draw(|f| {
                        let size = f.size();
                        if size.width < 10 || size.height < 5 {
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

                        let available_height = size.height.saturating_sub(10);
                        let lines_to_show = current_logs.len().min(available_height as usize);
                        let start_idx = if current_logs.len() > lines_to_show {
                            current_logs.len() - lines_to_show
                        } else {
                            0
                        };

                        for line in &current_logs[start_idx..] {
                            let max_width = (size.width.saturating_sub(4)) as usize;
                            let display_line = if line.len() > max_width {
                                format!("{}...", &line[..max_width.saturating_sub(3)])
                            } else {
                                line.clone()
                            };
                            text.push(Line::from(format!("  {}", display_line)));
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

                thread::sleep(std::time::Duration::from_millis(100));
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

    let mut error_messages = Vec::new();
    let mut success_message = None;

    let stdout_lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .collect();

    let stderr_lines: Vec<String> = String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .collect();

    for line in &stdout_lines {
        if line.contains("Recovery Upgrader completed successfully") {
            success_message = Some("Recovery Upgrader completed successfully".to_string());
        }
    }

    let mut explicit_errors = Vec::new();
    let mut debug_messages = Vec::new();

    for line in &stdout_lines {
        if line.contains("ERROR:") || line.contains("error:") || line.contains("Error:") {
            explicit_errors.push(line.clone());
        }
        if line.contains("Received") && line.contains("arguments") {
            debug_messages.push(line.clone());
        }
        if line.contains("Parsed VERSION") || line.contains("Parsed VERSION_HASH") {
            debug_messages.push(line.clone());
        }
    }
    for line in &stderr_lines {
        if line.contains("ERROR:") || line.contains("error:") || line.contains("Error:") {
            explicit_errors.push(line.clone());
        }
    }

    if !explicit_errors.is_empty() {
        error_messages = debug_messages;
        error_messages.extend(explicit_errors);
    } else if !output.status.success() {
        if !stderr_lines.is_empty() {
            let start = stderr_lines.len().saturating_sub(30);
            error_messages = stderr_lines[start..].to_vec();
        } else if !stdout_lines.is_empty() {
            let start = stdout_lines.len().saturating_sub(30);
            error_messages = stdout_lines[start..].to_vec();
        }
    }

    if error_messages.is_empty() && !output.status.success() {
        let journalctl_output = Command::new("journalctl")
            .arg("-t")
            .arg("guestos-recovery-upgrader")
            .arg("--since")
            .arg(format!("@{}", start_time))
            .arg("--no-pager")
            .arg("-o")
            .arg("cat")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        if let Ok(journal_output) = journalctl_output {
            let journalctl_lines: Vec<String> = String::from_utf8_lossy(&journal_output.stdout)
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.trim().is_empty())
                .collect();

            let mut explicit_errors = Vec::new();
            for line in &journalctl_lines {
                if line.contains("ERROR:") || line.contains("error:") || line.contains("Error:") {
                    explicit_errors.push(line.clone());
                }
            }
            if !explicit_errors.is_empty() {
                error_messages = explicit_errors;
            } else if !journalctl_lines.is_empty() {
                let start = journalctl_lines.len().saturating_sub(30);
                error_messages = journalctl_lines[start..].to_vec();
            }
        }
    }

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

    // Poll for key events with periodic redraws to prevent background logs from interfering
    // Direct writes to /dev/tty1 or /dev/ttyS0 bypass the TUI, so we need to clear before redraw
    // Logs come every 15 minutes, so 2 seconds is plenty
    loop {
        // Poll with timeout - logs come every 15 minutes, so 2 seconds is plenty
        if event::poll(Duration::from_millis(2000))? {
            if let Event::Key(_) = event::read()? {
                break;
            }
        } else {
            // No event yet, clear and redraw to ensure screen stays clean if logs wrote to terminal
            // Must clear before redraw because direct terminal writes aren't fully overwritten by draw() alone
            let _ = terminal_guard.get_mut().clear();
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
        }
    }

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
