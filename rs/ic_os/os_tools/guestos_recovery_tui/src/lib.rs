use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
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
use std::io;
use std::process::Command;

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("Failed to create terminal")
}

fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().context("Failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("Failed to leave alternate screen")?;
    terminal.show_cursor().context("Failed to show cursor")?;
    Ok(())
}

fn build_upgrader_command(params: &RecoveryParams) -> Command {
    let mut cmd = Command::new("bash");
    cmd.arg("/opt/ic/bin/guestos-recovery-upgrader.sh")
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

    pub fn run(&mut self) -> Result<Option<RecoveryParams>> {
        // Check if we're in a TTY (both stdin and stdout need to be TTYs for interactive TUI)
        if !atty::is(atty::Stream::Stdout) || !atty::is(atty::Stream::Stdin) {
            anyhow::bail!(
                "This program requires an interactive terminal.\n\
                VS Code terminal and regular terminals should work.\n\
                Make sure you're not piping or redirecting output."
            );
        }

        let mut terminal = setup_terminal()?;
        execute!(terminal.backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        // Initial draw
        terminal.draw(|f: &mut Frame| self.ui(f))?;

        let result = loop {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
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
                        terminal.draw(|f: &mut Frame| self.ui(f))?;
                    }
                }
            }
        };

        execute!(terminal.backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;
        teardown_terminal(&mut terminal)?;
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

        // Create main layout: [Title(1), Instructions(3), Fields(9), Buttons(1), Spacer(flex)]
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Title
                Constraint::Length(3), // Instructions
                Constraint::Length(9), // Fields (exactly 3 fields × 3 lines each)
                Constraint::Length(1), // Buttons
                Constraint::Min(0),    // Spacer (takes remaining space)
            ])
            .split(size);

        // Title
        let title = Paragraph::new("NNS recovery")
            .block(
                Block::default()
                    .borders(Borders::NONE)
                    .style(Style::default().bold()),
            )
            .alignment(Alignment::Center)
            .style(Style::default().bold());
        f.render_widget(title, main_layout[0]);

        // Instructions
        let instructions = vec![
            Line::from("Enter the information supplied by the recovery coordinator."),
            Line::from("Use Up/Down arrows or TAB to move between fields."),
        ];
        let instructions_para = Paragraph::new(instructions)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        f.render_widget(instructions_para, main_layout[1]);

        // Fields area - split into 3 equal parts for the input fields
        let fields_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // VERSION field
                Constraint::Length(3), // VERSION-HASH field
                Constraint::Length(3), // RECOVERY-HASH field
            ])
            .split(main_layout[2]);

        // Input fields
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

        // Buttons - center horizontally
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

        // Error message (overlay)
        if let Some(ref error) = self.error_message {
            const MIN_BOX_WIDTH: u16 = 60;
            const BOX_HEIGHT: u16 = 5;
            const BORDER_PADDING: u16 = 4;

            // Calculate box width: clamp error length between min and max, add border padding
            let max_width = (size.width * 80 / 100).max(MIN_BOX_WIDTH);
            let error_text_width = error.len().min(u16::MAX as usize) as u16;
            let box_width = error_text_width.clamp(MIN_BOX_WIDTH, max_width) + BORDER_PADDING;

            // Center vertically: split screen into 50% top, box height, 50% bottom
            let vertical_area = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(BOX_HEIGHT),
                    Constraint::Percentage(50),
                ])
                .split(size)[1];

            // Center horizontally: calculate start position to center the box
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

pub fn show_status_and_run_upgrader(params: &RecoveryParams) -> Result<()> {
    let mut terminal = setup_terminal()?;

    // Show status screen
    let version_line = format!("  VERSION: {}", params.version);
    let version_hash_line = format!("  VERSION-HASH: {}", params.version_hash);
    let recovery_hash_line = format!("  RECOVERY-HASH: {}", params.recovery_hash);
    terminal.draw(|f| {
        let size = f.size();
        let block = Block::default()
            .borders(Borders::ALL)
            .title("GuestOS Recovery Upgrader")
            .style(Style::default().bold());

        let text = vec![
            Line::from(""),
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

    // Run the upgrader script with command line parameters
    // Output will go to tty1 via the script's log_message function
    let status = build_upgrader_command(params)
        .status()
        .context("Failed to run recovery upgrader")?;

    // Show completion message
    terminal.draw(|f| {
        let size = f.size();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(if status.success() {
                "Recovery Completed"
            } else {
                "Recovery Failed"
            })
            .style(if status.success() {
                Style::default().fg(Color::Green).bold()
            } else {
                Style::default().fg(Color::Red).bold()
            });

        let status_msg = if status.success() {
            "Recovery completed successfully!".to_string()
        } else {
            format!("Recovery failed with exit code: {:?}", status.code())
        };
        let text = vec![
            Line::from(""),
            Line::from(status_msg),
            Line::from(""),
            Line::from("Press any key to continue..."),
        ];

        let para = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(para, size);
    })?;

    // Wait for key press
    if let Event::Key(_) = event::read()? {}

    teardown_terminal(&mut terminal)?;

    if !status.success() {
        anyhow::bail!(
            "Recovery upgrader failed with exit code: {:?}",
            status.code()
        );
    }

    Ok(())
}
