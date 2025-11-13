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
use std::io::{self, Write};
use std::process::{Command, Stdio};

// Check if we're likely in a web console by checking TERM
// Web consoles often use basic terminal types that don't support alternate screen well
// Note: "linux" is commonly used by VGA consoles which DO support TUI, so we don't exclude it
fn is_likely_web_console() -> bool {
    // Check TERM environment variable
    if let Ok(term) = std::env::var("TERM") {
        // "dumb" is a non-interactive terminal that definitely won't work
        // "vt100" might work but is often used by web consoles
        // "linux" is used by VGA consoles which support TUI, so we allow it
        if term == "dumb" {
            return true;
        }
        // For other basic terminals, we'll let the TUI setup try and fail gracefully
    }
    false
}

// Test if we can actually write to the terminal and see output
fn test_terminal_output() -> Result<()> {
    use std::io::Write;
    let mut stdout = io::stdout();
    // Write a test message that should be visible
    write!(stdout, "\r\n\x1b[2KTesting terminal output...\r\n")?;
    stdout.flush()?;
    // Give it a moment to appear
    std::thread::sleep(std::time::Duration::from_millis(200));
    Ok(())
}

fn setup_terminal() -> Result<(Terminal<CrosstermBackend<io::Stdout>>, bool)> {
    // For web consoles, skip alternate screen mode entirely to avoid issues
    let skip_alternate_screen = is_likely_web_console();

    // Test if output works BEFORE enabling raw mode
    // If this fails or output doesn't appear, we know the terminal won't work
    if let Err(e) = test_terminal_output() {
        anyhow::bail!(
            "Cannot write to terminal: {}. This terminal may not support the required features.",
            e
        );
    }

    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();

    let use_alternate_screen = if skip_alternate_screen {
        // Skip alternate screen for web consoles - it often causes issues
        false
    } else {
        // Try to enter alternate screen mode, but don't fail if it doesn't work
        match execute!(stdout, EnterAlternateScreen) {
            Ok(_) => true,
            Err(_) => false,
        }
    };

    // Explicitly clear the screen to ensure we start with a clean slate
    // This is especially important for web consoles where alternate screen might not work
    let _ = execute!(stdout, TerminalClear(ClearType::All));
    // Flush to ensure clear command is sent
    stdout.flush()?;

    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend).context("Failed to create terminal")?;
    Ok((terminal, use_alternate_screen))
}

fn teardown_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    use_alternate_screen: bool,
) -> Result<()> {
    disable_raw_mode().context("Failed to disable raw mode")?;
    if use_alternate_screen {
        execute!(terminal.backend_mut(), LeaveAlternateScreen)
            .context("Failed to leave alternate screen")?;
    }
    terminal.show_cursor().context("Failed to show cursor")?;
    Ok(())
}

// Guard struct to ensure terminal cleanup on panic
struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
    use_alternate_screen: bool,
}

impl TerminalGuard {
    fn new(terminal: Terminal<CrosstermBackend<io::Stdout>>, use_alternate_screen: bool) -> Self {
        Self {
            terminal: Some(terminal),
            use_alternate_screen,
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
            if self.use_alternate_screen {
                let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            }
            let _ = terminal.show_cursor();
        }
    }
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

    // Simple text-based fallback for web consoles that don't support TUI
    fn run_text_mode(&mut self) -> Result<Option<RecoveryParams>> {
        println!("\n=== NNS Recovery Tool (Text Mode) ===");
        println!("Enter the information supplied by the recovery coordinator.\n");

        // Get VERSION
        print!("VERSION (40 hex characters): ");
        io::stdout().flush()?;
        let mut version = String::new();
        io::stdin().read_line(&mut version)?;
        self.params.version = version.trim().to_string();

        // Get VERSION-HASH
        print!("VERSION-HASH (64 hex characters): ");
        io::stdout().flush()?;
        let mut version_hash = String::new();
        io::stdin().read_line(&mut version_hash)?;
        self.params.version_hash = version_hash.trim().to_string();

        // Get RECOVERY-HASH
        print!("RECOVERY-HASH (64 hex characters): ");
        io::stdout().flush()?;
        let mut recovery_hash = String::new();
        io::stdin().read_line(&mut recovery_hash)?;
        self.params.recovery_hash = recovery_hash.trim().to_string();

        // Validate
        if let Err(e) = self.params.validate() {
            eprintln!("\nError: {}", e);
            return Ok(None);
        }

        println!("\nParameters entered:");
        println!("  VERSION: {}", self.params.version);
        println!("  VERSION-HASH: {}", self.params.version_hash);
        println!("  RECOVERY-HASH: {}", self.params.recovery_hash);
        print!("\nProceed with recovery? (yes/no): ");
        io::stdout().flush()?;

        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;

        if confirm.trim().to_lowercase() == "yes" {
            Ok(Some(self.params.clone()))
        } else {
            println!("Recovery cancelled.");
            Ok(None)
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

        // For web consoles, use simple text mode instead of TUI
        if is_likely_web_console() {
            return self.run_text_mode();
        }

        let (terminal, use_alternate_screen) = setup_terminal()?;
        let mut terminal_guard = TerminalGuard::new(terminal, use_alternate_screen);

        // Test that we can actually render - check terminal size first
        let test_size = terminal_guard.get_mut().size()?;
        if test_size.width < 10 || test_size.height < 15 {
            // Clean up before bailing
            let use_alt = terminal_guard.use_alternate_screen;
            let mut term = terminal_guard.terminal.take().unwrap();
            teardown_terminal(&mut term, use_alt)?;
            anyhow::bail!(
                "Terminal too small: {}x{} (minimum: 10x15). Please resize your terminal.",
                test_size.width,
                test_size.height
            );
        }

        execute!(terminal_guard.get_mut().backend_mut(), EnableMouseCapture)
            .context("Failed to enable mouse capture")?;

        // Test render to verify terminal works
        terminal_guard.get_mut().draw(|f: &mut Frame| {
            let size = f.size();
            let test_text = vec![
                Line::from(""),
                Line::from("Testing terminal..."),
                Line::from(""),
            ];
            let para = Paragraph::new(test_text)
                .block(Block::default().borders(Borders::NONE))
                .alignment(Alignment::Center);
            f.render_widget(para, size);
        })?;

        // Small delay to ensure the test render is visible
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Initial draw
        terminal_guard.get_mut().draw(|f: &mut Frame| self.ui(f))?;

        let result = loop {
            match event::read() {
                Ok(Event::Key(key)) => {
                    if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                        // Handle Ctrl+C explicitly to ensure we can always exit
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
                                // If rendering fails, clean up and bail
                                let use_alt = terminal_guard.use_alternate_screen;
                                let mut term = terminal_guard.terminal.take().unwrap();
                                teardown_terminal(&mut term, use_alt)?;
                                return Err(e).context("Failed to render TUI - terminal may not support required features");
                            }
                        }
                    }
                }
                Ok(_) => {
                    // Ignore non-key events
                }
                Err(e) => {
                    // If we can't read events, clean up and bail
                    let use_alt = terminal_guard.use_alternate_screen;
                    let mut term = terminal_guard.terminal.take().unwrap();
                    teardown_terminal(&mut term, use_alt)?;
                    return Err(e).context("Failed to read terminal events - terminal may not support required features");
                }
            }
        };

        execute!(terminal_guard.get_mut().backend_mut(), DisableMouseCapture)
            .context("Failed to disable mouse capture")?;
        // Explicitly clean up (guard will also clean up on drop, but this ensures proper order)
        let use_alternate_screen = terminal_guard.use_alternate_screen;
        let mut terminal = terminal_guard.terminal.take().unwrap();
        teardown_terminal(&mut terminal, use_alternate_screen)?;
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

        // Ensure minimum terminal size to prevent panics
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
    let (terminal, use_alternate_screen) = setup_terminal()?;
    let mut terminal_guard = TerminalGuard::new(terminal, use_alternate_screen);

    // Show status screen
    let version_line = format!("  VERSION: {}", params.version);
    let version_hash_line = format!("  VERSION-HASH: {}", params.version_hash);
    let recovery_hash_line = format!("  RECOVERY-HASH: {}", params.recovery_hash);
    terminal_guard.get_mut().draw(|f| {
        let size = f.size();
        // Ensure minimum terminal size
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

    // Run the upgrader script with command line parameters
    // Capture output to parse for errors and success messages
    let output = build_upgrader_command(params)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run recovery upgrader")?;

    // Parse output for errors and success messages
    let mut error_messages = Vec::new();
    let mut success_message = None;

    // Parse stderr for errors
    let stderr_lines: Vec<String> = String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|s| s.to_string())
        .collect();

    for line in &stderr_lines {
        if line.contains("ERROR:") {
            error_messages.push(line.clone());
        }
    }

    // Parse stdout for errors and success messages
    let stdout_lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    for line in &stdout_lines {
        if line.contains("ERROR:") {
            error_messages.push(line.clone());
        }
        if line.contains("Recovery Upgrader completed successfully") {
            success_message = Some("Recovery Upgrader completed successfully".to_string());
        }
    }

    // Show completion message
    terminal_guard.get_mut().draw(|f| {
        let size = f.size();
        // Ensure minimum terminal size
        if size.width < 10 || size.height < 5 {
            return;
        }
        let success = output.status.success();
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
            if let Some(ref msg) = success_message {
                text.push(Line::from(msg.clone()));
            } else {
                text.push(Line::from("Recovery completed successfully!"));
            }
        } else {
            text.push(Line::from(format!(
                "Recovery failed with exit code: {:?}",
                output.status.code()
            )));
        }

        // Add error messages if any
        if !error_messages.is_empty() {
            text.push(Line::from(""));
            text.push(Line::from("Errors:"));
            for error in &error_messages {
                text.push(Line::from(format!("  {}", error)));
            }
        }

        // Ensure we always have at least one line
        if text.is_empty() {
            text.push(Line::from("Processing complete."));
        }

        text.push(Line::from(""));
        text.push(Line::from("Press any key to continue..."));

        let para = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true });
        f.render_widget(para, size);
    })?;

    // Wait for key press
    if let Event::Key(_) = event::read()? {}

    // Explicitly clean up (guard will also clean up on drop, but this ensures proper order)
    let use_alternate_screen = terminal_guard.use_alternate_screen;
    let mut terminal = terminal_guard.terminal.take().unwrap();
    teardown_terminal(&mut terminal, use_alternate_screen)?;

    if !output.status.success() {
        let error_summary = if !error_messages.is_empty() {
            format!("\nErrors encountered:\n{}", error_messages.join("\n"))
        } else {
            String::new()
        };
        anyhow::bail!(
            "Recovery upgrader failed with exit code: {:?}{}",
            output.status.code(),
            error_summary
        );
    }

    // Log success message if available
    if let Some(ref msg) = success_message {
        eprintln!("{}", msg);
    } else if output.status.success() {
        eprintln!("Recovery completed successfully!");
    }

    Ok(())
}
