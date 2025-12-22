use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use tui_textarea::TextArea;

use crate::{
    AppState, ConfirmationOption, ConfirmationState, FailureState, Field, InputState,
    RecoveryParams, RunningState,
};

// ============================================================================
// Constants
// ============================================================================

// Terminal size constants
const MIN_TERMINAL_WIDTH: u16 = 10;
const MIN_TERMINAL_HEIGHT: u16 = 15;

// UI layout constants
const TEXT_PADDING: u16 = 4;
const MIN_BOX_WIDTH: u16 = 60;
const BOX_HEIGHT: u16 = 5;
const BORDER_PADDING: u16 = 4;
const STATUS_SCREEN_OVERHEAD: u16 = 10;
const COMPLETION_SCREEN_OVERHEAD: u16 = 16;

// ============================================================================
// Shared UI Components & Helpers
// ============================================================================

// We use ASCII characters for borders to ensure compatibility with all terminal types,
// specifically serial consoles (e.g. "linux" or "vt100") which may default to non-UTF-8 encodings.
// This avoids rendering corruption where Unicode box-drawing characters appear as garbage.
const ASCII_BORDER_SET: symbols::border::Set = symbols::border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// Unified helper to create consistent UI blocks
fn create_block<'a>(title: &'a str, active: bool, is_error: bool) -> Block<'a> {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_set(ASCII_BORDER_SET);

    if is_error {
        block = block.fg(Color::Red).bg(Color::Black).title(title);
    } else if active {
        block = block.bg(Color::Blue).title(Span::styled(
            title,
            Style::default().bold().fg(Color::White),
        ));
    } else {
        block = block
            .bg(Color::Reset)
            .title(Span::styled(title, Style::default().bold().fg(Color::Cyan)));
    }
    block
}

/// Helper to create a centered rect with fixed height and constrained width
fn centered_rect(width: Constraint, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area)[1];

    match width {
        Constraint::Percentage(p) => {
            let p = p.min(100);
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage((100 - p) / 2),
                    Constraint::Percentage(p),
                    Constraint::Percentage((100 - p) / 2),
                ])
                .split(vertical)[1]
        }
        Constraint::Length(l) => {
            let l = l.min(vertical.width);
            let start_x = vertical.x + (vertical.width.saturating_sub(l)) / 2;
            Rect::new(start_x, vertical.y, l, height)
        }
        _ => vertical,
    }
}

fn is_terminal_too_small(size: Rect) -> bool {
    size.width < MIN_TERMINAL_WIDTH || size.height < MIN_TERMINAL_HEIGHT
}

/// Renders an error message when the terminal is too small.
fn render_if_too_small(f: &mut Frame, size: Rect) -> bool {
    if !is_terminal_too_small(size) {
        return false;
    }
    let error_text = vec![
        Line::from("Terminal too small"),
        Line::from(format!(
            "Minimum size: {}x{}, current: {}x{}",
            MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT, size.width, size.height
        )),
        Line::from("Please resize your terminal"),
    ];
    let para = Paragraph::new(error_text)
        .block(create_block("Error", false, true))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    f.render_widget(para, size);
    true
}

fn create_parameter_lines(params: &RecoveryParams) -> Vec<Line<'_>> {
    let calculated_version_hash = params.version_hash_full.as_deref().unwrap_or("<pending>");
    let calculated_recovery_hash = params.recovery_hash_full.as_deref().unwrap_or("<pending>");
    let lines = vec![
        format!("Inputted parameters:"),
        format!("VERSION: {}", params.version),
        format!("RECOVERY-HASH-PREFIX: {}", params.recovery_hash_prefix),
        format!(""),
        format!("Calculated hashes:"),
        format!("    VERSION-HASH: {}", calculated_version_hash),
        format!("    RECOVERY-HASH: {}", calculated_recovery_hash),
    ];

    lines
        .into_iter()
        .map(|text| Line::from(vec![Span::styled(text, Style::default().fg(Color::Yellow))]))
        .collect()
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Renders the main UI for the App
pub(crate) fn render(f: &mut Frame, state: &AppState) {
    let size = f.area();

    if render_if_too_small(f, size) {
        return;
    }

    match state {
        AppState::Input(s) => render_input_screen(f, s, size),
        AppState::InputConfirmation(s) => render_input_confirmation_screen(f, s, size),
        AppState::Running(s) => render_logs_screen(f, s, size),
        AppState::Failure(s) => render_failure_screen(f, s, size),
    }
}

// ============================================================================
// Screen: Input Confirmation
// ============================================================================

fn render_input_confirmation_screen(f: &mut Frame, state: &ConfirmationState, size: Rect) {
    // 1. Render the underlying input screen (background)
    render_input_screen(f, &state.input_state, size);

    // 2. Render the popup overlay
    let area = centered_rect(Constraint::Percentage(85), 16, size);

    f.render_widget(Clear, area);

    let block = create_block("Confirm Parameters", true, false);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header spacing
            Constraint::Min(1),    // Parameters (Takes remaining space)
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Question
            Constraint::Length(1), // Buttons
        ])
        .margin(1)
        .split(area);

    f.render_widget(block, area);

    let params_text = create_parameter_lines(&state.params);
    let params_para = Paragraph::new(params_text).wrap(Wrap { trim: true });
    f.render_widget(params_para, layout[1]);

    let question = Paragraph::new(
        "Please confirm: do these input values match the recovery coordinator's information?",
    )
    .alignment(Alignment::Center)
    .style(Style::default().fg(Color::White).bold());
    f.render_widget(question, layout[3]);

    let yes_selected = state.selected_option == ConfirmationOption::Yes;
    let no_selected = state.selected_option == ConfirmationOption::No;

    let yes_style = if yes_selected {
        Style::default().bg(Color::White).fg(Color::Blue)
    } else {
        Style::default().fg(Color::White)
    };
    let no_style = if no_selected {
        Style::default().bg(Color::White).fg(Color::Blue)
    } else {
        Style::default().fg(Color::White)
    };

    let buttons = Line::from(vec![
        Span::styled(" < Yes > ", yes_style),
        Span::raw("   "),
        Span::styled(" < No > ", no_style),
    ]);

    let buttons_para = Paragraph::new(buttons).alignment(Alignment::Center);
    f.render_widget(buttons_para, layout[4]);
}

// ============================================================================
// Screen: Input
// ============================================================================

fn render_input_screen(f: &mut Frame, state: &InputState, size: Rect) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Title area
            Constraint::Length(3), // Instructions area
            Constraint::Length(6), // Input fields area (2 fields × 3 rows each)
            Constraint::Length(1), // Button area
            Constraint::Length(1), // Spacing after buttons
            Constraint::Min(0),    // Remaining space
        ])
        .split(size);

    let title = Paragraph::new("Manual Recovery TUI")
        .block(
            Block::default()
                .borders(Borders::NONE)
                .style(Style::default().bold()),
        )
        .alignment(Alignment::Center)
        .style(Style::default().bold());
    f.render_widget(title, main_layout[0]);

    let instructions = vec![
        Line::from("Enter the recovery version and the 6-character recovery hash prefix."),
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
            Constraint::Length(3), // Recovery hash prefix field
        ])
        .split(main_layout[2]);

    for (i, field) in Field::INPUT_FIELDS.iter().enumerate() {
        let meta = field.metadata();
        render_input_field(
            state,
            f,
            *field,
            &format!("{}:", meta.name),
            &state.inputs[i],
            fields_layout[i],
        );
    }

    let button_area = main_layout[3];
    render_action_buttons(
        state,
        f,
        &[
            ("<Run recovery>", Field::CheckArtifactsButton),
            ("<Exit>", Field::ExitButton),
        ],
        button_area,
        5,
    );

    // Display exit message in the remaining space area with proper spacing
    if let Some(ref msg) = state.exit_message {
        let message_area = main_layout[5];
        let para = Paragraph::new(msg.as_str())
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center);
        f.render_widget(para, message_area);
    }

    if let Some(ref error) = state.error_message {
        let max_width = (size.width * 80 / 100).max(MIN_BOX_WIDTH);
        let error_text_width = error.len().min(u16::MAX as usize) as u16;
        let box_width = error_text_width.clamp(MIN_BOX_WIDTH, max_width) + BORDER_PADDING;

        let error_area = centered_rect(Constraint::Length(box_width), BOX_HEIGHT, size);

        let error_para = Paragraph::new(error.as_str())
            .block(create_block("Error", false, true))
            .wrap(Wrap { trim: true });
        f.render_widget(Clear, error_area);
        f.render_widget(error_para, error_area);
    }
}

fn render_input_field(
    state: &InputState,
    f: &mut Frame,
    field: Field,
    label: &str,
    textarea: &TextArea<'static>,
    area: Rect,
) {
    let selected = state.current_field() == field;
    let block = create_block(label, selected, false);

    // Clone textarea to modify styles for rendering without affecting state
    let mut ta = textarea.clone();

    if selected {
        ta.set_cursor_style(Style::default().bg(Color::White).fg(Color::Black));
    } else {
        // Hide cursor/line highlight when not selected
        ta.set_cursor_style(Style::default());
        ta.set_cursor_line_style(Style::default());
    }

    ta.set_block(block);
    f.render_widget(&ta, area);
}

/// Renders buttons horizontally centered in the given area with spacing between them
fn render_action_buttons(
    state: &InputState,
    f: &mut Frame,
    buttons: &[(&str, Field)],
    area: Rect,
    spacing: u16,
) {
    let total_text_width: u16 = buttons.iter().map(|(text, _)| text.len() as u16).sum();
    let total_spacing = spacing * (buttons.len().saturating_sub(1)) as u16;
    let total_width = total_text_width + total_spacing;

    let start_x = area.x + (area.width.saturating_sub(total_width)) / 2;

    // Render each button
    let mut x = start_x;
    for (text, field) in buttons {
        let width = text.len() as u16;
        let selected = state.current_field() == *field;
        let para = Paragraph::new(*text)
            .bg(if selected { Color::Blue } else { Color::Reset })
            .fg(if selected { Color::White } else { Color::Reset });
        f.render_widget(para, Rect::new(x, area.y, width, 1));
        x += width + spacing;
    }
}

// ============================================================================
// Screen: Running (Logs)
// ============================================================================

fn render_logs_screen(f: &mut Frame, state: &RunningState, size: Rect) {
    let logs = state.task.get_logs();

    let block = create_block("GuestOS Recovery Upgrader", false, false);

    let mut text = create_parameter_lines(&state.params);
    text.push(Line::from(""));
    text.push(Line::from("Recovery process logs:"));
    text.push(Line::from(""));

    let available_height = size.height.saturating_sub(STATUS_SCREEN_OVERHEAD) as usize;
    let (start_idx, lines_to_show) = calculate_log_viewport(logs.len(), available_height);

    let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
    text.extend(format_log_lines(&logs[start_idx..], max_width));

    if logs.len() > lines_to_show {
        text.push(Line::from(""));
        text.push(Line::from(format!(
            "  ... (showing last {} of {} log lines)",
            lines_to_show,
            logs.len()
        )));
    }

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(para, size);
}

fn calculate_log_viewport(total_lines: usize, available_height: usize) -> (usize, usize) {
    let lines_to_show = total_lines.min(available_height);
    let start_idx = total_lines.saturating_sub(lines_to_show);
    (start_idx, lines_to_show)
}

/// Truncates a line to fit within the maximum width, appending "..." if needed
fn truncate_line(line: &str, max_width: usize) -> String {
    if line.len() > max_width {
        format!("{}...", &line[..max_width.saturating_sub(3)])
    } else {
        line.to_string()
    }
}

/// Formats log lines with indentation and truncation for display.
#[allow(mismatched_lifetime_syntaxes)]
fn format_log_lines(lines: &[String], max_width: usize) -> Vec<Line> {
    lines
        .iter()
        .map(|line| Line::from(format!("  {}", truncate_line(line, max_width))))
        .collect()
}

// ============================================================================
// Screen: Failure
// ============================================================================

fn render_failure_screen(f: &mut Frame, state: &FailureState, size: Rect) {
    draw_failure_screen(
        f,
        state.exit_status.code(),
        &state.logs,
        &state.error_messages,
        &state.params,
        size,
    );
}

/// Draws the failure completion screen with error details
fn draw_failure_screen(
    f: &mut Frame,
    exit_code: Option<i32>,
    log_lines: &[String],
    error_messages: &[String],
    params: &RecoveryParams,
    size: Rect,
) {
    let block = create_block("Recovery Failed", false, true);

    let mut text = build_failure_text(exit_code, log_lines, error_messages, params, size);

    text.push(Line::from(""));
    text.push(Line::from("Press any key to continue..."));

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(para, size);
}

/// Builds the text content for the failure completion screen
fn build_failure_text<'a>(
    exit_code: Option<i32>,
    log_lines: &'a [String],
    error_messages: &'a [String],
    params: &'a RecoveryParams,
    size: Rect,
) -> Vec<Line<'a>> {
    let mut text = Vec::new();
    let create_separator =
        || "-".repeat((size.width.saturating_sub(TEXT_PADDING)).max(10) as usize);

    text.push(Line::from(""));
    text.push(
        Line::from(format!("✗ Recovery failed with exit code: {:?}", exit_code))
            .red()
            .bold(),
    );
    text.push(Line::from(""));
    let separator = create_separator();
    text.push(Line::from(vec![Span::styled(
        separator,
        Style::default().fg(Color::DarkGray),
    )]));
    text.push(Line::from(""));

    // Add recovery parameters
    text.push(Line::from(vec![Span::styled(
        "Recovery Parameters:",
        Style::default().fg(Color::Yellow).bold(),
    )]));
    text.extend(create_parameter_lines(params));
    text.push(Line::from(""));
    text.push(Line::from(vec![Span::styled(
        create_separator(),
        Style::default().fg(Color::DarkGray),
    )]));
    text.push(Line::from(""));

    // Add error logs or error messages
    if !log_lines.is_empty() {
        text.push(Line::from("Error logs:").red().bold());
        text.push(Line::from(""));

        let available_height = size.height.saturating_sub(COMPLETION_SCREEN_OVERHEAD) as usize;
        let (start_idx, _) = calculate_log_viewport(log_lines.len(), available_height);

        let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
        let formatted_lines: Vec<Line> = log_lines[start_idx..]
            .iter()
            .map(|line| Line::from(format!("  {}", truncate_line(line, max_width))))
            .collect();
        text.extend(formatted_lines);
    } else if !error_messages.is_empty() {
        text.push(Line::from("Error details:").red().bold());
        text.push(Line::from(""));
        let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
        text.extend(format_log_lines(error_messages, max_width));
    } else {
        text.push(Line::from(""));
        text.push(Line::from(
            "No error logs captured. Check system logs for details:",
        ));
        text.push(Line::from("  journalctl -t guestos-recovery-upgrader"));
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    mod helpers {
        use super::*;

        #[test]
        fn truncate_line_no_change_when_fits() {
            assert_eq!(truncate_line("hello", 10), "hello");
        }

        #[test]
        fn truncate_line_adds_ellipsis() {
            assert_eq!(truncate_line("hello world", 8), "hello...");
        }

        #[test]
        fn calculate_log_viewport_shows_all_when_under_limit() {
            let (start, count) = calculate_log_viewport(5, 20);
            assert_eq!((start, count), (0, 5));
        }

        #[test]
        fn calculate_log_viewport_shows_last_n_when_over_limit() {
            let (start, count) = calculate_log_viewport(100, 20);
            assert_eq!((start, count), (80, 20));
        }

        #[test]
        fn centered_rect_with_fixed_length() {
            let area = Rect::new(0, 0, 100, 50);
            let result = centered_rect(Constraint::Length(40), 10, area);

            assert_eq!(result.width, 40);
            assert_eq!(result.height, 10);
            assert_eq!(result.x, 30); // (100 - 40) / 2
            assert_eq!(result.y, 20); // (50 - 10) / 2
        }

        #[test]
        fn centered_rect_with_percentage() {
            let area = Rect::new(0, 0, 100, 50);
            let result = centered_rect(Constraint::Percentage(50), 10, area);

            assert_eq!(result.width, 50);
            assert_eq!(result.height, 10);
        }
    }

    mod rendering {
        use super::*;
        use crate::{RecoveryParams, RecoveryPhase, RecoveryTask};
        use ratatui::{Terminal, backend::TestBackend};

        // ====================================================================
        // Test Helpers
        // ====================================================================

        /// Renders a state to a test buffer and returns the terminal
        fn render_state(state: &AppState, width: u16, height: u16) -> Terminal<TestBackend> {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|f| render(f, state))
                .expect("Failed to render");
            terminal
        }

        /// Extracts all text content from the terminal buffer as a single string
        fn buffer_to_string(terminal: &Terminal<TestBackend>) -> String {
            terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect()
        }

        /// Checks if the buffer contains a specific substring
        fn buffer_contains(terminal: &Terminal<TestBackend>, text: &str) -> bool {
            buffer_to_string(terminal).contains(text)
        }

        fn create_test_failure_state() -> FailureState {
            let status = std::process::Command::new("false")
                .status()
                .expect("Failed to run 'false' command");
            FailureState {
                params: RecoveryParams {
                    version: "a".repeat(40),
                    recovery_hash_prefix: "abc123".to_string(),
                    version_hash_full: Some("fullhash123".to_string()),
                    recovery_hash_full: Some("rechash456".to_string()),
                },
                logs: vec!["Error line 1".to_string(), "Error line 2".to_string()],
                exit_status: status,
                error_messages: vec!["Test error".to_string()],
            }
        }

        #[test]
        fn too_small_terminal_hides_normal_ui() {
            let state = AppState::Input(InputState::default());

            // Width below minimum
            let terminal = render_state(&state, MIN_TERMINAL_WIDTH - 1, 20);
            assert!(!buffer_contains(&terminal, "Manual Recovery TUI"));

            // Height below minimum
            let terminal = render_state(&state, 40, MIN_TERMINAL_HEIGHT - 1);
            assert!(buffer_contains(&terminal, "too small"));
            assert!(!buffer_contains(&terminal, "Manual Recovery TUI"));
        }

        #[test]
        fn input_screen_renders_all_elements() {
            let state = AppState::Input(InputState::default());
            let terminal = render_state(&state, 80, 24);

            // Title and instructions
            assert!(buffer_contains(&terminal, "Manual Recovery TUI"));
            assert!(buffer_contains(&terminal, "recovery version"));
            assert!(buffer_contains(&terminal, "TAB"));

            // Field labels
            assert!(buffer_contains(&terminal, "VERSION"));
            assert!(buffer_contains(&terminal, "RECOVERY-HASH-PREFIX"));

            // Buttons
            assert!(buffer_contains(&terminal, "<Run recovery>"));
            assert!(buffer_contains(&terminal, "<Exit>"));
        }

        #[test]
        fn input_screen_shows_error_popup() {
            let input = InputState {
                error_message: Some("Validation failed".to_string()),
                ..Default::default()
            };
            let state = AppState::Input(input);
            let terminal = render_state(&state, 80, 24);

            assert!(buffer_contains(&terminal, "Error"));
            assert!(buffer_contains(&terminal, "Validation failed"));
        }

        #[test]
        fn input_screen_shows_exit_message() {
            let input = InputState {
                exit_message: Some("Recovery cancelled".to_string()),
                ..Default::default()
            };
            let state = AppState::Input(input);
            let terminal = render_state(&state, 80, 24);

            assert!(buffer_contains(&terminal, "Recovery cancelled"));
        }

        #[test]
        fn confirmation_screen_renders_all_elements() {
            let state = AppState::InputConfirmation(ConfirmationState {
                input_state: InputState::default(),
                params: RecoveryParams {
                    version: "abc123def456".to_string(),
                    recovery_hash_prefix: "fedcba".to_string(),
                    version_hash_full: Some("fullversionhash".to_string()),
                    recovery_hash_full: Some("fullrecoveryhash".to_string()),
                },
                selected_option: ConfirmationOption::Yes,
            });
            let terminal = render_state(&state, 100, 30);

            // Title and question
            assert!(buffer_contains(&terminal, "Confirm Parameters"));
            assert!(buffer_contains(&terminal, "confirm"));

            // Input parameters
            assert!(buffer_contains(&terminal, "VERSION:"));
            assert!(buffer_contains(&terminal, "abc123def456"));
            assert!(buffer_contains(&terminal, "RECOVERY-HASH-PREFIX:"));
            assert!(buffer_contains(&terminal, "fedcba"));

            // Calculated hashes
            assert!(buffer_contains(&terminal, "VERSION-HASH:"));
            assert!(buffer_contains(&terminal, "fullversionhash"));
            assert!(buffer_contains(&terminal, "RECOVERY-HASH:"));
            assert!(buffer_contains(&terminal, "fullrecoveryhash"));

            // Buttons
            assert!(buffer_contains(&terminal, "< Yes >"));
            assert!(buffer_contains(&terminal, "< No >"));
        }

        #[test]
        fn failure_screen_renders_all_elements() {
            let state = AppState::Failure(create_test_failure_state());
            let terminal = render_state(&state, 100, 30);

            assert!(buffer_contains(&terminal, "Recovery Failed"));
            assert!(buffer_contains(&terminal, "exit code"));
            assert!(buffer_contains(&terminal, "Recovery Parameters"));
            assert!(buffer_contains(&terminal, "Error line 1"));
            assert!(buffer_contains(&terminal, "Error line 2"));
            assert!(buffer_contains(&terminal, "Press any key"));
        }

        #[test]
        fn running_screen_renders_all_elements() {
            let state = AppState::Running(RunningState {
                task: RecoveryTask::mock_with_logs(vec![]),
                params: RecoveryParams {
                    version: "testversion123".to_string(),
                    recovery_hash_prefix: "abc123".to_string(),
                    version_hash_full: None,
                    recovery_hash_full: None,
                },
                phase: RecoveryPhase::Prep,
                previous_input_state: None,
            });
            let terminal = render_state(&state, 100, 30);

            assert!(buffer_contains(&terminal, "GuestOS Recovery Upgrader"));
            assert!(buffer_contains(&terminal, "VERSION:"));
            assert!(buffer_contains(&terminal, "testversion123"));
            assert!(buffer_contains(&terminal, "<pending>"));
            assert!(buffer_contains(&terminal, "Recovery process logs"));
        }

        #[test]
        fn running_screen_displays_log_output() {
            let state = AppState::Running(RunningState {
                task: RecoveryTask::mock_with_logs(vec![
                    "Downloading artifacts...".to_string(),
                    "Verifying checksums...".to_string(),
                ]),
                params: RecoveryParams::default(),
                phase: RecoveryPhase::Prep,
                previous_input_state: None,
            });
            let terminal = render_state(&state, 100, 30);

            assert!(buffer_contains(&terminal, "Downloading artifacts"));
            assert!(buffer_contains(&terminal, "Verifying checksums"));
        }
    }
}
