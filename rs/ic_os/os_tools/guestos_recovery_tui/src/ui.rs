use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::{AppState, DoneState, Field, InputState, RecoveryParams, RunningState};

// ============================================================================
// Constants
// ============================================================================

// Terminal size constants
const MIN_TERMINAL_WIDTH: u16 = 10;
const MIN_TERMINAL_HEIGHT: u16 = 15;

// UI layout constants
pub(crate) const TEXT_PADDING: u16 = 4; // Padding for text display
const MIN_BOX_WIDTH: u16 = 60;
const BOX_HEIGHT: u16 = 5;
const BORDER_PADDING: u16 = 4;
const STATUS_SCREEN_OVERHEAD: u16 = 10;
const COMPLETION_SCREEN_OVERHEAD: u16 = 16;

// ============================================================================
// Shared UI Components & Helpers
// ============================================================================

/// Unified helper to create consistent UI blocks
fn create_block<'a>(title: &'a str, active: bool, is_error: bool) -> Block<'a> {
    let mut block = Block::default().borders(Borders::ALL);

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

fn is_terminal_too_small(size: Rect) -> bool {
    size.width < MIN_TERMINAL_WIDTH || size.height < MIN_TERMINAL_HEIGHT
}

/// Renders an error message when the terminal is too small.
fn render_terminal_too_small_error(f: &mut Frame, size: Rect) -> bool {
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

// ============================================================================
// Main Entry Point
// ============================================================================

/// Renders the main UI for the App
pub(crate) fn render(f: &mut Frame, state: &AppState) {
    let size = f.area();

    if render_terminal_too_small_error(f, size) {
        return;
    }

    match state {
        AppState::Input(s) => render_input_screen(f, s, size),
        AppState::Running(s) => render_running_screen(f, s, size),
        AppState::Done(s) => render_done_screen(f, s, size),
    }
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
            Constraint::Length(9), // Input fields area (3 fields × 3 rows each)
            Constraint::Length(1), // Button area
            Constraint::Length(1), // Spacing after buttons
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
        let meta = field.metadata();
        render_input_field(
            state,
            f,
            *field,
            &format!("{}:", meta.name),
            field.get_value(&state.params),
            meta.description,
            fields_layout[i],
        );
    }

    let button_area = main_layout[3];
    render_buttons_centered(
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
    value: &str,
    description: &str,
    area: Rect,
) {
    let selected = state.current_field() == field;
    let block = create_block(label, selected, false);
    let input = if selected {
        format!("{}█", value)
    } else {
        value.to_string()
    };
    let content = vec![Line::from(input), Line::from(""), Line::from(description)];
    let para = Paragraph::new(content).block(block).fg(Color::Cyan);
    f.render_widget(para, area);
}

/// Renders buttons horizontally centered in the given area with spacing between them
fn render_buttons_centered(
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

fn render_running_screen(f: &mut Frame, state: &RunningState, size: Rect) {
    let logs = state.log_lines.lock().unwrap();
    draw_logs_screen(f, &state.params, &logs, size);
}

/// Draws the real-time logs screen during recovery process
fn draw_logs_screen(f: &mut Frame, params: &RecoveryParams, logs: &[String], size: Rect) {
    let block = create_block("GuestOS Recovery Upgrader", false, false);

    let mut text = create_parameter_lines(params);
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

pub(crate) fn calculate_log_viewport(
    total_lines: usize,
    available_height: usize,
) -> (usize, usize) {
    let lines_to_show = total_lines.min(available_height);
    let start_idx = total_lines.saturating_sub(lines_to_show);
    (start_idx, lines_to_show)
}

/// Truncates a line to fit within the maximum width, appending "..." if needed
pub(crate) fn truncate_line(line: &str, max_width: usize) -> String {
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
// Screen: Done (Failure)
// ============================================================================

fn render_done_screen(f: &mut Frame, state: &DoneState, size: Rect) {
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
        || "─".repeat((size.width.saturating_sub(TEXT_PADDING)).max(10) as usize);

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

/// Creates the parameter display lines for the UI
fn create_parameter_lines(params: &RecoveryParams) -> Vec<Line<'_>> {
    let lines = vec![
        format!("  VERSION: {}", params.version),
        format!("  VERSION-HASH: {}", params.version_hash),
        format!("  RECOVERY-HASH: {}", params.recovery_hash),
    ];

    lines
        .into_iter()
        .map(|text| Line::from(vec![Span::styled(text, Style::default().fg(Color::Yellow))]))
        .collect()
}
