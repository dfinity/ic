use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::{App, Field, RecoveryParams};

// UI layout constants
pub(crate) const TEXT_PADDING: u16 = 4; // Padding for text display
const MIN_BOX_WIDTH: u16 = 60;
const BOX_HEIGHT: u16 = 5;
const BORDER_PADDING: u16 = 4;
const STATUS_SCREEN_OVERHEAD: u16 = 10;
const COMPLETION_SCREEN_OVERHEAD: u16 = 16;

// Terminal size constants (needed for UI rendering)
const MIN_TERMINAL_WIDTH: u16 = 10;
const MIN_TERMINAL_HEIGHT: u16 = 15;

/// Checks if the terminal size is too small for the UI
fn is_terminal_too_small(size: Rect) -> bool {
    size.width < MIN_TERMINAL_WIDTH || size.height < MIN_TERMINAL_HEIGHT
}

/// Renders the main UI for the App
pub(crate) fn render_app_ui(app: &App, f: &mut Frame) {
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
        render_input_field(
            app,
            f,
            *field,
            field.label(),
            field.get_value(&app.params),
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

    render_button(
        app,
        f,
        check_text,
        Field::CheckArtifactsButton,
        Rect::new(start_x, button_area.y, check_text_len, 1),
    );
    render_button(
        app,
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

    if let Some(ref error) = app.error_message {
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
    app: &App,
    f: &mut Frame,
    field: Field,
    label: &str,
    value: &str,
    description: &str,
    area: Rect,
) {
    let selected = app.current_field == field;
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

fn render_button(app: &App, f: &mut Frame, text: &str, field: Field, area: Rect) {
    let selected = app.current_field == field;
    let para = Paragraph::new(text)
        .bg(if selected { Color::Blue } else { Color::Reset })
        .fg(if selected { Color::White } else { Color::Reset });
    f.render_widget(para, area);
}

/// Creates the parameter display lines for the UI
pub(crate) fn create_parameter_lines(params: &RecoveryParams) -> Vec<Line<'_>> {
    vec![
        Line::from("Parameters:"),
        Line::from(format!("  VERSION: {}", params.version)),
        Line::from(format!("  VERSION-HASH: {}", params.version_hash)),
        Line::from(format!("  RECOVERY-HASH: {}", params.recovery_hash)),
    ]
}

pub(crate) fn calculate_log_viewport(
    total_lines: usize,
    available_height: usize,
) -> (usize, usize) {
    let lines_to_show = total_lines.min(available_height);
    let start_idx = total_lines.saturating_sub(lines_to_show);
    (start_idx, lines_to_show)
}

pub(crate) fn truncate_line(line: &str, max_width: usize) -> String {
    if line.len() > max_width {
        format!("{}...", &line[..max_width.saturating_sub(3)])
    } else {
        line.to_string()
    }
}

fn create_separator(width: u16) -> String {
    "─".repeat((width.saturating_sub(TEXT_PADDING)).max(10) as usize)
}

/// Draws the initial status screen showing parameters and "Starting recovery..." message
pub(crate) fn draw_status_screen(f: &mut Frame, params: &RecoveryParams) {
    let size = f.size();
    if is_terminal_too_small(size) {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title("GuestOS Recovery Upgrader")
        .style(Style::default().bold());

    let mut text = create_parameter_lines(params);
    text.push(Line::from(""));
    text.push(Line::from("Starting recovery process..."));
    text.push(Line::from("This may take several minutes. Please wait..."));

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(para, size);
}

/// Draws the real-time logs screen during recovery process
pub(crate) fn draw_logs_screen(f: &mut Frame, params: &RecoveryParams, logs: &[String]) {
    let size = f.size();
    if is_terminal_too_small(size) {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title("GuestOS Recovery Upgrader")
        .style(Style::default().bold());

    let mut text = create_parameter_lines(params);
    text.push(Line::from(""));
    text.push(Line::from("Recovery process logs:"));
    text.push(Line::from(""));

    let available_height = size.height.saturating_sub(STATUS_SCREEN_OVERHEAD) as usize;
    let (start_idx, lines_to_show) = calculate_log_viewport(logs.len(), available_height);

    let max_width = (size.width.saturating_sub(TEXT_PADDING)) as usize;
    for line in &logs[start_idx..] {
        text.push(Line::from(format!("  {}", truncate_line(line, max_width))));
    }

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

/// Draws the completion screen showing success or failure with details
pub(crate) fn draw_completion_screen(
    f: &mut Frame,
    success: bool,
    success_message: &Option<String>,
    output: &std::process::Output,
    stdout_lines: &[String],
    stderr_lines: &[String],
    error_messages: &[String],
    params: &RecoveryParams,
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

        // Add recovery parameters
        text.push(Line::from(vec![Span::styled(
            "Recovery Parameters:",
            Style::default().fg(Color::Yellow).bold(),
        )]));
        text.extend(create_parameter_lines(params));
        text.push(Line::from(""));
        text.push(Line::from(vec![Span::styled(
            create_separator(size.width),
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

            let available_height = size.height.saturating_sub(COMPLETION_SCREEN_OVERHEAD) as usize;
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
