pub(crate) trait TableRow {
    fn column_names() -> Vec<&'static str>;
    fn column_values(&self) -> Vec<String>;
}

/// Formats the input as a markdown-style table
pub(crate) fn as_table<T: TableRow>(table: &[T]) -> String {
    if table.is_empty() {
        return String::new();
    }

    let column_names = T::column_names();
    let mut max_widths: Vec<usize> = column_names.iter().map(|name| name.len()).collect();

    for row in table {
        let values = row.column_values();
        for (i, value) in values.iter().enumerate() {
            max_widths[i] = max_widths[i].max(value.chars().count());
        }
    }

    let mut result = String::new();

    // Header row
    result.push('|');
    for (i, name) in column_names.iter().enumerate() {
        result.push_str(&format!(" {:<width$} |", name, width = max_widths[i]));
    }
    result.push('\n');

    // Separator row
    result.push('|');
    for width in &max_widths {
        result.push_str(&format!("{:-<width$}|", "", width = width + 2));
    }
    result.push('\n');

    // Data rows
    for row in table {
        result.push('|');
        let values = row.column_values();
        for (i, value) in values.iter().enumerate() {
            result.push_str(&format!(" {:<width$} |", value, width = max_widths[i]));
        }
        result.push('\n');
    }

    result
}
