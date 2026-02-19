const POSITIVE_INFINITY_PERCENT: &str = "1.0E99";
const NEGATIVE_INFINITY_PERCENT: &str = "-1.0E99";

/// Format numbers with unit suffixes (e.g., K, M, B, T) for better readability.
fn format_with_unit(val: f64) -> (f64, &'static str) {
    const UNITS: &[(f64, &str)] = &[(1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")];
    for &(divisor, suffix) in UNITS {
        if val.abs() >= divisor {
            return (val / divisor, suffix);
        }
    }
    (val, "")
}

/// Format an unsigned integer with unit suffixes.
pub(crate) fn fmt_human_u64(value: u64) -> String {
    let (scaled, unit) = format_with_unit(value as f64);
    match unit {
        "" => format!("{scaled}"),
        _ => format!("{scaled:.2}{unit}"),
    }
}

/// Format a signed integer with unit suffixes.
pub(crate) fn fmt_human_i64(value: i64) -> String {
    if value == 0 {
        return "0".to_string(); // No sign for zero values.
    }
    let (scaled, unit) = format_with_unit(value as f64);
    match unit {
        "" => format!("{scaled:+.0}"),
        _ => format!("{scaled:+.2}{unit}"),
    }
}

/// Format a floating-point number with a sign and two decimal places.
/// This is used for displaying percentage changes in human-readable format
/// with a sign in the short table report.
pub(crate) fn fmt_human_percent(value: f64) -> String {
    if value.abs() < 0.01 {
        format!("{:.2}%", value) // Don't show sign for small values.
    } else {
        format!("{:+.2}%", value)
    }
}

/// Format a floating-point number with two decimal places.
/// This is used for displaying absolute values in the CSV report.
pub(crate) fn fmt_percent(value: f64) -> String {
    if value.is_infinite() {
        if value.is_sign_positive() {
            POSITIVE_INFINITY_PERCENT.to_string() // Represents +inf%
        } else {
            NEGATIVE_INFINITY_PERCENT.to_string() // Represents -inf%
        }
    } else {
        format!("{:.2}%", value)
    }
}
