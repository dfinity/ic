//! A library for working with timestamps used in canister code.
//!
//! While existing Rust libraries (e.g., chrono) may also provide similar (or richer) functions,
//! those libraries cannot be used by Rust canisters built in this repo, as that requires enabling
//! Rust compiler features that are not available in this repo.

/// Attempts to format `` as a human-readable string.
///
/// For example:
/// ```
/// assert_eq!(format_timestamp(1732896850), Some("2024-11-29 16:14:10 UTC".to_string()));
/// ```
pub fn format_timestamp(timestamp_seconds: u64) -> Option<String> {
    let timestamp_seconds = i64::try_from(timestamp_seconds).ok()?;
    let dt_offset = time::OffsetDateTime::from_unix_timestamp(timestamp_seconds).ok()?;
    let format =
        time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
            .ok()?;
    dt_offset.format(&format).ok()
}

/// Formats `timestamp_seconds` as a human-readable string, unless it is outside of the range
/// from +1970-01-01 00:00:00 UTC (0)
/// till +9999-12-31 23:59:59 UTC (253402300799),
/// in which case falls back to a string containing the literal `timestamp_seconds`.
pub fn format_timestamp_for_humans(timestamp_seconds: u64) -> String {
    format_timestamp(timestamp_seconds)
        .unwrap_or_else(|| format!("timestamp {timestamp_seconds} seconds"))
}
