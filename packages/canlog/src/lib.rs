//! This crate extends [`ic_canister_log`] to provide native support for log priority levels,
//! filtering and sorting.
//!
//! The main functionality is provided by the [`LogPriorityLevels`] and [`GetLogFilter`] traits
//! as well as the [`log`] macro.
//!
//! Custom log priority levels may be defined by declaring an enum and implementing the
//! [`LogPriorityLevels`] trait for it, usually through the [`derive`] annotation available with
//! the `derive` feature of [`canlog`].
//!
//! Additionally, log filtering may be achieved by implementing the [`GetLogFilter`] trait on
//! the enum defining the log priorities.
//!
//! * Example:
//! ```rust
//! # #[cfg(feature="derive")]
//! # mod wrapper_module {
//! use canlog::{GetLogFilter, LogFilter, LogPriorityLevels, log};
//!
//! #[derive(LogPriorityLevels)]
//! enum LogPriority {
//!     #[log_level(capacity = 100, name = "INFO")]
//!     Info,
//!     #[log_level(capacity = 500, name = "DEBUG")]
//!     Debug,
//! }
//!
//! impl GetLogFilter for LogPriority {
//!     fn get_log_filter() -> LogFilter {
//!         LogFilter::ShowAll
//!     }
//! }
//!
//! fn main() {
//!     log!(LogPriority::Info, "Some rather important message.");
//!     log!(LogPriority::Debug, "Some less important message.");
//! }
//! # }
//! ```
//!
//! **Expected Output:**
//! ```text
//! 2025-02-26 08:27:10 UTC: [Canister lxzze-o7777-77777-aaaaa-cai] INFO main.rs:13 Some rather important message.
//! 2025-02-26 08:27:10 UTC: [Canister lxzze-o7777-77777-aaaaa-cai] DEBUG main.rs:14 Some less important message.
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(test)]
mod tests;
mod types;

extern crate self as canlog;

pub use crate::types::{LogFilter, Sort};

pub use ic_canister_log::{
    declare_log_buffer, export as export_logs, log as raw_log, GlobalBuffer, Sink,
};
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "derive", test))]
/// A procedural macro to implement [`LogPriorityLevels`] for an enum.
///
/// This macro expects the variants to be annotated with `#[log_level(capacity = N, name = "NAME")]`
/// where `N` is an integer representing buffer capacity and `"NAME"` is a string display
/// representation for the corresponding log level.
///
/// The enum annotated with `#[derive(LogPriorityLevels)]` must also implement the
/// [`Serialize`], [`Deserialize`], [`Clone`] and [`Copy`] traits.
///
/// See the top-level crate documentation for example usage.
#[doc(inline)]
pub use canlog_derive::LogPriorityLevels;

/// Wrapper for the [`ic_canister_log::log`](ic_canister_log::log!) macro that allows
/// logging for a given variant of an enum implementing the [`LogPriorityLevels`]
/// trait. See the example in the crate documentation.
#[macro_export]
macro_rules! log {
    ($enum_variant:expr, $($args:tt)*) => {
        {
            use ::canlog::LogPriorityLevels;
            ::canlog::raw_log!($enum_variant.get_sink(), $($args)*);
        }
    };
}

/// Represents a log priority level. This trait is meant to be implemented
/// automatically with the [`derive`](macro@derive) attribute macro which
/// is available with the `derive` feature of this crate.
pub trait LogPriorityLevels {
    #[doc(hidden)]
    fn get_buffer(&self) -> &'static GlobalBuffer;
    #[doc(hidden)]
    fn get_sink(&self) -> &impl Sink;

    /// Returns a display representation for a log priority level.
    fn display_name(&self) -> &'static str;

    /// Returns an array containing all the log priority levels.
    fn get_priorities() -> &'static [Self]
    where
        Self: Sized;
}

/// Returns the [`LogFilter`] to check what entries to record. This trait should
/// be implemented manually.
pub trait GetLogFilter {
    /// Returns a [`LogFilter`]. Only log entries matching this filter will be recorded.
    fn get_log_filter() -> LogFilter;
}

/// A single log entry.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, serde::Serialize)]
pub struct LogEntry<Priority> {
    /// The time at which the log entry is recorded.
    pub timestamp: u64,
    /// The log entry priority level.
    pub priority: Priority,
    /// The source file in which this log entry was generated.
    pub file: String,
    /// The line in [`file`] in which this log entry was generated.
    pub line: u32,
    /// The log message.
    pub message: String,
    /// The index of this entry starting from the last canister upgrade.
    pub counter: u64,
}

/// A container for log entries at a given log priority level.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct Log<Priority> {
    /// The log entries for this priority level.
    pub entries: Vec<LogEntry<Priority>>,
}

impl<Priority> Default for Log<Priority> {
    fn default() -> Self {
        Self { entries: vec![] }
    }
}

impl<'de, Priority> Log<Priority>
where
    Priority: LogPriorityLevels + Clone + Copy + Deserialize<'de> + Serialize + 'static,
{
    /// Append all the entries from the given `Priority` to [`Log::entries`].
    pub fn push_logs(&mut self, priority: Priority) {
        for entry in export_logs(priority.get_buffer()) {
            self.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
    }

    /// Append all the entries from all priority levels to [`Log::entries`].
    pub fn push_all(&mut self) {
        Priority::get_priorities()
            .iter()
            .for_each(|priority| self.push_logs(*priority));
    }

    /// Serialize the logs contained in `entries` into a JSON string.
    ///
    /// If the resulting string is larger than `max_body_size` bytes,
    /// truncate `entries` so the resulting serialized JSON string
    /// contains no more than `max_body_size` bytes.
    pub fn serialize_logs(&self, max_body_size: usize) -> String {
        let mut entries_json: String = serde_json::to_string(&self).unwrap_or_default();

        if entries_json.len() > max_body_size {
            let mut left = 0;
            let mut right = self.entries.len();

            while left < right {
                let mid = left + (right - left) / 2;
                let mut temp_log = self.clone();
                temp_log.entries.truncate(mid);
                let temp_entries_json = serde_json::to_string(&temp_log).unwrap_or_default();

                if temp_entries_json.len() <= max_body_size {
                    entries_json = temp_entries_json;
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
        }
        entries_json
    }

    /// Sort the log entries according `sort_order`.
    pub fn sort_logs(&mut self, sort_order: Sort) {
        match sort_order {
            Sort::Ascending => self.sort_asc(),
            Sort::Descending => self.sort_desc(),
        }
    }

    fn sort_asc(&mut self) {
        self.entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    fn sort_desc(&mut self) {
        self.entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct PrintProxySink<Priority: 'static>(pub &'static Priority, pub &'static GlobalBuffer);

impl<Priority: LogPriorityLevels + GetLogFilter> Sink for PrintProxySink<Priority> {
    fn append(&self, entry: ic_canister_log::LogEntry) {
        let message = format!(
            "{} {}:{} {}",
            self.0.display_name(),
            entry.file,
            entry.line,
            entry.message,
        );
        if Priority::get_log_filter().is_match(&message) {
            ic_cdk::println!("{}", message);
            self.1.append(entry)
        }
    }
}
