#[cfg(test)]
mod tests;

use ic_canister_log::{declare_log_buffer, export as export_logs, GlobalBuffer, Sink};
use serde::Deserialize;
use std::str::FromStr;

// TODO move to separate crate, copied from ckETH

// High-priority messages.
declare_log_buffer!(name = INFO_BUF, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = DEBUG_BUF, capacity = 1000);

pub const INFO: PrintProxySink = PrintProxySink("INFO", &INFO_BUF);
pub const DEBUG: PrintProxySink = PrintProxySink("DEBUG", &DEBUG_BUF);

pub struct PrintProxySink(&'static str, &'static GlobalBuffer);

impl Sink for PrintProxySink {
    fn append(&self, entry: ic_canister_log::LogEntry) {
        ic_cdk::println!("{} {}:{} {}", self.0, entry.file, entry.line, entry.message);
        self.1.append(entry)
    }
}

#[derive(Clone, serde::Serialize, Deserialize, Debug, Copy)]
pub enum Priority {
    Info,
    Debug,
}

impl FromStr for Priority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Priority::Info),
            "debug" => Ok(Priority::Debug),
            _ => Err("could not recognize priority".to_string()),
        }
    }
}

#[derive(Clone, serde::Serialize, Deserialize, Debug, Copy)]
pub enum Sort {
    Ascending,
    Descending,
}

impl FromStr for Sort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "asc" => Ok(Sort::Ascending),
            "desc" => Ok(Sort::Descending),
            _ => Err("could not recognize sort order".to_string()),
        }
    }
}

#[derive(Clone, serde::Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: Priority,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub counter: u64,
}

#[derive(Clone, Default, serde::Serialize, Deserialize, Debug)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

impl Log {
    pub fn push_logs(&mut self, priority: Priority) {
        let logs = match priority {
            Priority::Info => export_logs(&INFO_BUF),
            Priority::Debug => export_logs(&DEBUG_BUF),
        };
        for entry in logs {
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

    pub fn push_all(&mut self) {
        self.push_logs(Priority::Info);
        self.push_logs(Priority::Debug);
    }

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

    pub fn sort_logs(&mut self, sort_order: Sort) {
        match sort_order {
            Sort::Ascending => self.sort_asc(),
            Sort::Descending => self.sort_desc(),
        }
    }

    pub fn sort_asc(&mut self) {
        self.entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    pub fn sort_desc(&mut self) {
        self.entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    }
}
