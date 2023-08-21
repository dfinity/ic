use ic_canister_log::{declare_log_buffer, export as export_logs};
use serde::Deserialize;
use std::str::FromStr;

// High-priority messages.
declare_log_buffer!(name = INFO, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = DEBUG, capacity = 1000);

// Trace of HTTP requests and responses.
declare_log_buffer!(name = TRACE_HTTP, capacity = 1000);

#[derive(Clone, serde::Serialize, Deserialize, Debug, Copy)]
pub enum Priority {
    Info,
    TraceHttp,
    Debug,
}

impl FromStr for Priority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Priority::Info),
            "trace_http" => Ok(Priority::TraceHttp),
            "debug" => Ok(Priority::Debug),
            _ => Err("could not recognize priority".to_string()),
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
            Priority::Info => export_logs(&INFO),
            Priority::TraceHttp => export_logs(&TRACE_HTTP),
            Priority::Debug => export_logs(&DEBUG),
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
        self.push_logs(Priority::TraceHttp);
        self.push_logs(Priority::Debug);
    }
}
