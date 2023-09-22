use ic_canister_log::{declare_log_buffer, export as export_logs, GlobalBuffer, Sink};
use serde::Deserialize;
use std::str::FromStr;

// High-priority messages.
declare_log_buffer!(name = INFO_BUF, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = DEBUG_BUF, capacity = 1000);

// Trace of HTTP requests and responses.
declare_log_buffer!(name = TRACE_HTTP_BUF, capacity = 1000);

pub const INFO: PrintProxySink = PrintProxySink("INFO", &INFO_BUF);
pub const DEBUG: PrintProxySink = PrintProxySink("DEBUG", &DEBUG_BUF);
pub const TRACE_HTTP: PrintProxySink = PrintProxySink("TRACE_HTTP", &TRACE_HTTP_BUF);

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
            Priority::Info => export_logs(&INFO_BUF),
            Priority::TraceHttp => export_logs(&TRACE_HTTP_BUF),
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
        self.push_logs(Priority::TraceHttp);
        self.push_logs(Priority::Debug);
    }
}
