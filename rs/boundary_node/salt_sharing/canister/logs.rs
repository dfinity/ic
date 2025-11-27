use candid::Deserialize;
use ic_canister_log::{declare_log_buffer, export as export_logs};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use std::str::FromStr;

// High-priority messages.
declare_log_buffer!(name = P0, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = P1, capacity = 1000);

#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: Priority,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub counter: u64,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub enum Priority {
    P0,
    P1,
}

pub fn export_logs_as_http_response(request: HttpRequest) -> HttpResponse {
    let max_skip_timestamp = match request.raw_query_param("time") {
        Some(arg) => match u64::from_str(arg) {
            Ok(value) => value,
            Err(_) => {
                return HttpResponseBuilder::bad_request()
                    .with_body_and_content_length("failed to parse the 'time' parameter")
                    .build();
            }
        },
        None => 0,
    };

    let mut entries: Log = Default::default();

    for entry in export_logs(&P0) {
        entries.entries.push(LogEntry {
            timestamp: entry.timestamp,
            counter: entry.counter,
            priority: Priority::P0,
            file: entry.file.to_string(),
            line: entry.line,
            message: entry.message,
        });
    }

    for entry in export_logs(&P1) {
        entries.entries.push(LogEntry {
            timestamp: entry.timestamp,
            counter: entry.counter,
            priority: Priority::P1,
            file: entry.file.to_string(),
            line: entry.line,
            message: entry.message,
        });
    }

    entries
        .entries
        .retain(|entry| entry.timestamp >= max_skip_timestamp);

    HttpResponseBuilder::ok()
        .header("Content-Type", "application/json; charset=utf-8")
        .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
        .build()
}
