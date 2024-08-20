use serde::{Deserialize, Serialize};
use slog::info;

#[derive(Serialize, Deserialize)]
pub struct LogEvent<T> {
    pub event_name: String,
    pub body: T,
}

impl<'a, T> LogEvent<T>
where
    T: Serialize + Deserialize<'a>,
{
    pub fn new(event_name: String, body: T) -> Self {
        Self { event_name, body }
    }

    pub fn emit_log(&self, log: &slog::Logger) {
        let json_str = serde_json::to_string(self).expect("Failed to serialize JSON");
        info!(log, "{json_str}");
    }
}
