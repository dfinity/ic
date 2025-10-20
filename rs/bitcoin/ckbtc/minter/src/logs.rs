use candid::Deserialize;
use canlog::{GetLogFilter, LogFilter};
use canlog_derive::LogPriorityLevels;
use ic_canister_log::declare_log_buffer;
use serde::Serialize;

// High-priority messages.
declare_log_buffer!(name = P0, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = P1, capacity = 1000);

#[derive(LogPriorityLevels, Serialize, Deserialize, PartialEq, Debug, Copy, Clone)]
pub enum Priority {
    #[log_level(capacity = 1000, name = "INFO")]
    Info,
    #[log_level(capacity = 1000, name = "DEBUG")]
    Debug,
}

impl GetLogFilter for Priority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}
