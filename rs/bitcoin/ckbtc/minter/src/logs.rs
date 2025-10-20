use candid::Deserialize;
use canlog::{GetLogFilter, LogFilter};
use canlog_derive::LogPriorityLevels;
use serde::Serialize;

#[derive(LogPriorityLevels, Serialize, Deserialize, PartialEq, Debug, Copy, Clone)]
pub enum Priority {
    #[log_level(capacity = 1000, name = "INFO")]
    P0,
    #[log_level(capacity = 1000, name = "DEBUG")]
    P1,
}

impl GetLogFilter for Priority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}
