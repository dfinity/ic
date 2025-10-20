use candid::Deserialize;
use canlog::{GetLogFilter, LogFilter};
use canlog_derive::LogPriorityLevels;
use serde::Serialize;
use std::str::FromStr;

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

impl FromStr for Priority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Priority::P0),
            "debug" => Ok(Priority::P1),
            _ => Err("could not recognize priority".to_string()),
        }
    }
}
