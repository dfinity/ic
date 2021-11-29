//! From [Process Fields]:
//!
//! These fields contain information about a process.
//!
//! These fields can help you correlate metrics information with a process
//! id/name from a log message. The process.pid often stays in the metric itself
//! and is copied to the global field for correlation.
//!
//! [Process Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-process.html

use std::{
    env::{args, current_dir, current_exe},
    process,
};

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::Long;

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Process {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_count: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Thread {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

pub trait WithCurrentProcess {
    fn with_current_process(&mut self);
}

impl WithCurrentProcess for Option<Process> {
    /// Fill in with information about the current process.
    fn with_current_process(&mut self) {
        let process = self.get_or_insert(Process::default());

        let args: Vec<String> = args().collect();

        process.args_count = Some(args.len() as Long);
        process.command_line = Some(args.join(" "));
        process.args = Some(args);

        if let Ok(path) = current_exe() {
            process.executable = Some(path.canonicalize().unwrap().to_string_lossy().into_owned());
        }

        if let Ok(path) = current_dir() {
            process.working_directory =
                Some(path.canonicalize().unwrap().to_string_lossy().into_owned());
        }

        process.pid = Some(process::id() as Long);
    }
}
