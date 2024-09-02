use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter, Result},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::driver::event::TaskId;

#[allow(dead_code)]
fn get_duration(
    task_id: &TaskId,
    start_times: &BTreeMap<TaskId, SystemTime>,
    end_times: &BTreeMap<TaskId, SystemTime>,
) -> Option<Duration> {
    if !start_times.contains_key(task_id) || !end_times.contains_key(task_id) {
        return None;
    }
    Some(
        end_times
            .get(task_id)
            .unwrap()
            .duration_since(*start_times.get(task_id).unwrap())
            .expect("Failed to calculate task duration."),
    )
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SystemGroupSummary {
    pub test_name: String,
    pub success: Vec<TaskReport>,
    pub failure: Vec<TaskReport>,
    pub skipped: Vec<TaskReport>,
}

impl Display for SystemGroupSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl SystemGroupSummary {
    pub fn pretty_print(&self) -> String {
        let max_name_len = self.max_name_len();
        let mut out_lines = vec![];
        for res in self.success.iter() {
            out_lines.append(&mut res.pretty_print(max_name_len, "PASSED "));
        }
        for res in self.failure.iter() {
            out_lines.append(&mut res.pretty_print(max_name_len, "FAILED "));
        }
        for res in self.skipped.iter() {
            out_lines.append(&mut res.pretty_print(max_name_len, "SKIPPED"));
        }
        let mx_len = out_lines.iter().max_by_key(|x| x.len()).unwrap().len();
        let test_name = if let Ok(test_target) = std::env::var("TEST_TARGET") {
            test_target
        } else {
            self.test_name.clone()
        };
        let title = format!(" Summary for {} ", test_name);
        let mx_len = std::cmp::max(mx_len, title.len() + 10);
        let mx_len = std::cmp::min(mx_len, 200);
        let start = format!("{:=^mx_len$}", title);
        let end = format!("{:=^mx_len$}", "");
        let mut summary = vec![];
        summary.push(start);
        summary.append(&mut out_lines);
        summary.push(end);
        summary.iter().fold(String::new(), |a, b| a + b + "\n")
    }

    fn all_reports(&self) -> impl Iterator<Item = &TaskReport> {
        self.success
            .iter()
            .chain(self.failure.iter())
            .chain(self.skipped.iter())
    }

    fn max_name_len(&self) -> usize {
        let mut mx = 6;
        for x in self.all_reports() {
            mx = std::cmp::max(mx, x.name.chars().count());
        }
        mx
    }

    pub fn to_map(&self) -> HashMap<String, (f64, Option<String>)> {
        let mut map = HashMap::new();
        for TaskReport {
            name,
            runtime,
            message,
        } in self.all_reports()
        {
            map.insert(name.clone(), (*runtime, message.clone()));
        }
        map
    }
}

// short messages (without newlines) are appended to the end of a report line.
// multi-line messages are indented so they are visually distinct from report lines.
impl TaskReport {
    fn pretty_print(&self, max_name_len: usize, verb: &str) -> Vec<String> {
        let time = if self.runtime > 0.0 {
            format!(" in {:>6.2}s", self.runtime)
        } else {
            "".to_owned()
        };
        let mut report_lines: Vec<String> = vec![];
        let message = if let Some(msg) = &self.message {
            let msg = msg.replace("\\n", "\n");
            if !msg.contains('\n') {
                format!(" -- {}", msg)
            } else {
                report_lines.append(&mut msg.lines().map(|line| format!("     {line}")).collect());
                "".to_owned()
            }
        } else {
            "".to_owned()
        };
        let mut res = vec![format!(
            "Task {:<max_name_len$} {}{:<13}{}",
            self.name, verb, time, message
        )];
        res.append(&mut report_lines);
        res
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct TaskReport {
    pub name: String,
    pub runtime: f64,
    pub message: Option<String>,
}

#[derive(Clone, Debug)]
pub enum SystemTestGroupError {
    TestDriverError {
        message: String,
    },
    PreconditionViolation {
        condition: String,
        counterexample: String,
    },
    ExternalSignalReceived {
        task_id: TaskId,
        signal: i32,
    },
    SystemTestFailure(SystemGroupSummary),
}

impl Display for SystemTestGroupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            SystemTestGroupError::TestDriverError { message } => {
                write!(f, "Internal test driver error: {}", message)
            }
            SystemTestGroupError::PreconditionViolation {
                condition,
                counterexample,
            } => write!(
                f,
                "Test driver precondition `{}` is violated, e.g.: {}",
                condition, counterexample
            ),
            SystemTestGroupError::ExternalSignalReceived { task_id, signal } => write!(
                f,
                "Process running test {} received external signal {}",
                task_id.name(),
                signal
            ),
            SystemTestGroupError::SystemTestFailure(report) => writeln!(
                f,
                "Test driver completed normally, but some tests failed"
            )
            .and(write!(f, "{}", report)),
        }
    }
}

// The following trait allows using the `result?` syntax in SystemTestGroup.execute()
impl std::convert::From<anyhow::Error> for SystemTestGroupError {
    fn from(e: anyhow::Error) -> Self {
        Self::TestDriverError {
            message: format!("{:?}", e),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Outcome {
    FromParentProcess(SystemGroupSummary),
    FromSubProcess,
}
