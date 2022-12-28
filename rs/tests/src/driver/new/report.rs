use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter, Result},
    time::{Duration, Instant},
};

use crate::driver::test_setup::GroupSetup;

use super::event::TaskId;

pub trait TargetFunctionOutcome {
    fn task_id(&self) -> TaskId;
}

#[derive(Clone, Debug)]
pub struct TargetFunctionSuccess {
    pub task_id: TaskId,
    pub runtime: Duration,
}

impl TargetFunctionOutcome for TargetFunctionSuccess {
    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

#[derive(Clone, Debug)]
pub enum TargetFunctionFailure {
    Panicked {
        task_id: TaskId,
        message: String,
        runtime: Duration,
    },
    TimedOut {
        task_id: TaskId,
        timeout: Duration,
    },
}

impl TargetFunctionOutcome for TargetFunctionFailure {
    fn task_id(&self) -> TaskId {
        match self {
            TargetFunctionFailure::Panicked { task_id, .. } => task_id.clone(),
            TargetFunctionFailure::TimedOut { task_id, .. } => task_id.clone(),
        }
    }
}

fn fmt_succs(succs: &[TargetFunctionSuccess], f: &mut Formatter<'_>, min_width: usize) -> Result {
    succs.iter().fold(write!(f, ""), |acc, success| {
        acc.and(writeln!(
            f,
            "{}",
            &format!(
                "Test {:<min_width$}  PASSED in {:>6.2}s",
                success.task_id().name(),
                success.runtime.as_secs_f64()
            )
        ))
    })
}

fn fmt_fails(fails: &[TargetFunctionFailure], f: &mut Formatter<'_>, min_width: usize) -> Result {
    fails
        .iter()
        .fold(write!(f, ""), |acc, failure| match failure {
            TargetFunctionFailure::Panicked {
                task_id,
                message,
                runtime,
            } => acc.and(writeln!(
                f,
                "Test {:<min_width$}  FAILED in {:>6.2}s -- {}",
                task_id.name(),
                runtime.as_secs_f64(),
                message
            )),
            TargetFunctionFailure::TimedOut { task_id, timeout } => acc.and(writeln!(
                f,
                "Test {:<min_width$} TIMEOUT in {:>6.2}s",
                task_id.name(),
                timeout.as_secs_f64()
            )),
        })
}

#[derive(Clone, Debug)]
pub struct FarmGroupReport {
    pub group_setup: GroupSetup,
}

#[derive(Clone, Debug, Default)]
pub struct SystemTestGroupReport {
    successes: Vec<TargetFunctionSuccess>,
    failures: Vec<TargetFunctionFailure>,

    start_times: BTreeMap<TaskId, Instant>,
    end_times: BTreeMap<TaskId, Instant>,

    running_tasks: BTreeSet<TaskId>,

    detected_timeouts: BTreeSet<TaskId>,

    is_group_timed_out: bool,

    pub farm_group_report: Option<FarmGroupReport>,
}

impl SystemTestGroupReport {
    pub fn add_succ(&mut self, succ: TargetFunctionSuccess) {
        self.successes.push(succ);
    }

    pub fn add_fail(&mut self, fail: TargetFunctionFailure) {
        self.failures.push(fail);
    }

    pub fn is_failure_free(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn set_test_start_time(&mut self, test_id: TaskId) {
        assert!(
            self.running_tasks.insert(test_id.clone()),
            "cannot set start time for {} more than once",
            &test_id
        );
        self.start_times.entry(test_id).or_insert_with(Instant::now);
    }

    pub fn set_test_end_time(&mut self, test_id: TaskId) {
        assert!(
            self.running_tasks.remove(&test_id),
            "cannot set end time for {} which did not start",
            &test_id
        );
        self.end_times.entry(test_id).or_insert_with(Instant::now);
    }

    pub fn get_test_duration(&self, test_id: &TaskId) -> Duration {
        let msg = |which_instant| {
            format!(
                "{} time is needed to compute duration of {}",
                which_instant, test_id
            )
        };
        let start = self
            .start_times
            .get(test_id)
            .unwrap_or_else(|| panic!("{}", msg("start")));
        let end = self
            .end_times
            .get(test_id)
            .unwrap_or_else(|| panic!("{}", msg("end")));
        end.duration_since(*start)
    }

    pub fn set_test_as_timed_out(&mut self, test_id: TaskId) {
        self.detected_timeouts.insert(test_id);
    }

    pub fn is_test_timed_out(&self, test_id: &TaskId) -> bool {
        self.detected_timeouts.contains(test_id)
    }

    pub fn all_tasks_finished(&self) -> bool {
        self.running_tasks.is_empty()
    }

    pub fn set_group_timed_out(&mut self) {
        self.is_group_timed_out = true;
    }

    pub fn is_group_timed_out(&self) -> bool {
        self.is_group_timed_out
    }
}

fn compute_min_width<T>(xs: &[T]) -> Option<usize>
where
    T: TargetFunctionOutcome,
{
    xs.iter()
        .max_by(|a, b| a.task_id().name().cmp(&b.task_id().name()))
        .map(|x| x.task_id().name().chars().count())
}

impl Display for SystemTestGroupReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let min_width_succs = compute_min_width(&self.successes);
        let min_width_fails = compute_min_width(&self.failures);

        // Compute number of symbols in longest task name
        let w = std::cmp::max(min_width_succs, min_width_fails).unwrap_or(10);
        let table_width = "Test ".len() + w + "  PASSED in xxx.xxs".len();

        writeln!(f, "{:=^table_width$}", " Summary ")
            .and(if self.failures.is_empty() && self.successes.is_empty() {
                writeln!(f, "No test outcomes were reported.")
            } else if self.failures.is_empty() {
                fmt_succs(&self.successes, f, w).and(writeln!(
                    f,
                    "{:.^table_width$}",
                    format!(" All {} tests passed! ", self.successes.len())
                ))
            } else if self.successes.is_empty() {
                fmt_fails(&self.failures, f, w).and(writeln!(
                    f,
                    "{:.^table_width$}",
                    format!(" All {} tests failed ", self.failures.len())
                ))
            } else {
                fmt_succs(&self.successes, f, w)
                    .and(writeln!(
                        f,
                        "{:.^table_width$}",
                        format!(" Tests passed: {:>2} ", self.successes.len())
                    ))
                    .and(fmt_fails(&self.failures, f, w))
                    .and(writeln!(
                        f,
                        "{:.^table_width$}",
                        format!(" Tests failed: {:>2} ", self.failures.len())
                    ))
            })
            .and(write!(f, "{:=^table_width$}", ""))
    }
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
    SystemTestFailure(SystemTestGroupReport),
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
    FromParentProcess(SystemTestGroupReport),
    FromSubProcess,
}
