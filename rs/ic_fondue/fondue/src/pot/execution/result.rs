#![allow(clippy::ptr_arg)]
use super::super::report::*;
use crate::pot::PotResult;
use nix::unistd::Pid;
use serde::Serialize;
use std::time::{Duration, Instant};

/// Execution will fork and run one pot per process. Pots themselves
/// consist in a number of composable test steps and a passive monitoring
/// component, it is possible for all tests to pass even though the status of
/// the pot is a failure. At the end of execution, we return a [ExecutionResult]
/// which contains information about all pots in [CompletedPot].
pub struct ExecutionResult(pub Vec<CompletedPot>);

impl ExecutionResult {
    pub fn extract_runtime_summary(&self, name: String, started_at: Instant) -> TestResultNode {
        let to_test_result = |r: PotResult| {
            r.test_reports
                .into_iter()
                .map(|test| TestResultNode {
                    name: test.test_name,
                    started_at: test.started_at,
                    duration: test.duration,
                    succeeded: test.test_result.is_success(),
                    children: vec![],
                })
                .collect()
        };
        let children: Vec<TestResultNode> = self
            .0
            .clone()
            .into_iter()
            .map(|pot| {
                let succeeded = pot.is_success();
                TestResultNode {
                    name: pot.pot_name,
                    started_at: pot.started_at,
                    duration: pot.duration,
                    succeeded,
                    children: pot.result.map_or(vec![], to_test_result),
                }
            })
            .collect();
        let succeeded = children.iter().all(|p| p.succeeded);
        TestResultNode {
            name,
            started_at,
            duration: Instant::now() - started_at,
            children,
            succeeded,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A tree-like structure containing statistics on how much time it took to
/// complete a node and all its children.
pub struct TestResultNode {
    name: String,
    #[serde(with = "serde_millis")]
    started_at: Instant,
    duration: Duration,
    succeeded: bool,
    children: Vec<TestResultNode>,
}

/// Contains information about a pot, whether or not
/// the given pot was run. The vector of [TestReport] should contain
/// one report for each test declared within the pot; `pid_and_status`
/// is `Some` when the pot was ran or `None` when it was skipped.
#[derive(Clone, Debug)]
pub struct CompletedPot {
    /// Carries the pot derived name
    pub pot_name: String,

    /// In case this pot was run, carries the process id and the returned
    /// status.
    pub pid_and_status: Option<(Pid, Status)>,

    /// What was the result of the pot, if any.
    /// This result, if present, contains reports for each individual test.
    /// These report contains the test name, the duration and the result.
    /// The result can be a success, failure or skipped.
    pub result: Option<PotResult>,

    /// Regardless of whether a result was produced or not, we keep the test
    /// names to be able to finish the summary nicely.
    pub test_names: Vec<String>,

    /// How long did this pot take to complete
    pub duration: std::time::Duration,

    /// When evaluation of the pot started.
    pub started_at: std::time::Instant,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Success,
    Failure(i32),
    Signaled(&'static str),
    Timeout,
}

impl Status {
    pub fn is_success(&self) -> bool {
        matches!(self, Status::Success)
    }

    pub fn count_on(&self, ts: &mut TestStatistics) {
        match self {
            Status::Success => ts.inc_passed(),
            Status::Timeout => ts.inc_timeout(),
            Status::Signaled(_) => ts.inc_failed(),
            Status::Failure(_) => ts.inc_failed(),
        }
    }
}

impl CompletedPot {
    pub fn new(pot_name: String, test_names: Vec<String>, result: TestResult) -> Self {
        CompletedPot {
            pid_and_status: None,
            pot_name,
            result: Some(PotResult {
                test_reports: test_names
                    .iter()
                    .map(|tn| TestReport::new(tn.clone(), result))
                    .collect(),
            }),
            test_names,
            started_at: std::time::Instant::now(),
            duration: std::time::Duration::default(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.pid_and_status
            .clone()
            .map(|(_, s)| s.is_success())
            .unwrap_or(true)
            && self.result.clone().map(|r| r.is_success()).unwrap_or(false)
    }
}

impl ExecutionResult {
    pub fn was_successful(&self) -> bool {
        self.0.iter().all(|s| s.is_success())
    }

    pub fn print_summary(&self) {
        let mut ts = TestStatistics::new();
        let mut pot_stats = TestStatistics::new();

        println!("\nExecution Summary:");
        for info in self.0.iter() {
            if let Some((ref pid, ref status)) = info.pid_and_status {
                println!(
                    "- Pot '{}' process ({}), took {:.3}s and returned {:?}",
                    info.pot_name,
                    pid.as_raw(),
                    info.duration.as_secs_f64(),
                    status,
                );
                status.count_on(&mut pot_stats);
            } else {
                println!("- Pot '{}' did not run", info.pot_name);
                pot_stats.inc_skipped();
            }

            let mut res = info.result.clone().unwrap_or_default();
            // If a pot failed due to timing out or crashing, results of individual tests
            // are missing. We create dummy TestReports in order to:
            // - keep the execution statistics sound,
            // - include in the execution summary all tests which should have been executed.
            if res.test_reports.is_empty() {
                let now = std::time::Instant::now();
                res.test_reports = info
                    .test_names
                    .iter()
                    .map(|t| TestReport {
                        test_name: t.clone(),
                        test_result: TestResult::Failure,
                        started_at: now,
                        duration: Default::default(),
                    })
                    .collect();
            }
            summarize_pot_result(&res, &mut ts);
            println!();
        }

        explain_semantics();
        print_assessment(self.was_successful(), ts, pot_stats);
    }
}

fn print_assessment(was_success: bool, tests: TestStatistics, pots: TestStatistics) {
    println!(
        "Tests: {} passed, {} skipped and {} failed",
        tests.passed, tests.skipped, tests.failed
    );
    println!(
        "Pots:  {} passed, {} skipped, {} failed and {} timed-out",
        pots.passed, pots.skipped, pots.failed, pots.timeout
    );

    println!("Assessment: {}", if was_success { "PASS" } else { "FAIL" });
    if tests.is_success() && !was_success {
        println!("(there were soft failures)");
    }
}

fn summarize_pot_result(res: &PotResult, ts: &mut TestStatistics) {
    for t in res.test_reports.iter() {
        ts.register(t);
        let lbl = match t.test_result {
            TestResult::Success => "  OK ",
            TestResult::Skipped => "SKIP ",
            TestResult::Failure => "FAIL ",
        };
        println!(
            "    {} {} (in {:.3}s)",
            lbl,
            t.test_name,
            t.duration.as_secs_f64()
        );
    }
}

fn explain_semantics() {
    println!(
        r#"
Above you will see an execution summary. A pot can contain multiple tests and
a passive pipeline:
  * A TEST passes when it doesn't panic
  * A POT passes when all its tests pass and the pipeline detects no passive failures.

Recall that this is a SUMMARY. Refer to the logs for details about each pot.
Search the name of the pot in question to get to where you should start looking easily."#
    );
    println!();
}
