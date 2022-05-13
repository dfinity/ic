#![allow(clippy::ptr_arg)]
use crate::pot::PotResult;
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Execution will fork and run one pot per process. Pots themselves
/// consist in a number of composable test steps and a passive monitoring
/// component, it is possible for all tests to pass even though the status of
/// the pot is a failure. At the end of execution, we return a [ExecutionResult]
/// which contains information about all pots in [CompletedPot].
pub struct ExecutionResult(pub Vec<CompletedPot>);

impl ExecutionResult {
    pub fn treeify(&self, name: String, started_at: Instant) -> TestResultNode {
        let to_test_result = |r: PotResult| {
            r.test_reports
                .into_iter()
                .map(|test| TestResultNode {
                    name: test.name.clone(),
                    group_name: None,
                    started_at: test.started_at,
                    duration: test.duration,
                    result: test.result,
                    children: vec![],
                })
                .collect()
        };
        let children: Vec<TestResultNode> = self
            .0
            .clone()
            .into_iter()
            .map(|pot| {
                let result = if pot.is_success() {
                    TestResult::Passed
                } else {
                    TestResult::failed_with_message("")
                };
                TestResultNode {
                    name: pot.pot_name,
                    group_name: None,
                    started_at: pot.started_at,
                    duration: pot.duration,
                    result,
                    children: pot.result.map_or(vec![], to_test_result),
                }
            })
            .collect();
        let result = infer_result(children.as_slice());
        TestResultNode {
            name,
            group_name: None,
            started_at,
            duration: Instant::now() - started_at,
            children,
            result,
        }
    }

    pub fn was_successful(&self) -> bool {
        self.0.iter().all(|s| s.is_success())
    }
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
}

impl CompletedPot {
    pub fn new(pot_name: String, test_names: Vec<String>, result: TestResult) -> Self {
        CompletedPot {
            pid_and_status: None,
            pot_name,
            result: Some(PotResult {
                test_reports: test_names
                    .iter()
                    .map(|tn| TestResultNode {
                        name: tn.clone(),
                        result: result.clone(),
                        ..TestResultNode::default()
                    })
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// A tree-like structure containing statistics on how much time it took to
/// complete a node and all its children, i.e. threads spawned from the node.
pub struct TestResultNode {
    pub name: String,
    pub group_name: Option<String>,
    #[serde(with = "serde_millis")]
    pub started_at: Instant,
    pub duration: Duration,
    pub result: TestResult,
    pub children: Vec<TestResultNode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TestResult {
    Passed,
    Failed(String),
    Skipped,
}

impl TestResult {
    pub fn failed_with_message(message: &str) -> TestResult {
        TestResult::Failed(message.to_string())
    }
}

impl Default for TestResultNode {
    fn default() -> Self {
        Self {
            name: String::default(),
            group_name: None,
            started_at: Instant::now(),
            duration: Duration::default(),
            result: TestResult::Skipped,
            children: vec![],
        }
    }
}

pub fn infer_result(tests: &[TestResultNode]) -> TestResult {
    if tests.iter().all(|t| t.result == TestResult::Skipped) {
        return TestResult::Skipped;
    }
    if tests
        .iter()
        .any(|t| matches!(t.result, TestResult::Failed(_)))
    {
        TestResult::failed_with_message("")
    } else {
        TestResult::Passed
    }
}
