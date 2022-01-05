#![allow(clippy::new_without_default)]
use super::execution::stream_decoder::serialize_and_write;
use mio::unix::pipe;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Eq, Serialize, Deserialize, PartialEq)]
pub enum TestResult {
    Success,
    Failure,
    Skipped,
}

impl TestResult {
    pub fn is_success(&self) -> bool {
        matches!(self, TestResult::Success | TestResult::Skipped)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub test_name: String,
    pub test_result: TestResult,
    #[serde(with = "serde_millis")]
    pub started_at: Instant,
    pub duration: Duration,
}

impl TestReport {
    pub fn new(test_name: String, test_result: TestResult) -> Self {
        TestReport {
            test_name,
            test_result,
            started_at: Instant::now(),
            duration: Duration::from_secs(0),
        }
    }

    pub fn is_success(&self) -> bool {
        self.test_result.is_success()
    }
}

pub trait Report {
    fn report(&mut self, rep: &TestReport);
    fn done(self);
}

/// Sends reports to a parent process for further processing.
pub struct ReportToParent(pipe::Sender);

impl ReportToParent {
    pub fn new(s: pipe::Sender) -> Self {
        ReportToParent(s)
    }
}

impl Report for ReportToParent {
    fn report(&mut self, rep: &TestReport) {
        serialize_and_write(&mut self.0, rep).expect("Couldn't send report");
    }

    fn done(self) {}
}

/// Produces reports in json
pub struct ReportJSON(());

impl ReportJSON {
    pub fn new() -> Self {
        ReportJSON(())
    }

    pub fn write_test_event(name: &str, evt: &str, exec_time: Duration) {
        // A doc test's name includes a filename which must be escaped for correct json.
        println!(
            r#"{{ "type": "test", "name": "{}", "event": "{}", "exec_time": "{:.4}s" }}"#,
            name,
            evt,
            exec_time.as_secs_f64(),
        )
    }
}

impl Report for ReportJSON {
    fn done(self) {}
    fn report(&mut self, rep: &TestReport) {
        let ev = match rep.test_result {
            TestResult::Success => "ok",
            TestResult::Failure => "failed",
            TestResult::Skipped => "skipped",
        };
        ReportJSON::write_test_event(&rep.test_name, ev, rep.duration);
    }
}

/// A reporter that ignores everything
pub struct ReportIgnore(());
impl ReportIgnore {
    pub fn new() -> Self {
        ReportIgnore(())
    }
}
impl Report for ReportIgnore {
    fn done(self) {}
    fn report(&mut self, _rep: &TestReport) {}
}

pub struct TestStatistics {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub timeout: usize,
}

impl TestStatistics {
    pub fn new() -> Self {
        TestStatistics {
            passed: 0,
            failed: 0,
            skipped: 0,
            timeout: 0,
        }
    }

    pub fn inc_passed(&mut self) {
        self.passed += 1;
    }

    pub fn inc_failed(&mut self) {
        self.failed += 1;
    }

    pub fn inc_timeout(&mut self) {
        self.timeout += 1;
    }

    pub fn inc_skipped(&mut self) {
        self.skipped += 1;
    }

    pub fn register(&mut self, rep: &TestReport) {
        match rep.test_result {
            TestResult::Success => self.passed += 1,
            TestResult::Failure => self.failed += 1,
            TestResult::Skipped => self.skipped += 1,
        }
    }

    pub fn is_success(&self) -> bool {
        self.failed == 0 && self.timeout == 0
    }
}
