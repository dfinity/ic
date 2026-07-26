use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter, Result},
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::Context;
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
        let test_name = self.display_name();
        let title = format!(" Summary for {test_name} ");
        let mx_len = std::cmp::max(mx_len, title.len() + 10);
        let mx_len = std::cmp::min(mx_len, 200);
        let start = format!("{title:=^mx_len$}");
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

    /// The name this test is known by: its Bazel label when running under
    /// `bazel test` (which sets `$TEST_TARGET` to e.g.
    /// `//rs/tests/consensus:adding_nodes_to_subnet_test_local`), the group's
    /// base name otherwise.
    pub fn display_name(&self) -> String {
        std::env::var("TEST_TARGET").unwrap_or_else(|_| self.test_name.clone())
    }

    /// Renders this summary as a JUnit XML report: one `<testsuite>` for the
    /// system-test group, one `<testcase>` per task that ran.
    pub fn to_junit_xml(&self) -> String {
        let suite = xml_escape(&self.display_name());
        // Fold explicitly instead of `sum()`: `f64`'s `Sum` folds from -0.0, so an
        // empty summary would render as time="-0.000".
        let time = self
            .all_reports()
            .fold(0.0, |total, report| total + report.runtime);
        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<testsuites>\n");
        out.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"{}\" time=\"{:.3}\">\n",
            suite,
            self.all_reports().count(),
            self.failure.len(),
            self.skipped.len(),
            time,
        ));
        for report in self.success.iter() {
            out.push_str(&report.to_junit_testcase(&suite, TaskOutcome::Passed));
        }
        for report in self.failure.iter() {
            out.push_str(&report.to_junit_testcase(&suite, TaskOutcome::Failed));
        }
        for report in self.skipped.iter() {
            out.push_str(&report.to_junit_testcase(&suite, TaskOutcome::Skipped));
        }
        out.push_str("  </testsuite>\n");
        out.push_str("</testsuites>\n");
        out
    }

    /// Writes this summary as a JUnit XML report to `$XML_OUTPUT_FILE`, the path
    /// Bazel tells a test to write its report to. Returns the path written to, or
    /// `None` when the variable isn't set, i.e. we're not running under
    /// `bazel test`.
    ///
    /// Writing this file matters beyond the report itself: `test.xml` is a
    /// declared output of every Bazel test action, so when a test doesn't produce
    /// it, Bazel runs a *second* spawn
    /// (`@bazel_tools//tools/test:test_xml_generator`) to derive it from
    /// `test.log`. Under remote execution that spawn has to queue for a free
    /// worker -- often for minutes -- to do well under a second of work. Writing
    /// the file ourselves makes Bazel skip that spawn entirely.
    pub fn write_junit_xml_report(&self) -> anyhow::Result<Option<PathBuf>> {
        let Some(path) = std::env::var_os("XML_OUTPUT_FILE") else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create the directory of {}", path.display()))?;
        }
        std::fs::write(&path, self.to_junit_xml()).with_context(|| {
            format!("Failed to write the JUnit XML report to {}", path.display())
        })?;
        Ok(Some(path))
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

/// How a task ended, which decides the child element of its `<testcase>`.
enum TaskOutcome {
    Passed,
    Failed,
    Skipped,
}

/// Escapes `s` so it can be used both as XML character data and as an attribute
/// value, and replaces the code points that XML 1.0 cannot represent at all
/// (most control characters) with `?`.
///
/// Both halves are needed: task messages carry arbitrary output from the system
/// under test, and a single unescaped `<` or a stray escape sequence from a
/// coloured log line would make the whole report unparsable.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}' => {
                out.push(c)
            }
            _ => out.push('?'),
        }
    }
    out
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
                format!(" -- {msg}")
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

    /// Renders this task as a JUnit `<testcase>` element, already escaped and
    /// indented to sit inside a `<testsuite>`. `classname` is expected to be
    /// escaped already.
    fn to_junit_testcase(&self, classname: &str, outcome: TaskOutcome) -> String {
        // Messages are stored with newlines escaped; undo that so the report is
        // readable, exactly like `pretty_print` does.
        let message = self
            .message
            .as_ref()
            .map(|message| message.replace("\\n", "\n"));
        // JUnit consumers show the `message` attribute in list views and the
        // element body on drill-down, so put the first line in the attribute and
        // the whole thing in the body.
        let summary = message
            .as_deref()
            .and_then(|message| message.lines().next())
            .unwrap_or("")
            .to_string();
        let body = match outcome {
            TaskOutcome::Passed => String::new(),
            TaskOutcome::Failed => format!(
                "\n      <failure message=\"{}\">{}</failure>\n    ",
                xml_escape(&summary),
                xml_escape(message.as_deref().unwrap_or("")),
            ),
            TaskOutcome::Skipped => {
                format!(
                    "\n      <skipped message=\"{}\"/>\n    ",
                    xml_escape(&summary)
                )
            }
        };
        // `status` follows GoogleTest's convention, which Bazel's own
        // test_xml_generator also emits: "run" for a case that executed,
        // "notrun" for one that didn't.
        let status = match outcome {
            TaskOutcome::Passed | TaskOutcome::Failed => "run",
            TaskOutcome::Skipped => "notrun",
        };
        format!(
            "    <testcase name=\"{}\" classname=\"{}\" status=\"{}\" duration=\"{:.3}\" time=\"{:.3}\">{}</testcase>\n",
            xml_escape(&self.name),
            classname,
            status,
            self.runtime,
            self.runtime,
            body,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
                write!(f, "Internal test driver error: {message}")
            }
            SystemTestGroupError::PreconditionViolation {
                condition,
                counterexample,
            } => write!(
                f,
                "Test driver precondition `{condition}` is violated, e.g.: {counterexample}"
            ),
            SystemTestGroupError::ExternalSignalReceived { task_id, signal } => write!(
                f,
                "Process running test {} received external signal {}",
                task_id.name(),
                signal
            ),
            SystemTestGroupError::SystemTestFailure(report) => {
                writeln!(f, "Test driver completed normally, but some tests failed")
                    .and(write!(f, "{report}"))
            }
        }
    }
}

// The following trait allows using the `result?` syntax in SystemTestGroup.execute()
impl std::convert::From<anyhow::Error> for SystemTestGroupError {
    fn from(e: anyhow::Error) -> Self {
        Self::TestDriverError {
            message: format!("{e:?}"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Outcome {
    FromParentProcess(SystemGroupSummary),
    FromSubProcess,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(name: &str, runtime: f64, message: Option<&str>) -> TaskReport {
        TaskReport {
            name: name.to_string(),
            runtime,
            message: message.map(str::to_string),
        }
    }

    fn summary() -> SystemGroupSummary {
        SystemGroupSummary {
            test_name: "my_test".to_string(),
            success: vec![task("setup", 1.5, None)],
            // Messages are stored with their newlines escaped, and carry
            // arbitrary output from the system under test.
            failure: vec![task(
                "test <a & b>",
                12.25,
                Some("assertion failed\\ngot \"x\"\\nwant \u{1b}[31my\u{1b}[0m"),
            )],
            skipped: vec![task("teardown", 0.0, Some("Task skipped"))],
        }
    }

    #[test]
    fn junit_xml_reports_counts_and_durations() {
        let summary = summary();
        let suite = xml_escape(&summary.display_name());
        let xml = summary.to_junit_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n"));
        assert!(xml.ends_with("  </testsuite>\n</testsuites>\n"));
        assert!(
            xml.contains(&format!(
                "<testsuite name=\"{suite}\" tests=\"3\" failures=\"1\" errors=\"0\" skipped=\"1\" time=\"13.750\">"
            )),
            "{xml}"
        );
        assert!(
            xml.contains(&format!(
                "<testcase name=\"setup\" classname=\"{suite}\" status=\"run\" duration=\"1.500\" time=\"1.500\"></testcase>"
            )),
            "a passing task has an empty testcase body: {xml}"
        );
        assert!(
            xml.contains(&format!(
                "<testcase name=\"teardown\" classname=\"{suite}\" status=\"notrun\" duration=\"0.000\" time=\"0.000\">"
            )),
            "a skipped task is reported as notrun: {xml}"
        );
    }

    #[test]
    fn junit_xml_escapes_task_names_and_messages() {
        let xml = summary().to_junit_xml();
        assert!(
            xml.contains("<testcase name=\"test &lt;a &amp; b&gt;\""),
            "{xml}"
        );
        // Only the first line goes into the attribute, the whole message into the
        // body, with quotes escaped and the control characters of the coloured
        // log line replaced.
        assert!(
            xml.contains("<failure message=\"assertion failed\">"),
            "{xml}"
        );
        assert!(
            xml.contains("assertion failed\ngot &quot;x&quot;\nwant ?[31my?[0m</failure>"),
            "{xml}"
        );
        assert!(xml.contains("<skipped message=\"Task skipped\"/>"), "{xml}");
    }

    #[test]
    fn junit_xml_of_an_empty_summary_is_well_formed() {
        let xml = SystemGroupSummary::default().to_junit_xml();
        assert!(
            xml.contains("tests=\"0\" failures=\"0\" errors=\"0\" skipped=\"0\" time=\"0.000\""),
            "{xml}"
        );
    }

    #[test]
    fn xml_escape_keeps_legal_whitespace_and_drops_illegal_control_characters() {
        assert_eq!(xml_escape("a\tb\nc\rd"), "a\tb\nc\rd");
        assert_eq!(xml_escape("a\u{0}b\u{8}c"), "a?b?c");
        assert_eq!(xml_escape("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
    }
}
