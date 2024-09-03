use crate::scheduler::{Task, TaskError};
use ic_metrics_encoder::MetricsEncoder;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

thread_local! {
    static METRICS: RefCell<OrchestratorMetrics> = RefCell::default();
}

pub fn observe_task_duration(
    task: &Task,
    result: &Result<(), TaskError>,
    start_time_ns: u64,
    end_time_ns: u64,
) {
    METRICS.with(|metrics| {
        metrics
            .borrow_mut()
            .observe_task_duration(task, result, start_time_ns, end_time_ns)
    });
}

pub fn encode_orchestrator_metrics<W: std::io::Write>(
    encoder: &mut MetricsEncoder<W>,
) -> std::io::Result<()> {
    METRICS.with(|metrics| metrics.borrow().encode(encoder))
}

#[derive(Default)]
pub struct OrchestratorMetrics {
    histogram_per_task: BTreeMap<TaskExecutionResult, TaskHistogram>,
}

impl OrchestratorMetrics {
    pub fn observe_task_duration(
        &mut self,
        task: &Task,
        result: &Result<(), TaskError>,
        start_time_ns: u64,
        end_time_ns: u64,
    ) {
        let elapsed_ns = end_time_ns.saturating_sub(start_time_ns);
        let duration_secs = Duration::from_nanos(elapsed_ns).as_secs_f64();
        let task = TaskExecutionResult {
            task_name: match task {
                Task::InstallLedgerSuite(_) => "install_ledger_suite",
                Task::MaybeTopUp => "maybe_top_up",
                Task::NotifyErc20Added { .. } => "notify_erc20_added",
                Task::DiscoverArchives => "discover_archives",
                Task::UpgradeLedgerSuite(_) => "upgrade_ledger_suite",
                Task::ManageAlreadyInstalledLedgerSuite(_) => {
                    "manage_already_installed_ledger_suite"
                }
            }
            .to_string(),
            result: match result {
                Ok(_) => MetricsResult::Ok,
                Err(_) => MetricsResult::Err,
            },
        };

        let task_histogram = self.histogram_per_task.entry(task).or_default();
        task_histogram.total_duration += duration_secs;
        for (i, v) in task_histogram.histogram.iter_mut().enumerate() {
            if BUCKETS[i] >= duration_secs {
                *v += 1;
                break;
            }
        }
    }

    pub fn encode<W: std::io::Write>(
        &self,
        encoder: &mut MetricsEncoder<W>,
    ) -> std::io::Result<()> {
        if self.histogram_per_task.is_empty() {
            return Ok(());
        }

        let mut histogram_vec = encoder.histogram_vec(
            "orchestrator_tasks_duration_seconds",
            "Histogram of task execution durations in seconds.",
        )?;

        for (task, histogram) in &self.histogram_per_task {
            histogram_vec = histogram_vec.histogram(
                &[
                    ("task", task.task_name.as_str()),
                    ("result", task.result.as_str()),
                ],
                histogram.iter(),
                histogram.total_duration,
            )?;
        }

        Ok(())
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
struct TaskExecutionResult {
    task_name: String,
    result: MetricsResult,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
enum MetricsResult {
    Ok,
    Err,
}

impl MetricsResult {
    fn as_str(&self) -> &'static str {
        match self {
            MetricsResult::Ok => "ok",
            MetricsResult::Err => "err",
        }
    }
}

/// The number of buckets in a histogram.
const BUCKET_COUNT: usize = 25;

/// Buckets for measuring duration in seconds.
/// Note that for a canister the granularity of `ic0::time` is around 1s.
const BUCKETS: [f64; BUCKET_COUNT] = [
    0.1, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0, 14.0, 16.0, 18.0, 20.0,
    25.0, 30.0, 35.0, 40.0, 50.0, 100.0, 200.0, 500.0,
];

/// The distribution of task durations.
///
/// `histogram[i]` contains the number of measurements m such that
/// `BUCKETS[i - 1] < m <= BUCKETS[i]`.
/// `BUCKETS[-1]` is defined to be zero.
#[derive(Default)]
struct TaskHistogram {
    histogram: [u64; BUCKET_COUNT],
    total_duration: f64,
}

impl TaskHistogram {
    fn iter(&self) -> impl Iterator<Item = (f64, f64)> + '_ {
        BUCKETS
            .iter()
            .copied()
            .zip(self.histogram.iter().copied())
            .map(|(bucket, count)| (bucket, count as f64))
    }
}
