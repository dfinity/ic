use ic_metrics_encoder::MetricsEncoder;
use std::{cell::RefCell, collections::HashMap, thread::LocalKey};

/// Metrics for a synchronous task.
#[derive(Default)]
pub(crate) struct SyncTaskMetrics {
    instruction: InstructionMetrics,
    last_executed: u64,
}

impl SyncTaskMetrics {
    pub(crate) fn record(&mut self, instructions_used: u64, time_seconds: u64) {
        self.last_executed = time_seconds;
        self.instruction.record(instructions_used);
    }
}

/// Metrics for an asynchronous task.
#[derive(Default)]
pub(crate) struct AsyncTaskMetrics {
    outstanding_count: u64,
    instruction: InstructionMetrics,
    last_started: u64,
    last_finished: u64,
}

impl AsyncTaskMetrics {
    pub(crate) fn record_start(&mut self, time_seconds: u64) {
        self.outstanding_count += 1;
        self.last_started = time_seconds;
    }

    pub(crate) fn record_finish(&mut self, instructions_used: u64, time_seconds: u64) {
        self.outstanding_count -= 1;
        self.last_finished = time_seconds;
        self.instruction.record(instructions_used);
    }
}

/// Metrics for the number of instructions used by a task (synchronous or
/// asynchronous).
#[derive(Default)]
pub(crate) struct InstructionMetrics {
    sum: u128,
    histogram: InstructionHistogram,
}

pub const INSTRUCTION_BUCKET_COUNT: usize = 29;
pub const INSTRUCTION_BUCKETS: [u64; INSTRUCTION_BUCKET_COUNT] = [
    10_000,
    20_000,
    50_000,
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    200_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
    20_000_000_000,
    50_000_000_000,
    100_000_000_000,
    200_000_000_000,
    500_000_000_000,
    1_000_000_000_000,
    2_000_000_000_000,
    5_000_000_000_000,
    10_000_000_000_000,
    u64::MAX,
];
type InstructionHistogram = [u64; INSTRUCTION_BUCKET_COUNT];

impl InstructionMetrics {
    fn record(&mut self, instruction_count: u64) {
        self.sum += instruction_count as u128;
        for (i, &bucket) in INSTRUCTION_BUCKETS.iter().enumerate() {
            if instruction_count <= bucket {
                self.histogram[i] += 1;
                break;
            }
        }
    }

    fn encode(
        &self,
        task_name: &str,
        histogram: ic_metrics_encoder::LabeledHistogramBuilder<Vec<u8>>,
    ) -> std::io::Result<()> {
        let buckets = INSTRUCTION_BUCKETS
            .iter()
            .cloned()
            .zip(self.histogram.iter().cloned())
            .map(|(b, m)| (b as f64, m as f64));
        histogram.histogram(&[("task_name", task_name)], buckets, self.sum as f64)?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MetricsRegistry {
    sync_metrics: HashMap<String, SyncTaskMetrics>,
    async_metrics: HashMap<String, AsyncTaskMetrics>,
}

pub(crate) type MetricsRegistryRef = &'static LocalKey<RefCell<MetricsRegistry>>;

pub(crate) fn with_sync_metrics(
    metrics_registry: MetricsRegistryRef,
    task_name: &'static str,
    f: impl FnOnce(&mut SyncTaskMetrics),
) {
    metrics_registry.with_borrow_mut(|metrics_registry| {
        let task_metrics = metrics_registry
            .sync_metrics
            .entry(task_name.to_string())
            .or_default();
        f(task_metrics);
    });
}

pub(crate) fn with_async_metrics(
    metrics_registry: MetricsRegistryRef,
    task_name: &'static str,
    f: impl FnOnce(&mut AsyncTaskMetrics),
) {
    metrics_registry.with_borrow_mut(|metrics_registry| {
        let task_metrics = metrics_registry
            .async_metrics
            .entry(task_name.to_string())
            .or_default();
        f(task_metrics);
    });
}

impl MetricsRegistry {
    /// Encodes the metrics into the given encoder.
    pub fn encode(
        &self,
        prefix: &'static str,
        encoder: &mut MetricsEncoder<Vec<u8>>,
    ) -> std::io::Result<()> {
        let instruction_histogram_metric_name = format!("{prefix}_task_instruction");

        let sync_last_executed_metric_name = format!("{prefix}_sync_task_last_executed");
        for (task_name, metrics) in &self.sync_metrics {
            metrics.instruction.encode(
                task_name,
                encoder.histogram_vec(
                    &instruction_histogram_metric_name,
                    "The number of instructions used by a task.",
                )?,
            )?;
            encoder
                .gauge_vec(
                    &sync_last_executed_metric_name,
                    "The time when the task was last executed",
                )?
                .value(&[("task_name", task_name)], metrics.last_executed as f64)?;
        }

        let async_outstanding_counter_metric_name =
            format!("{prefix}_async_task_outstanding_count");
        let async_last_started_metric_name = format!("{prefix}_async_task_last_started");
        let async_last_finished_metric_name = format!("{prefix}_async_task_last_finished");
        for (task_name, metrics) in &self.async_metrics {
            metrics.instruction.encode(
                task_name,
                encoder.histogram_vec(
                    &instruction_histogram_metric_name,
                    "The number of instructions used by a task. Note that the instructions \
                    of an async task are counted across multiple messages",
                )?,
            )?;
            encoder
                .counter_vec(
                    &async_outstanding_counter_metric_name,
                    "The number of async tasks that have been started but not finished",
                )?
                .value(
                    &[("task_name", task_name)],
                    metrics.outstanding_count as f64,
                )?;
            encoder
                .gauge_vec(
                    &async_last_started_metric_name,
                    "The time when the task was last started",
                )?
                .value(&[("task_name", task_name)], metrics.last_started as f64)?;
            encoder
                .gauge_vec(
                    &async_last_finished_metric_name,
                    "The time when the task was last finished",
                )?
                .value(&[("task_name", task_name)], metrics.last_finished as f64)?;
        }
        Ok(())
    }
}
