use std::sync::{Arc, Mutex};

use prometheus::{
    Gauge, IntCounter,
    core::{Collector, Desc, Opts},
    proto,
};
use tokio_metrics::TaskMonitor;

/// Wrapper around `tokio_metrics::TaskMonitor` that can be
/// registered with a prometheus metrics registry.
#[derive(Clone)]
pub struct TokioTaskMetricsCollector {
    task_monitor: Arc<Mutex<dyn Iterator<Item = tokio_metrics::TaskMetrics> + Send + Sync>>,

    dropped_count: IntCounter,
    instrumented_count: IntCounter,

    long_delay_ratio: Gauge,
    mean_idle_duration: Gauge,
    mean_poll_duration: Gauge,
    mean_scheduled_duration: Gauge,
    mean_slow_poll_duration: Gauge,
    slow_poll_ratio: Gauge,
}

impl TokioTaskMetricsCollector {
    /// Create a new tokio task metric collector.
    /// Returns the collector that needs to be registered with the
    /// prometheus registry and the `TaskMonitor` that is used to
    /// instrument tasks.
    pub fn new(namespace: &str) -> (Self, TaskMonitor) {
        let task_monitor = TaskMonitor::new();

        let dropped_count = IntCounter::with_opts(
            Opts::new(
                "tokio_task_dropped_count",
                r#"The number of tasks dropped."#,
            )
            .namespace(namespace),
        )
        .unwrap();
        let instrumented_count = IntCounter::with_opts(
            Opts::new(
                "tokio_task_instrumented_count",
                r#"The number of tasks instrumented."#,
            )
            .namespace(namespace),
        )
        .unwrap();

        let long_delay_ratio = Gauge::with_opts(
            Opts::new("tokio_task_long_delay_ratio", r#"The long delay ratio."#)
                .namespace(namespace),
        )
        .unwrap();
        let mean_idle_duration = Gauge::with_opts(
            Opts::new(
                "tokio_task_mean_idle_duration",
                r#"The mean idle duration."#,
            )
            .namespace(namespace),
        )
        .unwrap();
        let mean_poll_duration = Gauge::with_opts(
            Opts::new(
                "tokio_task_mean_poll_duration",
                r#"The mean poll duration."#,
            )
            .namespace(namespace),
        )
        .unwrap();
        let mean_scheduled_duration = Gauge::with_opts(
            Opts::new(
                "tokio_task_mean_scheduled_duration",
                r#"The mean scheduled duration."#,
            )
            .namespace(namespace),
        )
        .unwrap();
        let mean_slow_poll_duration = Gauge::with_opts(
            Opts::new(
                "tokio_task_mean_slow_poll_duration",
                r#"The mean poll duration for polls classified as slow."#,
            )
            .namespace(namespace),
        )
        .unwrap();
        let slow_poll_ratio = Gauge::with_opts(
            Opts::new("tokio_task_slow_poll_ratio", r#"The slow poll ratio."#).namespace(namespace),
        )
        .unwrap();

        (
            Self {
                task_monitor: Arc::new(Mutex::new(task_monitor.intervals())),

                dropped_count,
                instrumented_count,

                long_delay_ratio,
                mean_idle_duration,
                mean_poll_duration,
                mean_scheduled_duration,
                mean_slow_poll_duration,
                slow_poll_ratio,
            },
            task_monitor,
        )
    }

    fn update(&self) {
        let interval = match self.task_monitor.lock().unwrap().next() {
            Some(interval) => interval,
            None => return,
        };

        self.dropped_count.inc_by(interval.dropped_count);
        self.instrumented_count.inc_by(interval.instrumented_count);

        self.long_delay_ratio.set(interval.long_delay_ratio());
        self.mean_idle_duration
            .set(interval.mean_idle_duration().as_secs_f64());
        self.mean_poll_duration
            .set(interval.mean_poll_duration().as_secs_f64());
        self.mean_scheduled_duration
            .set(interval.mean_scheduled_duration().as_secs_f64());
        self.mean_slow_poll_duration
            .set(interval.mean_slow_poll_duration().as_secs_f64());
        self.slow_poll_ratio.set(interval.slow_poll_ratio());
    }

    fn to_desc(&self) -> Vec<&Desc> {
        let mut desc = vec![];
        desc.extend(self.dropped_count.desc());
        desc.extend(self.instrumented_count.desc());

        desc.extend(self.long_delay_ratio.desc());
        desc.extend(self.mean_idle_duration.desc());
        desc.extend(self.mean_poll_duration.desc());
        desc.extend(self.mean_scheduled_duration.desc());
        desc.extend(self.mean_slow_poll_duration.desc());
        desc.extend(self.slow_poll_ratio.desc());

        desc
    }

    fn to_metrics(&self) -> Vec<proto::MetricFamily> {
        let mut metrics = vec![];
        metrics.extend(self.dropped_count.collect());
        metrics.extend(self.instrumented_count.collect());

        metrics.extend(self.long_delay_ratio.collect());
        metrics.extend(self.mean_idle_duration.collect());
        metrics.extend(self.mean_poll_duration.collect());
        metrics.extend(self.mean_scheduled_duration.collect());
        metrics.extend(self.mean_slow_poll_duration.collect());
        metrics.extend(self.slow_poll_ratio.collect());
        metrics
    }
}

impl Collector for TokioTaskMetricsCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.to_desc()
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        self.update();
        self.to_metrics()
    }
}
