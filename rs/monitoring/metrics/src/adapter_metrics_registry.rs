use crate::buckets::{add_bucket, decimal_buckets};
use futures::future::join_all;
use futures::future::FutureExt;
use ic_adapter_metrics_client::AdapterMetrics;
use prometheus::{proto::MetricFamily, Error, HistogramOpts, HistogramVec, Registry};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

/// Registry for remote process adapters.
#[derive(Clone, Debug)]
pub struct AdapterMetricsRegistry {
    adapters: Arc<RwLock<Vec<AdapterMetrics>>>,
    metrics: AdapterMetricsScrapeMetrics,
}

#[derive(Clone, Debug)]
struct AdapterMetricsScrapeMetrics {
    /// Records per-adapter metric scrape attempt outcome.
    scrape_duration: HistogramVec,
}

impl AdapterMetricsScrapeMetrics {
    pub fn new(metrics_registry: &Registry) -> Self {
        let scrape_duration = HistogramVec::new(
            HistogramOpts::new(
                "adapter_metrics_scrape_duration_seconds",
                "Status of adapter metric scrapes with time buckets (s)",
            )
            // 0.001s, 0.002s, 0.005s, 0.01s, 0.02s, 0.05s, 0.1s, 0.2s, 0.5s, 10s
            .buckets(add_bucket(10.0, decimal_buckets(-3, -1))),
            &["adapter", "status_code"],
        )
        .unwrap();

        metrics_registry
            .register(Box::new(scrape_duration.clone()))
            .ok();
        Self { scrape_duration }
    }
}

impl AdapterMetricsRegistry {
    /// Create empty adapter registry.
    pub fn new(metrics_registry: &Registry) -> Self {
        Self {
            adapters: Arc::new(RwLock::new(Vec::new())),
            metrics: AdapterMetricsScrapeMetrics::new(metrics_registry),
        }
    }

    /// Add `AdapterMetrics` to the adapter registry. This function blocks,
    /// because of blocking read/write lock accesses to the adapter registry.
    /// Write accesses to here can not be starved by `gather()` calls, due to
    /// the write-preffering behaviour of the used `tokio::sync::RwLock`.
    pub fn register(&self, adapter_metrics: AdapterMetrics) -> Result<(), Error> {
        if self
            .adapters
            .blocking_read()
            .iter()
            .any(|a| a.get_name() == adapter_metrics.get_name())
        {
            return Err(Error::AlreadyReg);
        }
        self.adapters.blocking_write().push(adapter_metrics);
        Ok(())
    }

    /// Concurrently scrapes metrics from all registered adapters.
    pub async fn gather(&self, timeout: Duration) -> Vec<MetricFamily> {
        join_all(
            self.adapters
                .read()
                .await
                .iter()
                .map(|a| {
                    let scrape_duration = self.metrics.scrape_duration.clone();
                    let adapter_name = a.get_name().to_owned();
                    let now = std::time::Instant::now();
                    a.scrape(timeout).then(move |adapter_metrics| async move {
                        match adapter_metrics {
                            Ok(m) => {
                                scrape_duration
                                    .with_label_values(&[&adapter_name, "success"])
                                    .observe(now.elapsed().as_secs_f64());
                                m
                            }
                            Err(err) => {
                                // Avoid panic if we can't get metric.
                                scrape_duration
                                    .with_label_values(&[&adapter_name, &err.code().to_string()])
                                    .observe(now.elapsed().as_secs_f64());
                                Vec::new()
                            }
                        }
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .flatten()
        .collect()
    }
}
