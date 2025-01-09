//! Fluent assertions for metrics.

use regex::Regex;

pub struct MetricsAssert<T> {
    actual: T,
    metrics: Vec<String>,
}

pub trait QueryMetrics {
    fn query_metrics(&self) -> Vec<String>;
}

impl From<Vec<String>> for MetricsAssert<()> {
    fn from(metrics: Vec<String>) -> Self {
        Self {
            actual: (),
            metrics,
        }
    }
}

impl<T: QueryMetrics> From<T> for MetricsAssert<T> {
    fn from(actual: T) -> Self {
        let metrics = actual.query_metrics();
        Self { metrics, actual }
    }
}

impl<T> MetricsAssert<T> {
    pub fn actual(self) -> T {
        self.actual
    }

    pub fn assert_contains_metric_matching(self, pattern: &str) -> Self {
        assert!(
            !self.find_metrics_matching(pattern).is_empty(),
            "Expected to find metric matching '{}', but none matched in:\n{:?}",
            pattern,
            self.metrics
        );
        self
    }

    pub fn assert_does_not_contain_metric_matching(self, pattern: &str) -> Self {
        let matches = self.find_metrics_matching(pattern);
        assert!(
            matches.is_empty(),
            "Expected not to find any metric matching '{}', but found the following matches:\n{:?}",
            pattern,
            matches
        );
        self
    }

    fn find_metrics_matching(&self, pattern: &str) -> Vec<String> {
        let regex = Regex::new(pattern).unwrap_or_else(|_| panic!("Invalid regex: {}", pattern));
        self.metrics
            .iter()
            .filter(|line| regex.is_match(line))
            .cloned()
            .collect()
    }
}
