use anyhow::{Context, Error};
use itertools::join;
use std::fmt;
use std::fs;
use std::path::Path;
use std::vec::Vec;

/// Types and utils for writing prometheus metrics to textfile collector
/// Unused for now:
/// const DEFAULT_TEXTFILE_COLLECTOR_DIR: &str = "/run/node_exporter/collector_textfile/";

#[allow(dead_code)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
    Untyped,
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MetricType::*;
        let s = match self {
            Counter => "counter",
            Gauge => "gauge",
            Histogram => "histogram",
            Summary => "summary",
            Untyped => "untyped",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone)]
pub struct LabelPair {
    pub label: String,
    pub value: String,
}

impl fmt::Display for LabelPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=\"{}\"", self.label, self.value)
    }
}

/// Metric containing enough info to meet the textfile_collector format
/// https://prometheus.io/docs/instrumenting/exposition_formats/
pub struct PrometheusMetric {
    pub name: String,
    pub help: String,
    pub metric_type: MetricType,
    pub labels: Vec<LabelPair>,
    pub value: f32,
}

impl fmt::Display for PrometheusMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.labels.len() {
            0 => write!(
                f,
                "# HELP {} {}\n\
                         # TYPE {} {}\n\
                         {} {}\n",
                self.name, self.help, self.name, self.metric_type, self.name, self.value
            ),
            _ => {
                let labels_joined = format!("{{{}}}", join(&self.labels, ", "));
                write!(
                    f,
                    "# HELP {} {}\n\
                          # TYPE {} {}\n\
                          {}{} {}\n",
                    self.name,
                    self.help,
                    self.name,
                    self.metric_type,
                    self.name,
                    labels_joined,
                    self.value
                )
            }
        }
    }
}

pub fn write_single_metric(metric: &PrometheusMetric, output_path: &Path) -> Result<(), Error> {
    fs::write(output_path, metric.to_string())
        .with_context(|| format!("Error writing to path: {}\n", output_path.display()))
}

// TODO -- pub fn write_metrics(Vec<PrometheusMetric>, output_path: &Path) -> Result<()>

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_metric_formatting() {
        let metric_with_labels = PrometheusMetric {
            name: "foos_per_second".into(),
            help: "Foos Per Second".into(),
            metric_type: MetricType::Gauge,
            labels: [
                LabelPair {
                    label: "first_label".into(),
                    value: "first_value".into(),
                },
                LabelPair {
                    label: "second_label".into(),
                    value: "second_value".into(),
                },
            ]
            .to_vec(),
            value: 42.0,
        };

        assert_eq!(
            metric_with_labels.to_string(),
            "# HELP foos_per_second Foos Per Second\n\
             # TYPE foos_per_second gauge\n\
             foos_per_second{first_label=\"first_value\", second_label=\"second_value\"} 42\n"
        );

        let metric_one_label = PrometheusMetric {
            name: "foos_per_second".into(),
            help: "Foos Per Second".into(),
            metric_type: MetricType::Gauge,
            labels: [LabelPair {
                label: "bar".into(),
                value: "baz".into(),
            }]
            .to_vec(),
            value: 42.0,
        };

        assert_eq!(
            metric_one_label.to_string(),
            "# HELP foos_per_second Foos Per Second\n\
             # TYPE foos_per_second gauge\n\
             foos_per_second{bar=\"baz\"} 42\n"
        );

        let metric_no_labels = PrometheusMetric {
            name: "foos_per_second".into(),
            help: "Foos Per Second".into(),
            metric_type: MetricType::Gauge,
            labels: [].to_vec(),
            value: 42.0,
        };

        assert_eq!(
            metric_no_labels.to_string(),
            "# HELP foos_per_second Foos Per Second\n\
             # TYPE foos_per_second gauge\n\
             foos_per_second 42\n"
        )
    }
}
