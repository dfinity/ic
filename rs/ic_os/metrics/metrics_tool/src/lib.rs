// TODO: refactor/merge this with fstrim_tool and guestos_tool metrics functionality
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

// TODO: everything is floating point for now
pub struct Metric {
    name: String,
    value: f64,
    annotation: String,
    labels: Vec<(String, String)>,
}

impl Metric {
    pub fn new(name: &str, value: f64) -> Self {
        Self {
            name: name.to_string(),
            value,
            annotation: "Custom metric".to_string(),
            labels: Vec::new(),
        }
    }
    pub fn with_annotation(name: &str, value: f64, annotation: &str) -> Self {
        Self {
            name: name.to_string(),
            value,
            annotation: annotation.to_string(),
            labels: Vec::new(),
        }
    }

    pub fn add_annotation(mut self, annotation: &str) -> Self {
        self.annotation = annotation.to_string();
        self
    }

    pub fn add_label(mut self, key: &str, value: &str) -> Self {
        self.labels.push((key.to_string(), value.to_string()));
        self
    }

    // TODO: formatting of floats
    // Convert to prometheus exposition format
    pub fn to_prom_string(&self) -> String {
        let labels_str = if self.labels.is_empty() {
            String::new()
        } else {
            let labels: Vec<String> = self
                .labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{v}\""))
                .collect();
            format!("{{{}}}", labels.join(","))
        };
        format!(
            "# HELP {} {}\n\
             # TYPE {} counter\n\
             {}{} {}",
            self.name, self.annotation, self.name, self.name, labels_str, self.value
        )
    }
}

pub struct MetricsWriter {
    file_path: PathBuf,
}

impl MetricsWriter {
    pub fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    pub fn write_metrics(&self, metrics: &[Metric]) -> io::Result<()> {
        let mut file = File::create(&self.file_path)?;
        for metric in metrics {
            writeln!(file, "{}", metric.to_prom_string())?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_to_string() {
        let metric = Metric::new("test_metric", 123.45)
            .add_label("label1", "value1")
            .add_label("label2", "value2");
        assert_eq!(
            metric.to_prom_string(),
            "# HELP test_metric Custom metric\n\
             # TYPE test_metric counter\n\
             test_metric{label1=\"value1\",label2=\"value2\"} 123.45"
        );
    }

    #[test]
    fn test_write_metrics() {
        let metrics = vec![
            Metric::new("metric1", 1.0),
            Metric::new("metric2", 2.0).add_label("label", "value"),
        ];
        let writer = MetricsWriter::new("/tmp/test_metrics.prom".into());
        writer.write_metrics(&metrics).unwrap();
        let content = std::fs::read_to_string("/tmp/test_metrics.prom").unwrap();
        assert!(content.contains(
            "# HELP metric1 Custom metric\n\
             # TYPE metric1 counter\n\
             metric1 1"
        ));
        assert!(content.contains(
            "# HELP metric2 Custom metric\n\
             # TYPE metric2 counter\n\
             metric2{label=\"value\"} 2"
        ));
    }

    #[test]
    fn test_metric_large_value() {
        let metric = Metric::new("large_value_metric", 1.0e64);
        assert_eq!(
            metric.to_prom_string(),
            "# HELP large_value_metric Custom metric\n\
             # TYPE large_value_metric counter\n\
             large_value_metric 10000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_metric_without_labels() {
        let metric = Metric::new("no_label_metric", 42.0);
        assert_eq!(
            metric.to_prom_string(),
            "# HELP no_label_metric Custom metric\n\
             # TYPE no_label_metric counter\n\
             no_label_metric 42"
        );
    }

    #[test]
    fn test_metric_with_annotation() {
        let metric = Metric::with_annotation("annotated_metric", 99.9, "This is a test metric");
        assert_eq!(
            metric.to_prom_string(),
            "# HELP annotated_metric This is a test metric\n\
             # TYPE annotated_metric counter\n\
             annotated_metric 99.9"
        );
    }

    #[test]
    fn test_write_empty_metrics() {
        let metrics: Vec<Metric> = Vec::new();
        let writer = MetricsWriter::new("/tmp/test_empty_metrics.prom".into());
        writer.write_metrics(&metrics).unwrap();
        let content = std::fs::read_to_string("/tmp/test_empty_metrics.prom").unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_metric_with_multiple_labels() {
        let metric = Metric::new("multi_label_metric", 10.0)
            .add_label("foo", "bar")
            .add_label("version", "1.0.0");
        assert_eq!(
            metric.to_prom_string(),
            "# HELP multi_label_metric Custom metric\n\
             # TYPE multi_label_metric counter\n\
             multi_label_metric{foo=\"bar\",version=\"1.0.0\"} 10"
        );
    }

    #[test]
    fn test_metric_with_empty_annotation() {
        let metric = Metric::with_annotation("empty_annotation_metric", 5.5, "");
        assert_eq!(
            metric.to_prom_string(),
            "# HELP empty_annotation_metric \n\
             # TYPE empty_annotation_metric counter\n\
             empty_annotation_metric 5.5"
        );
    }
}
