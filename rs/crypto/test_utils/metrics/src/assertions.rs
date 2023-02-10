//! Fluent assertions for log entries.

use ic_crypto_internal_logmon::metrics::MetricsResult;
use ic_metrics::MetricsRegistry;
use prometheus::proto::{Metric, MetricType};
use std::collections::HashSet;

pub struct MetricsObservationsAssert {
    metrics_registry: MetricsRegistry,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct MetricsLabel {
    name: String,
    value: String,
}

impl MetricsObservationsAssert {
    pub fn assert_that(metrics_registry: MetricsRegistry) -> Self {
        Self { metrics_registry }
    }

    pub fn contains_crypto_idkg_dealing_encryption_pubkey_count(
        &self,
        idkg_dealing_encryption_public_key_count: u8,
        result: MetricsResult,
    ) -> &Self {
        assert!(self.contains_crypto_gauge_metric(
            "crypto_idkg_dealing_encryption_pubkey_count",
            &vec![MetricsLabel {
                name: "result".to_string(),
                value: format!("{}", result),
            }],
            idkg_dealing_encryption_public_key_count as f64,
        ));
        self
    }

    pub fn contains_crypto_key_counts(
        &self,
        registry_public_key_count: u8,
        local_public_key_count: u8,
        secret_key_count: u8,
        result: MetricsResult,
    ) -> &Self {
        assert!(
            self.contains_crypto_gauge_metric(
                "crypto_key_counts",
                &vec![
                    MetricsLabel {
                        name: "key_type".to_string(),
                        value: "public_registry".to_string(),
                    },
                    MetricsLabel {
                        name: "result".to_string(),
                        value: format!("{}", result),
                    },
                ],
                registry_public_key_count as f64,
            ) && self.contains_crypto_gauge_metric(
                "crypto_key_counts",
                &vec![
                    MetricsLabel {
                        name: "key_type".to_string(),
                        value: "public_local".to_string(),
                    },
                    MetricsLabel {
                        name: "result".to_string(),
                        value: format!("{}", result),
                    },
                ],
                local_public_key_count as f64,
            ) && self.contains_crypto_gauge_metric(
                "crypto_key_counts",
                &vec![
                    MetricsLabel {
                        name: "key_type".to_string(),
                        value: "secret_sks".to_string(),
                    },
                    MetricsLabel {
                        name: "result".to_string(),
                        value: format!("{}", result),
                    },
                ],
                secret_key_count as f64,
            )
        );
        self
    }

    pub fn contains_keys_missing_locally_alert_metrics(&self, result: bool) -> &Self {
        assert_eq!(
            self.contains_crypto_boolean_counter_metric(
                "crypto_boolean_results",
                &vec![
                    MetricsLabel {
                        name: "operation".to_string(),
                        value: "key_in_registry_missing_locally".to_string(),
                    },
                    MetricsLabel {
                        name: "result".to_string(),
                        value: "true".to_string(),
                    },
                ],
            ),
            result
        );
        self
    }

    pub fn contains_latest_key_exists_in_registry(&self, result: bool) -> &Self {
        assert!(self.contains_crypto_boolean_counter_metric(
            "crypto_boolean_results",
            &vec![
                MetricsLabel {
                    name: "operation".to_string(),
                    value: "latest_local_idkg_key_exists_in_registry".to_string(),
                },
                MetricsLabel {
                    name: "result".to_string(),
                    value: format!("{}", result),
                },
            ],
        ));
        self
    }

    fn contains_crypto_boolean_counter_metric(
        &self,
        metric_name: &str,
        metric_labels: &Vec<MetricsLabel>,
    ) -> bool {
        let metric = self.get_metric(metric_name, MetricType::COUNTER, metric_labels);
        match metric {
            None => false,
            Some(found_metric) => {
                assert!(found_metric.has_counter());
                if found_metric.get_counter().get_value() > 0f64 {
                    true
                } else {
                    println!(
                        "Expected boolean counter value ge 0, found {}",
                        found_metric.get_counter().get_value()
                    );
                    false
                }
            }
        }
    }

    fn contains_crypto_gauge_metric(
        &self,
        metric_name: &str,
        metric_labels: &Vec<MetricsLabel>,
        metric_value: f64,
    ) -> bool {
        let metric = self.get_metric(metric_name, MetricType::GAUGE, metric_labels);
        match metric {
            None => false,
            Some(found_metric) => {
                if !found_metric.has_gauge() {
                    return false;
                }
                if found_metric.get_gauge().get_value() == metric_value {
                    true
                } else {
                    println!(
                        "Expected gauge value {}, found {}",
                        metric_value,
                        found_metric.get_gauge().get_value()
                    );
                    false
                }
            }
        }
    }

    fn get_metric(
        &self,
        metric_name: &str,
        metric_type: MetricType,
        metric_labels: &Vec<MetricsLabel>,
    ) -> Option<Metric> {
        let metric_families = self.metrics_registry.prometheus_registry().gather();
        for metric_family in metric_families {
            if metric_family.get_name() == metric_name {
                if metric_family.get_field_type() != metric_type {
                    continue;
                }
                let metrics = metric_family.get_metric();
                for metric in metrics {
                    if contains_metrics_value(metric, metric_labels) {
                        return Some(metric.clone());
                    }
                }
                println!("No value found for labels: {:?}", metric_labels);
                return None;
            }
        }
        println!("No gauge metric found for labels: {:?}", metric_labels);
        None
    }
}

fn contains_metrics_value(metric: &Metric, labels: &Vec<MetricsLabel>) -> bool {
    let mut found = HashSet::new();
    for metric_label in metric.get_label() {
        if metric_label.has_name() && metric_label.has_value() {
            for label in labels {
                if metric_label.get_name() == label.name && metric_label.get_value() == label.value
                {
                    found.insert(label);
                }
            }
        }
    }
    found.len() == labels.len()
}
