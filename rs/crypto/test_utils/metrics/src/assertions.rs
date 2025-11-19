//! Fluent assertions for log entries.

use ic_crypto_internal_logmon::metrics::MetricsResult;
use ic_metrics::MetricsRegistry;
use ic_test_utilities_metrics::{
    Labels, fetch_counter_vec, fetch_gauge, fetch_gauge_vec, fetch_int_counter, labels,
};

pub struct MetricsObservationsAssert {
    metrics_registry: MetricsRegistry,
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
        assert!(self.contains_crypto_gauge_vec_metric(
            "crypto_idkg_dealing_encryption_pubkey_count",
            labels(&[("result", format!("{result}"))]),
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
            self.contains_crypto_gauge_vec_metric(
                "crypto_key_counts",
                labels(&[
                    ("key_type", "public_registry"),
                    ("result", &format!("{result}"))
                ]),
                registry_public_key_count as f64,
            ) && self.contains_crypto_gauge_vec_metric(
                "crypto_key_counts",
                labels(&[
                    ("key_type", "public_local"),
                    ("result", &format!("{result}"))
                ]),
                local_public_key_count as f64,
            ) && self.contains_crypto_gauge_vec_metric(
                "crypto_key_counts",
                labels(&[("key_type", "secret_sks"), ("result", &format!("{result}"))]),
                secret_key_count as f64,
            )
        );
        self
    }

    pub fn contains_keys_missing_locally_alert_metrics(&self, value: u64) -> &Self {
        assert!(self.contains_crypto_counter_metric(
            "crypto_keys_in_registry_missing_locally_total",
            value,
        ));
        self
    }

    pub fn contains_latest_key_exists_in_registry(&self, result: bool) -> &Self {
        let labels = labels(&[
            ("operation", "latest_local_idkg_key_exists_in_registry"),
            ("result", &format!("{result}")),
        ]);
        assert!(self.contains_crypto_boolean_counter_metric("crypto_boolean_results", labels,));
        self
    }

    pub fn contains_key_too_old_but_not_in_registry(&self, value: u64) -> &Self {
        assert!(self.contains_crypto_counter_metric(
            "crypto_latest_idkg_dealing_encryption_public_key_too_old_but_not_in_registry",
            value,
        ));
        self
    }

    pub fn contains_crypto_secret_key_store_cleanup_error(&self, value: u64) -> &Self {
        assert!(
            self.contains_crypto_counter_metric("crypto_secret_key_store_cleanup_error", value)
        );
        self
    }

    pub fn contains_minimum_registry_version_in_active_idkg_transcripts(
        &self,
        value: u64,
    ) -> &Self {
        assert!(self.contains_crypto_gauge_metric(
            "crypto_minimum_registry_version_in_active_idkg_transcripts",
            value as f64
        ));
        self
    }

    fn contains_crypto_boolean_counter_metric(
        &self,
        metric_name: &str,
        metric_labels: Labels,
    ) -> bool {
        match fetch_counter_vec(&self.metrics_registry, metric_name).get(&metric_labels) {
            None => {
                println!(
                    "no boolean counter found with name {metric_name} and labels {metric_labels:?}"
                );
                false
            }
            Some(actual_value) => {
                if actual_value > &0f64 {
                    true
                } else {
                    println!("Expected boolean counter value ge 0, found {actual_value}");
                    false
                }
            }
        }
    }

    fn contains_crypto_counter_metric(&self, metric_name: &str, metric_value: u64) -> bool {
        match fetch_int_counter(&self.metrics_registry, metric_name) {
            None => {
                println!("no int counter found with name {metric_name}");
                false
            }
            Some(actual_counter) => {
                if actual_counter == metric_value {
                    true
                } else {
                    println!("Expected counter value {metric_value}, found {actual_counter}");
                    false
                }
            }
        }
    }

    fn contains_crypto_gauge_vec_metric(
        &self,
        metric_name: &str,
        metric_labels: Labels,
        metric_value: f64,
    ) -> bool {
        match fetch_gauge_vec(&self.metrics_registry, metric_name).get(&metric_labels) {
            None => {
                println!("no gauge found with name {metric_name} and labels {metric_labels:?}");
                false
            }
            Some(actual_value) => {
                if actual_value == &metric_value {
                    true
                } else {
                    println!("Expected gauge value {metric_value}, found {actual_value}");
                    false
                }
            }
        }
    }

    fn contains_crypto_gauge_metric(&self, metric_name: &str, metric_value: f64) -> bool {
        match fetch_gauge(&self.metrics_registry, metric_name) {
            None => {
                println!("no gauge found with name {metric_name}");
                false
            }
            Some(actual_value) => {
                if actual_value == metric_value {
                    true
                } else {
                    println!("Expected gauge value {metric_value}, found {actual_value}",);
                    false
                }
            }
        }
    }
}
