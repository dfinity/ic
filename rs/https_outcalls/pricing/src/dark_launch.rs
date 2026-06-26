use ic_logger::{ReplicaLogger, warn};
use ic_types::{CanisterId, NumBytes, NumInstructions, canister_http::CanisterHttpPaymentReceipt};

use crate::{AdapterLimits, BudgetTracker, NetworkUsage, PricingError, metrics::PricingMetrics};

/// A [`BudgetTracker`] that runs two child trackers side by side: a `real`
/// tracker whose results are the only ones returned (and therefore the only
/// ones that affect observable behaviour), and a `shadow` tracker whose results
/// are merely compared against the real one.
///
/// Whenever the shadow tracker disagrees with the real tracker (e.g. it returns
/// a pricing error where the real tracker succeeded), the divergence is counted
/// in a metric.
pub struct DarkLaunchTracker {
    real: Box<dyn BudgetTracker>,
    shadow: Box<dyn BudgetTracker>,
    canister_id: CanisterId,
    non_replicated: bool,
    metrics: PricingMetrics,
    log: ReplicaLogger,
    /// Whether an incompatibility has already been recorded for this request.
    /// Ensures we count and log at most once per request.
    reported: bool,
}

impl DarkLaunchTracker {
    pub fn new(
        real: Box<dyn BudgetTracker>,
        shadow: Box<dyn BudgetTracker>,
        canister_id: CanisterId,
        non_replicated: bool,
        metrics: PricingMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            real,
            shadow,
            canister_id,
            non_replicated,
            metrics,
            log,
            reported: false,
        }
    }

    /// Compares the results of the real and shadow trackers for a given
    /// accounting `step` and records a divergence if they disagree.
    fn compare(
        &mut self,
        step: &str,
        real: &Result<(), PricingError>,
        shadow: &Result<(), PricingError>,
    ) {
        if real.is_ok() == shadow.is_ok() {
            return;
        }
        if self.reported {
            return;
        }
        self.reported = true;
        self.metrics
            .shadow_incompatible_total
            .with_label_values(&[step, &self.non_replicated.to_string()])
            .inc();
        warn!(
            self.log,
            "Canister http request would not be compatible under shadow pricing: \
             canister_id {}, step {}, non_replicated {}, real_result {:?}, shadow_result {:?}",
            self.canister_id,
            step,
            self.non_replicated,
            real,
            shadow,
        );
    }
}

impl BudgetTracker for DarkLaunchTracker {
    fn get_adapter_limits(&self) -> AdapterLimits {
        self.real.get_adapter_limits()
    }

    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError> {
        let real = self.real.subtract_network_usage(network_usage);
        let shadow = self.shadow.subtract_network_usage(network_usage);
        self.compare("network_usage", &real, &shadow);
        real
    }

    fn get_transform_limit(&self) -> NumInstructions {
        self.real.get_transform_limit()
    }

    fn subtract_transform_usage(&mut self, usage: NumInstructions) -> Result<(), PricingError> {
        let real = self.real.subtract_transform_usage(usage);
        let shadow = self.shadow.subtract_transform_usage(usage);
        self.compare("transform_usage", &real, &shadow);
        real
    }

    fn subtract_gossip_usage(
        &mut self,
        transformed_response_size: NumBytes,
    ) -> Result<(), PricingError> {
        let real = self.real.subtract_gossip_usage(transformed_response_size);
        let shadow = self.shadow.subtract_gossip_usage(transformed_response_size);
        self.compare("gossip_usage", &real, &shadow);
        real
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        // Count every request that reaches the final accounting step so the
        // incompatible counter can be expressed as a fraction of the total.
        self.metrics.shadow_requests_total.inc();
        self.real.create_payment_receipt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use std::time::Duration;

    /// A [`BudgetTracker`] whose accounting steps return preconfigured results.
    struct FakeTracker {
        network: Result<(), PricingError>,
        transform: Result<(), PricingError>,
        transformed: Result<(), PricingError>,
    }

    impl FakeTracker {
        fn ok() -> Self {
            Self {
                network: Ok(()),
                transform: Ok(()),
                transformed: Ok(()),
            }
        }
    }

    impl BudgetTracker for FakeTracker {
        fn get_adapter_limits(&self) -> AdapterLimits {
            AdapterLimits {
                max_response_size: NumBytes::from(0),
                max_response_time: Duration::ZERO,
            }
        }
        fn subtract_network_usage(&mut self, _: NetworkUsage) -> Result<(), PricingError> {
            self.network
        }
        fn get_transform_limit(&self) -> NumInstructions {
            NumInstructions::from(0)
        }
        fn subtract_transform_usage(&mut self, _: NumInstructions) -> Result<(), PricingError> {
            self.transform
        }
        fn subtract_gossip_usage(&mut self, _: NumBytes) -> Result<(), PricingError> {
            self.transformed
        }
        fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
            CanisterHttpPaymentReceipt::default()
        }
    }

    fn dark_launch(
        real: FakeTracker,
        shadow: FakeTracker,
        non_replicated: bool,
        metrics: PricingMetrics,
    ) -> DarkLaunchTracker {
        DarkLaunchTracker::new(
            Box::new(real),
            Box::new(shadow),
            CanisterId::from_u64(7),
            non_replicated,
            metrics,
            no_op_logger(),
        )
    }

    fn network_usage() -> NetworkUsage {
        NetworkUsage {
            response_size: NumBytes::from(0),
            response_time: Duration::ZERO,
        }
    }

    fn incompatible_count(metrics: &PricingMetrics) -> u64 {
        let mut total = 0;
        for step in ["network_usage", "transform_usage", "gossip_usage"] {
            for non_replicated in ["true", "false"] {
                total += metrics
                    .shadow_incompatible_total
                    .with_label_values(&[step, non_replicated])
                    .get();
            }
        }
        total
    }

    #[test]
    fn returns_real_result_and_counts_divergence() {
        let metrics = PricingMetrics::new(&MetricsRegistry::new());
        let shadow = FakeTracker {
            network: Err(PricingError::InsufficientCycles),
            ..FakeTracker::ok()
        };
        let mut tracker = dark_launch(FakeTracker::ok(), shadow, false, metrics.clone());

        // The real (always-Ok) result is returned even though the shadow fails.
        assert_eq!(tracker.subtract_network_usage(network_usage()), Ok(()));
        assert_eq!(
            metrics
                .shadow_incompatible_total
                .with_label_values(&["network_usage", "false"])
                .get(),
            1
        );

        let _ = tracker.create_payment_receipt();
        assert_eq!(metrics.shadow_requests_total.get(), 1);
    }

    #[test]
    fn counts_divergence_at_most_once_per_request() {
        let metrics = PricingMetrics::new(&MetricsRegistry::new());
        let shadow = FakeTracker {
            network: Err(PricingError::InsufficientCycles),
            transform: Err(PricingError::InsufficientCycles),
            transformed: Err(PricingError::InsufficientCycles),
        };
        let mut tracker = dark_launch(FakeTracker::ok(), shadow, false, metrics.clone());

        assert_eq!(tracker.subtract_network_usage(network_usage()), Ok(()));
        assert_eq!(
            tracker.subtract_transform_usage(NumInstructions::from(0)),
            Ok(())
        );
        assert_eq!(tracker.subtract_gossip_usage(NumBytes::from(0)), Ok(()));

        // Only the first divergence is recorded for the request.
        assert_eq!(incompatible_count(&metrics), 1);
    }

    #[test]
    fn no_divergence_when_results_agree() {
        let metrics = PricingMetrics::new(&MetricsRegistry::new());
        let mut tracker = dark_launch(FakeTracker::ok(), FakeTracker::ok(), false, metrics.clone());

        assert_eq!(tracker.subtract_network_usage(network_usage()), Ok(()));
        assert_eq!(
            tracker.subtract_transform_usage(NumInstructions::from(0)),
            Ok(())
        );
        let _ = tracker.create_payment_receipt();

        assert_eq!(incompatible_count(&metrics), 0);
        assert_eq!(metrics.shadow_requests_total.get(), 1);
    }

    #[test]
    fn labels_divergence_by_replication_type() {
        let metrics = PricingMetrics::new(&MetricsRegistry::new());
        let shadow = FakeTracker {
            network: Err(PricingError::InsufficientCycles),
            ..FakeTracker::ok()
        };
        let mut tracker = dark_launch(FakeTracker::ok(), shadow, true, metrics.clone());

        assert_eq!(tracker.subtract_network_usage(network_usage()), Ok(()));

        // The divergence is attributed to the non-replicated label.
        assert_eq!(
            metrics
                .shadow_incompatible_total
                .with_label_values(&["network_usage", "true"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .shadow_incompatible_total
                .with_label_values(&["network_usage", "false"])
                .get(),
            0
        );
    }
}
