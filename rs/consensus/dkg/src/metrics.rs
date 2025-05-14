use ic_metrics::MetricsRegistry;
use prometheus::IntCounterVec;

pub(crate) struct DkgPayloadBuilderMetrics {
    pub(crate) dkg_validator: IntCounterVec,
}

impl DkgPayloadBuilderMetrics {
    pub(crate) fn new(registry: &MetricsRegistry) -> Self {
        Self {
            dkg_validator: registry.int_counter_vec(
                // TODO: Remove the _new end before merging
                "consensus_dkg_validator_new",
                "DKG validator counter",
                &["type"],
            ),
        }
    }
}
