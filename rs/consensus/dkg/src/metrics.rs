use ic_metrics::MetricsRegistry;

pub(crate) struct DkgPayloadBuilderMetrics {
    pub(crate) dkg_validator: IntCounterVec,
}

impl DkgPayloadBuilderMetrics {
    pub(crate) fn new(registry: &MetricsRegistry) -> Self {
        Self {
            dkg_validator: metrics_registry.int_counter_vec(
                "consensus_dkg_validator",
                "DKG validator counter",
                &["type"],
            ),
        }
    }
}
