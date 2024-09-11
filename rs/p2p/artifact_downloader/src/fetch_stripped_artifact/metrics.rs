use ic_metrics::MetricsRegistry;

#[derive(Clone)]
pub(super) struct FetchStrippedConsensusArtifactMetrics {}

impl FetchStrippedConsensusArtifactMetrics {
    pub(crate) fn new(_metrics_registry: &MetricsRegistry) -> Self {
        Self {}
    }
}
