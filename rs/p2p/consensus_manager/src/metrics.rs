use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use ic_types::artifact::ArtifactKind;
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGauge};

#[derive(Clone)]

pub(crate) struct ConsensusManagerMetrics {
    pub active_downloads: IntGauge,
    /// free slots in the slot table of the send side.
    pub free_slots: IntGauge,

    // Slots in use per peer on receive side.
    pub slots_in_use_per_peer: IntCounterVec,

    /// The capacity of the slot table on the send side.
    pub maximum_slots_total: IntCounter,

    /// Number of adverts sent to peers from this node.
    pub adverts_to_send_total: IntCounter,

    pub adverts_to_purge_total: IntCounter,

    pub artifacts_pushed_total: IntCounter,

    /// Number of adverts received from peers.
    pub adverts_received_total: IntCounter,

    /// Number of adverts received from after joining the task and already deleted the advert.
    pub peer_advertising_after_deletion_total: IntCounter,

    /// Number of adverts that were stashed at least once.
    pub adverts_stashed_total: IntCounter,

    /// Download attempts for an advert
    pub advert_download_attempts: Histogram,

    /// Dropped adverts
    pub adverts_dropped_total: IntCounter,

    /// Active advert being sent to peers.
    pub active_advert_transmits: IntGauge,

    pub receive_new_adverts_total: IntCounter,

    pub receive_seen_adverts_total: IntCounter,

    pub receive_slot_table_removals_total: IntCounter,

    pub active_download_removals_total: IntCounter,

    pub receive_used_slot_to_overwrite_total: IntCounter,

    pub receive_used_slot_stale_total: IntCounter,
}

impl ConsensusManagerMetrics {
    pub fn new<Artifact: ArtifactKind>(metrics_registry: &MetricsRegistry) -> Self {
        let prefix = Artifact::TAG.to_string().to_lowercase();
        Self {
            active_downloads: metrics_registry.int_gauge(
                format!("{prefix}_manager_active_downloads").as_str(),
                "TODO.",
            ),
            free_slots: metrics_registry
                .int_gauge(format!("{prefix}_manager_free_slots").as_str(), "TODO."),
            maximum_slots_total: metrics_registry.int_counter(
                format!("{prefix}_manager_maximum_slots_total").as_str(),
                "TODO.",
            ),
            slots_in_use_per_peer: metrics_registry.int_counter_vec(
                format!("{prefix}_manager_slots_in_use_per_peer").as_str(),
                "TODO",
                &["peer_id"],
            ),
            adverts_to_send_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_to_send_total").as_str(),
                "TODO.",
            ),
            adverts_to_purge_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_to_purge_total").as_str(),
                "TODO.",
            ),
            artifacts_pushed_total: metrics_registry.int_counter(
                format!("{prefix}_manager_artifacts_pushed_total").as_str(),
                "TODO.",
            ),
            adverts_received_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_received_total").as_str(),
                "TODO.",
            ),
            peer_advertising_after_deletion_total: metrics_registry.int_counter(
                format!("{prefix}_manager_peer_advertising_after_deletion_total").as_str(),
                "TODO.",
            ),
            adverts_stashed_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_stashed_total").as_str(),
                "TODO.",
            ),
            advert_download_attempts: metrics_registry.histogram(
                format!("{prefix}_manager_advert_download_attempts").as_str(),
                "TODO.",
                decimal_buckets_with_zero(0, 1),
            ),
            active_advert_transmits: metrics_registry.int_gauge(
                format!("{prefix}_manager_active_advert_transmits").as_str(),
                "TODO.",
            ),
            adverts_dropped_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_dropped_total").as_str(),
                "TODO.",
            ),
            receive_new_adverts_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_new_adverts_total").as_str(),
                "TODO.",
            ),
            receive_seen_adverts_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_seen_adverts_total").as_str(),
                "TODO.",
            ),
            receive_slot_table_removals_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_slot_table_removals_total").as_str(),
                "TODO.",
            ),
            active_download_removals_total: metrics_registry.int_counter(
                format!("{prefix}_manager_active_download_removals_total").as_str(),
                "TODO.",
            ),
            receive_used_slot_to_overwrite_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_used_slot_to_overwrite_total").as_str(),
                "TODO.",
            ),
            receive_used_slot_stale_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_used_slot_stale_total").as_str(),
                "TODO.",
            ),
        }
    }
}
