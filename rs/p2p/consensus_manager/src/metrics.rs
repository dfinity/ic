use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::artifact::ArtifactKind;
use prometheus::{histogram_opts, labels, opts, Histogram, IntCounter, IntCounterVec, IntGauge};

use crate::uri_prefix;

pub(crate) const PEER_LABEL: &str = "peer_id";
pub(crate) const DOWNLOAD_TASK_RESULT_LABEL: &str = "result";
pub(crate) const DOWNLOAD_TASK_RESULT_COMPLETED: &str = "completed";
pub(crate) const DOWNLOAD_TASK_RESULT_DROP: &str = "drop";
pub(crate) const DOWNLOAD_TASK_RESULT_ALL_PEERS_DELETED: &str = "all_peers_removed";

#[derive(Clone)]
pub(crate) struct ConsensusManagerMetrics {
    // Download management
    pub download_task_started_total: IntCounter,
    pub download_task_finished_total: IntCounter,
    pub download_task_duration: Histogram,
    pub download_task_result_total: IntCounterVec,
    pub download_task_stashed_total: IntCounter,
    pub download_task_artifact_download_duration: Histogram,
    pub download_task_restart_after_join_total: IntCounter,
    pub download_task_artifact_download_errors_total: IntCounter,

    // Slot table
    pub slot_table_updates_total: IntCounter,
    pub slot_table_updates_with_artifact_total: IntCounter,
    pub slot_table_overwrite_total: IntCounter,
    pub slot_table_stale_total: IntCounter,
    pub slot_table_new_entry_total: IntCounterVec,
    pub slot_table_seen_id_total: IntCounter,
    pub slot_table_removals_total: IntCounter,

    // Topology update
    pub topology_updates_total: IntCounter,

    // Send view
    pub send_view_consensus_new_adverts_total: IntCounter,
    pub send_view_consensus_dup_adverts_total: IntCounter,
    pub send_view_consensus_purge_active_total: IntCounter,
    pub send_view_consensus_dup_purge_total: IntCounter,
    pub send_view_send_to_peer_total: IntCounter,
    pub send_view_send_to_peer_delivered_total: IntCounter,
    pub send_view_send_to_peer_cancelled_total: IntCounter,
    pub send_view_resend_reconnect_total: IntCounter,

    // Available slot set
    pub slot_set_in_use_slots: IntGauge,
    pub slot_set_allocated_slots_total: IntCounter,
}

impl ConsensusManagerMetrics {
    pub fn new<Artifact: ArtifactKind>(metrics_registry: &MetricsRegistry) -> Self {
        let prefix = uri_prefix::<Artifact>();
        let const_labels_string = labels! {"client".to_string() => prefix.clone()};
        let const_labels = labels! {"client" => prefix.as_str()};
        Self {
            download_task_started_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_download_task_started_total",
                    "Artifact download tasks started.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            download_task_finished_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_download_task_finished_total",
                    "Artifact download tasks finished.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            download_task_duration: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_consensus_manager_download_task_duration",
                    "Duration for which the download task was alive. This includes downloading and waiting for close.",
                    decimal_buckets(0, 2),
                    const_labels_string.clone(),
                ))
                .unwrap(),
            ),
            download_task_result_total: metrics_registry.register(
                IntCounterVec::new(
                    opts!(
                        "ic_consensus_manager_download_task_result_total",
                        "Download task result.",
                        const_labels.clone(),
                    ),
                    &[DOWNLOAD_TASK_RESULT_LABEL],
                )
                .unwrap(),
            ),
            download_task_stashed_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_download_task_stashed_total",
                    "Adverts stashed at least once.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            download_task_artifact_download_duration: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_consensus_manager_download_task_artifact_download_duration",
                    "Download time for artifact.",
                    decimal_buckets(-2, 1),
                    const_labels_string.clone(),
                ))
                .unwrap(),
            ),
            download_task_restart_after_join_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_download_task_restart_after_join_total",
                    "Download task immediately restarted due to advert appearing when closing.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            download_task_artifact_download_errors_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_download_task_artifact_download_errors_total",
                    "Error occurred when downloading artifact.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),

            slot_table_updates_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_updates_total",
                    "Slot table updates.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_table_updates_with_artifact_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_updates_with_artifact_total",
                    "Slot table updates that contained artifact itself.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_table_overwrite_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_overwrite_total",
                    "Existing slot updated.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_table_stale_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_stale_total",
                    "Slot not updated because it referred to an older version.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_table_new_entry_total: metrics_registry.register(
                IntCounterVec::new(
                    opts!(
                        "ic_consensus_manager_slot_table_new_entry_total",
                        "Slot updates for new slot.",
                        const_labels.clone(),
                    ),
                    &[PEER_LABEL],
                )
                .unwrap(),
            ),
            slot_table_seen_id_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_seen_id_total",
                    "Added peer to existing download.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_table_removals_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_table_removals_total",
                    "Peer removed from active download task.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),

            topology_updates_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_topology_updates_total",
                    "Slot table pruning due to topology update.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),

            send_view_consensus_new_adverts_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_consensus_new_adverts_total",
                    "New adverts received from consensus.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_consensus_dup_adverts_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_consnsus_dup_adverts_total",
                    "Adverts received from consensus that are already in the send view.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_consensus_purge_active_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_consensus_purge_active_total",
                    "Purges to currently active downloads.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_consensus_dup_purge_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_consensus_dup_purge_total",
                    "Purges for adverts with no existing download task.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_send_to_peer_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_send_to_peer_total",
                    "Slot updates sent to peers.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_send_to_peer_delivered_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_send_to_peer_delivered_total",
                    "Slot updates delivered to peers.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_send_to_peer_cancelled_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_send_to_peer_cancelled_total",
                    "Cancelled slot updates to peers.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            send_view_resend_reconnect_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_send_view_resend_reconnect_total",
                    "Artifact was sent again due to reconnection.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),

            slot_set_in_use_slots: metrics_registry.register(
                IntGauge::with_opts(opts!(
                    "ic_consensus_manager_slot_set_in_use_slots",
                    "Active slots in use.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            slot_set_allocated_slots_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_consensus_manager_slot_set_allocated_slots_total",
                    "Maximum of slots simultaneously used.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
        }
    }
}
