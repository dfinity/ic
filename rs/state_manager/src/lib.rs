// Needs to be `pub` so that the benchmarking code in `state_benches`
// can access it.
pub mod checkpoint;
pub mod labeled_tree_visitor;
pub mod manifest;
pub mod split;
pub mod state_sync;
pub mod stream_encoding;
pub mod tip;
pub mod tree_diff;
pub mod tree_hash;

use crate::{
    manifest::compute_bundled_manifest,
    state_sync::{
        chunkable::cache::StateSyncCache,
        types::{FileGroupChunks, Manifest, MetaManifest},
    },
    tip::{spawn_tip_thread, HasDowngrade, PageMapToFlush, TipRequest},
};
use crossbeam_channel::{unbounded, Sender};
use ic_canonical_state::lazy_tree_conversion::replicated_state_as_lazy_tree;
use ic_canonical_state_tree_hash::{
    hash_tree::{hash_lazy_tree, HashTree, HashTreeError},
    lazy_tree::materialize::materialize_partial,
};
use ic_config::flag_status::FlagStatus;
use ic_config::state_manager::Config;
use ic_crypto_tree_hash::{recompute_digest, Digest, LabeledTree, MixedHashTree, Witness};
use ic_interfaces::certification::Verifier;
use ic_interfaces_certified_stream_store::{
    CertifiedStreamStore, DecodeStreamError, EncodeStreamError,
};
use ic_interfaces_state_manager::{
    CertificationMask, CertificationScope, CertifiedStateSnapshot, Labeled,
    PermanentStateHashError::*, StateHashError, StateManager, StateManagerError,
    StateManagerResult, StateReader, TransientStateHashError::*, CERT_CERTIFIED, CERT_UNCERTIFIED,
};
use ic_logger::{debug, error, fatal, info, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_protobuf::{messaging::xnet::v1, state::v1 as pb};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_snapshots::SnapshotOperation, page_map::PageAllocatorFileDescriptor,
};
use ic_replicated_state::{
    canister_state::execution_state::SandboxMemory,
    page_map::{PersistenceError, StorageMetrics},
    PageIndex, PageMap, ReplicatedState,
};
use ic_state_layout::{
    error::LayoutError, AccessPolicy, CheckpointLayout, PageMapLayout, ReadOnly, StateLayout,
};
use ic_types::{
    batch::BatchSummary,
    consensus::certification::Certification,
    crypto::CryptoHash,
    malicious_flags::MaliciousFlags,
    state_sync::CURRENT_STATE_SYNC_VERSION,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    CanisterId, CryptoHashOfPartialState, CryptoHashOfState, Height, RegistryVersion, SnapshotId,
    SubnetId,
};
use ic_utils_thread::JoinOnDrop;
use ic_validate_eq::ValidateEq;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};
use prost::Message;
use std::convert::{From, TryFrom};
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::RawFd;
use std::os::unix::prelude::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Mutex,
};
use tempfile::tempfile;
use uuid::Uuid;

/// The number of threads that state manager starts to construct checkpoints.
/// It is exported as public for use in tests and benchmarks.
pub const NUMBER_OF_CHECKPOINT_THREADS: u32 = 16;

/// Critical error tracking mismatches between reused and recomputed chunk
/// hashes during manifest computation.
const CRITICAL_ERROR_REUSED_CHUNK_HASH: &str =
    "state_manager_manifest_reused_chunk_hash_error_count";

/// Critical error tracking unexpectedly corrupted chunks.
const CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS: &str = "state_sync_corrupted_chunks";

/// Critical error tracking that chunk ID space usage of any state sync chunk type is nearing the limit.
const CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS: &str =
    "state_sync_chunk_id_usage_nearing_limits";

/// Critical error tracking broken soft invariants encountered upon checkpoint loading.
/// See note [Replicated State Invariants].
pub(crate) const CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN: &str =
    "state_manager_checkpoint_soft_invariant_broken";

/// Critical error tracking ReplicatedState altering after checkpoint.
const CRITICAL_ERROR_REPLICATED_STATE_ALTERED_AFTER_CHECKPOINT: &str =
    "state_manager_replicated_state_altered_after_checkpoint";

/// How long to keep archived and diverged states.
const ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60); // 30 days

/// Write an overlay file this many rounds before each checkpoint.
pub const NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY: u64 = 50;

/// Labels for manifest metrics
const LABEL_TYPE: &str = "type";
const LABEL_VALUE_HASHED: &str = "hashed";
const LABEL_VALUE_HASHED_AND_COMPARED: &str = "hashed_and_compared";
const LABEL_VALUE_REUSED: &str = "reused";

/// Labels for state sync metrics
const LABEL_FETCH: &str = "fetch";
const LABEL_COPY_FILES: &str = "copy_files";
const LABEL_COPY_CHUNKS: &str = "copy_chunks";
const LABEL_PREALLOCATE: &str = "preallocate";
const LABEL_STATE_SYNC_MAKE_CHECKPOINT: &str = "state_sync_make_checkpoint";
const LABEL_FETCH_META_MANIFEST_CHUNK: &str = "fetch_meta_manifest_chunk";
const LABEL_FETCH_MANIFEST_CHUNK: &str = "fetch_manifest_chunk";
const LABEL_FETCH_STATE_CHUNK: &str = "fetch_state_chunk";

/// Labels for slice validation metrics
const LABEL_VERIFY_SIG: &str = "verify";
const LABEL_CMP_HASH: &str = "compare";
const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_FAILURE: &str = "failure";

#[derive(Clone)]
pub struct StateManagerMetrics {
    state_manager_error_count: IntCounterVec,
    checkpoint_op_duration: HistogramVec,
    api_call_duration: HistogramVec,
    last_diverged_state_timestamp: IntGauge,
    latest_certified_height: IntGauge,
    max_resident_height: IntGauge,
    min_resident_height: IntGauge,
    last_computed_manifest_height: IntGauge,
    resident_state_count: IntGauge,
    checkpoints_on_disk_count: IntGauge,
    state_sync_metrics: StateSyncMetrics,
    state_size: IntGauge,
    states_metadata_pbuf_size: IntGauge,
    checkpoint_metrics: CheckpointMetrics,
    manifest_metrics: ManifestMetrics,
    tip_handler_queue_length: IntGauge,
    decode_slice_status: IntCounterVec,
    height_update_time_seconds: Histogram,
    storage_metrics: StorageMetrics,
    merge_metrics: MergeMetrics,
    latest_hash_tree_size: IntGauge,
    latest_hash_tree_max_index: IntGauge,
}

#[derive(Clone)]
pub struct ManifestMetrics {
    chunk_bytes: IntCounterVec,
    reused_chunk_hash_error_count: IntCounter,
    manifest_size: IntGauge,
    chunk_table_length: IntGauge,
    file_table_length: IntGauge,
    file_group_chunks: IntGauge,
    sub_manifest_chunks: IntGauge,
    chunk_id_usage_nearing_limits_critical: IntCounter,
}

#[derive(Clone)]
pub struct StateSyncMetrics {
    size: IntCounterVec,
    duration: HistogramVec,
    step_duration: HistogramVec,
    remaining: IntGauge,
    corrupted_chunks_critical: IntCounter,
    corrupted_chunks: IntCounterVec,
}

#[derive(Clone)]
pub struct CheckpointMetrics {
    make_checkpoint_step_duration: HistogramVec,
    load_checkpoint_step_duration: HistogramVec,
    load_canister_step_duration: HistogramVec,
    load_checkpoint_soft_invariant_broken: IntCounter,
    replicated_state_altered_after_checkpoint: IntCounter,
    tip_handler_request_duration: HistogramVec,
    page_map_flushes: IntCounter,
    page_map_flush_skips: IntCounter,
    log: ReplicaLogger,
}

impl CheckpointMetrics {
    pub fn new(metrics_registry: &MetricsRegistry, replica_logger: ReplicaLogger) -> Self {
        let make_checkpoint_step_duration = metrics_registry.histogram_vec(
            "state_manager_checkpoint_steps_duration_seconds",
            "Duration of make_checkpoint steps in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["step"],
        );
        let load_checkpoint_step_duration = metrics_registry.histogram_vec(
            "state_manager_load_checkpoint_steps_duration_seconds",
            "Duration of load_checkpoint steps in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["step"],
        );

        let load_canister_step_duration = metrics_registry.histogram_vec(
            "state_manager_load_canister_steps_duration_seconds",
            "Duration of load_canister_state steps in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["step"],
        );

        let load_checkpoint_soft_invariant_broken =
            metrics_registry.error_counter(CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN);

        let replicated_state_altered_after_checkpoint = metrics_registry
            .error_counter(CRITICAL_ERROR_REPLICATED_STATE_ALTERED_AFTER_CHECKPOINT);

        let tip_handler_request_duration = metrics_registry.histogram_vec(
            "state_manager_tip_handler_request_duration_seconds",
            "Duration to execute requests to Tip handling thread in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["request"],
        );

        let page_map_flushes = metrics_registry.int_counter(
            "state_manager_page_map_flushes",
            "Amount of sent FlushPageMap requests.",
        );
        let page_map_flush_skips = metrics_registry.int_counter(
            "state_manager_page_map_flush_skips",
            "Amount of FlushPageMap requests that were skipped.",
        );

        Self {
            make_checkpoint_step_duration,
            load_checkpoint_step_duration,
            load_canister_step_duration,
            load_checkpoint_soft_invariant_broken,
            replicated_state_altered_after_checkpoint,
            tip_handler_request_duration,
            page_map_flushes,
            page_map_flush_skips,
            log: replica_logger,
        }
    }
}

#[derive(Clone)]
pub struct MergeMetrics {
    disk_size_bytes: IntGauge,
    memory_size_bytes: IntGauge,
    estimated_storage_savings_bytes: Histogram,
    num_page_maps_merged: HistogramVec,
}

impl MergeMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let disk_size_bytes = metrics_registry.int_gauge(
            "state_manager_merge_disk_size_bytes",
            "Number of bytes of on disk for all PageMaps, measured before merging.",
        );

        let memory_size_bytes = metrics_registry.int_gauge(
            "state_manager_merge_memory_size_bytes",
            "Number of bytes of memory for all PageMaps, not counting duplicate data in overlays, measured before merging.",
        );

        let estimated_storage_savings_bytes = metrics_registry.histogram(
            "state_manager_merge_estimated_storage_savings_bytes",
            "Estimated number of bytes saved in disk space across all PageMaps for a merge, estimated by the merge strategy.",
            // 10MB, 20MB, 50MB, 100MB, 200MB, 500MB, …, 100GB, 200GB, 500GB
            decimal_buckets(7, 11),
        );

        let num_page_maps_merged = metrics_registry.histogram_vec(
            "state_manager_num_page_maps_merged",
            "Number of PapeMaps merged separated by which part of the merge strategy triggered the merge.",
            // 1, 2, 5, 10, 20, 50, …, 10k, 20k, 50k
            decimal_buckets(0, 4),
            &["reason"],
        );

        Self {
            disk_size_bytes,
            memory_size_bytes,
            estimated_storage_savings_bytes,
            num_page_maps_merged,
        }
    }
}

// Note [Metrics preallocation]
// ============================
//
// If vectorized metrics are used for events that happen rarely (like state
// sync), it becomes a challenge to visualize them.  As Prometheus doesn't know
// which label values are going to be used in advance, the values are simply
// missing until they are set for the first time.  This leads to
// rate(metric[period]) returning 0 because the value switched from NONE to,
// say, 1, not from 0 to 1.  So only the next update of the metric will result
// in a meaningful rate, which in the case of state sync might never appear.
//
// In order to solve this, we "preallocate" metrics with values of labels we
// expect to see. This makes initial vectorized metric values equal to 0, so the
// very first metric update should be visible to Prometheus.

impl StateManagerMetrics {
    fn new(metrics_registry: &MetricsRegistry, log: ReplicaLogger) -> Self {
        let checkpoint_op_duration = metrics_registry.histogram_vec(
            "state_manager_checkpoint_op_duration_seconds",
            "Duration of checkpoint operations in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["op"],
        );

        for op in &["compute_manifest", "create"] {
            checkpoint_op_duration.with_label_values(&[*op]);
        }

        let api_call_duration = metrics_registry.histogram_vec(
            "state_manager_api_call_duration_seconds",
            "Duration of a StateManager API call in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["op"],
        );

        let state_manager_error_count = metrics_registry.int_counter_vec(
            "state_manager_error_count",
            "Total number of errors encountered in the state manager.",
            &["source"],
        );

        let last_diverged_state_timestamp = metrics_registry.int_gauge(
            "state_manager_last_diverged_state_timestamp_seconds",
            "The (UTC) timestamp of the last diverged state report.",
        );

        let latest_certified_height = metrics_registry.int_gauge(
            "state_manager_latest_certified_height",
            "Height of the latest certified state.",
        );

        let min_resident_height = metrics_registry.int_gauge(
            "state_manager_min_resident_height",
            "Height of the oldest state resident in memory.",
        );

        let max_resident_height = metrics_registry.int_gauge(
            "state_manager_max_resident_height",
            "Height of the latest state resident in memory.",
        );

        let resident_state_count = metrics_registry.int_gauge(
            "state_manager_resident_state_count",
            "Total count of states loaded to memory by the state manager.",
        );

        let checkpoints_on_disk_count = metrics_registry.int_gauge(
            "state_manager_checkpoints_on_disk_count",
            "Number of verified checkpoints on disk, independent of if they are loaded or not.",
        );

        let last_computed_manifest_height = metrics_registry.int_gauge(
            "state_manager_last_computed_manifest_height",
            "Height of the last checkpoint we computed manifest for.",
        );

        let state_size = metrics_registry.int_gauge(
            "state_manager_state_size_bytes",
            "Total size of the state on disk in bytes.",
        );

        let states_metadata_pbuf_size = metrics_registry.int_gauge(
            "state_manager_states_metadata_pbuf_size_bytes",
            "Size of states_metadata.pbuf in bytes.",
        );

        let tip_handler_queue_length = metrics_registry.int_gauge(
            "state_manager_tip_handler_queue_length",
            "Length of TipChannel queue.",
        );

        let decode_slice_status = metrics_registry.int_counter_vec(
            "state_manager_decode_slice",
            "Statuses of slice decoding.",
            &["op", "status"],
        );

        // Initialize all `decode_slice_status` counters with zero, so they are all
        // exported from process start (`IntCounterVec` is really a map).
        for op in &[LABEL_VERIFY_SIG, LABEL_CMP_HASH] {
            for status in &[LABEL_VALUE_SUCCESS, LABEL_VALUE_FAILURE] {
                decode_slice_status.with_label_values(&[op, status]);
            }
        }
        let height_update_time_seconds = metrics_registry.histogram(
            "state_manager_height_update_time_seconds",
            "Time between invocations of commit_and_certify that update height.",
            // 1s, 2s, 5s, 10s, …, 100s, 200s, 500s
            decimal_buckets(0, 2),
        );

        let latest_hash_tree_size = metrics_registry.int_gauge(
            "state_manager_latest_hash_tree_size",
            "Number of digests in the latest hash tree.",
        );

        let latest_hash_tree_max_index = metrics_registry.int_gauge(
            "state_manager_latest_hash_tree_max_index",
            "Largest index in the latest hash tree.",
        );

        Self {
            state_manager_error_count,
            checkpoint_op_duration,
            api_call_duration,
            last_diverged_state_timestamp,
            latest_certified_height,
            max_resident_height,
            min_resident_height,
            last_computed_manifest_height,
            resident_state_count,
            checkpoints_on_disk_count,
            state_sync_metrics: StateSyncMetrics::new(metrics_registry),
            state_size,
            states_metadata_pbuf_size,
            checkpoint_metrics: CheckpointMetrics::new(metrics_registry, log),
            manifest_metrics: ManifestMetrics::new(metrics_registry),
            tip_handler_queue_length,
            decode_slice_status,
            height_update_time_seconds,
            storage_metrics: StorageMetrics::new(metrics_registry),
            merge_metrics: MergeMetrics::new(metrics_registry),
            latest_hash_tree_size,
            latest_hash_tree_max_index,
        }
    }

    /// Records a decode slice status for `label`.
    fn observe_decode_slice(&self, operation: &str, success: bool) {
        let status = if success {
            LABEL_VALUE_SUCCESS
        } else {
            LABEL_VALUE_FAILURE
        };
        self.decode_slice_status
            .with_label_values(&[operation, status])
            .inc();
    }

    /// Records a decode slice status for a signature verification.
    fn observe_decode_slice_signature_verification(&self, success: bool) {
        self.observe_decode_slice(LABEL_VERIFY_SIG, success);
    }

    /// Records a decode slice status for a comparison of a tree's root
    /// hash and the hash in the corresponding certification.
    fn observe_decode_slice_hash_comparison(&self, success: bool) {
        self.observe_decode_slice(LABEL_CMP_HASH, success);
    }
}

impl ManifestMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let chunk_bytes = metrics_registry.int_counter_vec(
            "state_manager_manifest_chunk_bytes",
            "Size of chunks in manifest by hash type ('reused', 'hashed', 'hashed_and_compared') during all manifest computations in bytes.",
            &[LABEL_TYPE],
        );

        for tp in &[
            LABEL_VALUE_REUSED,
            LABEL_VALUE_HASHED,
            LABEL_VALUE_HASHED_AND_COMPARED,
        ] {
            chunk_bytes.with_label_values(&[*tp]);
        }

        let manifest_size = metrics_registry.int_gauge(
            "state_manager_manifest_state_size_bytes",
            "Size of the encoded manifest in bytes.",
        );

        let chunk_table_length = metrics_registry.int_gauge(
            "state_manager_manifest_chunk_table_length",
            "Number of chunks in the manifest chunk table.",
        );

        let file_table_length = metrics_registry.int_gauge(
            "state_manager_manifest_file_table_length",
            "Number of files in the manifest file table.",
        );

        let file_group_chunks = metrics_registry.int_gauge(
            "state_manager_file_group_chunks",
            "Number of virtual chunks containing the grouped small files.",
        );

        let sub_manifest_chunks = metrics_registry.int_gauge(
            "state_manager_sub_manifest_chunks",
            "Number of chunks of the manifest after it is encoded and split into sub-manifests.",
        );

        Self {
            // Number of bytes that are either reused, hashed, or hashed and compared during the
            // manifest computation
            chunk_bytes,
            // Count of the chunks which have a mismatch between the recomputed hash and the reused
            // one.
            reused_chunk_hash_error_count: metrics_registry
                .error_counter(CRITICAL_ERROR_REUSED_CHUNK_HASH),
            manifest_size,
            chunk_table_length,
            file_table_length,
            file_group_chunks,
            sub_manifest_chunks,
            chunk_id_usage_nearing_limits_critical: metrics_registry
                .error_counter(CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS),
        }
    }
}

impl StateSyncMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let size = metrics_registry.int_counter_vec(
            "state_sync_size_bytes_total",
            "Size of chunks synchronized by different operations ('fetch', 'copy_files', 'copy_chunks', 'preallocate') during all the state sync in bytes.",
            &["op"],
        );

        // Note [Metrics preallocation]
        for op in &[
            LABEL_FETCH,
            LABEL_COPY_FILES,
            LABEL_COPY_CHUNKS,
            LABEL_PREALLOCATE,
        ] {
            size.with_label_values(&[*op]);
        }

        let remaining = metrics_registry.int_gauge(
            "state_sync_remaining_chunks",
            "Number of chunks not synchronized yet of all active state syncs",
        );

        let duration = metrics_registry.histogram_vec(
            "state_sync_duration_seconds",
            "Duration of state sync in seconds indexed by status ('ok', 'already_exists', 'unrecoverable', 'io_err', 'aborted', 'aborted_blank').",
            // 1s, 2s, 5s, 10s, 20s, 50s, …, 1000s, 2000s, 5000s
            decimal_buckets(0, 3),
            &["status"],
        );

        // Note [Metrics preallocation]
        for status in &[
            "ok",
            "already_exists",
            "unrecoverable",
            "io_err",
            "aborted",
            "aborted_blank",
        ] {
            duration.with_label_values(&[*status]);
        }

        let step_duration = metrics_registry.histogram_vec(
            "state_sync_step_duration_seconds",
            "Duration of state sync sub-steps in seconds indexed by step ('copy_files', 'copy_chunks', 'fetch', 'state_sync_make_checkpoint')",
            // 0.1s, 0.2s, 0.5s, 1s, 2s, 5s, …, 1000s, 2000s, 5000s
            decimal_buckets(-1, 3),
            &["step"],
        );

        // Note [Metrics preallocation]
        for step in &[
            LABEL_COPY_FILES,
            LABEL_COPY_CHUNKS,
            LABEL_FETCH,
            LABEL_STATE_SYNC_MAKE_CHECKPOINT,
        ] {
            step_duration.with_label_values(&[*step]);
        }

        let corrupted_chunks_critical =
            metrics_registry.error_counter(CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS);

        let corrupted_chunks = metrics_registry.int_counter_vec(
            "state_sync_corrupted_chunks",
            "Number of chunks not copied/applied during state sync due to hash mismatch by source ('copy_files', 'copy_chunks', 'fetch_meta_manifest_chunk', 'fetch_manifest_chunk', 'fetch_state_chunk')",
            &["source"],
        );

        // Note [Metrics preallocation]
        for source in &[
            LABEL_COPY_FILES,
            LABEL_COPY_CHUNKS,
            LABEL_FETCH_META_MANIFEST_CHUNK,
            LABEL_FETCH_MANIFEST_CHUNK,
            LABEL_FETCH_STATE_CHUNK,
        ] {
            corrupted_chunks.with_label_values(&[*source]);
        }

        Self {
            size,
            duration,
            step_duration,
            remaining,
            corrupted_chunks_critical,
            corrupted_chunks,
        }
    }
}

type StatesMetadata = BTreeMap<Height, StateMetadata>;

type CertificationsMetadata = BTreeMap<Height, CertificationMetadata>;

/// This struct bundles the root hash, manifest and meta-manifest.
#[derive(Debug, Clone)]
pub(crate) struct BundledManifest {
    root_hash: CryptoHashOfState,
    manifest: Manifest,
    meta_manifest: Arc<MetaManifest>,
}

#[derive(Debug, Default, Clone)]
struct StateMetadata {
    /// We don't persist the checkpoint layout because we re-create it every
    /// time we discover a checkpoint on disk.
    checkpoint_layout: Option<CheckpointLayout<ReadOnly>>,
    /// Manifest and root hash are computed asynchronously, so the bundle is set to
    /// None before the values are computed.
    bundled_manifest: Option<BundledManifest>,
    /// The field is set as `None` until we serve a state sync for the first time.
    state_sync_file_group: Option<Arc<FileGroupChunks>>,
}

impl StateMetadata {
    pub fn root_hash(&self) -> Option<&CryptoHashOfState> {
        self.bundled_manifest
            .as_ref()
            .map(|bundled_manifest| &bundled_manifest.root_hash)
    }
    pub fn manifest(&self) -> Option<&Manifest> {
        self.bundled_manifest
            .as_ref()
            .map(|bundled_manifest| &bundled_manifest.manifest)
    }

    pub fn meta_manifest(&self) -> Option<Arc<MetaManifest>> {
        self.bundled_manifest
            .as_ref()
            .map(|bundled_manifest| bundled_manifest.meta_manifest.clone())
    }
}

impl From<&StateMetadata> for pb::StateMetadata {
    fn from(metadata: &StateMetadata) -> Self {
        Self {
            manifest: metadata.manifest().map(|m| m.clone().into()),
        }
    }
}

impl TryFrom<pb::StateMetadata> for StateMetadata {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::StateMetadata) -> Result<Self, ProxyDecodeError> {
        match proto.manifest {
            None => Ok(Default::default()),
            Some(manifest) => {
                let manifest = Manifest::try_from(manifest)?;
                let bundled_manifest = compute_bundled_manifest(manifest);

                Ok(Self {
                    checkpoint_layout: None,
                    bundled_manifest: Some(bundled_manifest),
                    state_sync_file_group: None,
                })
            }
        }
    }
}

/// This type holds per-height metadata related to certification.
#[derive(Debug)]
struct CertificationMetadata {
    /// Fully materialized hash tree built from the part of the state that is
    /// certified every round.  Dropped as soon as a higher state is certified.
    hash_tree: Option<Arc<HashTree>>,
    /// Root hash of the tree above. It's stored even if the hash tree is
    /// dropped.
    certified_state_hash: CryptoHash,
    /// Certification of the root hash delivered by consensus via
    /// `deliver_state_certification()`.
    certification: Option<Certification>,
}

fn crypto_hash_of_partial_state(d: &Digest) -> CryptoHashOfPartialState {
    CryptoHashOfPartialState::from(CryptoHash(d.0.to_vec()))
}

#[derive(Clone)]
pub struct Snapshot {
    pub height: Height,
    pub state: Arc<ReplicatedState>,
}

/// StateSyncRefs keeps track of the ongoing and aborted state syncs.
#[derive(Clone)]
pub struct StateSyncRefs {
    /// IncompleteState adds the corresponding height to StateSyncRefs when
    /// it's constructed and removes the height from active syncs when it's
    /// dropped.
    /// The priority function for state sync artifacts uses this information on
    /// to prioritize state fetches.
    active: Arc<parking_lot::RwLock<Option<(Height, CryptoHashOfState)>>>,
    /// A cache of chunks from a previously aborted IncompleteState. State syncs
    /// can take chunks from the cache instead of fetching them from other nodes
    /// when possible.
    cache: Arc<parking_lot::RwLock<StateSyncCache>>,
}

impl StateSyncRefs {
    fn new(log: ReplicaLogger) -> Self {
        Self {
            active: Arc::new(parking_lot::RwLock::new(None)),
            cache: Arc::new(parking_lot::RwLock::new(StateSyncCache::new(log))),
        }
    }
}

/// SharedState is mutable state that can be accessed from multiple threads.
struct SharedState {
    /// Certifications metadata kept for all states
    certifications_metadata: CertificationsMetadata,
    /// Metadata for each checkpoint
    states_metadata: StatesMetadata,
    /// A list of states present in the memory.  This list is guaranteed to not be
    /// empty as it should always contain the state at height=0.
    snapshots: VecDeque<Snapshot>,
    /// The last checkpoint that was advertised.
    last_advertised: Height,
    /// The state we are are trying to fetch.
    fetch_state: Option<(Height, CryptoHashOfState, Height)>,
    /// State representing the on disk mutable state
    tip: Option<(Height, ReplicatedState)>,
}

impl SharedState {
    fn disable_state_fetch_below(&mut self, height: Height) {
        if let Some((sync_height, _hash, _cup_interval_length)) = &self.fetch_state {
            if *sync_height <= height {
                self.fetch_state = None
            }
        }
    }
}

// We send complex objects to a different thread to free them. This will spread
// the cost of deallocation over a longer period of time, and avoid long pauses.
type Deallocation = Box<dyn std::any::Any + Send + 'static>;

// We will not use the deallocation thread when the number of pending
// deallocation objects goes above the threshold.
const DEALLOCATION_BACKLOG_THRESHOLD: usize = 500;

/// The number of archived and diverged states to keep before we start deleting the old ones.
const MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP: usize = 1;

/// The number of diverged state markers to keep.
const MAX_DIVERGED_STATE_MARKERS_TO_KEEP: usize = 100;

/// The number of extra checkpoints to keep for state sync.
const EXTRA_CHECKPOINTS_TO_KEEP: usize = 0;

pub struct StateManagerImpl {
    log: ReplicaLogger,
    metrics: StateManagerMetrics,
    state_layout: StateLayout,
    /// The main metadata. Different threads will need to access this field.
    ///
    /// To avoid the risk of deadlocks, this lock should be held as short a time
    /// as possible.
    states: Arc<parking_lot::RwLock<SharedState>>,
    verifier: Arc<dyn Verifier>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    deallocation_sender: Sender<Deallocation>,
    // Cached latest state height.  We cache it separately because it's
    // requested quite often and this causes high contention on the lock.
    latest_state_height: AtomicU64,
    latest_certified_height: AtomicU64,
    _deallocation_handle: JoinOnDrop<()>,
    persist_metadata_guard: Arc<Mutex<()>>,
    tip_channel: Sender<TipRequest>,
    _tip_thread_handle: JoinOnDrop<()>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    malicious_flags: MaliciousFlags,
    latest_height_update_time: Arc<Mutex<Instant>>,
    lsmt_status: FlagStatus,
}

#[cfg(debug_assertions)]
impl Drop for StateManagerImpl {
    fn drop(&mut self) {
        // Make sure the tip thread didn't panic. Otherwise we may be blind to it in tests.
        // If the tip thread panics after the latest communication with tip_channel the test returns
        // success.
        self.flush_tip_channel();
    }
}

fn load_checkpoint(
    state_layout: &StateLayout,
    height: Height,
    metrics: &StateManagerMetrics,
    own_subnet_type: SubnetType,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(ReplicatedState, CheckpointLayout<ReadOnly>), CheckpointError> {
    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);

    let cp_layout = state_layout.checkpoint_verified(height)?;
    let _timer = metrics
        .checkpoint_op_duration
        .with_label_values(&["recover"])
        .start_timer();
    let state = checkpoint::load_checkpoint(
        &cp_layout,
        own_subnet_type,
        &metrics.checkpoint_metrics,
        Some(&mut thread_pool),
        Arc::clone(&fd_factory),
    )?;
    Ok((state, cp_layout))
}

#[cfg(debug_assertions)]
fn check_certifications_metadata_snapshots_and_states_metadata_are_consistent(
    states: &SharedState,
) {
    let certification_heights = states
        .certifications_metadata
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let snapshot_heights = states
        .snapshots
        .iter()
        .map(|s| s.height)
        .filter(|h| h.get() != 0)
        .collect::<Vec<_>>();
    debug_assert_eq!(certification_heights, snapshot_heights);
    for h in states.states_metadata.keys() {
        debug_assert!(states.certifications_metadata.contains_key(h));
    }
}

fn initialize_tip(
    log: &ReplicaLogger,
    tip_channel: &Sender<TipRequest>,
    snapshot: &Snapshot,
    checkpoint_layout: CheckpointLayout<ReadOnly>,
) -> ReplicatedState {
    debug_assert_eq!(snapshot.height, checkpoint_layout.height());

    // Since we initialize tip from checkpoint states, we expect a clean sandbox slate
    #[cfg(debug_assertions)]
    for canister in snapshot.state.canisters_iter() {
        if let Some(canister_state) = &canister.execution_state {
            if let SandboxMemory::Synced(_) =
                *canister_state.wasm_memory.sandbox_memory.lock().unwrap()
            {
                panic!(
                    "Unexpected sandbox state for canister {}",
                    canister.canister_id()
                );
            }
            if let SandboxMemory::Synced(_) =
                *canister_state.stable_memory.sandbox_memory.lock().unwrap()
            {
                panic!(
                    "Unexpected sandbox state for canister {}",
                    canister.canister_id()
                );
            }
        }
    }

    info!(log, "Recovering checkpoint @{} as tip", snapshot.height);

    tip_channel
        .send(TipRequest::ResetTipAndMerge {
            checkpoint_layout,
            pagemaptypes_with_num_pages: pagemaptypes_with_num_pages(&snapshot.state),
            is_initializing_tip: true,
        })
        .unwrap();
    ReplicatedState::clone(&snapshot.state)
}

fn pagemaptypes_with_num_pages(state: &ReplicatedState) -> Vec<(PageMapType, usize)> {
    let mut result = Vec::new();
    for entry in PageMapType::list_all_including_snapshots(state) {
        if let Some(page_map) = entry.get(state) {
            result.push((entry, page_map.num_host_pages()));
        }
    }
    result
}

/// Return duration since path creation (or modification, if no creation)
/// Return zero duration and log a warning on failure.
fn path_age(log: &ReplicaLogger, path: &Path) -> Duration {
    let now = SystemTime::now();
    match path.metadata().and_then(|m| m.modified()) {
        Ok(mtime) => {
            if let Ok(duration) = now.duration_since(mtime) {
                duration
            } else {
                // Only happens when created in the future. Return 0 is OK
                Duration::from_secs(0)
            }
        }
        Err(err) => {
            warn!(
                log,
                "Could not determine age for the path {}; error: {:?}",
                path.display(),
                err
            );
            Duration::from_secs(0)
        }
    }
}

/// Deletes obsolete diverged states and state backups, keeping at most
/// MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP archived checkpoints and backups no older than
/// ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE. The same for diverged checkpoints.
/// On top of that we keep maximum MAX_DIVERGED_STATE_MARKERS_TO_KEEP of diverged markers
/// no older then ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE
fn cleanup_diverged_states(log: &ReplicaLogger, layout: &StateLayout) {
    let last_checkpoint: Height = match layout.checkpoint_heights() {
        Err(err) => {
            fatal!(log, "Failed to get list of checkpoints: {}", err);
        }
        Ok(v) => v
            .last()
            .copied()
            .unwrap_or(StateManagerImpl::INITIAL_STATE_HEIGHT),
    };
    if let Ok(diverged_heights) = layout.diverged_checkpoint_heights() {
        let to_remove = diverged_heights
            .len()
            .saturating_sub(MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP);
        for (i, h) in diverged_heights.iter().enumerate() {
            if i < to_remove
                || (last_checkpoint > *h
                    && path_age(log, &layout.diverged_checkpoint_path(*h))
                        > ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE)
            {
                match layout.remove_diverged_checkpoint(*h) {
                    Ok(()) => info!(log, "Successfully removed diverged state {}", *h),
                    Err(err) => info!(log, "{}", err),
                }
            }
        }
    }
    if let Ok(backup_heights) = layout.backup_heights() {
        let to_remove = backup_heights
            .len()
            .saturating_sub(MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP);
        for (i, h) in backup_heights.iter().enumerate() {
            if i < to_remove
                || (last_checkpoint > *h
                    && path_age(log, &layout.backup_checkpoint_path(*h))
                        > ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE)
            {
                match layout.remove_backup(*h) {
                    Ok(()) => info!(log, "Successfully removed backup {}", *h),
                    Err(err) => info!(log, "Failed to remove backup {}", err),
                }
            }
        }
    }
    if let Ok(state_heights) = layout.diverged_state_heights() {
        let to_remove = state_heights
            .len()
            .saturating_sub(MAX_DIVERGED_STATE_MARKERS_TO_KEEP);
        for (i, h) in state_heights.iter().enumerate() {
            if i < to_remove
                || path_age(log, &layout.diverged_state_marker_path(*h))
                    > ARCHIVED_DIVERGED_CHECKPOINT_MAX_AGE
            {
                match layout.remove_diverged_state_marker(*h) {
                    Ok(()) => info!(log, "Successfully removed diverged state marker {}", h),
                    Err(err) => info!(log, "{}", err),
                }
            }
        }
    }
}

fn report_last_diverged_state(
    log: &ReplicaLogger,
    metrics: &StateManagerMetrics,
    state_layout: &StateLayout,
) {
    let mut diverged_paths = std::vec::Vec::new();
    let mut last_time = SystemTime::UNIX_EPOCH;
    match state_layout.diverged_checkpoint_heights() {
        Err(e) => warn!(log, "failed to enumerate diverged checkpoints: {}", e),
        Ok(heights) => {
            for h in heights {
                diverged_paths.push(state_layout.diverged_checkpoint_path(h));
            }
        }
    }
    match state_layout.diverged_state_heights() {
        Err(e) => warn!(log, "failed to enumerate diverged states: {}", e),
        Ok(heights) => {
            for h in heights {
                diverged_paths.push(state_layout.diverged_state_marker_path(h));
            }
        }
    }
    for p in diverged_paths {
        match p.metadata().and_then(|m| m.modified()) {
            Ok(mtime) => {
                last_time = last_time.max(mtime);
            }
            Err(e) => info!(
                log,
                "Failed to stat diverged checkpoint directory {}: {}",
                p.display(),
                e
            ),
        }
    }
    metrics.last_diverged_state_timestamp.set(
        last_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
}

/// Type for the return value of populate_metadata
#[derive(Default)]
struct PopulatedMetadata {
    certifications_metadata: CertificationsMetadata,
    states_metadata: StatesMetadata,
    checkpoint_layouts_to_compute_manifest: Vec<CheckpointLayout<ReadOnly>>,
    snapshots_with_checkpoint_layouts: Vec<(Snapshot, CheckpointLayout<ReadOnly>)>,
}

/// An enum describing all possible PageMaps in ReplicatedState
/// When adding additional PageMaps, add an appropriate entry here
/// to enable all relevant state manager features, e.g. incremental
/// manifest computations
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PageMapType {
    WasmMemory(CanisterId),
    StableMemory(CanisterId),
    WasmChunkStore(CanisterId),
    SnapshotWasmMemory(SnapshotId),
    SnapshotStableMemory(SnapshotId),
    SnapshotWasmChunkStore(SnapshotId),
}

impl PageMapType {
    /// List all PageMaps contained in `state`, ignoring PageMaps that are in snapshots.
    fn list_all_without_snapshots(state: &ReplicatedState) -> Vec<PageMapType> {
        let mut result = vec![];
        for (id, canister) in &state.canister_states {
            result.push(Self::WasmChunkStore(id.to_owned()));
            if canister.execution_state.is_some() {
                result.push(Self::WasmMemory(id.to_owned()));
                result.push(Self::StableMemory(id.to_owned()));
            }
        }

        result
    }

    /// List all PageMaps contained in `state`, including those in snapshots.
    fn list_all_including_snapshots(state: &ReplicatedState) -> Vec<PageMapType> {
        let mut result = Self::list_all_without_snapshots(state);
        for (id, _snapshot) in state.canister_snapshots.iter() {
            result.push(Self::SnapshotWasmMemory(id.to_owned()));
            result.push(Self::SnapshotStableMemory(id.to_owned()));
            result.push(Self::SnapshotWasmChunkStore(id.to_owned()));
        }

        result
    }

    /// The layout of the files on disk for this PageMap.
    fn layout<Access>(
        &self,
        layout: &CheckpointLayout<Access>,
    ) -> Result<PageMapLayout<Access>, LayoutError>
    where
        Access: AccessPolicy,
    {
        match &self {
            PageMapType::WasmMemory(id) => Ok(layout.canister(id)?.vmemory_0()),
            PageMapType::StableMemory(id) => Ok(layout.canister(id)?.stable_memory()),
            PageMapType::WasmChunkStore(id) => Ok(layout.canister(id)?.wasm_chunk_store()),
            PageMapType::SnapshotWasmMemory(id) => Ok(layout.snapshot(id)?.vmemory_0()),
            PageMapType::SnapshotStableMemory(id) => Ok(layout.snapshot(id)?.stable_memory()),
            PageMapType::SnapshotWasmChunkStore(id) => Ok(layout.snapshot(id)?.wasm_chunk_store()),
        }
    }

    /// Maps a PageMapType to the the `&PageMap` in `state`
    fn get<'a>(&self, state: &'a ReplicatedState) -> Option<&'a PageMap> {
        match &self {
            PageMapType::WasmMemory(id) => state.canister_state(id).and_then(|can| {
                can.execution_state
                    .as_ref()
                    .map(|ex| &ex.wasm_memory.page_map)
            }),
            PageMapType::StableMemory(id) => state.canister_state(id).and_then(|can| {
                can.execution_state
                    .as_ref()
                    .map(|ex| &ex.stable_memory.page_map)
            }),
            PageMapType::WasmChunkStore(id) => state
                .canister_state(id)
                .map(|can| can.system_state.wasm_chunk_store.page_map()),
            PageMapType::SnapshotWasmMemory(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| &snap.execution_snapshot().wasm_memory.page_map),
            PageMapType::SnapshotStableMemory(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| &snap.execution_snapshot().stable_memory.page_map),
            PageMapType::SnapshotWasmChunkStore(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| snap.chunk_store().page_map()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirtyPageMap {
    pub height: Height,
    pub page_type: PageMapType,
    pub page_delta_indices: Vec<PageIndex>,
}

pub type DirtyPages = Vec<DirtyPageMap>;

/// Get dirty pages of all PageMaps backed by a checkpoint
/// file.
pub fn get_dirty_pages(state: &ReplicatedState) -> DirtyPages {
    PageMapType::list_all_without_snapshots(state) // Snapshots don't have dirty pages for the manifest computation.
        .into_iter()
        .filter_map(|entry| {
            let page_map = entry.get(state)?;
            let height = page_map.base_height?;
            Some(DirtyPageMap {
                height,
                page_type: entry,
                page_delta_indices: page_map.get_page_delta_indices(),
            })
        })
        .collect()
}

/// Strips away the deltas from all page maps of the replicated state.
/// We execute this procedure before making a checkpoint because we
/// don't want those deltas to be persisted to TIP as we apply deltas
/// incrementally.
fn strip_page_map_deltas(
    state: &mut ReplicatedState,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) {
    for (_id, canister) in state.canister_states.iter_mut() {
        canister
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .strip_all_deltas(Arc::clone(&fd_factory));
        if let Some(execution_state) = canister.execution_state.as_mut() {
            execution_state
                .wasm_memory
                .page_map
                .strip_all_deltas(Arc::clone(&fd_factory));
            execution_state
                .stable_memory
                .page_map
                .strip_all_deltas(Arc::clone(&fd_factory));
        }
    }

    for (_id, canister_snapshot) in state.canister_snapshots.iter_mut() {
        let new_snapshot = Arc::make_mut(canister_snapshot);
        new_snapshot
            .chunk_store_mut()
            .page_map_mut()
            .strip_all_deltas(Arc::clone(&fd_factory));
        new_snapshot
            .execution_snapshot_mut()
            .wasm_memory
            .page_map
            .strip_all_deltas(Arc::clone(&fd_factory));
        new_snapshot
            .execution_snapshot_mut()
            .stable_memory
            .page_map
            .strip_all_deltas(Arc::clone(&fd_factory));
    }

    // Reset the sandbox state to force full synchronization on the next execution
    // since the page deltas are out of sync now.
    for canister in state.canisters_iter_mut() {
        if let Some(execution_state) = &mut canister.execution_state {
            execution_state.wasm_memory.sandbox_memory = SandboxMemory::new();
            execution_state.stable_memory.sandbox_memory = SandboxMemory::new();
        }
    }
}

/// Switches `tip` to the most recent checkpoint file provided by `src`.
///
/// Preconditions:
/// 1) `tip` and `src` mut have exactly the same set of canisters.
/// 2) The page deltas must be empty in both states.
/// 3) The memory sizes must match.
fn switch_to_checkpoint(tip: &mut ReplicatedState, src: &ReplicatedState) {
    for ((tip_id, tip_canister), (src_id, src_canister)) in tip
        .canister_states
        .iter_mut()
        .zip(src.canister_states.iter())
    {
        assert_eq!(tip_id, src_id);

        tip_canister
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .switch_to_checkpoint(src_canister.system_state.wasm_chunk_store.page_map());

        assert_eq!(
            src_canister.execution_state.is_some(),
            tip_canister.execution_state.is_some()
        );

        if let (Some(src_execution), Some(tip_execution)) = (
            src_canister.execution_state.as_ref(),
            tip_canister.execution_state.as_mut(),
        ) {
            tip_execution
                .wasm_memory
                .page_map
                .switch_to_checkpoint(&src_execution.wasm_memory.page_map);
            tip_execution
                .stable_memory
                .page_map
                .switch_to_checkpoint(&src_execution.stable_memory.page_map);
        }
    }

    for ((tip_id, tip_snapshot), (src_id, src_snapshot)) in tip
        .canister_snapshots
        .iter_mut()
        .zip(src.canister_snapshots.iter())
    {
        let new_snapshot = Arc::make_mut(tip_snapshot);

        assert_eq!(tip_id, src_id);

        new_snapshot
            .chunk_store_mut()
            .page_map_mut()
            .switch_to_checkpoint(src_snapshot.chunk_store().page_map());

        new_snapshot
            .execution_snapshot_mut()
            .wasm_memory
            .page_map
            .switch_to_checkpoint(&src_snapshot.execution_snapshot().wasm_memory.page_map);
        new_snapshot
            .execution_snapshot_mut()
            .stable_memory
            .page_map
            .switch_to_checkpoint(&src_snapshot.execution_snapshot().stable_memory.page_map);
    }

    for (tip_canister, src_canister) in tip.canisters_iter_mut().zip(src.canisters_iter()) {
        assert_eq!(
            tip_canister.system_state.canister_id,
            src_canister.system_state.canister_id
        );
        assert_eq!(
            tip_canister.execution_state.is_some(),
            src_canister.execution_state.is_some(),
            "execution state of canister {} unexpectedly (dis)appeared after creating a checkpoint",
            tip_canister.system_state.canister_id
        );
        if let (Some(tip_state), Some(src_state)) = (
            &mut tip_canister.execution_state,
            &src_canister.execution_state,
        ) {
            debug_assert_eq!(
                tip_state.wasm_binary.binary.as_slice(),
                src_state.wasm_binary.binary.as_slice()
            );

            // We can reuse the cache because the Wasm binary has the same
            // contents, only the storage of that binary changed.
            let embedder_cache = Arc::clone(&tip_state.wasm_binary.embedder_cache);
            tip_state.wasm_binary = Arc::new(
                ic_replicated_state::canister_state::execution_state::WasmBinary {
                    binary: src_state.wasm_binary.binary.clone(),
                    embedder_cache,
                },
            );

            assert_eq!(tip_state.wasm_memory.size, src_state.wasm_memory.size);
            // Reset the sandbox state to force full synchronization on the next message
            // execution because the checkpoint file of `tip` has changed.
            tip_state.wasm_memory.sandbox_memory = SandboxMemory::new();
            tip_state.stable_memory.sandbox_memory = SandboxMemory::new();
        }
    }
}

/// Persists metadata after releasing the write lock
///
/// A common pattern is that we modify the metadata in
/// StateManagerImpl.states.states_metadata and then want to persist
/// this change to disk using persist_metadata_or_die.
///
/// In order to modify states_metadata a write lock on states is
/// required. As persisting needs to interact with the disk and hence
/// is slow, we can't afford to hold the write lock for the duration
/// of that step. At the same time, we want to ensure that all changes
/// are persisted, with no race conditions such as reordering of write
/// commands.
///
/// Hence we do the following pattern:
/// 1. Clone the relevant data
/// 2. Grab a lock to be held for the duration of the persist step
/// 3. Release the write lock on states_metadata
/// 4. Persist the cloned data
fn release_lock_and_persist_metadata(
    log: &ReplicaLogger,
    metrics: &StateManagerMetrics,
    state_layout: &StateLayout,
    states: parking_lot::RwLockWriteGuard<SharedState>,
    persist_metadata_lock: &Arc<Mutex<()>>,
) {
    let states_metadata = states.states_metadata.clone();
    // This should be the only place where we lock this mutex
    let _guard = persist_metadata_lock.lock().unwrap();
    drop(states);
    persist_metadata_or_die(log, metrics, state_layout, &states_metadata);
}

/// Persist the metadata of `StateManagerImpl` to disk
///
/// This function is a free function, so that it can easily be called
/// by threads computing manifests.
///
/// An important principle is that any persisted metadata is not
/// necessary for correct behaviour of `StateManager`, and the
/// checkpoints alone are sufficient. The metadata does however
/// improve performance. For example, if the metadata is missing or
/// corrupt, manifests will have to be recomputed for any checkpoints
/// on disk.
fn persist_metadata_or_die(
    log: &ReplicaLogger,
    metrics: &StateManagerMetrics,
    state_layout: &StateLayout,
    metadata: &StatesMetadata,
) {
    use std::io::Write;

    let started_at = Instant::now();
    let tmp = state_layout.tmp().join("tmp_states_metadata.pb");

    ic_sys::fs::write_atomically_using_tmp_file(state_layout.states_metadata(), &tmp, |w| {
        let mut pb_meta = pb::StatesMetadata::default();
        for (h, m) in metadata.iter() {
            pb_meta.by_height.insert(h.get(), m.into());
        }

        let mut buf = vec![];
        pb_meta.encode(&mut buf).unwrap_or_else(|e| {
            fatal!(log, "Failed to encode states metadata to protobuf: {}", e);
        });
        metrics.states_metadata_pbuf_size.set(buf.len() as i64);
        w.write_all(&buf[..])
    })
    .unwrap_or_else(|err| {
        fatal!(
            log,
            "Failed to serialize states metadata to {}: {}",
            tmp.display(),
            err
        )
    });
    let elapsed = started_at.elapsed();
    metrics
        .checkpoint_op_duration
        .with_label_values(&["persist_meta"])
        .observe(elapsed.as_secs_f64());

    debug!(log, "Persisted states metadata in {:?}", elapsed);
}

struct CreateCheckpointResult {
    checkpointed_state: ReplicatedState,
    state_metadata: StateMetadata,
    // TipRequest to compute manifest.
    compute_manifest_request: TipRequest,
    // Other TipRequests to perform after the compute manifest.
    tip_requests: Vec<TipRequest>,
}

impl StateManagerImpl {
    pub fn flush_tip_channel(&self) {
        #[allow(clippy::disallowed_methods)]
        let (sender, recv) = unbounded();
        self.tip_channel
            .send(TipRequest::Wait { sender })
            .expect("failed to send TipHandler Wait message");
        recv.recv().expect("failed to wait for TipHandler thread");
    }

    /// Height for the initial default state.
    const INITIAL_STATE_HEIGHT: Height = Height::new(0);

    pub fn new(
        verifier: Arc<dyn Verifier>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        config: &Config,
        starting_height: Option<Height>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let metrics = StateManagerMetrics::new(metrics_registry, log.clone());
        info!(
            log,
            "Using path '{}' to manage local state",
            config.state_root.display()
        );
        let starting_time = Instant::now();
        let state_layout =
            StateLayout::try_new(log.clone(), config.state_root.clone(), metrics_registry)
                .unwrap_or_else(|err| fatal!(&log, "Failed to init state layout: {:?}", err));
        // Init scripts after upgrade change all files to be read write. This introduces a danger
        // of accidental modification of checkpoint data and also confuses hard-linking logic.
        state_layout
            .mark_checkpoint_files_readonly(&mut Some(scoped_threadpool::Pool::new(
                NUMBER_OF_CHECKPOINT_THREADS,
            )))
            .unwrap_or_else(|err| fatal!(&log, "Failed to mark checkpoints readonly: {:?}", err));
        info!(log, "StateLayout init took {:?}", starting_time.elapsed());

        // Create the file descriptor factory that is used to create files for PageMaps.
        let page_delta_path = state_layout.page_deltas();
        let fd_factory: Arc<dyn PageAllocatorFileDescriptor> =
            Arc::new(PageAllocatorFileDescriptorImpl {
                root: page_delta_path,
                file_backed_memory_allocator: config.file_backed_memory_allocator,
            });

        let (_tip_thread_handle, tip_channel) = spawn_tip_thread(
            log.clone(),
            state_layout.capture_tip_handler(),
            state_layout.clone(),
            config.lsmt_config.clone(),
            metrics.clone(),
            malicious_flags.clone(),
        );

        let starting_time = Instant::now();
        let loaded_states_metadata =
            Self::load_metadata(&log, state_layout.states_metadata().as_path());
        info!(log, "Loading metadata took {:?}", starting_time.elapsed());

        let starting_time = Instant::now();
        // Archive unverified checkpoints.
        let unfiltered_checkpoint_heights = state_layout
            .unfiltered_checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(
                    &log,
                    "Failed to retrieve unfiltered checkpoint heights: {:?}",
                    err
                )
            });

        for h in unfiltered_checkpoint_heights {
            match state_layout.checkpoint_verification_status(h) {
                // If the checkpoint is verified, we don't need to do anything.
                Ok(true) => {}
                // If the checkpoint is unverified, we archive it.
                Ok(false) => {
                    info!(log, "Archiving unverified checkpoint {}", h);
                    state_layout
                        .archive_checkpoint(h)
                        .unwrap_or_else(|err| fatal!(&log, "{:?}", err))
                }
                Err(err) => {
                    fatal!(
                        log,
                        "Failed to retrieve the checkpoint status @{} from disk: {}",
                        h,
                        err
                    )
                }
            }
        }

        let mut checkpoint_heights = state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| fatal!(&log, "Failed to retrieve checkpoint heights: {:?}", err));

        if let Some(starting_height) = starting_height {
            // Note [Starting Height State Recovery]
            // =====================================
            //
            // We "archive" all the checkpoints that are newer than `starting_height` and can
            // prevent us from recomputing states that consensus might still need.
            // If `starting_height` is None, we start from the most recent checkpoint.
            //
            // For example, let's say we have checkpoints @100 and @200, and consensus still
            // needs all states from 150 onwards. If we now recover from checkpoint @200, we'll never
            // recompute states 150 and above.  So we archive checkpoint @200, to make sure it doesn't
            // interfere with normal operation and continue from @100 instead.
            //
            // NB. We do not apply this heuristic if we only have one
            // checkpoint. Rationale:
            //
            //   1. It's unlikely that we'll be able to recompute old states
            //      this way as we'll have to start from the genesis state.
            //
            //   2. It's a common case if we completed a state sync and
            //      restarted, in which case we'll have to sync again.
            //
            //   3. It looks dangerous to remove the only last state.
            //      What if this somehow happens on all the nodes simultaneously?
            while checkpoint_heights.len() > 1
                && checkpoint_heights.last().cloned().unwrap() > starting_height
            {
                let h = checkpoint_heights.pop().unwrap();
                info!(
                    log,
                    "Archiving checkpoint {} (starting height = {})", h, starting_height
                );
                state_layout
                    .archive_checkpoint(h)
                    .unwrap_or_else(|err| fatal!(&log, "{:?}", err));
            }
        }

        info!(
            log,
            "Archiving checkpoints took {:?}",
            starting_time.elapsed()
        );

        let starting_time = Instant::now();
        cleanup_diverged_states(&log, &state_layout);
        info!(
            log,
            "Cleaning up diverged states took {:?}",
            starting_time.elapsed()
        );

        let starting_time = Instant::now();

        let states = checkpoint_heights
            .iter()
            .map(|height| {
                let cp_layout = state_layout
                    .checkpoint_verified(*height)
                    .unwrap_or_else(|err| {
                        fatal!(
                            log,
                            "Failed to create checkpoint layout @{}: {}",
                            height,
                            err
                        )
                    });
                let state = checkpoint::load_checkpoint_parallel(
                    &cp_layout,
                    own_subnet_type,
                    &metrics.checkpoint_metrics,
                    Arc::clone(&fd_factory),
                )
                .unwrap_or_else(|err| {
                    fatal!(log, "Failed to load checkpoint @{}: {}", height, err)
                });

                (cp_layout, state)
            })
            .collect();

        info!(
            log,
            "Loading checkpoints took {:?}",
            starting_time.elapsed()
        );

        let starting_time = Instant::now();
        let PopulatedMetadata {
            certifications_metadata,
            states_metadata,
            checkpoint_layouts_to_compute_manifest,
            snapshots_with_checkpoint_layouts,
        } = Self::populate_metadata(&log, &metrics, loaded_states_metadata, states);

        info!(
            log,
            "Populating metadata took {:?}",
            starting_time.elapsed()
        );

        let latest_state_height = AtomicU64::new(0);
        let latest_certified_height = AtomicU64::new(0);

        let initial_snapshot = Snapshot {
            height: Self::INITIAL_STATE_HEIGHT,
            state: Arc::new(initial_state(own_subnet_id, own_subnet_type).take()),
        };

        let tip_height_and_state = match snapshots_with_checkpoint_layouts.last() {
            Some((snapshot, checkpoint_layout)) => {
                // Set latest state height in metadata to be last checkpoint height
                latest_state_height.store(snapshot.height.get(), Ordering::Relaxed);
                let starting_time = Instant::now();

                let tip = initialize_tip(&log, &tip_channel, snapshot, checkpoint_layout.clone());

                info!(log, "Initialize tip took {:?}", starting_time.elapsed());
                (snapshot.height, tip)
            }
            None => (
                Self::INITIAL_STATE_HEIGHT,
                ReplicatedState::new(own_subnet_id, own_subnet_type),
            ),
        };

        let snapshots: VecDeque<Snapshot> = std::iter::once(initial_snapshot)
            .chain(
                snapshots_with_checkpoint_layouts
                    .into_iter()
                    .map(|(snapshot, _)| snapshot),
            )
            .collect();

        // Make sure the snapshots' order is maintained in initialization.
        debug_assert!(snapshots
            .iter()
            .zip(snapshots.iter().skip(1))
            .all(|(s0, s1)| s0.height < s1.height));

        let last_snapshot_height = snapshots.back().map(|s| s.height.get() as i64).unwrap_or(0);

        metrics.resident_state_count.set(snapshots.len() as i64);

        metrics.min_resident_height.set(last_snapshot_height);
        metrics.max_resident_height.set(last_snapshot_height);

        let states = Arc::new(parking_lot::RwLock::new(SharedState {
            certifications_metadata,
            states_metadata,
            snapshots,
            last_advertised: Self::INITIAL_STATE_HEIGHT,
            fetch_state: None,
            tip: Some(tip_height_and_state),
        }));

        let persist_metadata_guard = Arc::new(Mutex::new(()));

        #[allow(clippy::disallowed_methods)]
        let (deallocation_sender, deallocation_receiver) = unbounded();
        let _deallocation_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name("StateDeallocation".to_string())
                .spawn({
                    move || {
                        while let Ok(object) = deallocation_receiver.recv() {
                            std::mem::drop(object);
                            // The sleep below is to spread out the load on memory allocator
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }
                })
                .expect("failed to spawn background deallocation thread"),
        );

        for checkpoint_layout in checkpoint_layouts_to_compute_manifest {
            tip_channel
                .send(TipRequest::ComputeManifest {
                    checkpoint_layout,
                    manifest_delta: None,
                    states: states.clone(),
                    persist_metadata_guard: persist_metadata_guard.clone(),
                })
                .expect("failed to send ComputeManifestRequest");
        }

        report_last_diverged_state(&log, &metrics, &state_layout);

        Self {
            log,
            metrics,
            state_layout,
            states,
            verifier,
            own_subnet_id,
            own_subnet_type,
            deallocation_sender,
            latest_state_height,
            latest_certified_height,
            _deallocation_handle,
            persist_metadata_guard,
            tip_channel,
            _tip_thread_handle,
            fd_factory,
            malicious_flags,
            latest_height_update_time: Arc::new(Mutex::new(Instant::now())),
            lsmt_status: config.lsmt_config.lsmt_status,
        }
    }
    /// Returns the Page Allocator file descriptor factory. This will then be
    /// used down the line in hypervisor and state to pass to the page allocators
    /// that are instantiated by the page maps
    pub fn get_fd_factory(&self) -> Arc<dyn PageAllocatorFileDescriptor> {
        Arc::clone(&self.fd_factory)
    }

    /// Returns `StateLayout` pointing to the directory managed by this
    /// StateManager.
    pub fn state_layout(&self) -> &StateLayout {
        &self.state_layout
    }

    /// Reads states metadata file, returning an empty one if any errors occurs.
    ///
    /// It's OK to miss some (or all) metadata entries as it will be re-computed
    /// as part of the recovery procedure.
    fn load_metadata(log: &ReplicaLogger, path: &Path) -> StatesMetadata {
        use std::io::Read;

        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                return Default::default();
            }
            Err(io_err) => {
                error!(
                    log,
                    "Failed to open system metadata file {}: {}",
                    path.display(),
                    io_err
                );
                return Default::default();
            }
        };

        let mut buf = vec![];
        if let Err(e) = file.read_to_end(&mut buf) {
            warn!(
                log,
                "Failed to read metadata file {}: {}",
                path.display(),
                e
            );
            return Default::default();
        }

        match pb::StatesMetadata::decode(&buf[..]) {
            Ok(pb_meta) => {
                let mut map = StatesMetadata::new();
                for (h, pb) in pb_meta.by_height {
                    match StateMetadata::try_from(pb) {
                        Ok(meta) => {
                            if let Some(root_hash) = meta.root_hash() {
                                info!(log, "Recomputed root hash {:?} when loading state metadata at height {}", root_hash, h);
                            }
                            map.insert(Height::new(h), meta);
                        }
                        Err(e) => {
                            warn!(log, "Failed to decode metadata for state {}: {}", h, e);
                        }
                    }
                }
                map
            }
            Err(err) => {
                warn!(
                    log,
                    "Failed to deserialize states metadata at {}: {}",
                    path.display(),
                    err
                );
                Default::default()
            }
        }
    }

    fn release_lock_and_persist_metadata(
        &self,
        states: parking_lot::RwLockWriteGuard<SharedState>,
    ) {
        release_lock_and_persist_metadata(
            &self.log,
            &self.metrics,
            &self.state_layout,
            states,
            &self.persist_metadata_guard,
        );
    }

    fn latest_certified_state(
        &self,
    ) -> Option<(Arc<ReplicatedState>, Certification, Arc<HashTree>)> {
        let states = self.states.read();

        let (height, certification, hash_tree) = states
            .certifications_metadata
            .iter()
            .rev()
            .find_map(|(height, metadata)| {
                let hash_tree = metadata.hash_tree.as_ref()?;
                metadata
                    .certification
                    .clone()
                    .map(|certification| (*height, certification, Arc::clone(hash_tree)))
            })
            .or_else(|| {
                warn!(every_n_seconds => 5,
                      self.log,
                      "No state available with certification.");
                None
            })?;
        let state = states
            .snapshots
            .iter()
            .find_map(|snapshot| (snapshot.height == height).then(|| Arc::clone(&snapshot.state)))
            .or_else(|| {
                warn!(
                    self.log,
                    "Certified state at height {} not available.", height
                );
                None
            })?;
        Some((state, certification, hash_tree))
    }

    /// Returns the state hash of the latest state, irrespective of whether that state was
    /// certified or not. Primarily used for testing.
    pub fn latest_state_certification_hash(&self) -> Option<(Height, CryptoHash)> {
        let states = self.states.read();

        states
            .certifications_metadata
            .iter()
            .next_back()
            .map(|(h, m)| (*h, m.certified_state_hash.clone()))
    }

    /// Returns the manifest of the latest checkpoint on disk with its
    /// checkpoint layout.
    fn latest_manifest(&self) -> Option<(Manifest, CheckpointLayout<ReadOnly>)> {
        self.checkpoint_heights()
            .iter()
            .rev()
            .find_map(|checkpointed_height| {
                let states = self.states.read();
                let metadata = states.states_metadata.get(checkpointed_height)?;
                let manifest = metadata.manifest()?.clone();
                let checkpoint_layout = metadata.checkpoint_layout.clone()?;
                Some((manifest, checkpoint_layout))
            })
    }

    fn compute_certification_metadata(
        metrics: &StateManagerMetrics,
        log: &ReplicaLogger,
        state: &ReplicatedState,
    ) -> Result<CertificationMetadata, HashTreeError> {
        let started_hashing_at = Instant::now();
        let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(state))?;
        let elapsed = started_hashing_at.elapsed();
        debug!(log, "Computed hash tree in {:?}", elapsed);

        update_hash_tree_metrics(&hash_tree, metrics);
        metrics
            .checkpoint_op_duration
            .with_label_values(&["hash_tree"])
            .observe(elapsed.as_secs_f64());

        let certified_state_hash = crypto_hash_of_tree(&hash_tree);

        Ok(CertificationMetadata {
            hash_tree: Some(Arc::new(hash_tree)),
            certified_state_hash,
            certification: None,
        })
    }

    /// Populates appropriate CertificationsMetadata and StatesMetadata for a StateManager
    /// that contains the heights from `states`. A StateMetadata for that state can also
    /// be provided for a subnet of the heights if available.
    fn populate_metadata(
        log: &ReplicaLogger,
        metrics: &StateManagerMetrics,
        mut metadatas: BTreeMap<Height, StateMetadata>,
        states: Vec<(CheckpointLayout<ReadOnly>, ReplicatedState)>,
    ) -> PopulatedMetadata {
        let mut checkpoint_layouts_to_compute_manifest = Vec::<CheckpointLayout<ReadOnly>>::new();

        let mut certifications_metadata = CertificationsMetadata::default();
        let mut states_metadata = StatesMetadata::default();
        let mut snapshots_with_checkpoint_layouts: Vec<(Snapshot, CheckpointLayout<ReadOnly>)> =
            Default::default();

        for (checkpoint_layout, state) in states {
            let height = checkpoint_layout.height();
            certifications_metadata.insert(
                height,
                Self::compute_certification_metadata(metrics, log, &state)
                    .unwrap_or_else(|err| fatal!(log, "Failed to compute hash tree: {:?}", err)),
            );

            let metadata = metadatas.remove(&height);

            let bundled_manifest = metadata.and_then(|metadata| metadata.bundled_manifest);

            if bundled_manifest.is_some() {
                states_metadata.insert(
                    height,
                    StateMetadata {
                        checkpoint_layout: Some(checkpoint_layout.clone()),
                        bundled_manifest,
                        state_sync_file_group: None,
                    },
                );
            } else {
                // It is possible that the replica did not finish manifest computation before restarting.
                // In this case, we need to send a request of manifest computation for this checkpoint.
                checkpoint_layouts_to_compute_manifest.push(checkpoint_layout.clone());

                states_metadata.insert(
                    height,
                    StateMetadata {
                        checkpoint_layout: Some(checkpoint_layout.clone()),
                        bundled_manifest: None,
                        state_sync_file_group: None,
                    },
                );
            }

            snapshots_with_checkpoint_layouts.push((
                Snapshot {
                    height,
                    state: Arc::new(state),
                },
                checkpoint_layout,
            ));
        }

        PopulatedMetadata {
            certifications_metadata,
            states_metadata,
            checkpoint_layouts_to_compute_manifest,
            snapshots_with_checkpoint_layouts,
        }
    }

    fn populate_extra_metadata(&self, state: &mut ReplicatedState, height: Height) {
        state.metadata.state_sync_version = CURRENT_STATE_SYNC_VERSION;
        state.metadata.certification_version = ic_canonical_state::CURRENT_CERTIFICATION_VERSION;

        if height == Self::INITIAL_STATE_HEIGHT {
            return;
        }
        let prev_height = height - Height::from(1);

        if prev_height == Self::INITIAL_STATE_HEIGHT {
            return;
        }

        let states = self.states.read();
        if let Some(metadata) = states.certifications_metadata.get(&prev_height) {
            assert_eq!(
                state.metadata.prev_state_hash,
                Some(CryptoHashOfPartialState::from(
                    metadata.certified_state_hash.clone(),
                ))
            );
        } else {
            info!(
                self.log,
                "The previous certification metadata at height {} has been removed. This can happen when the replica \
                syncs a newer state concurrently and removes the states below.",
                prev_height,
            );
        }
    }

    /// Flushes to disk all the canister heap deltas accumulated in memory
    /// during execution from the last flush.
    fn flush_canister_snapshots_and_page_maps(
        &self,
        tip_state: &mut ReplicatedState,
        height: Height,
    ) {
        flush_canister_snapshots_and_page_maps(
            tip_state,
            height,
            &self.tip_channel,
            &self.metrics.checkpoint_metrics,
        );
    }

    fn find_checkpoint_by_root_hash(
        &self,
        root_hash: &CryptoHashOfState,
    ) -> Option<(Height, Manifest, Arc<MetaManifest>)> {
        self.states
            .read()
            .states_metadata
            .iter()
            .find_map(|(h, metadata)| {
                let bundled_manifest = metadata.bundled_manifest.clone()?;
                if &bundled_manifest.root_hash == root_hash {
                    Some((
                        *h,
                        bundled_manifest.manifest,
                        bundled_manifest.meta_manifest,
                    ))
                } else {
                    None
                }
            })
    }

    fn on_synced_checkpoint(
        &self,
        state: ReplicatedState,
        cp_layout: CheckpointLayout<ReadOnly>,
        manifest: Manifest,
        meta_manifest: Arc<MetaManifest>,
        root_hash: CryptoHashOfState,
    ) {
        let height = cp_layout.height();
        if self
            .state_layout
            .diverged_checkpoint_heights()
            .unwrap_or_default()
            .contains(&height)
        {
            // We have just fetched a state that was marked as diverged
            // before. We make a backup of the pristine state for future
            // investigation and debugging.
            if let Err(err) = self.state_layout.backup_checkpoint(height) {
                info!(
                    self.log,
                    "Failed to backup a pristine version of diverged state {}: {}", height, err
                );
            }
        }

        let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state))
            .unwrap_or_else(|err| fatal!(self.log, "Failed to compute hash tree: {:?}", err));
        update_hash_tree_metrics(&hash_tree, &self.metrics);
        let certification_metadata = CertificationMetadata {
            certified_state_hash: crypto_hash_of_tree(&hash_tree),
            hash_tree: Some(Arc::new(hash_tree)),
            certification: None,
        };

        let mut states = self.states.write();
        #[cfg(debug_assertions)]
        check_certifications_metadata_snapshots_and_states_metadata_are_consistent(&states);
        states.disable_state_fetch_below(height);

        if states
            .snapshots
            .iter()
            .any(|snapshot| snapshot.height == height)
        {
            info!(
                self.log,
                "Completed StateSync for state {} that we already have locally", height
            );
            return;
        }

        states.snapshots.push_back(Snapshot {
            height,
            state: Arc::new(state),
        });
        states
            .snapshots
            .make_contiguous()
            .sort_by_key(|snapshot| snapshot.height);

        self.metrics
            .resident_state_count
            .set(states.snapshots.len() as i64);

        states
            .certifications_metadata
            .insert(height, certification_metadata);

        let state_size_bytes: i64 = manifest
            .file_table
            .iter()
            .map(|f| f.size_bytes as i64)
            .sum();

        states.states_metadata.insert(
            height,
            StateMetadata {
                checkpoint_layout: Some(cp_layout),
                bundled_manifest: Some(BundledManifest {
                    root_hash,
                    manifest,
                    meta_manifest,
                }),
                state_sync_file_group: None,
            },
        );

        let latest_height = update_latest_height(&self.latest_state_height, height);
        if latest_height == height.get() {
            self.metrics.max_resident_height.set(latest_height as i64);
            self.metrics.state_size.set(state_size_bytes);
        }

        self.release_lock_and_persist_metadata(states);

        // Note: it might feel tempting to also set states.tip here.  We should
        // NOT do that.  We might be applying blocks and fetching states in
        // parallel.  Tip is a unique resource that only the state machine
        // should touch.  Instead of pro-actively updating tip here, we let the
        // state machine discover a newer state the next time it calls
        // `take_tip()` and update the tip accordingly.
    }

    /// Remove any inmemory state at height h with h < last_height_to_keep, and
    /// any checkpoint at height h < last_checkpoint_to_keep
    ///
    /// Shared inner function of the public functions remove_states_below
    /// and remove_inmemory_states_below
    fn remove_states_below_impl(
        &self,
        last_height_to_keep: Height,
        last_checkpoint_to_keep: Height,
    ) {
        debug_assert!(
            last_height_to_keep >= last_checkpoint_to_keep,
            "last_height_to_keep: {}, last_checkpoint_to_keep: {}",
            last_height_to_keep,
            last_checkpoint_to_keep
        );

        // In debug builds we store the latest_state_height here so
        // that we can verify later that this height is retained.
        #[cfg(debug_assertions)]
        let latest_state_height = self.latest_state_height();

        let heights_to_remove = std::ops::Range {
            start: Height::new(1),
            end: last_height_to_keep,
        };

        let mut states = self.states.write();

        let number_of_checkpoints = states.states_metadata.len();

        // We obtain the latest certified state inside the state mutex to avoid race conditions where new certifications might arrive
        let latest_certified_height = self.latest_certified_height();
        let latest_manifest_height =
            states
                .states_metadata
                .iter()
                .rev()
                .find_map(|(height, state_metadata)| {
                    state_metadata.bundled_manifest.as_ref().map(|_| *height)
                });

        let heights_to_keep: BTreeSet<Height> = states
            .states_metadata
            .keys()
            .copied()
            .filter(|height| {
                *height == Self::INITIAL_STATE_HEIGHT || *height >= last_checkpoint_to_keep
            })
            .chain(std::iter::once(latest_certified_height))
            .chain(latest_manifest_height)
            .collect();

        // Send object to deallocation thread if it has capacity.
        let deallocate = |x| {
            if self.deallocation_sender.len() < DEALLOCATION_BACKLOG_THRESHOLD {
                self.deallocation_sender
                    .send(x)
                    .expect("failed to send object to deallocation thread");
            } else {
                std::mem::drop(x);
            }
        };

        let (removed, retained) = states.snapshots.drain(0..).partition(|snapshot| {
            heights_to_remove.contains(&snapshot.height)
                && !heights_to_keep.contains(&snapshot.height)
        });
        states.snapshots = retained;

        self.metrics
            .resident_state_count
            .set(states.snapshots.len() as i64);

        let latest_height = states
            .snapshots
            .back()
            .map(|s| s.height)
            .unwrap_or(Self::INITIAL_STATE_HEIGHT);

        self.latest_state_height
            .store(latest_height.get(), Ordering::Relaxed);

        let min_resident_height: Option<Height> = states
            .snapshots
            .iter()
            .map(|s| s.height)
            .filter(|h| h.get() != 0)
            .chain(states.states_metadata.keys().copied())
            .min();
        if let Some(min_resident_height) = min_resident_height {
            self.metrics
                .min_resident_height
                .set(min_resident_height.get() as i64);
        }

        self.metrics
            .max_resident_height
            .set(latest_height.get() as i64);

        // Send removed snapshot to deallocator thread
        deallocate(Box::new(removed));

        for (height, metadata) in states.states_metadata.range(heights_to_remove) {
            if heights_to_keep.contains(height) {
                continue;
            }
            if let Some(ref checkpoint_layout) = metadata.checkpoint_layout {
                self.state_layout
                    .remove_checkpoint_when_unused(checkpoint_layout.height());
            }
        }

        let mut certifications_metadata = states
            .certifications_metadata
            .split_off(&last_height_to_keep);

        for h in heights_to_keep.iter() {
            if let Some(cert_metadata) = states.certifications_metadata.remove(h) {
                certifications_metadata.insert(*h, cert_metadata);
            }
        }

        std::mem::swap(
            &mut certifications_metadata,
            &mut states.certifications_metadata,
        );

        // Send removed certification metadata to deallocator thread
        deallocate(Box::new(certifications_metadata));

        let latest_certified_height = states
            .certifications_metadata
            .iter()
            .rev()
            .find_map(|(h, m)| m.certification.as_ref().map(|_| *h))
            .unwrap_or(Self::INITIAL_STATE_HEIGHT);

        self.latest_certified_height
            .store(latest_certified_height.get(), Ordering::Relaxed);

        self.metrics
            .latest_certified_height
            .set(latest_certified_height.get() as i64);

        let mut metadata_to_keep = states.states_metadata.split_off(&last_height_to_keep);

        for h in heights_to_keep.iter() {
            if let Some(metadata) = states.states_metadata.remove(h) {
                metadata_to_keep.insert(*h, metadata);
            }
        }
        std::mem::swap(&mut states.states_metadata, &mut metadata_to_keep);
        if *ic_sys::IS_WSL {
            // We send obsolete metadata to deallocation thread so that they are freed
            // AFTER the in-memory states. We do this because in-memory states might
            // have PageMap objects that are still referencing the checkpoints, and
            // attempting to delete a file that is still open causes errors when
            // running on WSL (even though it's a perfectly valid usage on UNIX systems).
            //
            // NOTE: we rely on deallocations happening sequentially, adding more
            // deallocation threads might break the desired behavior.
            deallocate(Box::new(metadata_to_keep));
        }

        if number_of_checkpoints != states.states_metadata.len() {
            // We removed a checkpoint, so states_metadata needs to be updated on disk
            self.release_lock_and_persist_metadata(states);
        } else {
            drop(states);
        }

        #[cfg(debug_assertions)]
        {
            use ic_interfaces_state_manager::CERT_ANY;
            let unfiltered_checkpoint_heights = self
                .state_layout
                .unfiltered_checkpoint_heights()
                .unwrap_or_else(|err| {
                    fatal!(
                        &self.log,
                        "Failed to retrieve unfiltered checkpoint heights: {:?}",
                        err
                    )
                });

            let state_heights = self.list_state_heights(CERT_ANY);

            debug_assert!(heights_to_keep.iter().all(|h| unfiltered_checkpoint_heights
                .contains(h)
                || *h == latest_certified_height));

            debug_assert!(state_heights.contains(&latest_state_height));
            debug_assert!(state_heights.contains(&latest_certified_height));
        }
    }

    pub fn checkpoint_heights(&self) -> Vec<Height> {
        let result = self
            .state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(self.log, "Failed to gather checkpoint heights: {:?}", err)
            });

        self.metrics
            .checkpoints_on_disk_count
            .set(result.len() as i64);

        result
    }

    // Creates a checkpoint and switches state to it.
    fn create_checkpoint_and_switch(
        &self,
        state: &mut ReplicatedState,
        height: Height,
    ) -> CreateCheckpointResult {
        struct PreviousCheckpointInfo {
            dirty_pages: DirtyPages,
            base_manifest: Manifest,
            base_height: Height,
            checkpoint_layout: CheckpointLayout<ReadOnly>,
        }

        let start = Instant::now();
        {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["wait_for_manifest_and_flush"])
                .start_timer();
            // We need the previous manifest computation to complete because:
            //   1) We need it it speed up the next manifest computation using ManifestDelta
            //   2) We don't want to run too much ahead of the latest ready manifest.
            self.flush_tip_channel();
        }

        let previous_checkpoint_info = {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["previous_checkpoint_info"])
                .start_timer();
            let states = self.states.read();
            states
                .states_metadata
                .iter()
                .rev()
                .find_map(|(base_height, state_metadata)| {
                    let base_manifest = state_metadata.manifest()?.clone();
                    Some((base_manifest, *base_height))
                })
                .and_then(|(base_manifest, base_height)| {
                    if let Ok(checkpoint_layout) = self.state_layout.checkpoint_verified(base_height) {
                        // If `lsmt_status` is enabled, then `dirty_pages` is not needed, as each file is either completely
                        // new, or identical (same inode) to before.
                        let dirty_pages = match self.lsmt_status {
                            FlagStatus::Enabled => Vec::new(),
                            FlagStatus::Disabled => get_dirty_pages(state),
                        };
                        Some(PreviousCheckpointInfo {
                            dirty_pages,
                            base_manifest,
                            base_height,
                            checkpoint_layout,
                        })
                    } else {
                        warn!(self.log,
                            "Failed to get base checkpoint layout for height {}. Fallback to full manifest computation",
                            base_height);
                        None
                    }
                })
        };

        {
            // We don't need to persist the deltas to the tip because we
            // flush deltas before calling this method, see flush_page_maps.
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["strip_page_map_deltas"])
                .start_timer();
            strip_page_map_deltas(state, self.get_fd_factory());
        }
        let result = {
            checkpoint::make_checkpoint(
                state,
                height,
                &self.tip_channel,
                &self.metrics.checkpoint_metrics,
                &mut scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS),
                self.get_fd_factory(),
                self.lsmt_status,
            )
        };
        let (cp_layout, checkpointed_state, has_downgrade) = match result {
            Ok(response) => response,
            Err(CheckpointError::AlreadyExists(_)) => {
                warn!(
                    self.log,
                    "Failed to create checkpoint @{} because it already exists, \
                    re-loading the checkpoint from disk",
                    height
                );

                let (cp_verified, checkpointed_state) = self
                    .state_layout
                    .checkpoint_in_verification(height)
                    .map_err(CheckpointError::from)
                    .and_then(|layout| {
                        let _timer = self
                            .metrics
                            .checkpoint_op_duration
                            .with_label_values(&["recover"])
                            .start_timer();
                        let state = checkpoint::load_checkpoint_parallel_and_mark_verified(
                            &layout,
                            self.own_subnet_type,
                            &self.metrics.checkpoint_metrics,
                            self.get_fd_factory(),
                        )?;
                        Ok((layout, state))
                    })
                    .unwrap_or_else(|err| {
                        fatal!(
                            self.log,
                            "Failed to load existing checkpoint @{}: {}",
                            height,
                            err
                        )
                    });
                (
                    cp_verified,
                    checkpointed_state,
                    // HasDowngrade::Yes is the conservative choice, opting for full Manifest computation.
                    HasDowngrade::Yes,
                )
            }
            Err(err) => fatal!(
                self.log,
                "Failed to make a checkpoint @{}: {:?}",
                height,
                err
            ),
        };
        {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["validate_eq"])
                .start_timer();
            let start = Instant::now();
            if let Err(err) = checkpointed_state.validate_eq(&state) {
                error!(
                    self.log,
                    "{}: Replicated state altered: {}",
                    CRITICAL_ERROR_REPLICATED_STATE_ALTERED_AFTER_CHECKPOINT,
                    err
                );
                self.metrics
                    .checkpoint_metrics
                    .replicated_state_altered_after_checkpoint
                    .inc();
            }
        }
        {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["switch_to_checkpoint"])
                .start_timer();
            switch_to_checkpoint(state, &checkpointed_state);
            #[cfg(debug_assertions)]
            {
                self.tip_channel
                    .send(TipRequest::ValidateReplicatedState {
                        checkpointed_state: Box::new(checkpointed_state.clone()),
                        execution_state: Box::new(state.clone()),
                    })
                    .expect("Failed to send Validate request");
                self.flush_tip_channel();
            }
        }

        // On the NNS subnet we never allow incremental manifest computation
        let is_nns = self.own_subnet_id == state.metadata.network_topology.nns_subnet_id;
        let manifest_delta = if is_nns || has_downgrade == HasDowngrade::Yes {
            None
        } else {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["manifest_delta"])
                .start_timer();
            previous_checkpoint_info.map(
                |PreviousCheckpointInfo {
                     dirty_pages,
                     checkpoint_layout,
                     base_manifest,
                     base_height,
                 }| {
                    manifest::ManifestDelta {
                        base_manifest,
                        base_height,
                        target_height: height,
                        dirty_memory_pages: dirty_pages,
                        base_checkpoint: checkpoint_layout,
                        lsmt_status: self.lsmt_status,
                    }
                },
            )
        };

        let result = {
            let _timer = self
                .metrics
                .checkpoint_metrics
                .make_checkpoint_step_duration
                .with_label_values(&["create_checkpoint_result"])
                .start_timer();
            // With lsmt, we do not need the defrag.
            // Without lsmt, the ResetTipAndMerge happens earlier in make_checkpoint.
            let tip_requests = if self.lsmt_status == FlagStatus::Enabled {
                vec![TipRequest::ResetTipAndMerge {
                    checkpoint_layout: cp_layout.clone(),
                    pagemaptypes_with_num_pages: pagemaptypes_with_num_pages(state),
                    is_initializing_tip: false,
                }]
            } else {
                vec![TipRequest::DefragTip {
                    height,
                    page_map_types: PageMapType::list_all_without_snapshots(state),
                }]
            };

            CreateCheckpointResult {
                tip_requests,
                checkpointed_state,
                state_metadata: StateMetadata {
                    checkpoint_layout: Some(cp_layout.clone()),
                    bundled_manifest: None,
                    state_sync_file_group: None,
                },
                compute_manifest_request: TipRequest::ComputeManifest {
                    checkpoint_layout: cp_layout,
                    manifest_delta,
                    states: self.states.clone(),
                    persist_metadata_guard: self.persist_metadata_guard.clone(),
                },
            }
        };

        let elapsed = start.elapsed();
        info!(self.log, "Created checkpoint @{} in {:?}", height, elapsed);
        self.metrics
            .checkpoint_op_duration
            .with_label_values(&["create"])
            .observe(elapsed.as_secs_f64());
        result
    }

    pub fn test_only_send_wait_to_tip_channel(&self, sender: Sender<()>) {
        self.tip_channel.send(TipRequest::Wait { sender }).unwrap();
    }

    fn certified_state_reader(&self) -> Option<CertifiedStateSnapshotImpl> {
        let read_certified_state_duration_histogram = self
            .metrics
            .api_call_duration
            .with_label_values(&["read_certified_state"]);

        let (state, certification, hash_tree) = self.latest_certified_state()?;
        Some(CertifiedStateSnapshotImpl {
            read_certified_state_duration_histogram,
            state,
            certification,
            hash_tree,
        })
    }
}

/// Flushes to disk all the canister heap deltas accumulated in memory
/// during execution from the last flush.
fn flush_canister_snapshots_and_page_maps(
    tip_state: &mut ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    metrics: &CheckpointMetrics,
) {
    metrics.page_map_flushes.inc();
    let mut pagemaps = Vec::new();

    let mut add_to_pagemaps_and_strip = |entry, page_map: &mut PageMap| {
        // In cases where a PageMap's data has to be wiped, execution will replace the PageMap with a newly
        // created one. In these cases, we also need to wipe the data from the file on disk.
        // If the PageMap represents a new file, then the base_height will be None, as we set base_height only
        // when loading a PageMap from a checkpoint. Furthermore, we only want to wipe data from the file on
        // disk before applying any unflushed deltas of that PageMap. We detect this case by looking at
        // has_stripped_unflushed_deltas, which will be false at the beginning, but true as soon as we strip unflushed
        // deltas for the first time in the lifetime of the PageMap. As a result, if there is no base_height and
        // we have not persisted unflushed deltas before, then there are no relevant pages beyond the ones in the
        // unlushed delta, and we truncate the file on disk to size 0.
        let truncate = page_map.base_height.is_none() && !page_map.has_stripped_unflushed_deltas();
        let page_map_clone = if !page_map.unflushed_delta_is_empty() {
            Some(page_map.clone())
        } else {
            None
        };
        if truncate || page_map_clone.is_some() {
            pagemaps.push(PageMapToFlush {
                page_map_type: entry,
                truncate,
                page_map: page_map_clone,
            });
        }
        // We strip empty unflushed deltas to keep has_stripped_unflushed_deltas() correct
        page_map.strip_unflushed_delta();
    };

    for (id, canister) in tip_state.canister_states.iter_mut() {
        add_to_pagemaps_and_strip(
            PageMapType::WasmChunkStore(id.to_owned()),
            canister.system_state.wasm_chunk_store.page_map_mut(),
        );
        if let Some(execution_state) = canister.execution_state.as_mut() {
            add_to_pagemaps_and_strip(
                PageMapType::WasmMemory(id.to_owned()),
                &mut execution_state.wasm_memory.page_map,
            );
            add_to_pagemaps_and_strip(
                PageMapType::StableMemory(id.to_owned()),
                &mut execution_state.stable_memory.page_map,
            );
        }
    }

    // Take all snapshot operations that happened since the last flush and clear the list stored in `tip_state`.
    // This way each operation is executed exactly once, independent of how many times `flush_page_maps` is called.
    let snapshot_operations = tip_state.canister_snapshots.take_unflushed_changes();

    for op in &snapshot_operations {
        // Only CanisterSnapshots that are new since the last flush will have PageMaps that need to be flushed. They will
        // have a corresponding Backup in the snapshot operations list.
        if let SnapshotOperation::Backup(_canister_id, snapshot_id) = op {
            // If we can't find the CanisterSnapshot they must have been already deleted again. Nothing to flush in this case.
            if let Some(canister_snapshot) = tip_state.canister_snapshots.get_mut(*snapshot_id) {
                let new_snapshot = Arc::make_mut(canister_snapshot);

                add_to_pagemaps_and_strip(
                    PageMapType::SnapshotWasmChunkStore(*snapshot_id),
                    new_snapshot.chunk_store_mut().page_map_mut(),
                );
                add_to_pagemaps_and_strip(
                    PageMapType::SnapshotWasmMemory(*snapshot_id),
                    &mut new_snapshot.execution_snapshot_mut().wasm_memory.page_map,
                );
                add_to_pagemaps_and_strip(
                    PageMapType::SnapshotStableMemory(*snapshot_id),
                    &mut new_snapshot.execution_snapshot_mut().stable_memory.page_map,
                );
            }
        }
    }

    if !pagemaps.is_empty() || !snapshot_operations.is_empty() {
        tip_channel
            .send(TipRequest::FlushPageMapDelta {
                height,
                pagemaps,
                snapshot_operations,
            })
            .unwrap();
        // We flush further when the tip_channel queue is not empty. Meaning we're blind
        // to a request being processed, so we send Noop to signal for the busy Tip Thread.
        tip_channel.send(TipRequest::Noop).unwrap();
    }
}

fn initial_state(own_subnet_id: SubnetId, own_subnet_type: SubnetType) -> Labeled<ReplicatedState> {
    Labeled::new(
        StateManagerImpl::INITIAL_STATE_HEIGHT,
        ReplicatedState::new(own_subnet_id, own_subnet_type),
    )
}

fn crypto_hash_of_tree(t: &HashTree) -> CryptoHash {
    CryptoHash(t.root_hash().0.to_vec())
}

fn update_latest_height(cached: &AtomicU64, h: Height) -> u64 {
    let h = h.get();
    cached.fetch_max(h, Ordering::Relaxed).max(h)
}

/// Helper function to set metrics related to hash trees
fn update_hash_tree_metrics(hash_tree: &HashTree, metrics: &StateManagerMetrics) {
    metrics.latest_hash_tree_size.set(hash_tree.size() as i64);
    metrics
        .latest_hash_tree_max_index
        .set(hash_tree.max_index() as i64);
}

impl StateManager for StateManagerImpl {
    /// Note that this function intentionally does not use
    /// `latest_state_height()` to figure out if state at the requested height
    /// has been committed yet or not because `latest_state_height()` consults
    /// the disk to figure out what the latest state is.  So if the state at the
    /// requested height is only available on disk, there is still no snapshot
    /// of the state so the root_hash is not available.
    fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_state_hash_at"])
            .start_timer();

        let states = self.states.read();

        states
            .states_metadata
            .get(&height)
            .ok_or_else(|| match states.certifications_metadata.iter().next_back() {
                Some((key, _)) => {
                    if *key < height {
                        StateHashError::Transient(StateNotCommittedYet(height))
                    } else {
                        // If the state is older than the oldest state we still have,
                        // we report it as having been removed
                        let oldest_kept = states
                            .certifications_metadata
                            .iter()
                            .next()
                            .map(|(height, _)| *height)
                            .unwrap(); // certifications_metadata cannot be empty in this branch

                        if height < oldest_kept {
                            // The state might have been not fully certified in addition to
                            // being removed. We don't know anymore.
                            StateHashError::Permanent(StateRemoved(height))
                        } else {
                            StateHashError::Permanent(StateNotFullyCertified(height))
                        }
                    }
                }
                None => StateHashError::Transient(StateNotCommittedYet(height)),
            })
            .map(|metadata| metadata.root_hash().cloned())
            .transpose()
            .unwrap_or(Err(StateHashError::Transient(HashNotComputedYet(height))))
    }

    fn take_tip(&self) -> (Height, ReplicatedState) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["take_tip"])
            .start_timer();

        let hash_at = |tip_height: Height, certifications_metadata: &CertificationsMetadata| {
            if tip_height > Self::INITIAL_STATE_HEIGHT {
                let tip_metadata = certifications_metadata.get(&tip_height).unwrap_or_else(|| {
                    fatal!(self.log, "Bug: missing tip metadata @{}", tip_height)
                });

                // Since the state machine will use this tip to compute the *next* state,
                // we populate the prev_state_hash with the hash of the current tip.
                Some(CryptoHashOfPartialState::from(
                    tip_metadata.certified_state_hash.clone(),
                ))
            } else {
                // This code is executed at most once per subnet, no need to
                // optimize this.
                let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(
                    initial_state(self.own_subnet_id, self.own_subnet_type).get_ref(),
                ))
                .unwrap_or_else(|err| fatal!(self.log, "Failed to compute hash tree: {:?}", err));
                update_hash_tree_metrics(&hash_tree, &self.metrics);
                Some(CryptoHashOfPartialState::from(crypto_hash_of_tree(
                    &hash_tree,
                )))
            }
        };

        let mut states = self.states.write();
        let (tip_height, mut tip) = states.tip.take().expect("failed to get TIP");

        let (target_snapshot, target_hash) = match states.snapshots.back() {
            Some(snapshot) if snapshot.height > tip_height => (
                snapshot.clone(),
                hash_at(snapshot.height, &states.certifications_metadata),
            ),
            _ => {
                tip.metadata.prev_state_hash = hash_at(tip_height, &states.certifications_metadata);
                return (tip_height, tip);
            }
        };

        // The latest checkpoint is newer than tip.
        // This can happen when we replay blocks and sync states concurrently.
        //
        // We release the states write lock here because loading a checkpoint
        // can take a lot of time (many seconds), and we do not want to block
        // state readers (like HTTP handler) for too long.
        //
        // We are keeping a CheckpointLayout for the checkpoint that is becoming
        // the tip, in order to ensure that it does not get deleted.
        //
        // Note that we still will not call initialize_tip()
        // concurrently because only a thread that owns the tip can call
        // this function.
        //
        // This thread has already consumed states.tip, so a concurrent call to
        // take_tip() will fail on states.tip.take().
        //
        // In general, there should always be one thread that calls
        // take_tip() and commit_and_certify() — the state machine thread.

        let checkpoint_layout = states
            .states_metadata
            .get(&target_snapshot.height)
            .unwrap()
            .checkpoint_layout
            .as_ref()
            .unwrap()
            .clone();
        std::mem::drop(states);

        let mut new_tip = initialize_tip(
            &self.log,
            &self.tip_channel,
            &target_snapshot,
            checkpoint_layout,
        );

        new_tip.metadata.prev_state_hash = target_hash;

        // This might still not be the latest version: there might have been
        // another successful state sync while we were updating the tip.
        // That is not a problem: we will handle this case later in commit_and_certify().
        (target_snapshot.height, new_tip)
    }

    fn take_tip_at(&self, height: Height) -> StateManagerResult<ReplicatedState> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["take_tip_at"])
            .start_timer();

        let (tip_height, state) = self.take_tip();

        let mut states = self.states.write();
        assert!(states.tip.is_none());

        if height < tip_height {
            states.tip = Some((tip_height, state));
            return Err(StateManagerError::StateRemoved(height));
        }
        if tip_height < height {
            states.tip = Some((tip_height, state));
            return Err(StateManagerError::StateNotCommittedYet(height));
        }

        Ok(state)
    }

    fn fetch_state(
        &self,
        height: Height,
        root_hash: CryptoHashOfState,
        cup_interval_length: Height,
    ) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["fetch_state"])
            .start_timer();

        match self.get_state_hash_at(height) {
            Ok(hash) => assert_eq!(
                hash, root_hash,
                "The hash of requested state {:?} at height {} doesn't match the locally computed hash {:?}",
                root_hash, height, hash
            ),
            Err(StateHashError::Transient(HashNotComputedYet(_))) => {
                // The state is already available, but we haven't finished
                // computing the hash yet.
            }
            Err(StateHashError::Permanent(StateRemoved(_))) => {
                // No need to fetch an old state, nothing to do.
                info!(
                    self.log,
                    "Requested fetch of an old state @{}, hash = {:?}", height, root_hash
                );
            }
            Err(StateHashError::Permanent(StateNotFullyCertified(_)))=> {
                // This could trigger if we already have a local state at that height, but that height is not a checkpoint. This could possibly be a fatal log.
                error!(
                    self.log,
                    "Requested fetch of a state @{}, which was committed with `CertificationScope::Metadata`, hash = {:?}", height, root_hash
                );
            }
            Err(StateHashError::Transient(StateNotCommittedYet(_))) => {
                // Let's see if we already have this state locally.  This might
                // be the case if we are in subnet recovery mode and
                // re-introducing some old state with a new height.
                if let Some((checkpoint_height, manifest, meta_manifest)) = self.find_checkpoint_by_root_hash(&root_hash) {
                    info!(self.log,
                          "Copying checkpoint {} with root hash {:?} under new height {}",
                          checkpoint_height, root_hash, height);

                    match self.state_layout.checkpoint_verification_status(checkpoint_height) {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(self.log,
                                "Unverified checkpoint @{} cannot be cloned to a new checkpoint height.",
                                checkpoint_height
                            );
                            return;
                        }
                        Err(err) => {
                            warn!(self.log,
                                "Checkpoint @{} does not exist but it is found in states metadata: {:?}",
                                checkpoint_height,
                                err
                            );
                            return;
                        }
                    }

                    // Clone the checkpoint if it is verified.
                    match self.state_layout.clone_checkpoint(checkpoint_height, height) {
                        Ok(_) => {
                            let (state, cp_layout) = load_checkpoint(&self.state_layout, height, &self.metrics, self.own_subnet_type, Arc::clone(&self.get_fd_factory()))
                                .expect("failed to load checkpoint");
                            self.on_synced_checkpoint(state, cp_layout, manifest, meta_manifest, root_hash);
                            return;
                        }
                        Err(e) => {
                            warn!(self.log,
                                  "Failed to clone checkpoint {} => {}: {}",
                                  checkpoint_height, height, e
                            );
                        }
                    }
                }

                // Normal path: we don't have the state locally, let's fetch it.
                let mut states = self.states.write();
                match &states.fetch_state {
                    None => {
                        info!(
                            self.log,
                            "Setting new target state to fetch: height = {}, hash = {:?}",
                            height,
                            root_hash
                        );
                        states.fetch_state = Some((height, root_hash, cup_interval_length));
                    }
                    Some((prev_height, prev_hash, _prev_cup_interval_length)) => {
                        use std::cmp::Ordering;

                        match prev_height.cmp(&height) {
                            Ordering::Less => {
                                info!(
                                    self.log,
                                    "Updating target state to fetch from {} to {}",
                                    prev_height,
                                    height
                                );
                                states.fetch_state = Some((height, root_hash, cup_interval_length))
                            }
                            Ordering::Equal => {
                                assert_eq!(
                                    *prev_hash, root_hash,
                                    "Requested to fetch the same state {} twice with different hashes: first {:?}, then {:?}",
                                    height, prev_hash, root_hash
                                );
                            }
                            Ordering::Greater => {
                                info!(self.log, "Ignoring request to fetch state {} below current target state {}", height, prev_height);
                            }
                        }
                    }
                }
            }
        }
    }

    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["list_state_hashes_to_certify"])
            .start_timer();

        self.states
            .read()
            .certifications_metadata
            .iter()
            .filter(|(_, metadata)| metadata.certification.is_none())
            .map(|(height, metadata)| {
                (
                    *height,
                    CryptoHashOfPartialState::from(metadata.certified_state_hash.clone()),
                )
            })
            .collect()
    }

    fn deliver_state_certification(&self, certification: Certification) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["deliver_state_certification"])
            .start_timer();
        let certification_height = certification.height;
        let mut states = self.states.write();
        if let Some(metadata) = states
            .certifications_metadata
            .get_mut(&certification.height)
        {
            let hash = metadata.certified_state_hash.clone();
            if certification.signed.content.hash.get_ref() != &hash {
                if let Err(err) = self
                    .state_layout
                    .create_diverged_state_marker(certification_height)
                {
                    error!(
                        self.log,
                        "Failed to mark state @{} diverged: {}", certification_height, err
                    );
                }
                panic!(
                    "delivered certification has invalid hash, expected {:?}, received {:?}",
                    hash, certification.signed.content.hash
                );
            }
            let latest_certified =
                update_latest_height(&self.latest_certified_height, certification.height);

            self.metrics
                .latest_certified_height
                .set(latest_certified as i64);

            metadata.certification = Some(certification);

            for (_, certification_metadata) in states
                .certifications_metadata
                .range_mut(Self::INITIAL_STATE_HEIGHT..certification_height)
            {
                if let Some(tree) = certification_metadata.hash_tree.take() {
                    self.deallocation_sender
                        .send(Box::new(tree))
                        .expect("failed to send object to deallocation thread");
                }
            }
        }
    }

    /// # Panics
    ///
    /// This method panics if checkpoint labels can not be retrieved
    /// from the disk.
    fn list_state_heights(&self, cert_mask: CertificationMask) -> Vec<Height> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["list_state_heights"])
            .start_timer();

        fn matches(cert: Option<&Certification>, mask: CertificationMask) -> bool {
            match cert {
                Some(_) => mask.is_set(CERT_CERTIFIED),
                None => mask.is_set(CERT_UNCERTIFIED),
            }
        }

        let states = self.states.read();

        let heights: BTreeSet<_> = self
            .checkpoint_heights()
            .into_iter()
            .chain(states.snapshots.iter().map(|snapshot| snapshot.height))
            .filter(|h| {
                matches(
                    states
                        .certifications_metadata
                        .get(h)
                        .and_then(|metadata| metadata.certification.as_ref()),
                    cert_mask,
                )
            })
            .collect();

        // convert the b-tree into a vector
        heights.into_iter().collect()
    }

    /// This method instructs the state manager that Consensus doesn't need
    /// any states strictly lower than the specified `height`.  The
    /// implementation purges some of these states using the heuristic
    /// described below.
    ///
    /// # Notation
    ///
    ///  * *OCK* stands for "Oldest verified Checkpoint to Keep". This is the height of
    ///    the latest verified checkpoint ≤ H passed to `remove_states_below`.
    ///  * *LSH* stands for "Latest State Height". This is the latest state that
    ///    the state manager has.
    ///  * *LCH* stands for "Latest verified Checkpoint Height". This is the height of
    ///    the latest verified checkpoint that the state manager created.
    ///  * *CHS* stands for "verified CHeckpoint Heights". These are heights of all the
    ///    verified checkpoints available.
    ///
    /// # Heuristic
    ///
    /// We remove all states with heights greater than 0 and smaller than
    /// `min(LSH, H)` while keeping all the checkpoints more recent or equal
    /// to OCK together with the most recent checkpoint.
    ///
    /// ```text
    ///   removed_states(H) := (0, min(LSH, H))
    ///                        \ { ch | ch ∈ CHS ∧ ch >= OCK }
    ///                        \ { max(CHS) }
    ///  ```
    ///
    /// # Rationale
    ///
    /// * We can only remove states strictly lower than LSH because the replica won't
    ///   be able to make progress otherwise. It's quite normal for Consensus to be
    ///   slightly ahead of execution, so we can't blindly remove everything that
    ///   Consensus doesn't need anymore.
    ///
    /// * When state manager restarts, it needs to load the oldest checkpoint to keep,
    ///   see Note [Oldest Required State Recovery]. Therefore, we keep the
    ///   oldest checkpoint to keep and more recent checkpoints.
    ///
    /// * We keep the (EXTRA_CHECKPOINTS_TO_KEEP + 1) most recent checkpoints to increase
    ///   average checkpoint lifetime. The larger the lifetime, the more time other nodes
    ///   have to sync states.
    ///
    /// * We always keep the latest certified state
    fn remove_states_below(&self, requested_height: Height) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["remove_states_below"])
            .start_timer();

        let checkpoint_heights: BTreeSet<Height> = self.checkpoint_heights().into_iter().collect();

        // The latest state must be kept.
        let latest_state_height = self.latest_state_height();
        let oldest_height_to_keep = latest_state_height
            .min(requested_height)
            .max(Height::new(1));

        let oldest_checkpoint_to_keep = if checkpoint_heights.is_empty() {
            Self::INITIAL_STATE_HEIGHT
        } else {
            // The latest checkpoint below or at the requested height will also be kept
            // because the state manager needs to load from it when restarting.
            let oldest_checkpoint_to_keep = checkpoint_heights
                .iter()
                .filter(|x| **x <= requested_height)
                .max()
                .copied()
                .unwrap_or(requested_height);

            // Keep extra checkpoints for state sync.
            checkpoint_heights
                .iter()
                .rev()
                .take(EXTRA_CHECKPOINTS_TO_KEEP + 1)
                .copied()
                .min()
                .unwrap_or(oldest_height_to_keep)
                .min(oldest_height_to_keep)
                .min(oldest_checkpoint_to_keep)
        };

        self.remove_states_below_impl(oldest_height_to_keep, oldest_checkpoint_to_keep);
    }

    /// Variant of `remove_states_below()` that only removes states committed with
    /// partial certification scope.
    ///
    /// The following states are NOT removed:
    /// * Any state with height >= requested_height
    /// * Checkpoint heights
    /// * The latest state
    /// * The latest certified state
    /// * State 0
    fn remove_inmemory_states_below(&self, requested_height: Height) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["remove_inmemory_states_below"])
            .start_timer();

        // The latest state must be kept.
        let latest_state_height = self.latest_state_height();
        let oldest_height_to_keep = latest_state_height
            .min(requested_height)
            .max(Height::new(1));

        self.remove_states_below_impl(oldest_height_to_keep, Self::INITIAL_STATE_HEIGHT);
    }

    fn commit_and_certify(
        &self,
        mut state: Self::State,
        height: Height,
        scope: CertificationScope,
        batch_summary: Option<BatchSummary>,
    ) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["commit_and_certify"])
            .start_timer();

        self.metrics
            .tip_handler_queue_length
            .set(self.tip_channel.len() as i64);

        self.populate_extra_metadata(&mut state, height);

        let mut state_metadata_and_compute_manifest_request: Option<(StateMetadata, TipRequest)> =
            None;
        let mut follow_up_tip_requests = Vec::new();

        let checkpointed_state = match scope {
            CertificationScope::Full => {
                self.flush_canister_snapshots_and_page_maps(&mut state, height);
                let CreateCheckpointResult {
                    checkpointed_state,
                    state_metadata,
                    compute_manifest_request,
                    tip_requests,
                } = self.create_checkpoint_and_switch(&mut state, height);
                state_metadata_and_compute_manifest_request =
                    Some((state_metadata, compute_manifest_request));
                follow_up_tip_requests = tip_requests;

                checkpointed_state
            }
            CertificationScope::Metadata => {
                match self.lsmt_status {
                    FlagStatus::Enabled => {
                        // We want to balance writing too many overlay files with having too many unflushed pages at
                        // checkpoint time, when we always flush all remaining pages while blocking. As a compromise,
                        // we flush all pages `NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY` rounds before each
                        // checkpoint, giving us roughly that many seconds to write these overlay files in the background.
                        if let Some(batch_summary) = batch_summary {
                            if batch_summary
                                .next_checkpoint_height
                                .get()
                                .saturating_sub(height.get())
                                == NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY
                            {
                                self.flush_canister_snapshots_and_page_maps(&mut state, height);
                            }
                        }
                    }
                    FlagStatus::Disabled => {
                        if self.tip_channel.is_empty() {
                            self.flush_canister_snapshots_and_page_maps(&mut state, height);
                        } else {
                            self.metrics.checkpoint_metrics.page_map_flush_skips.inc();
                        }
                    }
                }

                {
                    let _timer = self
                        .metrics
                        .checkpoint_op_duration
                        .with_label_values(&["copy_state"])
                        .start_timer();
                    state.clone()
                }
            }
        };

        let certification_metadata =
            Self::compute_certification_metadata(&self.metrics, &self.log, &checkpointed_state)
                .unwrap_or_else(|err| fatal!(self.log, "Failed to compute hash tree: {:?}", err));

        let mut states = self.states.write();
        #[cfg(debug_assertions)]
        check_certifications_metadata_snapshots_and_states_metadata_are_consistent(&states);

        // The following assert validates that we don't have two clients
        // modifying TIP at the same time and that each commit_and_certify()
        // is preceded by a call to take_tip().
        if let Some((tip_height, _)) = &states.tip {
            fatal!(
                self.log,
                "Attempt to commit state not borrowed from this StateManager, height = {}, tip_height = {}",
                height,
                tip_height,
            );
        }

        // It's possible that we already computed this state before.  We
        // validate that hashes agree to spot bugs causing non-determinism as
        // early as possible.
        if let Some(prev_metadata) = states.certifications_metadata.get(&height) {
            let prev_hash = &prev_metadata.certified_state_hash;
            let hash = &certification_metadata.certified_state_hash;
            assert_eq!(
                prev_hash, hash,
                "Committed state @{} twice with different hashes: first with {:?}, then with {:?}",
                height, prev_hash, hash,
            );
        }

        if !states
            .snapshots
            .iter()
            .any(|snapshot| snapshot.height == height)
        {
            states.snapshots.push_back(Snapshot {
                height,
                state: Arc::new(checkpointed_state),
            });
            states
                .snapshots
                .make_contiguous()
                .sort_by_key(|snapshot| snapshot.height);

            states
                .certifications_metadata
                .insert(height, certification_metadata);

            if let Some((state_metadata, compute_manifest_request)) =
                state_metadata_and_compute_manifest_request
            {
                states.states_metadata.insert(height, state_metadata);
                debug_assert!(self.tip_channel.len() <= 1);
                self.tip_channel
                    .send(compute_manifest_request)
                    .expect("failed to send ComputeManifestRequest message");
            } else {
                debug_assert!(scope != CertificationScope::Full);
            }

            let latest_height = update_latest_height(&self.latest_state_height, height);
            self.metrics.max_resident_height.set(latest_height as i64);
            {
                let mut last_height_update_time = self
                    .latest_height_update_time
                    .lock()
                    .expect("Failed to lock last height update time.");
                let now = Instant::now();
                self.metrics
                    .height_update_time_seconds
                    .observe((now - *last_height_update_time).as_secs_f64());
                *last_height_update_time = now;
            }
        }

        self.metrics
            .resident_state_count
            .set(states.snapshots.len() as i64);

        // The next call to take_tip() will take care of updating the
        // tip if needed.
        states.tip = Some((height, state));

        if scope == CertificationScope::Full {
            self.release_lock_and_persist_metadata(states);
        }
        for req in follow_up_tip_requests {
            self.tip_channel
                .send(req)
                .expect("failed to send tip request");
        }
    }

    fn report_diverged_checkpoint(&self, height: Height) {
        let mut states = self.states.write();
        // Unverified checkpoints should also be considered when removing checkpoints higher than the diverged height.
        let heights = self
            .state_layout
            .unfiltered_checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(
                    &self.log,
                    "Failed to retrieve unfiltered checkpoint heights: {:?}",
                    err
                )
            });

        info!(self.log, "Moving diverged checkpoint @{}", height);
        if let Err(err) = self.state_layout.mark_checkpoint_diverged(height) {
            error!(
                self.log,
                "Failed to mark checkpoint @{} diverged: {}", height, err
            );
        }
        // At this point we broke quite few assumptions by removing files outside the
        // Tip thread, so Tip thread may panic if it tries to do some work with the checkpoint
        // files.
        // But the rename is atomic, and all the work past this comment is optional. If we don't
        // remove further diverged checkpoint, we crash again at the next startup but each restart
        // we do progress by removing the diverged checkpoints.
        // The metadata part is for performance.
        for h in heights {
            if h > height {
                info!(self.log, "Removing diverged checkpoint @{}", h);
                if let Err(err) = self.state_layout.force_remove_checkpoint(h) {
                    error!(
                        self.log,
                        "Failed to remove diverged checkpoint @{}: {}", h, err
                    );
                }
            }
        }

        states.states_metadata.split_off(&height);

        self.release_lock_and_persist_metadata(states);

        fatal!(self.log, "Replica diverged at height {}", height)
    }
}

struct CertifiedStateSnapshotImpl {
    certification: Certification,
    state: Arc<ReplicatedState>,
    hash_tree: Arc<HashTree>,
    read_certified_state_duration_histogram: Histogram,
}

impl CertifiedStateSnapshot for CertifiedStateSnapshotImpl {
    type State = ReplicatedState;

    fn get_state(&self) -> &Self::State {
        &self.state
    }

    fn get_height(&self) -> Height {
        self.certification.height
    }

    fn read_certified_state(
        &self,
        paths: &LabeledTree<()>,
    ) -> Option<(MixedHashTree, Certification)> {
        let _timer = self.read_certified_state_duration_histogram.start_timer();

        let mixed_hash_tree = {
            let lazy_tree = replicated_state_as_lazy_tree(self.get_state());
            let partial_tree = materialize_partial(&lazy_tree, paths);
            self.hash_tree.witness::<MixedHashTree>(&partial_tree)
        }
        .ok()?;

        debug_assert_eq!(
            crypto_hash_of_partial_state(&mixed_hash_tree.digest()),
            self.certification.signed.content.hash,
            "produced invalid hash tree {:?} for paths {:?}, full hash tree: {:?}",
            mixed_hash_tree,
            paths,
            self.hash_tree
        );

        Some((mixed_hash_tree, self.certification.clone()))
    }
}

impl StateReader for StateManagerImpl {
    type State = ReplicatedState;

    fn latest_state_height(&self) -> Height {
        Height::new(self.latest_state_height.load(Ordering::Relaxed))
    }

    fn latest_certified_height(&self) -> Height {
        Height::new(self.latest_certified_height.load(Ordering::Relaxed))
    }

    fn get_latest_state(&self) -> Labeled<Arc<Self::State>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_latest_state"])
            .start_timer();

        self.states
            .read()
            .snapshots
            .back()
            .map(|snapshot| Labeled::new(snapshot.height, snapshot.state.clone()))
            .unwrap_or_else(|| {
                Labeled::new(
                    Self::INITIAL_STATE_HEIGHT,
                    Arc::new(initial_state(self.own_subnet_id, self.own_subnet_type).take()),
                )
            })
    }

    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_state_at"])
            .start_timer();

        if self.latest_state_height() < height {
            return Err(StateManagerError::StateNotCommittedYet(height));
        }
        match self.states.read().snapshots.iter().find_map(|snapshot| {
            (snapshot.height == height).then(|| Labeled::new(height, snapshot.state.clone()))
        }) {
            Some(state) => Ok(state),
            None => match load_checkpoint(
                &self.state_layout,
                height,
                &self.metrics,
                self.own_subnet_type,
                Arc::clone(&self.get_fd_factory()),
            ) {
                Ok((state, _)) => Ok(Labeled::new(height, Arc::new(state))),
                Err(CheckpointError::NotFound(_)) => Err(StateManagerError::StateRemoved(height)),
                Err(err) => {
                    self.metrics
                        .state_manager_error_count
                        .with_label_values(&["recover_checkpoint"])
                        .inc();
                    error!(self.log, "Failed to recover state @{}: {}", height, err);

                    Err(StateManagerError::StateRemoved(height))
                }
            },
        }
    }

    fn read_certified_state(
        &self,
        paths: &LabeledTree<()>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        let reader = self.certified_state_reader()?;
        let (mixed_hash_tree, certification) = reader.read_certified_state(paths)?;

        Some((reader.state, mixed_hash_tree, certification))
    }

    fn get_certified_state_snapshot(
        &self,
    ) -> Option<Box<dyn CertifiedStateSnapshot<State = Self::State> + 'static>> {
        self.certified_state_reader()
            .map(|reader| Box::new(reader) as Box<_>)
    }
}

impl CertifiedStreamStore for StateManagerImpl {
    fn encode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<CertifiedStreamSlice, EncodeStreamError> {
        match (witness_begin, msg_begin) {
            (None, None) => {}
            (Some(witness_begin), Some(msg_begin)) if witness_begin <= msg_begin => {}
            _ => {
                return Err(EncodeStreamError::InvalidSliceIndices {
                    witness_begin,
                    msg_begin,
                })
            }
        }

        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["encode_certified_stream"])
            .start_timer();

        let (state, certification, hash_tree) = self
            .latest_certified_state()
            .ok_or(EncodeStreamError::NoStreamForSubnet(remote_subnet))?;

        let stream = state
            .get_stream(&remote_subnet)
            .ok_or(EncodeStreamError::NoStreamForSubnet(remote_subnet))?;

        let validate_slice_begin = |begin| {
            if begin < stream.messages_begin() || stream.messages_end() < begin {
                return Err(EncodeStreamError::InvalidSliceBegin {
                    slice_begin: begin,
                    stream_begin: stream.messages_begin(),
                    stream_end: stream.messages_end(),
                });
            }
            Ok(())
        };
        let msg_from = msg_begin.unwrap_or_else(|| stream.messages_begin());
        validate_slice_begin(msg_from)?;
        let witness_from = witness_begin.unwrap_or(msg_from);
        validate_slice_begin(witness_from)?;

        let to = msg_limit
            .map(|n| msg_from + StreamIndex::new(n as u64))
            .filter(|end| end <= &stream.messages_end())
            .unwrap_or_else(|| stream.messages_end());

        let (slice_as_tree, to) =
            stream_encoding::encode_stream_slice(&state, remote_subnet, msg_from, to, byte_limit);

        let witness_partial_tree =
            stream_encoding::stream_slice_partial_tree(remote_subnet, witness_from, to);
        let witness = hash_tree
            .witness::<Witness>(&witness_partial_tree)
            .expect("Failed to generate witness.");

        Ok(CertifiedStreamSlice {
            payload: stream_encoding::encode_tree(slice_as_tree),
            merkle_proof: v1::Witness::proxy_encode(witness),
            certification,
        })
    }

    fn decode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        registry_version: RegistryVersion,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["decode_certified_stream"])
            .start_timer();

        fn verify_recomputed_digest(
            verifier: &Arc<dyn Verifier>,
            remote_subnet: SubnetId,
            certification: &Certification,
            registry_version: RegistryVersion,
            digest: Digest,
            metrics: &StateManagerMetrics,
            #[allow(unused_variables)] log: &ReplicaLogger,
            #[allow(unused_variables)] malicious_flags: &MaliciousFlags,
        ) -> bool {
            #[cfg(feature = "malicious_code")]
            let certification = &maliciously_alter_certified_hash(
                certification.clone(),
                malicious_flags,
                &remote_subnet,
                log,
            );

            let hash_matches = digest.as_bytes() == certification.signed.content.hash.get_ref().0;
            let verification_status =
                verifier.validate(remote_subnet, certification, registry_version);
            let signature_verifies = verification_status.is_ok();

            metrics.observe_decode_slice_hash_comparison(hash_matches);
            metrics.observe_decode_slice_signature_verification(signature_verifies);

            hash_matches && signature_verifies
        }

        let tree = stream_encoding::decode_labeled_tree(&certified_slice.payload)?;

        let witness = v1::Witness::proxy_decode(&certified_slice.merkle_proof).map_err(|e| {
            DecodeStreamError::SerializationError(format!("Failed to deserialize witness: {:?}", e))
        })?;

        let digest = recompute_digest(&tree, &witness).map_err(|e| {
            DecodeStreamError::SerializationError(format!("Failed to recompute digest: {:?}", e))
        })?;

        if !verify_recomputed_digest(
            &self.verifier,
            remote_subnet,
            &certified_slice.certification,
            registry_version,
            digest,
            &self.metrics,
            &self.log,
            &self.malicious_flags,
        ) {
            return Err(DecodeStreamError::InvalidSignature(remote_subnet));
        }

        // `decode_slice_from_tree()` already checks internally whether the
        // slice only contains a stream for a single destination subnet.
        let (subnet_id, slice) = stream_encoding::decode_slice_from_tree(&tree)?;

        if subnet_id != self.own_subnet_id {
            return Err(DecodeStreamError::InvalidDestination {
                sender: remote_subnet,
                receiver: subnet_id,
            });
        }

        Ok(slice)
    }

    fn decode_valid_certified_stream_slice(
        &self,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        let (_subnet, slice) = stream_encoding::decode_stream_slice(&certified_slice.payload)?;
        Ok(slice)
    }

    fn subnets_with_certified_streams(&self) -> Vec<SubnetId> {
        self.get_latest_state()
            .get_ref()
            .subnets_with_available_streams()
    }
}

#[cfg(feature = "malicious_code")]
fn maliciously_alter_certified_hash(
    mut certification: Certification,
    malicious_flags: &MaliciousFlags,
    remote_subnet: &SubnetId,
    log: &ReplicaLogger,
) -> Certification {
    if malicious_flags.maliciously_alter_certified_hash {
        info!(
            log,
            "[MALICIOUS] Corrupting root hash of certification at height {} in stream slice from {}",
            certification.height,
            remote_subnet
        );
        certification.signed.content.hash = CryptoHashOfPartialState::from(CryptoHash(vec![0; 32]));
    }
    certification
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointError {
    /// Wraps a stringified `std::io::Error`, a message and the path of the
    /// affected file/directory.
    IoError {
        path: PathBuf,
        message: String,
        io_err: String,
    },
    /// The layout of state root on disk is corrupted.
    CorruptedLayout { path: PathBuf, message: String },
    /// Wraps a stringified `ic_protobuf::proxy::ProxyDecodeError`, a field and
    /// the path of the affected file.
    ProtoError {
        path: std::path::PathBuf,
        field: String,
        proto_err: String,
    },
    /// Checkpoint at the specified height already exists.
    AlreadyExists(Height),
    /// Checkpoint for the requested height not found.
    NotFound(Height),
    /// Wraps a PageMap error.
    Persistence(PersistenceError),
    /// Trying to remove the last checkpoint.
    LatestCheckpoint(Height),
    /// Checkpoint for the requested height is unverified.
    CheckpointUnverified(Height),
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Persistence(err) => Some(err),
            _ => None,
        }
    }
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointError::IoError {
                path,
                message,
                io_err,
            } => write!(f, "{}: {}: {}", path.display(), message, io_err),

            CheckpointError::CorruptedLayout { path, message } => {
                write!(f, "{}: {}", path.display(), message)
            }

            CheckpointError::ProtoError {
                path,
                field,
                proto_err,
            } => write!(
                f,
                "{}: failed to deserialize {}: {}",
                path.display(),
                field,
                proto_err
            ),

            CheckpointError::AlreadyExists(height) => write!(
                f,
                "failed to create checkpoint at height {} because it already exists",
                height
            ),

            CheckpointError::NotFound(height) => {
                write!(f, "checkpoint at height {} not found", height)
            }

            CheckpointError::Persistence(err) => write!(f, "persistence error: {}", err),

            CheckpointError::LatestCheckpoint(height) => write!(
                f,
                "Trying to remove the latest checkpoint at height @{}",
                height
            ),
            CheckpointError::CheckpointUnverified(height) => {
                write!(f, "Checkpoint at height @{} is unverified", height)
            }
        }
    }
}

impl From<PersistenceError> for CheckpointError {
    fn from(err: PersistenceError) -> Self {
        CheckpointError::Persistence(err)
    }
}

impl From<LayoutError> for CheckpointError {
    fn from(err: LayoutError) -> Self {
        match err {
            LayoutError::IoError {
                path,
                message,
                io_err,
            } => CheckpointError::IoError {
                path,
                message,
                io_err: io_err.to_string(),
            },
            LayoutError::CorruptedLayout { path, message } => {
                CheckpointError::CorruptedLayout { path, message }
            }
            LayoutError::NotFound(h) => CheckpointError::NotFound(h),
            LayoutError::AlreadyExists(h) => CheckpointError::AlreadyExists(h),
            LayoutError::LatestCheckpoint(h) => CheckpointError::LatestCheckpoint(h),
            LayoutError::CheckpointUnverified(h) => CheckpointError::CheckpointUnverified(h),
        }
    }
}

#[cfg(feature = "malicious_code")]
/// When maliciously_corrupt_own_state_at_heights contains the given height,
/// this function returns a false hash that contains all 0s.
fn maliciously_return_wrong_hash(
    manifest: &Manifest,
    log: &ReplicaLogger,
    malicious_flags: &MaliciousFlags,
    height: Height,
) -> CryptoHashOfState {
    use ic_protobuf::log::malicious_behaviour_log_entry::v1::{
        MaliciousBehaviour, MaliciousBehaviourLogEntry,
    };

    if malicious_flags
        .maliciously_corrupt_own_state_at_heights
        .contains(&height.get())
    {
        ic_logger::info!(
            log,
            "[MALICIOUS] corrupting the hash of the state at height {}",
            height.get();
            malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::CorruptOwnStateAtHeights as i32}
        );
        CryptoHashOfState::from(CryptoHash(vec![0u8; 32]))
    } else {
        CryptoHashOfState::from(CryptoHash(
            crate::manifest::manifest_hash(manifest).to_vec(),
        ))
    }
}

#[derive(Debug)]
pub struct PageAllocatorFileDescriptorImpl {
    root: PathBuf,
    file_backed_memory_allocator: FlagStatus,
}

impl PageAllocatorFileDescriptor for PageAllocatorFileDescriptorImpl {
    fn get_fd(&self) -> RawFd {
        // Only use the file-backed allocator if the feature flag is enabled.
        if self.file_backed_memory_allocator == FlagStatus::Enabled {
            self.get_file_backed_fd()
        } else {
            self.get_memory_backed_fd()
        }
    }
}

impl PageAllocatorFileDescriptorImpl {
    /// Create a file using an unique name to back memory pages
    fn get_file_backed_fd(&self) -> RawFd {
        // create a string uuid
        let uuid_str = Uuid::new_v4().to_string();
        let uuid_str_file = uuid_str + ".mem";
        // first clone the root
        let mut file_path = self.root.clone();
        // add the unique uuid value
        file_path.push(uuid_str_file);
        // open the file and return the fd
        match File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&file_path)
        {
            Err(why) => panic!(
                "MmapPageAllocatorCore failed to create the backing file {}",
                why
            ),
            Ok(file) => {
                let crnt_fd = file.into_raw_fd();
                // In Unix-based systems, when deleting a file while there are still open file
                // descriptors pointing to it, the file still exists and can be used. It will
                // finally be deleted when the last file descriptor pointing to it is closed.
                std::fs::remove_file(file_path.as_path()).expect(
                    "Error when deleting the file backing up the heap delta page allocator",
                );
                crnt_fd
            }
        }
    }

    // A platform-specific function that creates the backing file of the page allocator.
    // On Linux it uses `memfd_create` to create an in-memory file.
    // On MacOS and WSL it uses an ordinary temporary file.
    #[cfg(target_os = "linux")]
    fn get_memory_backed_fd(&self) -> RawFd {
        if *ic_sys::IS_WSL {
            return self.create_backing_file_portable();
        }

        match nix::sys::memfd::memfd_create(
            &std::ffi::CString::default(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        ) {
            Ok(fd) => fd,
            Err(err) => {
                panic!(
                    "MmapPageAllocatorCore failed to create the memory backing file {}",
                    err
                )
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn get_memory_backed_fd(&self) -> RawFd {
        self.create_backing_file_portable()
    }

    fn create_backing_file_portable(&self) -> RawFd {
        match tempfile() {
            Ok(file) => file.into_raw_fd(),
            Err(err) => {
                panic!(
                    "MmapPageAllocatorCore failed to create the MacOS/WSL backing file {}",
                    err
                )
            }
        }
    }
}
