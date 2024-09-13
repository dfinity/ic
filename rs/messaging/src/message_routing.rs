use crate::{
    routing, scheduling,
    state_machine::{StateMachine, StateMachineImpl},
};
use ic_config::execution_environment::{BitcoinConfig, Config as HypervisorConfig};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::{crypto::ErrorReproducibility, execution_environment::ChainKeySettings};
use ic_interfaces::{
    execution_environment::{IngressHistoryWriter, RegistryExecutionSettings, Scheduler},
    messaging::{MessageRouting, MessageRoutingError},
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{CertificationScope, StateManager, StateManagerError};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::{debug, fatal, info, warn, ReplicaLogger};
use ic_metrics::buckets::{add_bucket, decimal_buckets, decimal_buckets_with_zero};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_query_stats::QueryStatsAggregatorMetrics;
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry,
    chain_keys::ChainKeysRegistry,
    crypto::CryptoRegistry,
    node::NodeRegistry,
    provisional_whitelist::ProvisionalWhitelistRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{get_node_ids_from_subnet_record, SubnetListRegistry, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_features::{ChainKeyConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    metadata_state::ApiBoundaryNodeEntry, NetworkTopology, ReplicatedState, SubnetTopology,
};
use ic_types::{
    batch::{Batch, BatchSummary},
    crypto::{threshold_sig::ThresholdSigPublicKey, KeyPurpose},
    malicious_flags::MaliciousFlags,
    registry::RegistryClientError,
    xnet::{StreamHeader, StreamIndex},
    Height, NodeId, NumBytes, PrincipalIdBlobParseError, RegistryVersion, SubnetId, Time,
};
use ic_utils_thread::JoinOnDrop;
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use std::ops::Range;
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::sleep;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};
use tracing::instrument;

#[cfg(test)]
mod tests;

// How many batches we allow in the execution queue before we start rejecting
// incoming batches.
const BATCH_QUEUE_BUFFER_SIZE: usize = 16;

const METRIC_DELIVER_BATCH_COUNT: &str = "mr_deliver_batch_count";
const METRIC_EXPECTED_BATCH_HEIGHT: &str = "mr_expected_batch_height";
const METRIC_REGISTRY_VERSION: &str = "mr_registry_version";
pub(crate) const METRIC_TIME_IN_BACKLOG: &str = "mr_time_in_backlog";
pub(crate) const METRIC_TIME_IN_STREAM: &str = "mr_time_in_stream";

const LABEL_STATUS: &str = "status";
pub(crate) const LABEL_REMOTE: &str = "remote";

const STATUS_IGNORED: &str = "ignored";
const STATUS_QUEUE_FULL: &str = "queue_full";
const STATUS_SUCCESS: &str = "success";

const PHASE_LOAD_STATE: &str = "load_state";
const PHASE_COMMIT: &str = "commit";

const METRIC_PROCESS_BATCH_DURATION: &str = "mr_process_batch_duration_seconds";
const METRIC_PROCESS_BATCH_PHASE_DURATION: &str = "mr_process_batch_phase_duration_seconds";
const METRIC_TIMED_OUT_MESSAGES_TOTAL: &str = "mr_timed_out_messages_total";
const METRIC_SUBNET_SPLIT_HEIGHT: &str = "mr_subnet_split_height";
const BLOCKS_PROPOSED_TOTAL: &str = "mr_blocks_proposed_total";
const BLOCKS_NOT_PROPOSED_TOTAL: &str = "mr_blocks_not_proposed_total";
const METRIC_NEXT_CHECKPOINT_HEIGHT: &str = "mr_next_checkpoint_height";
const METRIC_REMOTE_CERTIFIED_HEIGHTS: &str = "mr_remote_certified_heights";

const METRIC_WASM_CUSTOM_SECTIONS_MEMORY_USAGE_BYTES: &str =
    "mr_wasm_custom_sections_memory_usage_bytes";
const METRIC_CANISTER_HISTORY_MEMORY_USAGE_BYTES: &str = "mr_canister_history_memory_usage_bytes";
const METRIC_CANISTER_HISTORY_TOTAL_NUM_CHANGES: &str = "mr_canister_history_total_num_changes";

const CRITICAL_ERROR_MISSING_SUBNET_SIZE: &str = "cycles_account_manager_missing_subnet_size_error";
const CRITICAL_ERROR_MISSING_OR_INVALID_NODE_PUBLIC_KEYS: &str =
    "mr_missing_or_invalid_node_public_keys";
const CRITICAL_ERROR_MISSING_OR_INVALID_API_BOUNDARY_NODES: &str =
    "mr_missing_or_invalid_api_boundary_nodes";
const CRITICAL_ERROR_NO_CANISTER_ALLOCATION_RANGE: &str = "mr_empty_canister_allocation_range";
const CRITICAL_ERROR_FAILED_TO_READ_REGISTRY: &str = "mr_failed_to_read_registry_error";
pub const CRITICAL_ERROR_NON_INCREASING_BATCH_TIME: &str = "mr_non_increasing_batch_time";
const CRITICAL_ERROR_INDUCT_RESPONSE_FAILED: &str = "mr_induct_response_failed";

/// Records the timestamp when all messages before the given index (down to the
/// previous `MessageTime`) were first added to / learned about in a stream.
struct MessageTime {
    index: StreamIndex,
    time: Instant,
}

impl MessageTime {
    fn new(index: StreamIndex) -> Self {
        MessageTime {
            index,
            time: Instant::now(),
        }
    }
}

/// A timeline consisting of the timestamps of messages in a stream (usually at
/// block boundaries) providing the base for computing the time spent in the
/// stream / backlog by each message; plus a histogram to record these
/// observations.
struct StreamTimeline {
    /// A [`MessageTime`] queue with strictly increasing `index` and `time`
    /// values.
    entries: VecDeque<MessageTime>,

    /// Histogram to record the duration spent by a message in a stream /
    /// backlog.
    histogram: Histogram,
}

impl StreamTimeline {
    /// Creates a timeline to record message durations in the given `Histogram`.
    fn new(histogram: Histogram) -> Self {
        StreamTimeline {
            entries: VecDeque::new(),
            histogram,
        }
    }

    /// Adds a [`MessageTime`] with the given index and the current wall time to
    /// `entries` iff `index > self.entries.back().index`.
    fn add_entry(&mut self, index: StreamIndex) {
        match self.entries.back() {
            None => self.entries.push_back(MessageTime::new(index)),
            Some(observation) if observation.index < index => {
                self.entries.push_back(MessageTime::new(index));
            }
            _ => { /* do nothing */ }
        };
    }

    /// Records one histogram observation for every message in the given index
    /// range, with the time elapsed since the matching `MessageTime` entry (the
    /// first one with `index >= message.index`).
    fn observe(&mut self, index_range: Range<StreamIndex>) {
        for index in index_range.start.get()..index_range.end.get() {
            let entry = loop {
                match self.entries.front() {
                    // Discard all timeline entries with indexes smaller than the
                    // observed index.
                    Some(entry) if entry.index <= index.into() => {
                        self.entries.pop_front();
                        continue;
                    }
                    Some(entry) => break entry,
                    _ => return,
                }
            };

            self.histogram.observe(entry.time.elapsed().as_secs_f64());
        }
    }
}

/// Bundle of message latency metrics for incoming or outgoing streams and the
/// corresponding [`StreamTimelines`](StreamTimeline) needed to compute them.
pub(crate) struct LatencyMetrics {
    /// Map of message timelines by remote subnet ID.
    timelines: BTreeMap<SubnetId, StreamTimeline>,

    /// Per-remote-subnet histograms of message durations.
    histograms: HistogramVec,
}

impl LatencyMetrics {
    fn new(metrics_registry: &MetricsRegistry, name: &str, description: &str) -> Self {
        let mut buckets = decimal_buckets(0, 2);
        buckets = add_bucket(7.5, buckets);
        buckets = add_bucket(12.5, buckets);
        buckets = add_bucket(15.0, buckets);
        buckets = add_bucket(17.5, buckets);

        Self {
            timelines: BTreeMap::new(),
            histograms: metrics_registry.histogram_vec(name, description, buckets, &[LABEL_REMOTE]),
        }
    }

    /// Creates the `LatencyMetrics` to record [`METRIC_TIME_IN_STREAM`]
    /// observations.
    pub(crate) fn new_time_in_stream(metrics_registry: &MetricsRegistry) -> LatencyMetrics {
        LatencyMetrics::new(
            metrics_registry,
            METRIC_TIME_IN_STREAM,
            "Per-destination-subnet histogram of wall time spent by messages in the stream \
                before they are garbage collected.",
        )
    }

    /// Creates the `LatencyMetrics` to record [`METRIC_TIME_IN_BACKLOG`]
    /// observations.
    pub(crate) fn new_time_in_backlog(metrics_registry: &MetricsRegistry) -> LatencyMetrics {
        LatencyMetrics::new(
            metrics_registry,
            METRIC_TIME_IN_BACKLOG,
            "Per-source-subnet histogram of wall time between finding out about the \
                existence of a message from an incoming stream header; and inducting it.",
        )
    }

    /// Helper function: invokes the given function on the [`StreamTimeline`]
    /// for the given remote subnet, creating one if it doesn't exist yet.
    fn with_timeline(&mut self, subnet_id: SubnetId, f: impl FnOnce(&mut StreamTimeline)) {
        use std::collections::btree_map::Entry;

        match self.timelines.entry(subnet_id) {
            Entry::Occupied(mut o) => f(o.get_mut()),
            Entry::Vacant(v) => {
                let backlog = self.histograms.with_label_values(&[&subnet_id.to_string()]);
                f(v.insert(StreamTimeline::new(backlog)))
            }
        }
    }

    /// Records a `MessageTime` entry for messages to/from `subnet_id` before
    /// `header.end` (if not already recorded).
    pub(crate) fn record_header(&mut self, subnet_id: SubnetId, header: &StreamHeader) {
        self.with_timeline(subnet_id, |t| t.add_entry(header.end()));
    }

    /// Observes message durations for all messages to/from `subnet_id` with
    /// indices in the given `index_range`, as the time elapsed since the
    /// respective matching timeline entries.
    pub(crate) fn observe_message_durations(
        &mut self,
        subnet_id: SubnetId,
        index_range: Range<StreamIndex>,
    ) {
        self.with_timeline(subnet_id, |t| t.observe(index_range));
    }
}

/// Metrics for [`MessageRoutingImpl`].
#[derive(Clone)]
pub(crate) struct MessageRoutingMetrics {
    /// Number of `deliver_batch()` calls, by status.
    deliver_batch_count: IntCounterVec,
    /// Expected batch height.
    expected_batch_height: IntGauge,
    /// Registry version referenced in the most recently executed batch.
    registry_version: IntGauge,
    /// Batch processing durations.
    process_batch_duration: Histogram,
    /// Most recently seen certified height, per remote subnet
    pub(crate) remote_certified_heights: IntGaugeVec,
    /// Batch processing phase durations, by phase.
    pub(crate) process_batch_phase_duration: HistogramVec,
    /// Number of timed out messages.
    pub(crate) timed_out_messages_total: IntCounter,
    /// Height at which the subnet last split (if during the lifetime of this
    /// replica process; otherwise zero).
    pub(crate) subnet_split_height: IntGaugeVec,
    /// Number of blocks proposed.
    pub(crate) blocks_proposed_total: IntCounter,
    /// Number of blocks not proposed.
    pub(crate) blocks_not_proposed_total: IntCounter,

    /// The memory footprint of all the canisters on this subnet. Note that this
    /// counter is from the perspective of the canisters and does not account
    /// for the extra copies of the state that the protocol has to store for
    /// correct operations.
    canisters_memory_usage_bytes: IntGauge,
    /// The memory footprint of Wasm custom sections of all canisters on this
    /// subnet. Note that the value is from the perspective of the canisters
    /// and does not account for the extra copies of the state that the protocol
    /// has to store for correct operations.
    wasm_custom_sections_memory_usage_bytes: IntGauge,
    /// The memory footprint of canister history of all canisters on this
    /// subnet. Note that the value is from the perspective of the canisters
    /// and does not account for the extra copies of the state that the protocol
    /// has to store for correct operations.
    canister_history_memory_usage_bytes: IntGauge,
    /// The total number of changes in canister history per canister on this subnet.
    canister_history_total_num_changes: Histogram,

    /// Critical error for not being able to calculate a subnet size.
    critical_error_missing_subnet_size: IntCounter,
    /// Critical error: public keys of own subnet nodes are missing
    /// or they are not valid Ed25519 public keys.
    critical_error_missing_or_invalid_node_public_keys: IntCounter,
    /// Critical error: information of api boundary nodes is broken or missing.
    critical_error_missing_or_invalid_api_boundary_nodes: IntCounter,
    /// Critical error: subnet has no canister allocation range to generate new
    /// canister IDs from.
    critical_error_no_canister_allocation_range: IntCounter,
    /// Critical error: reading from the registry failed during processing a batch.
    critical_error_failed_to_read_registry: IntCounter,
    /// Critical error: the batch times of successive batches were not strictly
    /// monotonically increasing.
    critical_error_non_increasing_batch_time: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// failures to induct responses.
    pub critical_error_induct_response_failed: IntCounter,

    /// Metrics for query stats aggregator
    pub query_stats_metrics: QueryStatsAggregatorMetrics,

    /// Metrics for the `next_checkpoint_height` passed to `process_batch`.
    next_checkpoint_height: IntGauge,
}

impl MessageRoutingMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        let deliver_batch_count = metrics_registry.int_counter_vec(
            METRIC_DELIVER_BATCH_COUNT,
            "Number of `deliver_batch()` calls, by status.",
            &[LABEL_STATUS],
        );
        for status in &[STATUS_IGNORED, STATUS_QUEUE_FULL, STATUS_SUCCESS] {
            deliver_batch_count.with_label_values(&[status]);
        }
        Self {
            deliver_batch_count,
            process_batch_duration: metrics_registry.histogram(
                METRIC_PROCESS_BATCH_DURATION,
                "Batch processing durations.",
                // 1ms - 50s
                decimal_buckets(-3, 1),
            ),
            expected_batch_height: metrics_registry.int_gauge(
                METRIC_EXPECTED_BATCH_HEIGHT,
                "Height of the batch that MR expects to be delivered next.",
            ),
            registry_version: metrics_registry.int_gauge(
                METRIC_REGISTRY_VERSION,
                "Registry version referenced in the most recently executed batch.",
            ),
            process_batch_phase_duration: metrics_registry.histogram_vec(
                METRIC_PROCESS_BATCH_PHASE_DURATION,
                "Batch processing phase durations, by phase.",
                // 1ms - 50s
                decimal_buckets(-3, 1),
                &["phase"],
            ),
            remote_certified_heights: metrics_registry.int_gauge_vec(
                METRIC_REMOTE_CERTIFIED_HEIGHTS,
                "Most recently observed remote subnet certified heights.",
                &[LABEL_REMOTE],
            ),
            timed_out_messages_total: metrics_registry.int_counter(
                METRIC_TIMED_OUT_MESSAGES_TOTAL,
                "Count of timed out messages.",
            ),
            subnet_split_height: metrics_registry.int_gauge_vec(
                METRIC_SUBNET_SPLIT_HEIGHT,
                "Height at which the subnet last split (if during the lifetime of this replica process).",
                &["split_from"],
            ),
            blocks_proposed_total: metrics_registry.int_counter(
                BLOCKS_PROPOSED_TOTAL,
                "Successfully proposed blocks (blocks that became part of the blockchain)."
            ),
            blocks_not_proposed_total: metrics_registry.int_counter(
                BLOCKS_NOT_PROPOSED_TOTAL,
                "Failures to propose a block (when the node was block maker rank R but the subnet accepted the block from the block maker with rank S > R)."
            ),
            canisters_memory_usage_bytes: metrics_registry.int_gauge(
                "canister_memory_usage_bytes",
                "Total memory footprint of all canisters on this subnet.",
            ),
            wasm_custom_sections_memory_usage_bytes: metrics_registry.int_gauge(
                METRIC_WASM_CUSTOM_SECTIONS_MEMORY_USAGE_BYTES,
                "Total memory footprint of Wasm custom sections of all canisters on this subnet.",
            ),
            canister_history_memory_usage_bytes: metrics_registry.int_gauge(
                METRIC_CANISTER_HISTORY_MEMORY_USAGE_BYTES,
                "Total memory footprint of canister history of all canisters on this subnet.",
            ),
            canister_history_total_num_changes: metrics_registry.histogram(
                METRIC_CANISTER_HISTORY_TOTAL_NUM_CHANGES,
                "Total number of changes in canister history per canister on this subnet.",
                // 0, 1, 2, 5, …, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),

            critical_error_missing_subnet_size: metrics_registry
                .error_counter(CRITICAL_ERROR_MISSING_SUBNET_SIZE),
            critical_error_missing_or_invalid_node_public_keys: metrics_registry
                .error_counter(CRITICAL_ERROR_MISSING_OR_INVALID_NODE_PUBLIC_KEYS),
            critical_error_missing_or_invalid_api_boundary_nodes: metrics_registry
                .error_counter(CRITICAL_ERROR_MISSING_OR_INVALID_API_BOUNDARY_NODES),
            critical_error_no_canister_allocation_range: metrics_registry
                .error_counter(CRITICAL_ERROR_NO_CANISTER_ALLOCATION_RANGE),
            critical_error_failed_to_read_registry: metrics_registry
                .error_counter(CRITICAL_ERROR_FAILED_TO_READ_REGISTRY),
            critical_error_non_increasing_batch_time: metrics_registry
                .error_counter(CRITICAL_ERROR_NON_INCREASING_BATCH_TIME),
            critical_error_induct_response_failed: metrics_registry
                .error_counter(CRITICAL_ERROR_INDUCT_RESPONSE_FAILED),

            query_stats_metrics: QueryStatsAggregatorMetrics::new(metrics_registry),

            next_checkpoint_height: metrics_registry.int_gauge(
                METRIC_NEXT_CHECKPOINT_HEIGHT,
                "Next checkpoint height passed to process_batch."
            ),
        }
    }

    pub fn observe_no_canister_allocation_range(&self, log: &ReplicaLogger, message: String) {
        self.critical_error_no_canister_allocation_range.inc();
        warn!(
            log,
            "{}: Subnet is unable to generate new canister IDs: {}.",
            CRITICAL_ERROR_NO_CANISTER_ALLOCATION_RANGE,
            message
        );
    }

    pub fn observe_non_increasing_batch_time(
        &self,
        log: &ReplicaLogger,
        state_time: Time,
        batch_time: Time,
        batch_height: Height,
    ) {
        self.critical_error_non_increasing_batch_time.inc();
        warn!(
            log,
            "{}: Non-increasing batch time at height {}: state_time = {}, batch_time = {}.",
            CRITICAL_ERROR_NON_INCREASING_BATCH_TIME,
            batch_height,
            state_time,
            batch_time
        );
    }
}

/// Implementation of the `MessageRouting` trait.
pub struct MessageRoutingImpl {
    last_seen_batch: RwLock<Height>,
    batch_sender: std::sync::mpsc::SyncSender<Batch>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: MessageRoutingMetrics,
    log: ReplicaLogger,
    // Handle to the batch processor thread.  Stored so that in `drop`, we can wait
    // for it to exit. It must be declared after `batch_sender` so that the
    // thread is joined after the channel is destroyed.
    _batch_processor_handle: JoinOnDrop<()>,
}

/// A component that executes Consensus [batches](Batch) sequentially, by
/// retrieving the matching state, applying the batch and committing the result.
#[cfg_attr(test, automock)]
trait BatchProcessor: Send {
    fn process_batch(&self, batch: Batch);
}

/// Implementation of [`BatchProcessor`].
struct BatchProcessorImpl {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_machine: Box<dyn StateMachine>,
    registry: Arc<dyn RegistryClient>,
    bitcoin_config: BitcoinConfig,
    metrics: MessageRoutingMetrics,
    log: ReplicaLogger,
    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
}

/// Errors that can occur when reading from the registry.
#[derive(Debug)]
enum ReadRegistryError {
    /// Transient errors are errors that may be resolved in between attempts to read the registry, such
    /// as the registry at the requested version is not available (yet).
    Transient(String),
    /// Persistent errors are errors where repeated attempts do not make a difference such as reading a
    /// corrupted or missing record.
    Persistent(String),
}

/// Generates a `RegistryError` from a `RegistryClientError` including `what` failed to extracted
/// from the registry and possibly for which subnet id. This error is persistent iff the
/// `RegistryClientError` from which it is created is persistent.
fn registry_error(
    what: &str,
    subnet_id: Option<SubnetId>,
    err: RegistryClientError,
) -> ReadRegistryError {
    let errmsg = match subnet_id {
        Some(subnet_id) => format!(
            "'{} [for subnet {}]', RegistryClientError: {}",
            what, subnet_id, err
        ),
        None => format!("'{}', RegistryClientError: {}", what, err),
    };
    if err.is_reproducible() {
        ReadRegistryError::Persistent(errmsg)
    } else {
        ReadRegistryError::Transient(errmsg)
    }
}

/// Generates a `RegistryError` to handle cases where a record in the registry was unexpectedly
/// absent. This error is always considered persistent.
fn not_found_error(what: &str, subnet_id: Option<SubnetId>) -> ReadRegistryError {
    let errmsg = match subnet_id {
        Some(subnet_id) => format!("'{} for subnet {}' not found", what, subnet_id),
        None => format!("'{}' not found", what),
    };
    ReadRegistryError::Persistent(errmsg)
}

/// A mapping from node IDs to public keys.
/// The public key is a DER-encoded Ed25519 key.
pub(crate) type NodePublicKeys = BTreeMap<NodeId, Vec<u8>>;

/// A mapping from node IDs to ApiBoundaryNodeEntry.
pub(crate) type ApiBoundaryNodes = BTreeMap<NodeId, ApiBoundaryNodeEntry>;

impl BatchProcessorImpl {
    fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        hypervisor_config: HypervisorConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        subnet_id: SubnetId,
        metrics: MessageRoutingMetrics,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        registry: Arc<dyn RegistryClient>,
        malicious_flags: MaliciousFlags,
    ) -> BatchProcessorImpl {
        let time_in_stream_metrics = Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
            metrics_registry,
        )));
        let stream_handler = Box::new(routing::stream_handler::StreamHandlerImpl::new(
            subnet_id,
            hypervisor_config.clone(),
            metrics_registry,
            &metrics,
            Arc::clone(&time_in_stream_metrics),
            log.clone(),
        ));
        let vsr = Box::new(scheduling::valid_set_rule::ValidSetRuleImpl::new(
            ingress_history_writer,
            cycles_account_manager,
            metrics_registry,
            subnet_id,
            log.clone(),
        ));
        let demux = Box::new(routing::demux::DemuxImpl::new(
            vsr,
            stream_handler,
            certified_stream_store,
            metrics.clone(),
            log.clone(),
        ));
        let stream_builder = Box::new(routing::stream_builder::StreamBuilderImpl::new(
            subnet_id,
            metrics_registry,
            &metrics,
            time_in_stream_metrics,
            log.clone(),
        ));
        let state_machine = Box::new(StateMachineImpl::new(
            scheduler,
            demux,
            stream_builder,
            log.clone(),
            metrics.clone(),
        ));

        Self {
            state_manager,
            state_machine,
            registry,
            bitcoin_config: hypervisor_config.bitcoin,
            metrics,
            log,
            malicious_flags,
        }
    }

    /// Adds an observation to the `METRIC_PROCESS_BATCH_PHASE_DURATION`
    /// histogram for the given phase.
    fn observe_phase_duration(&self, phase: &str, since: &Instant) {
        self.metrics
            .process_batch_phase_duration
            .with_label_values(&[phase])
            .observe(since.elapsed().as_secs_f64());
    }

    /// Observes metrics related to memory used by canisters. It includes:
    ///   * total memory used
    ///   * memory used by Wasm Custom Sections
    ///   * memory used by canister history
    ///
    /// Returns the total memory usage of the canisters of this subnet.
    fn observe_canisters_memory_usage(&self, state: &ReplicatedState) -> NumBytes {
        let mut total_memory_usage = NumBytes::from(0);
        let mut wasm_custom_sections_memory_usage = NumBytes::from(0);
        let mut canister_history_memory_usage = NumBytes::from(0);
        for canister in state.canister_states.values() {
            // Export the total canister memory usage; execution and wasm custom section
            // memory are included in `memory_usage()`; message memory is added separately.
            total_memory_usage += canister.memory_usage() + canister.message_memory_usage();
            wasm_custom_sections_memory_usage += canister
                .execution_state
                .as_ref()
                .map(|es| es.metadata.memory_usage())
                .unwrap_or_default();
            canister_history_memory_usage += canister.canister_history_memory_usage();
            self.metrics.canister_history_total_num_changes.observe(
                canister
                    .system_state
                    .get_canister_history()
                    .get_total_num_changes() as f64,
            );
        }
        self.metrics
            .canisters_memory_usage_bytes
            .set(total_memory_usage.get() as i64);
        self.metrics
            .wasm_custom_sections_memory_usage_bytes
            .set(wasm_custom_sections_memory_usage.get() as i64);
        self.metrics
            .canister_history_memory_usage_bytes
            .set(canister_history_memory_usage.get() as i64);

        total_memory_usage
    }

    /// Reads registry contents required by `BatchProcessorImpl::process_batch()`.
    //
    /// # Warning
    /// If the registry is unavailable, this method loops until it becomes
    /// available. If registry contents are invalid, the method loops forever.
    fn read_registry(
        &self,
        registry_version: RegistryVersion,
        own_subnet_id: SubnetId,
    ) -> (
        NetworkTopology,
        SubnetFeatures,
        RegistryExecutionSettings,
        NodePublicKeys,
        ApiBoundaryNodes,
    ) {
        loop {
            match self.try_to_read_registry(registry_version, own_subnet_id) {
                Ok(result) => return result,
                Err(ReadRegistryError::Persistent(error_message)) => {
                    // Increment the critical error counter in case of a persistent error.
                    self.metrics.critical_error_failed_to_read_registry.inc();
                    warn!(
                        self.log,
                        "{}: Persistent error reading registry @ version {}: {:?}.",
                        CRITICAL_ERROR_FAILED_TO_READ_REGISTRY,
                        registry_version,
                        error_message
                    );
                }
                Err(ReadRegistryError::Transient(error_message)) => {
                    warn!(
                        self.log,
                        "Unable to read registry @ version {}: {:?}. Trying again...",
                        registry_version,
                        error_message
                    );
                }
            }
            sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Loads the `NetworkTopology`, `SubnetFeatures`, execution settings and
    /// own subnet node public keys from the registry.
    ///
    /// All of the above are required for deterministic processing, so if any
    /// entry is missing or cannot be decoded; or reading the registry fails; the
    /// call fails and returns an error.
    fn try_to_read_registry(
        &self,
        registry_version: RegistryVersion,
        own_subnet_id: SubnetId,
    ) -> Result<
        (
            NetworkTopology,
            SubnetFeatures,
            RegistryExecutionSettings,
            NodePublicKeys,
            ApiBoundaryNodes,
        ),
        ReadRegistryError,
    > {
        let api_boundary_nodes = self.try_to_populate_api_boundary_nodes(registry_version)?;
        let network_topology = self.try_to_populate_network_topology(registry_version)?;

        let provisional_whitelist = self
            .registry
            .get_provisional_whitelist(registry_version)
            .map_err(|err| registry_error("provisional_whitelist", None, err))?
            .unwrap_or_else(|| ProvisionalWhitelist::Set(BTreeSet::new()));

        let subnet_record = self
            .registry
            .get_subnet_record(own_subnet_id, registry_version)
            .map_err(|err| registry_error("subnet record", Some(own_subnet_id), err))?
            .ok_or_else(|| not_found_error("subnet record", Some(own_subnet_id)))?;

        let nodes = get_node_ids_from_subnet_record(&subnet_record)
            .map_err(|err| {
                ReadRegistryError::Persistent(format!(
                    "'nodes from subnet record for subnet {}', err: {}",
                    own_subnet_id, err
                ))
            })?
            .into_iter()
            .collect::<BTreeSet<_>>();

        let node_public_keys = self.try_to_populate_node_public_keys(nodes, registry_version)?;

        let subnet_features = subnet_record.features.unwrap_or_default().into();
        let max_number_of_canisters = subnet_record.max_number_of_canisters;

        let chain_key_settings = if let Some(chain_key_config) = subnet_record.chain_key_config {
            let chain_key_config = ChainKeyConfig::try_from(chain_key_config).map_err(|err| {
                ReadRegistryError::Persistent(format!(
                    "'failed to read chain key config', err: {:?}",
                    err
                ))
            })?;

            chain_key_config
                .key_configs
                .iter()
                .map(|key_config| {
                    (
                        key_config.key_id.clone(),
                        ChainKeySettings {
                            max_queue_size: key_config.max_queue_size,
                            pre_signatures_to_create_in_advance: key_config
                                .pre_signatures_to_create_in_advance,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };

        let subnet_size = if subnet_record.membership.is_empty() {
            self.metrics.critical_error_missing_subnet_size.inc();
            warn!(
                self.log,
                "{}: [EXC-1168] Unable to get subnet size from network topology. Cycles accounting may no longer be accurate.",
                CRITICAL_ERROR_MISSING_SUBNET_SIZE
            );
            SMALL_APP_SUBNET_MAX_SIZE
        } else {
            subnet_record
                .membership
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
        };

        Ok((
            network_topology,
            subnet_features,
            RegistryExecutionSettings {
                max_number_of_canisters,
                provisional_whitelist,
                chain_key_settings,
                subnet_size,
            },
            node_public_keys,
            api_boundary_nodes,
        ))
    }

    /// Tries to populate a `NetworkTopology` from the registry at a specific version.
    fn try_to_populate_network_topology(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<NetworkTopology, ReadRegistryError> {
        use ReadRegistryError::Persistent;

        // Return the list of subnets present in the registry. If no subnet list is
        // defined, as could be the case in tests, an empty `Vec` is returned.
        let subnet_ids_record = self
            .registry
            .get_subnet_ids(registry_version)
            .map_err(|err| registry_error("subnet IDs", None, err))?;
        let subnet_ids = subnet_ids_record.unwrap_or_default();

        // Populate subnet topologies.
        let mut subnets = BTreeMap::new();

        for subnet_id in &subnet_ids {
            let public_key = self
                .registry
                .get_initial_dkg_transcripts(*subnet_id, registry_version)
                .map_err(|err| registry_error("public key in transcript", Some(*subnet_id), err))?
                .value
                .map(|transcripts| {
                    match ThresholdSigPublicKey::try_from(&transcripts.high_threshold) {
                        Ok(public_key) => ic_crypto_utils_threshold_sig_der::public_key_to_der(
                            &public_key.into_bytes(),
                        )
                        .map_err(|err: String| {
                            Persistent(format!(
                                "'public key to DER for subnet {}' failed, err: {}",
                                *subnet_id, err
                            ))
                        }),
                        Err(err) => Err(Persistent(format!(
                            "'public key from transcript for subnet {}' failed, err: {:?}",
                            *subnet_id, err
                        ))),
                    }
                })
                .transpose()?
                .ok_or_else(|| not_found_error("public key in transcript", Some(*subnet_id)))?;

            // Read the subnet record.
            let subnet_record = self
                .registry
                .get_subnet_record(*subnet_id, registry_version)
                .map_err(|err| registry_error("subnet record", Some(*subnet_id), err))?
                .ok_or_else(|| not_found_error("subnet record", Some(*subnet_id)))?;

            let nodes = get_node_ids_from_subnet_record(&subnet_record)
                .map_err(|err: PrincipalIdBlobParseError| {
                    Persistent(format!(
                        "'nodes from subnet record for subnet {}', err: {}",
                        *subnet_id, err
                    ))
                })?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let subnet_type: SubnetType =
                subnet_record
                    .subnet_type
                    .try_into()
                    .map_err(|err: ProxyDecodeError| {
                        Persistent(format!(
                            "'subnet type from subnet record for subnet {}', err: {}",
                            *subnet_id, err
                        ))
                    })?;
            let subnet_features: SubnetFeatures = subnet_record.features.unwrap_or_default().into();
            let idkg_keys_held = subnet_record
                .chain_key_config
                .map(|chain_key_config| {
                    chain_key_config
                        .key_configs
                        .into_iter()
                        .map(|chain_key_config| {
                            try_from_option_field(chain_key_config.key_id, "key_id").map_err(
                                |err: ProxyDecodeError| {
                                    Persistent(format!(
                                        "'Chain key ID from subnet record for subnet {}', err: {}",
                                        *subnet_id, err,
                                    ))
                                },
                            )
                        })
                        .collect::<Result<BTreeSet<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();

            subnets.insert(
                *subnet_id,
                SubnetTopology {
                    public_key,
                    nodes,
                    subnet_type,
                    subnet_features,
                    idkg_keys_held,
                },
            );
        }

        let routing_table = self
            .registry
            .get_routing_table(registry_version)
            .map_err(|err| registry_error("routing table", None, err))?
            .unwrap_or_default();
        let canister_migrations = self
            .registry
            .get_canister_migrations(registry_version)
            .map_err(|err| registry_error("canister migrations", None, err))?
            .unwrap_or_default();

        let nns_subnet_id = self
            .registry
            .get_root_subnet_id(registry_version)
            .map_err(|err| registry_error("NNS subnet ID", None, err))?
            .ok_or_else(|| not_found_error("NNS subnet ID", None))?;

        let idkg_signing_subnets = self
            .registry
            .get_chain_key_signing_subnets(registry_version)
            .map_err(|err| registry_error("chain key signing subnets", None, err))?
            .unwrap_or_default();

        Ok(NetworkTopology {
            subnets,
            routing_table: Arc::new(routing_table),
            nns_subnet_id,
            canister_migrations: Arc::new(canister_migrations),
            idkg_signing_subnets,
            bitcoin_testnet_canister_id: self.bitcoin_config.testnet_canister_id,
            bitcoin_mainnet_canister_id: self.bitcoin_config.mainnet_canister_id,
        })
    }

    /// Tries to populate node public keys from the registry at a specific version.
    /// An error is returned if it fails to read the registry.
    /// This method skips missing or invalid node keys so that the `read_registry` method does not stall the subnet.
    fn try_to_populate_node_public_keys(
        &self,
        nodes: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> Result<NodePublicKeys, ReadRegistryError> {
        let mut node_public_keys: NodePublicKeys = BTreeMap::new();
        for node_id in nodes {
            let optional_public_key_proto = self
                .registry
                .get_crypto_key_for_node(node_id, KeyPurpose::NodeSigning, registry_version)
                .map_err(|err| {
                    registry_error(&format!("public key of node {}", node_id), None, err)
                })?;

            // If the public key is missing, we continue without stalling the subnet.
            match optional_public_key_proto {
                Some(public_key_proto) => {
                    // If the public key protobuf is invalid, we continue without stalling the subnet.
                    match ic_crypto_ed25519::PublicKey::convert_raw_to_der(
                        &public_key_proto.key_value,
                    ) {
                        Ok(pk_der) => {
                            node_public_keys.insert(node_id, pk_der);
                        }
                        Err(err) => {
                            self.metrics
                                .critical_error_missing_or_invalid_node_public_keys
                                .inc();
                            warn!(
                                self.log,
                                "{}: the PublicKey protobuf of node {} stored in registry is not a valid Ed25519 public key, {:?}.",
                                CRITICAL_ERROR_MISSING_OR_INVALID_NODE_PUBLIC_KEYS,
                                node_id,
                                err
                            );
                        }
                    }
                }
                None => {
                    self.metrics
                        .critical_error_missing_or_invalid_node_public_keys
                        .inc();
                    warn!(
                        self.log,
                        "{}: the public key of node {} missing in registry.",
                        CRITICAL_ERROR_MISSING_OR_INVALID_NODE_PUBLIC_KEYS,
                        node_id,
                    );
                }
            }
        }
        Ok(node_public_keys)
    }

    fn try_to_populate_api_boundary_nodes(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<ApiBoundaryNodes, ReadRegistryError> {
        let raise_critical_error_for_api_boundary_nodes = |err_msg: &str| {
            self.metrics
                .critical_error_missing_or_invalid_api_boundary_nodes
                .inc();
            warn!(
                &self.log,
                "{}: {}", CRITICAL_ERROR_MISSING_OR_INVALID_API_BOUNDARY_NODES, err_msg,
            );
        };

        // 1. Get all API Boundary Node IDs from the registry.
        // 2. For all obtained IDs, retrieve a corresponding NodeRecord from the registry. NOTE: If such NodeRecord doesn't exist, the registry is in a broken state.
        // 3. From the NodeRecord we form the ApiBoundaryNodeEntry to be saved in the ReplicatedState.
        let api_boundary_nodes_ids = self
            .registry
            .get_api_boundary_node_ids(registry_version)
            .map_err(|err| registry_error("api boundary nodes ids", None, err))?;

        let mut api_boundary_nodes: ApiBoundaryNodes = BTreeMap::new();

        for api_bn_id in api_boundary_nodes_ids {
            let node_record = self
                .registry
                .get_node_record(api_bn_id, registry_version)
                .map_err(|err| {
                    registry_error(&format!("NodeRecord for node_id {}", api_bn_id), None, err)
                })?;

            let Some(node_record) = node_record else {
                raise_critical_error_for_api_boundary_nodes(&format!(
                    "NodeRecord for node_id {} is missing in registry.",
                    api_bn_id,
                ));
                continue;
            };

            let Some(domain) = node_record.domain else {
                raise_critical_error_for_api_boundary_nodes(&format!(
                    "domain field in NodeRecord for node_id {} is None.",
                    api_bn_id,
                ));
                continue;
            };

            let Some(http) = node_record.http else {
                raise_critical_error_for_api_boundary_nodes(&format!(
                    "http field in NodeRecord for node_id {} is None.",
                    api_bn_id,
                ));
                continue;
            };

            let ipv6_address = http.ip_addr;
            if ipv6_address.parse::<Ipv6Addr>().is_err() {
                raise_critical_error_for_api_boundary_nodes(&format!(
                    "failed to parse ipv6 field in NodeRecord for node_id {api_bn_id}",
                ));
                continue;
            }

            // ipv4 is not mandatory for the node record. No critical errors need to be raised if it is `None`.
            let ipv4_address = node_record
                .public_ipv4_config
                .map(|ipv4_config| ipv4_config.ip_addr);
            if let Some(ref ipv4) = ipv4_address {
                if ipv4.parse::<Ipv4Addr>().is_err() {
                    raise_critical_error_for_api_boundary_nodes(&format!(
                        "failed to parse ipv4 address of node {api_bn_id}",
                    ));
                    continue;
                }
            }

            api_boundary_nodes.insert(
                api_bn_id,
                ApiBoundaryNodeEntry {
                    domain,
                    ipv6_address,
                    ipv4_address,
                    pubkey: None,
                },
            );
        }
        Ok(api_boundary_nodes)
    }
}

impl BatchProcessor for BatchProcessorImpl {
    #[instrument(skip_all)]
    fn process_batch(&self, batch: Batch) {
        let _process_batch_start = Instant::now();
        let since = Instant::now();

        // Fetch the mutable tip from StateManager
        let mut state = match self
            .state_manager
            .take_tip_at(batch.batch_number.decrement())
        {
            Ok(state) => state,
            Err(StateManagerError::StateRemoved(_)) => {
                info!(
                    self.log,
                    "Ignoring batch {} as we already have state {}",
                    batch.batch_number,
                    self.state_manager.latest_state_height()
                );
                return;
            }
            Err(StateManagerError::StateNotCommittedYet(_)) => fatal!(
                self.log,
                "Cannot apply batch {}, to state {}",
                batch.batch_number,
                self.state_manager.latest_state_height()
            ),
        };

        if let Some(BatchSummary {
            next_checkpoint_height,
            ..
        }) = batch.batch_summary
        {
            self.metrics
                .next_checkpoint_height
                .set(next_checkpoint_height.get() as i64);
        }

        // If the subnet is starting up after a split, execute splitting phase 2.
        if let Some(split_from) = state.metadata.split_from {
            info!(
                self.log,
                "State has resulted from splitting subnet {}, running phase 2 of state splitting",
                split_from
            );
            self.metrics
                .subnet_split_height
                .with_label_values(&[&split_from.to_string()])
                .set(batch.batch_number.get() as i64);
            state.after_split();
        }
        self.observe_phase_duration(PHASE_LOAD_STATE, &since);

        debug!(self.log, "Processing batch {}", batch.batch_number);
        let commit_height = Height::from(batch.batch_number.get());

        let certification_scope = if batch.requires_full_state_hash {
            CertificationScope::Full
        } else {
            CertificationScope::Metadata
        };

        // TODO (MR-29) Cache network topology and subnet_features; and populate only
        // if version referenced in batch changes.
        let registry_version = batch.registry_version;
        let (
            network_topology,
            subnet_features,
            registry_execution_settings,
            node_public_keys,
            api_boundary_nodes,
        ) = self.read_registry(registry_version, state.metadata.own_subnet_id);

        self.metrics.blocks_proposed_total.inc();
        self.metrics
            .blocks_not_proposed_total
            .inc_by(batch.blockmaker_metrics.failed_blockmakers.len() as u64);
        state
            .metadata
            .blockmaker_metrics_time_series
            .observe(batch.time, &batch.blockmaker_metrics);

        let batch_summary = batch.batch_summary.clone();

        let mut state_after_round = self.state_machine.execute_round(
            state,
            network_topology,
            batch,
            subnet_features,
            &registry_execution_settings,
            node_public_keys,
            api_boundary_nodes,
        );
        // Garbage collect empty canister queue pairs before checkpointing.
        if certification_scope == CertificationScope::Full {
            state_after_round.garbage_collect_canister_queues();
        }
        let total_memory_usage = self.observe_canisters_memory_usage(&state_after_round);
        state_after_round
            .metadata
            .subnet_metrics
            .canister_state_bytes = total_memory_usage;

        #[cfg(feature = "malicious_code")]
        if let Some(delay) = self.malicious_flags.delay_execution(_process_batch_start) {
            info!(self.log, "[MALICIOUS]: Delayed execution by {:?}", delay);
        }

        let phase_since = Instant::now();

        self.state_manager.commit_and_certify(
            state_after_round,
            commit_height,
            certification_scope,
            batch_summary,
        );
        self.observe_phase_duration(PHASE_COMMIT, &phase_since);

        self.metrics
            .process_batch_duration
            .observe(since.elapsed().as_secs_f64());
        self.metrics
            .registry_version
            .set(registry_version.get() as i64);
    }
}

pub(crate) struct FakeBatchProcessorImpl {
    stream_builder: Box<dyn routing::stream_builder::StreamBuilder>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    log: ReplicaLogger,
}

impl FakeBatchProcessorImpl {
    pub fn new(
        log: ReplicaLogger,
        stream_builder: Box<dyn routing::stream_builder::StreamBuilder>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    ) -> Self {
        Self {
            stream_builder,
            state_manager,
            ingress_history_writer,
            log,
        }
    }
}

impl BatchProcessor for FakeBatchProcessorImpl {
    fn process_batch(&self, batch: Batch) {
        // Fetch the mutable tip from StateManager
        let mut state = match self
            .state_manager
            .take_tip_at(batch.batch_number.decrement())
        {
            Ok(state) => state,
            Err(StateManagerError::StateRemoved(_)) => {
                info!(
                    self.log,
                    "Ignoring batch {} as we already have state {}",
                    batch.batch_number,
                    self.state_manager.latest_state_height()
                );
                return;
            }
            Err(StateManagerError::StateNotCommittedYet(_)) => fatal!(
                self.log,
                "Cannot apply batch {}, to state {}",
                batch.batch_number,
                self.state_manager.latest_state_height()
            ),
        };

        debug!(self.log, "Processing batch {}", batch.batch_number);
        let commit_height = Height::from(batch.batch_number.get());

        let time = batch.time;
        state.metadata.batch_time = time;

        // Get only ingress out of the batch_messages
        let signed_ingress_msgs = batch.messages.signed_ingress_msgs;

        // Treat all ingress messages as already executed.
        let all_ingress_execution_results = signed_ingress_msgs.into_iter().map(|ingress| {
            // It is safe to assume valid expiry time here
            (
                ingress.id(),
                ic_types::ingress::IngressStatus::Known {
                    receiver: ingress.canister_id().get(),
                    user_id: ingress.sender(),
                    time,
                    state: ic_types::ingress::IngressState::Completed(
                        // The byte content mimics a good reply for the counter example
                        ic_types::ingress::WasmResult::Reply(vec![68, 73, 68, 76, 0, 0]),
                    ),
                },
            )
        });

        for (msg_id, status) in all_ingress_execution_results {
            self.ingress_history_writer
                .set_status(&mut state, msg_id, status);
        }

        state.prune_ingress_history();

        // Postprocess the state and consolidate the Streams.
        let state_after_stream_builder = self.stream_builder.build_streams(state);

        let certification_scope = if batch.requires_full_state_hash {
            CertificationScope::Full
        } else {
            CertificationScope::Metadata
        };

        self.state_manager.commit_and_certify(
            state_after_stream_builder,
            commit_height,
            certification_scope,
            batch.batch_summary,
        );
    }
}

impl MessageRoutingImpl {
    fn from_batch_processor(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        batch_processor: Box<dyn BatchProcessor>,
        metrics: MessageRoutingMetrics,
        log: ReplicaLogger,
    ) -> Self {
        let (batch_sender, batch_receiver) = sync_channel(BATCH_QUEUE_BUFFER_SIZE);

        let _batch_processor_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name("MR Batch Processor".to_string())
                .spawn(move || {
                    while let Ok(batch) = batch_receiver.recv() {
                        batch_processor.process_batch(batch);
                    }
                })
                .expect("Can spawn a batch processing thread in MR"),
        );

        Self {
            last_seen_batch: RwLock::new(Height::from(0)),
            batch_sender,
            state_manager,
            metrics,
            log,
            _batch_processor_handle,
        }
    }

    /// Creates a new `MessageRoutingImpl` for the given subnet using the
    /// provided `StateManager` and `ExecutionEnvironment`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        hypervisor_config: HypervisorConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        registry: Arc<dyn RegistryClient>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let metrics = MessageRoutingMetrics::new(metrics_registry);
        let batch_processor = Box::new(BatchProcessorImpl::new(
            state_manager.clone(),
            certified_stream_store,
            ingress_history_writer,
            scheduler,
            hypervisor_config,
            cycles_account_manager,
            subnet_id,
            metrics.clone(),
            metrics_registry,
            log.clone(),
            registry,
            malicious_flags,
        ));

        Self::from_batch_processor(state_manager, batch_processor, metrics, log)
    }

    /// Creates a new `MessageRoutingImpl` for the given subnet using a fake
    /// `BatchProcessor` and the provided `StateManager`.
    pub fn new_fake(
        subnet_id: SubnetId,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let stream_builder = Box::new(routing::stream_builder::StreamBuilderImpl::new(
            subnet_id,
            metrics_registry,
            MessageRoutingMetrics::new(metrics_registry),
            Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
                metrics_registry,
            ))),
            log.clone(),
        ));

        let batch_processor = FakeBatchProcessorImpl::new(
            log.clone(),
            stream_builder,
            Arc::clone(&state_manager),
            ingress_history_writer,
        );
        let metrics = MessageRoutingMetrics::new(metrics_registry);

        Self::from_batch_processor(state_manager, Box::new(batch_processor), metrics, log)
    }

    fn inc_deliver_batch(&self, status: &str) {
        self.metrics
            .deliver_batch_count
            .with_label_values(&[status])
            .inc();
    }
}

impl MessageRouting for MessageRoutingImpl {
    #[instrument(skip_all)]
    fn deliver_batch(&self, batch: Batch) -> Result<(), MessageRoutingError> {
        let batch_number = batch.batch_number;
        let expected_number = self.expected_batch_height();
        self.metrics
            .expected_batch_height
            .set(expected_number.get() as i64);
        if batch_number != expected_number {
            self.inc_deliver_batch(STATUS_IGNORED);
            info!(
                self.log,
                "Ignoring batch {}, expected batch: {}", batch_number, expected_number,
            );
            return Err(MessageRoutingError::Ignored {
                expected_height: expected_number,
                actual_height: batch_number,
            });
        }

        match self.batch_sender.try_send(batch) {
            Ok(_) => {
                self.inc_deliver_batch(STATUS_SUCCESS);
                debug!(self.log, "Inserted batch {}", batch_number);
                *self.last_seen_batch.write().unwrap() = batch_number;
                Ok(())
            }
            // If the queue is already full, we pretend that we never received
            // the batch. It's important not to block Consensus, it will try to
            // resend the overflowing batches later.
            Err(TrySendError::Full(_)) => {
                self.inc_deliver_batch(STATUS_QUEUE_FULL);
                debug!(
                    self.log,
                    "Rejecting batch {}: execution queue overflow ({} batches queued)",
                    batch_number,
                    BATCH_QUEUE_BUFFER_SIZE
                );
                Err(MessageRoutingError::QueueIsFull)
            }
            Err(TrySendError::Disconnected(_)) => fatal!(
                self.log,
                "Failed to send batch {}: background worker is dead",
                batch_number,
            ),
        }
    }

    fn expected_batch_height(&self) -> Height {
        self.last_seen_batch
            .read()
            .unwrap()
            .increment()
            .max(self.state_manager.latest_state_height().increment())
    }
}

/// An MessageRouting implementation that processes batches synchronously. Primarily used for
/// testing.
pub struct SyncMessageRouting {
    batch_processor: Arc<Mutex<dyn BatchProcessor>>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
}

impl SyncMessageRouting {
    /// Creates a new `SyncMessageRoutingImpl` for the given subnet using the
    /// provided `StateManager` and `ExecutionEnvironment`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        hypervisor_config: HypervisorConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        registry: Arc<dyn RegistryClient>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let metrics = MessageRoutingMetrics::new(metrics_registry);

        let batch_processor = BatchProcessorImpl::new(
            state_manager.clone(),
            certified_stream_store,
            ingress_history_writer,
            scheduler,
            hypervisor_config,
            cycles_account_manager,
            subnet_id,
            metrics,
            metrics_registry,
            log.clone(),
            registry,
            malicious_flags,
        );
        let batch_processor = Arc::new(Mutex::new(batch_processor));

        Self {
            batch_processor,
            state_manager,
        }
    }

    /// Process a batch synchronously.
    ///
    /// This method blocks until the batch has been processed.
    ///
    /// An error is returned if the height of the given batch does not match the expected height.
    pub fn process_batch(&self, batch: Batch) -> Result<(), MessageRoutingError> {
        let batch_number = batch.batch_number;
        let batch_processor = self.batch_processor.lock().unwrap();
        let expected_number = self.expected_batch_height();
        if expected_number != batch_number {
            return Err(MessageRoutingError::Ignored {
                expected_height: expected_number,
                actual_height: batch_number,
            });
        }
        batch_processor.process_batch(batch);
        Ok(())
    }

    pub fn expected_batch_height(&self) -> Height {
        self.state_manager.latest_state_height().increment()
    }
}
