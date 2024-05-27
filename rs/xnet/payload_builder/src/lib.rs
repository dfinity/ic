pub mod certified_slice_pool;
mod proximity;

#[cfg(test)]
mod impl_tests;
#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod xnet_client_tests;

use crate::certified_slice_pool::{
    certified_slice_count_bytes, CertifiedSliceError, CertifiedSlicePool, CertifiedSliceResult,
};
use async_trait::async_trait;
use hyper::{client::Client, Body, Request, StatusCode, Uri};
use ic_async_utils::{receive_body_without_timeout, BodyReceiveError};
use ic_constants::SYSTEM_SUBNET_STREAM_MSG_LIMIT;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::{
    messaging::{
        InvalidXNetPayload, XNetPayloadBuilder, XNetPayloadValidationError,
        XNetPayloadValidationFailure,
    },
    validation::ValidationError,
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{error, info, log, warn, ReplicaLogger};
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero},
    MetricsRegistry,
};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetListRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{replicated_state::ReplicatedStateMessageRouting, ReplicatedState};
use ic_types::{
    batch::{ValidationContext, XNetPayload},
    registry::RegistryClientError,
    xnet::{CertifiedStreamSlice, StreamIndex},
    Height, NodeId, NumBytes, RegistryVersion, SubnetId,
};
use ic_xnet_hyper::{ExecuteOnRuntime, TlsConnector};
use ic_xnet_uri::XNetAuthority;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};
pub use proximity::{GenRangeFn, ProximityMap};
use rand::{rngs::StdRng, thread_rng, Rng};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{runtime, sync::mpsc};

/// Message and signal indices into a XNet stream or stream slice.
///
/// Used when computing the expected indices of a stream during payload building
/// and validation. Or as cutoff points when dealing with stream slices.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd)]
pub struct ExpectedIndices {
    pub message_index: StreamIndex,
    pub signal_index: StreamIndex,
}

/// Interface for a pool of incoming `CertifiedStreamSlices`.
pub trait XNetSlicePool: Send + Sync {
    /// Takes a sub-slice of the stream from `subnet_id` starting at `begin`,
    /// respecting the given message count and byte limits; or, if the provided
    /// `byte_limit` is too small for a header-only slice, returns `Ok(None)`.
    ///
    /// If all messages are taken, the slice is removed from the pool.
    ///
    /// Returns `Err(InvalidPayload)` or `Err(WitnessPruningFailed)` and drops
    /// the pooled slice if malformed. Returns `Err(TakeBeforeSliceBegin)` and
    /// drops the pooled slice if `begin`'s `message_index` is before the
    /// first pooled message.
    fn take_slice(
        &self,
        subnet_id: SubnetId,
        begin: Option<&ExpectedIndices>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<Option<(CertifiedStreamSlice, usize)>>;

    /// Observes the total size of all pooled slices.
    fn observe_pool_size_bytes(&self);

    /// Garbage collects all messages and signals before the given stream
    /// positions. Slices from subnets not present in the provided map are all
    /// dropped.
    fn garbage_collect(&self, new_stream_positions: BTreeMap<SubnetId, ExpectedIndices>);

    /// Garbage collects all messages and signals before the given stream
    /// position for the given slice.
    fn garbage_collect_slice(&self, subnet_id: SubnetId, stream_position: ExpectedIndices);
}

pub struct XNetPayloadBuilderMetrics {
    /// Records the time it took to build the payload, by status.
    pub build_payload_duration: HistogramVec,
    /// Records pull attempts, by status. Orthogonal to to slice queries, as some
    /// attempts may fail before querying (e.g. due to registry errors) and
    /// some successful queries may produce invalid slices.
    pub pull_attempt_count: IntCounterVec,
    /// Records the time it took to query a slice to be included into the
    /// payload, by status. Orthogonal to to pull attempts, as some attempts may
    /// fail before querying (e.g. due to registry errors) and some successful
    /// queries may produce invalid slices.
    pub query_slice_duration: HistogramVec,
    /// Message count per valid slice.
    pub slice_messages: Histogram,
    /// Valid slice payload sizes.
    pub slice_payload_size: Histogram,
    /// Records the time it took to validate a payload, by status.
    pub validate_payload_duration: HistogramVec,
    /// Track outstanding background query tasks
    pub outstanding_queries: IntGauge,
    /// Critical error: failed `count_bytes()` on valid slice.
    pub critical_error_slice_count_bytes_failed: IntCounter,
    /// Critical error: mismatch between the byte sizes computed by `take_slice()`,
    /// `certified_slice_count_bytes()` and `UnpackedStreamSlice::count_bytes()`.
    pub critical_error_slice_count_bytes_invalid: IntCounter,
}

pub const METRIC_BUILD_PAYLOAD_DURATION: &str = "xnet_builder_build_payload_duration_seconds";
pub const METRIC_PULL_ATTEMPT_COUNT: &str = "xnet_builder_pull_attempt_count";
pub const METRIC_QUERY_SLICE_DURATION: &str = "xnet_builder_query_slice_duration_seconds";
pub const METRIC_RESPONSE_BODY_SIZE: &str = "xnet_builder_response_body_size_bytes";
pub const METRIC_SLICE_MESSAGES: &str = "xnet_builder_slice_messages";
pub const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_builder_slice_payload_size_bytes";
pub const METRIC_VALIDATE_PAYLOAD_DURATION: &str = "xnet_builder_validate_payload_duration_seconds";
pub const METRIC_OUTSTANDING_XNET_QUERIES: &str = "xnet_builder_outstanding_queries";

pub const CRITICAL_ERROR_SLICE_COUNT_BYTES_FAILED: &str = "xnet_slice_count_bytes_failed";
pub const CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES: &str = "xnet_slice_count_bytes_invalid";

pub const LABEL_STATUS: &str = "status";
pub const LABEL_PROXIMITY: &str = "proximity";

pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_DECODE_ERROR: &str = "ProxyDecodeError";

pub const VALIDATION_STATUS_ERROR: &str = "error";
pub const VALIDATION_STATUS_INVALID: &str = "invalid";
pub const VALIDATION_STATUS_EMPTY_SLICE: &str = "empty_slice";
pub const VALIDATION_STATUS_VALID: &str = "valid";

impl XNetPayloadBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            build_payload_duration: metrics_registry.histogram_vec(
                METRIC_BUILD_PAYLOAD_DURATION,
                "The time it took to build the payload, by status.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS],
            ),
            pull_attempt_count: metrics_registry.int_counter_vec(
                METRIC_PULL_ATTEMPT_COUNT,
                "Attempted XNet pulls, by status.",
                &[LABEL_STATUS],
            ),
            query_slice_duration: metrics_registry.histogram_vec(
                METRIC_QUERY_SLICE_DURATION,
                "The time it took to query a slice to be included into the payload, by status and proximity.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS, LABEL_PROXIMITY],
            ),
            slice_messages: metrics_registry.histogram(
                METRIC_SLICE_MESSAGES,
                "Message count per valid slice.",
                // 1 - 500
                decimal_buckets_with_zero(0, 2),
            ),
            slice_payload_size: metrics_registry.histogram(
                METRIC_SLICE_PAYLOAD_SIZE,
                "Valid slice payload sizes.",
                // 10 B - 5 MB
                decimal_buckets(1, 6),
            ),
            validate_payload_duration: metrics_registry.histogram_vec(
                METRIC_VALIDATE_PAYLOAD_DURATION,
                "The time it took to validate a payload, by status.",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &[LABEL_STATUS],
            ),
            outstanding_queries: metrics_registry.int_gauge(
                METRIC_OUTSTANDING_XNET_QUERIES,
                "Number of xnet queries that have not finished",
            ),
            critical_error_slice_count_bytes_failed: metrics_registry
                .error_counter(CRITICAL_ERROR_SLICE_COUNT_BYTES_FAILED),
            critical_error_slice_count_bytes_invalid: metrics_registry
                .error_counter(CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES),
        }
    }

    /// Records the status and duration of a `get_xnet_payload()` call.
    fn observe_build_duration(&self, status: &str, since: Instant) {
        self.build_payload_duration
            .with_label_values(&[status])
            .observe(since.elapsed().as_secs_f64());
    }

    /// Increments the `pull_attempt_count` counter for the given status.
    fn observe_pull_attempt(&self, status: &str) {
        self.pull_attempt_count.with_label_values(&[status]).inc();
    }

    /// Observes the elapsed `query_slice_duration` under the given status.
    fn observe_query_slice_duration(&self, status: &str, proximity: &str, since: Instant) {
        self.query_slice_duration
            .with_label_values(&[status, proximity])
            .observe(since.elapsed().as_secs_f64());
    }

    /// Records the status and duration of a `validate_xnet_payload()` call.
    fn observe_validate_duration(&self, status: &str, since: Instant) {
        self.validate_payload_duration
            .with_label_values(&[status])
            .observe(since.elapsed().as_secs_f64());
    }
}

/// Implementation of `XNetPayloadBuilder` that uses a `StateManager`,
/// `RegistryClient` and `XNetClient` to build and validate `XNetPayloads`.
pub struct XNetPayloadBuilderImpl {
    /// Used for retrieving the execution state, for both payload building and
    /// validation.
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,

    /// Used for decoding certified streams.
    certified_stream_store: Arc<dyn CertifiedStreamStore>,

    /// Used for retrieving a subnet's nodes, in order to poll their
    /// `XNetEndpoints` for `CertifiedStreamSlices` to be included into
    /// `XNetPayloads`.
    registry: Arc<dyn RegistryClient>,

    /// A deterministic pseudo-random number generator.
    deterministic_rng_for_testing: Arc<Option<Mutex<StdRng>>>,

    /// A pool of slices, filled in the background by an async task.
    slice_pool: Box<dyn XNetSlicePool>,

    /// Handle to the pool refill task, used to asynchronously trigger refill.
    refill_task_handle: RefillTaskHandle,

    /// Function to be used for calculating deterministic `CertifiedStreamSlice`
    /// byte sizes. Always
    /// `crate::certified_slice_pool::certified_slice_count_bytes()` in
    /// production code, only replaced in unit tests.
    count_bytes_fn: fn(&CertifiedStreamSlice) -> CertifiedSliceResult<usize>,

    metrics: Arc<XNetPayloadBuilderMetrics>,

    log: ReplicaLogger,
}

/// Represents the location of a peer
#[derive(Debug, PartialEq, Eq)]
pub enum PeerLocation {
    /// Peer in the same datacenter
    Local,

    /// Peer in other datacenter
    Remote,
}

impl From<PeerLocation> for &str {
    fn from(proximity: PeerLocation) -> Self {
        match proximity {
            PeerLocation::Local => "local",
            PeerLocation::Remote => "remote",
        }
    }
}

/// Metadata describing a replica's XNet endpoint.
#[derive(Debug, PartialEq, Eq)]
pub struct EndpointLocator {
    /// The ID of the node hosting the replica.
    node_id: NodeId,

    /// The endpoint URL.
    pub url: Uri,

    /// The proximity of the peer.
    proximity: PeerLocation,
}

impl XNetPayloadBuilderImpl {
    /// Creates a new `XNetPayloadBuilderImpl` for a node on `subnet_id`, using
    /// the given `StateManager`, `CertifiedStreamStore` and`RegistryClient`.
    ///
    /// # Panics
    ///
    /// Panics if reading the node's own `node_operator_id` from the registry
    /// fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        tls_handshake: Arc<dyn TlsConfig + Send + Sync>,
        registry: Arc<dyn RegistryClient>,
        runtime_handle: runtime::Handle,
        node_id: NodeId,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        let proximity_map = Arc::new(ProximityMap::new(
            node_id,
            registry.clone(),
            metrics_registry,
            log.clone(),
        ));
        let xnet_client: Arc<dyn XNetClient> = Arc::new(XNetClientImpl::new(
            metrics_registry,
            runtime_handle.clone(),
            tls_handshake,
            proximity_map.clone(),
        ));

        let deterministic_rng_for_testing = Arc::new(None);
        let certified_slice_pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            Arc::clone(&certified_stream_store),
            metrics_registry,
        )));
        let slice_pool = Box::new(XNetSlicePoolImpl::new(certified_slice_pool.clone()));
        let metrics = Arc::new(XNetPayloadBuilderMetrics::new(metrics_registry));
        let endpoint_resolver = XNetEndpointResolver::new(
            Arc::clone(&registry),
            node_id,
            subnet_id,
            proximity_map,
            log.clone(),
        );
        let refill_task_handle = PoolRefillTask::start(
            Arc::clone(&certified_slice_pool),
            endpoint_resolver,
            Arc::clone(&xnet_client),
            runtime_handle,
            Arc::clone(&metrics),
            log.clone(),
        );
        Self::new_from_components(
            state_manager,
            certified_stream_store,
            registry,
            deterministic_rng_for_testing,
            slice_pool,
            refill_task_handle,
            metrics,
            log,
        )
    }

    /// Same as `new` except that this constructor uses the provided `slice_pool`
    /// instead of constructing a fresh one.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_components(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        registry: Arc<dyn RegistryClient>,
        deterministic_rng_for_testing: Arc<Option<Mutex<StdRng>>>,
        slice_pool: Box<dyn XNetSlicePool>,
        refill_task_handle: RefillTaskHandle,
        metrics: Arc<XNetPayloadBuilderMetrics>,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        Self {
            state_manager,
            certified_stream_store,
            registry,
            deterministic_rng_for_testing,
            slice_pool,
            refill_task_handle,
            count_bytes_fn: certified_slice_count_bytes,
            metrics,
            log,
        }
    }

    /// Testing only: replaces the function to be used for calculating
    /// `CertifiedStreamSlice` byte sizes with the provided one.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn with_count_bytes_fn(
        mut self,
        certified_slice_count_bytes: fn(&CertifiedStreamSlice) -> CertifiedSliceResult<usize>,
    ) -> Self {
        self.count_bytes_fn = certified_slice_count_bytes;
        self
    }

    /// Calculates the next expected message and signal indices for a given
    /// stream, based on `state` and the subsequent `payloads`.
    ///
    /// The next expected message index is the most recent `messages.end()` from
    /// `subnet_id` in `payloads`, when that exists; or `signals_end` of the
    /// outgoing `Stream` to `subnet_id` in `state`. The next expected signal
    /// index is the most recent `signals_end` from `subnet_id` in `payloads`,
    /// when that exists; or `messages_begin()` of the outgoing `Stream` to
    /// `subnet_id` in `state`.
    ///
    /// Returns the default value `(0, 0)` when no stream or slices from the
    /// given subnet exist.
    fn expected_indices_for_stream(
        &self,
        subnet_id: SubnetId,
        state: &ReplicatedState,
        payloads: &[&XNetPayload],
    ) -> ExpectedIndices {
        // Stream slices may contain signals only (and no message index). Remember the
        // first `signals_end` we encounter (if any) and return it as the expected
        // signal index, if present.
        let mut most_recent_signal_index = None;

        // Look for the most recent stream slice from `subnet_id`, if any.
        for payload in payloads.iter() {
            if let Some(certified_stream) = payload.stream_slices.get(&subnet_id) {
                let slice = self
                    .certified_stream_store
                    .decode_valid_certified_stream_slice(certified_stream)
                    .expect("failed to decode past certified stream");
                if let Some(messages) = slice.messages() {
                    return ExpectedIndices {
                        message_index: messages.end(),
                        signal_index: most_recent_signal_index
                            .unwrap_or_else(|| slice.header().signals_end()),
                    };
                }
                most_recent_signal_index.get_or_insert_with(|| slice.header().signals_end());
            }
        }

        // No stream slice from `subnet_id` in `payloads`, look in `state`.
        state
            .streams()
            .get(&subnet_id)
            .map(|stream| ExpectedIndices {
                message_index: stream.signals_end(),
                signal_index: most_recent_signal_index.unwrap_or_else(|| stream.messages_begin()),
            })
            .unwrap_or_default()
    }

    /// Computes the expected message and signal indices for every known subnet.
    fn expected_stream_indices(
        &self,
        validation_context: &ValidationContext,
        state: &ReplicatedState,
        past_payloads: &[&XNetPayload],
    ) -> Result<BTreeMap<SubnetId, ExpectedIndices>, Error> {
        let subnet_ids = self
            .registry
            .get_subnet_ids(validation_context.registry_version)
            .map_err(Error::RegistryGetSubnetsFailed)?
            .unwrap_or_default();

        let expected_indices = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                (
                    subnet_id,
                    self.expected_indices_for_stream(subnet_id, state, past_payloads),
                )
            })
            .collect::<BTreeMap<SubnetId, ExpectedIndices>>();
        Ok(expected_indices)
    }

    /// Validates the signals of the incoming `StreamSlice` from
    /// `subnet_id` with respect to `expected` (the expected signal index);
    /// and to `messages_end()` of the outgoing `Stream` to `subnet_id`.
    ///
    /// In particular:
    ///
    ///  1. `signals_end` must be monotonically increasing, i.e. `expected <=
    /// signals_end`;
    ///
    ///  2. signals must only refer to past and current messages, i.e.
    /// `signals_end <= stream.messages_end()`;
    ///
    ///  3. `signals_end - reject_signals[0] <= MAX_STREAM_MESSAGES`; and
    ///
    ///  4. `concat(reject_signals, [signals_end])` must be strictly increasing.
    /// and
    fn validate_signals(
        &self,
        subnet_id: SubnetId,
        signals_end: StreamIndex,
        reject_signals: &VecDeque<StreamIndex>,
        expected: StreamIndex,
        state: &ReplicatedState,
    ) -> SignalsValidationResult {
        // `messages_end()` of the outgoing stream.
        let (self_messages_begin, self_messages_end) = state
            .streams()
            .get(&subnet_id)
            .map(|s| (s.messages_begin(), s.messages_end()))
            .unwrap_or_default();

        // Must expect signal for existing message (or just beyond last message).
        assert!(
            self_messages_begin <= expected && expected <= self_messages_end,
            "Subnet {}: invalid expected signal; messages_begin() ({}) <= expected ({}) <= messages_end() ({})",
            subnet_id,
            self_messages_begin,
            expected,
            self_messages_end
        );

        if expected > signals_end || signals_end > self_messages_end {
            warn!(
                self.log,
                "Invalid stream from {}: expected ({}) <= signals_end ({}) <= self.messages_end() ({})",
                subnet_id,
                expected,
                signals_end,
                self_messages_end
            );
            return SignalsValidationResult::Invalid;
        }

        if !reject_signals.is_empty() {
            // Given the minimum message size (zero-length sender and receiver, no cycles,
            // no payload) of 17 bytes; plus 16 bytes for `LabelTree` encoding plus label;
            // and 16+6 bytes for a `Witness::Known` and a `Witness::Fork` node; we have
            // a minimum of 55 bytes per encoded message.
            //
            // With a `TARGET_STREAM_SIZE_BYTES` of 10 MiB, that means a maximum of just
            // over 190K messages in a stream. 200K to be conservative.
            const MAX_STREAM_MESSAGES: u64 = 200_000;

            // An honest subnet will only produce signals for the messages in the incoming
            // stream (i.e. no signals for future messages; and all signals for past
            // messages have been GC-ed). Meaning we can never have signals going back
            // farther than the maximum number of messages in a stream.
            let signals_begin = reject_signals.front().unwrap();
            if signals_end.get() - signals_begin.get() > MAX_STREAM_MESSAGES {
                warn!(
                    self.log,
                    "Too old reject signal in stream from {}: signals_begin {}, signals_end {}",
                    subnet_id,
                    signals_begin,
                    signals_end
                );
                return SignalsValidationResult::Invalid;
            }

            let mut next = signals_end;
            for index in reject_signals.iter().rev() {
                if index >= &next {
                    warn!(
                        self.log,
                        "Invalid signals in stream from {}: reject_signals {:?}, signals_end {}",
                        subnet_id,
                        reject_signals,
                        signals_end
                    );
                    return SignalsValidationResult::Invalid;
                }
                next = *index;
            }
        }

        SignalsValidationResult::Valid
    }

    /// Validates the `certified_slice` received from `subnet_id`:
    ///  * checks its signature against the public key of `subnet_id`;
    ///  * ensures stream message bounds are valid and slice message bounds are
    ///    within stream message bounds;
    ///  * looks for gaps/duplicates in its `messages` w.r.t. `expected`
    ///    indices;
    ///  * and ensures signals advance monotonically and don't cover more than
    ///    the maximum number of messages in a stream.
    ///
    /// Returns the validation result, including the `CountBytes`-like estimate
    /// (deterministic, but not exact) of the slice size in bytes if valid.
    fn validate_slice(
        &self,
        subnet_id: SubnetId,
        certified_slice: &CertifiedStreamSlice,
        expected: &ExpectedIndices,
        validation_context: &ValidationContext,
        state: &ReplicatedState,
    ) -> SliceValidationResult {
        // Do not accept loopback stream slices. Those are inducted separately, entirely
        // within the DSM.
        if subnet_id == state.metadata.own_subnet_id {
            return SliceValidationResult::Invalid(
                "Loopback stream is inducted separately".to_string(),
            );
        }

        let slice = match self.certified_stream_store.decode_certified_stream_slice(
            subnet_id,
            validation_context.registry_version,
            certified_slice,
        ) {
            Ok(slice) => slice,
            Err(err) => {
                info!(
                    self.log,
                    "Failed to decode stream slice from subnet {}: {}", subnet_id, err
                );
                return SliceValidationResult::Invalid(format!(
                    "Invalid stream from {}: {}",
                    subnet_id, err
                ));
            }
        };

        // Valid stream message bounds.
        if slice.header().begin() > slice.header().end() {
            warn!(
                self.log,
                "Stream from {}: begin index ({}) after end index ({})",
                subnet_id,
                slice.header().begin(),
                slice.header().end()
            );
            return SliceValidationResult::Invalid(format!(
                "Invalid stream bounds in stream from {}",
                subnet_id
            ));
        }

        // Expected message index within stream message bounds (always present in the
        // header, even for empty slices).
        if expected.message_index < slice.header().begin()
            || slice.header().end() < expected.message_index
        {
            warn!(
                self.log,
                "Stream from {}: expecting message {}, outside of stream bounds [{}, {})",
                subnet_id,
                expected.message_index,
                slice.header().begin(),
                slice.header().end()
            );
            return SliceValidationResult::Invalid(format!(
                "Unexpected messages in stream from {}",
                subnet_id
            ));
        }

        if slice.messages().is_none() && slice.header().signals_end() == expected.signal_index {
            // Empty slice: no messages and no additional signals (in addition to what we
            // have in state and any intervening payloads). Not actually invalid, but
            // we don't want it in a payload.
            return SliceValidationResult::Empty;
        }

        if let Some(messages) = slice.messages() {
            // Messages in slice within stream message bounds.
            if messages.begin() < slice.header().begin() || messages.end() > slice.header().end() {
                warn!(
                    self.log,
                    "Stream from {}: slice bounds [{}, {}) outside of stream bounds [{}, {})",
                    subnet_id,
                    messages.begin(),
                    messages.end(),
                    slice.header().begin(),
                    slice.header().end()
                );
                return SliceValidationResult::Invalid(format!(
                    "Invalid slice bounds in stream from {}",
                    subnet_id
                ));
            }

            // Messages begin exactly at the expected message index.
            if messages.begin() != expected.message_index {
                warn!(
                    self.log,
                    "Stream from {}: expecting message with index {}, found {}",
                    subnet_id,
                    expected.message_index,
                    messages.begin()
                );
                return SliceValidationResult::Invalid(format!(
                    "Unexpected messages in stream from {}",
                    subnet_id
                ));
            }

            // Ensure the message limit (dictated e.g. by the backlog size) is respected.
            if let Some(msg_limit) = get_msg_limit(subnet_id, state) {
                if messages.len() > msg_limit {
                    warn!(
                        self.log,
                        "Stream from {}: slice length ({}) above limit ({})",
                        subnet_id,
                        messages.len(),
                        msg_limit
                    );
                    return SliceValidationResult::Invalid(format!(
                        "Stream from {}: slice length above limit",
                        subnet_id
                    ));
                }
            }
        }

        let byte_size = match (self.count_bytes_fn)(certified_slice) {
            Ok(byte_size) => byte_size,
            Err(e) => {
                // This should not happen. We have already validated the slice.
                error!(
                    self.log,
                    "{}: Stream from {}: failed to compute CertifiedStreamSlice byte size for valid slice: {}",
                    CRITICAL_ERROR_SLICE_COUNT_BYTES_FAILED,
                    subnet_id,
                    e
                );
                self.metrics.critical_error_slice_count_bytes_failed.inc();
                return SliceValidationResult::Invalid(format!(
                    "Failed to compute CertifiedStreamSlice byte size: {}",
                    e
                ));
            }
        };

        // `signals_end` must point to a message in the stream (or just past the last
        // message).
        match self.validate_signals(
            subnet_id,
            slice.header().signals_end(),
            slice.header().reject_signals(),
            expected.signal_index,
            state,
        ) {
            SignalsValidationResult::Valid => {
                self.metrics
                    .slice_messages
                    .observe(slice.messages().map(|m| m.len()).unwrap_or(0) as f64);
                self.metrics
                    .slice_payload_size
                    .observe(certified_slice.payload.len() as f64);

                SliceValidationResult::Valid {
                    messages_end: slice
                        .messages()
                        .map(|messages| messages.end())
                        .unwrap_or(expected.message_index),
                    signals_end: slice.header().signals_end(),
                    byte_size,
                }
            }

            SignalsValidationResult::Invalid => SliceValidationResult::Invalid(format!(
                "Unexpected signals in stream from {}",
                subnet_id
            )),
        }
    }

    /// Given a number of subnets, choose a random subnet among them.
    fn choose_random_subnet(&self, num_subnets: usize) -> usize {
        let positions_range = 0..num_subnets;
        match *self.deterministic_rng_for_testing {
            None => thread_rng().gen_range(positions_range),
            Some(ref rng) => rng.lock().unwrap().gen_range(positions_range),
        }
    }

    /// Implementation of `get_xnet_payload()` that returns a `Result`, so it
    /// can use the `?` operator internally for clean and simple error handling.
    fn get_xnet_payload_impl(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> Result<(XNetPayload, NumBytes), Error> {
        // Retrieve the `ReplicatedState` required by `validation_context`.
        let state = self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|e| {
                let e = Error::GetStateFailed(validation_context.certified_height, e);
                warn!(self.log, "{}", e);
                e
            })?
            .take();

        // Build the payload based on indices computed from state + past payloads.
        let stream_positions =
            self.expected_stream_indices(validation_context, &state, past_payloads)?;
        if stream_positions.is_empty() {
            return Ok((XNetPayload::default(), 0.into()));
        }

        // Random rotation so all slices have equal chances if `byte_limit` is reached.
        let mut rotated_stream_positions: Vec<_> = stream_positions.clone().into_iter().collect();
        let first_subnet = self.choose_random_subnet(rotated_stream_positions.len());
        rotated_stream_positions.rotate_left(first_subnet);

        let mut bytes_left = byte_limit.get() as usize;
        let mut stream_slices = BTreeMap::new();

        {
            self.slice_pool.observe_pool_size_bytes();

            // Trim off messages in the state or past payloads.
            self.slice_pool.garbage_collect(stream_positions);

            // Keep adding slices until we run out of payload space.
            for (subnet_id, begin) in rotated_stream_positions {
                if !stream_slices.is_empty() && bytes_left < SLICE_BYTE_SIZE_MIN {
                    // Byte limit reached.
                    break;
                }

                let msg_limit = get_msg_limit(subnet_id, &state);
                let (slice, slice_bytes) = match self.slice_pool.take_slice(
                    subnet_id,
                    Some(&begin),
                    msg_limit,
                    Some(bytes_left),
                ) {
                    Ok(Some(slice)) => slice,
                    Ok(None) => continue,
                    // TODO(MR-6): Record failed pool take.
                    Err(_) => continue,
                };
                debug_assert!(slice_bytes <= bytes_left);

                // Filter out invalid slices.
                let validation_result =
                    self.validate_slice(subnet_id, &slice, &begin, validation_context, &state);
                // TODO(MR-6): Record valid/invalid slice.
                if let SliceValidationResult::Valid { byte_size, .. } = validation_result {
                    if byte_size != slice_bytes || byte_size > bytes_left {
                        let message = format!(
                            "Slice from {} has packed byte size {}, unpacked byte size {}, limit was {}",
                            subnet_id, byte_size, slice_bytes, bytes_left
                        );
                        debug_assert!(false, "{}", message);
                        error!(
                            self.log,
                            "{}: {}", CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES, message
                        );
                        self.metrics.critical_error_slice_count_bytes_invalid.inc();
                        continue;
                    }
                    bytes_left = bytes_left.saturating_sub(slice_bytes);
                    stream_slices.insert(subnet_id, slice);
                } else {
                    info!(
                        self.log,
                        "Invalid slice from {}: {:?}", subnet_id, validation_result
                    );
                }
            }
        }

        // Collect all successfully queried slices into an `XNetPayload`.
        Ok((
            XNetPayload { stream_slices },
            byte_limit.get().saturating_sub(bytes_left as u64).into(),
        ))
    }
}

/// Calculates an upper bound for how many messages can be included into a
/// block based on the size of the reverse stream, in an attempt to limit
/// the in-flight requests from and responses to a given subnet.
///
/// In order to prevent mutual stalling, only applies to incoming NNS
/// streams; and to `Application`-subnet-to-`System`-subnet streams.
pub fn get_msg_limit(subnet_id: SubnetId, state: &ReplicatedState) -> Option<usize> {
    use SubnetType::*;
    match state.metadata.own_subnet_type {
        // No limits for now on application subnets.
        Application | VerifiedApplication => None,

        System => {
            // If this is not the NNS subnet and the remote subnet is a system subnet, don't enforce the limit.
            if state.metadata.own_subnet_id != state.metadata.network_topology.nns_subnet_id {
                let remote_subnet_type = state
                    .metadata
                    .network_topology
                    .subnets
                    .get(&subnet_id)
                    .map(|subnet| subnet.subnet_type)
                    .unwrap_or(Application); // Technically unwrap() would work here, but this is safer.
                if remote_subnet_type == System {
                    return None;
                }
            }

            // Always stay below the limit on the NNS subnet; and on other system subnets for streams from application subnets.
            state
                .streams()
                .get(&subnet_id)
                .map(|stream| stream.messages().len())
                .or(Some(0))
                .map(|len| SYSTEM_SUBNET_STREAM_MSG_LIMIT.saturating_sub(len))
        }
    }
}

/// Resolves a stream index and byte limit to an `EndpointLocator`, consisting
/// of URL, node ID and proximity.
pub struct XNetEndpointResolver {
    /// Used for retrieving a subnet's nodes, in order to poll their
    /// `XNetEndpoints` for `CertifiedStreamSlices` to be included into
    /// `XNetPayloads`.
    registry: Arc<dyn RegistryClient>,

    // This node's subnet ID.
    subnet_id: SubnetId,

    // This node's operator ID.
    node_operator_id: Vec<u8>,

    /// Proximity map to use for probabilistically selecting nearby replicas.
    proximity_map: Arc<ProximityMap>,
}

impl XNetEndpointResolver {
    pub fn new(
        registry: Arc<dyn RegistryClient>,
        node_id: NodeId,
        subnet_id: SubnetId,
        proximity_map: Arc<ProximityMap>,
        log: ReplicaLogger,
    ) -> Self {
        let newest_registry = registry.get_latest_version();
        let node_operator_id =
            get_node_operator_id(&node_id, registry.as_ref(), &newest_registry, &log)
                .unwrap_or_else(|| {
                    panic!(
                    "Could not read own node's ({:?}) node record from registry of version ({:?}).",
                    node_id, newest_registry
                )
                });
        Self {
            registry,
            subnet_id,
            node_operator_id,
            proximity_map,
        }
    }

    /// Returns the `/api/v1/stream` `XNetEndpoint` URL of a slice of at most
    /// `byte_limit` bytes beginning at `msg_begin`, with a witness beginning at
    /// `witness_begin`, for an arbitrary node on `subnet_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving the node registry entry fails; if the
    /// requested subnet is missing or has no nodes; or if the node address
    /// is invalid.
    pub fn xnet_endpoint_url(
        &self,
        subnet_id: SubnetId,
        witness_begin: StreamIndex,
        msg_begin: StreamIndex,
        byte_limit: usize,
    ) -> Result<EndpointLocator, Error> {
        assert!(witness_begin <= msg_begin);

        let version = self.registry.get_latest_version();
        let (node, node_record) = self.proximity_map.pick_node(subnet_id, version)?;
        let proximity = if node_record.node_operator_id == self.node_operator_id {
            PeerLocation::Local
        } else {
            PeerLocation::Remote
        };

        let xnet_endpoint = node_record.xnet.ok_or(Error::MissingXNetEndpoint(node))?;

        let socket_addr = SocketAddr::new(
            xnet_endpoint.ip_addr.parse().map_err(|_| {
                Error::InvalidXNetEndpoint(node, format!("bad ip addr {}", xnet_endpoint.ip_addr))
            })?,
            u16::try_from(xnet_endpoint.port).map_err(|_| {
                Error::InvalidXNetEndpoint(node, format!("bad port {}", xnet_endpoint.port))
            })?,
        );

        let authority = XNetAuthority {
            node_id: node,
            registry_version: version,
            address: socket_addr,
        };

        let url = format!(
            "http://{}/api/v1/stream/{}?msg_begin={}&witness_begin={}&byte_limit={}",
            authority, self.subnet_id, msg_begin, witness_begin, byte_limit
        );

        url.parse::<Uri>()
            .map_err(|e| {
                panic!("Could not parse URL {} : {}", url, e);
            })
            .map(|url| EndpointLocator {
                node_id: node,
                url,
                proximity,
            })
    }
}

impl XNetPayloadBuilder for XNetPayloadBuilderImpl {
    fn get_xnet_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> (XNetPayload, NumBytes) {
        let since = Instant::now();
        let payload =
            match self.get_xnet_payload_impl(validation_context, past_payloads, byte_limit) {
                Ok((payload, byte_size)) => {
                    self.metrics.observe_build_duration(STATUS_SUCCESS, since);
                    (payload, byte_size)
                }

                Err(e) => {
                    log!(self.log, e.log_level(), "{}", e);
                    self.metrics
                        .observe_build_duration(e.to_label_value(), since);

                    (XNetPayload::default(), 0.into())
                }
            };

        // We don't care if the send succeeded or not. If it didn't, the refill task is
        // just behind.
        self.refill_task_handle
            .trigger_refill(validation_context.registry_version);

        payload
    }

    fn validate_xnet_payload(
        &self,
        payload: &XNetPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
    ) -> Result<NumBytes, XNetPayloadValidationError> {
        let since = Instant::now();
        let state = match self
            .state_manager
            .get_state_at(validation_context.certified_height)
        {
            Ok(state) => state.take(),
            Err(err) => {
                self.metrics
                    .observe_validate_duration(VALIDATION_STATUS_ERROR, since);
                return Err(from_state_manager_error(err));
            }
        };

        // For every slice in `payload`, check certification and gaps/duplicates.
        let mut new_stream_positions = Vec::new();
        let mut payload_byte_size = 0;
        for (subnet_id, certified_slice) in payload.stream_slices.iter() {
            let expected = self.expected_indices_for_stream(*subnet_id, &state, past_payloads);
            match self.validate_slice(
                *subnet_id,
                certified_slice,
                &expected,
                validation_context,
                &state,
            ) {
                SliceValidationResult::Invalid(reason) => {
                    self.metrics
                        .observe_validate_duration(VALIDATION_STATUS_INVALID, since);
                    return Err(ValidationError::InvalidArtifact(
                        InvalidXNetPayload::InvalidSlice(reason),
                    ));
                }
                SliceValidationResult::Empty => {
                    self.metrics
                        .observe_validate_duration(VALIDATION_STATUS_EMPTY_SLICE, since);
                    return Err(ValidationError::InvalidArtifact(
                        InvalidXNetPayload::InvalidSlice("Empty slice".to_string()),
                    ));
                }
                SliceValidationResult::Valid {
                    messages_end,
                    signals_end,
                    byte_size,
                } => {
                    new_stream_positions.push((*subnet_id, messages_end, signals_end));
                    payload_byte_size += byte_size;
                }
            }
        }

        // Garbage collect payload contents from the pool.
        {
            self.slice_pool.observe_pool_size_bytes();

            for (subnet_id, message_index, signal_index) in new_stream_positions {
                self.slice_pool.garbage_collect_slice(
                    subnet_id,
                    ExpectedIndices {
                        message_index,
                        signal_index,
                    },
                );
            }
        }
        // And trigger a pool refill.
        self.refill_task_handle
            .trigger_refill(validation_context.registry_version);

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, since);
        Ok(NumBytes::new(payload_byte_size as u64))
    }
}

/// Retrieves the given node's operator ID at the given registry version.
///
/// Returns `None` if the node record does not exist or the registry read
/// failed.
fn get_node_operator_id(
    node_id: &NodeId,
    registry: &dyn RegistryClient,
    registry_version: &RegistryVersion,
    log: &ReplicaLogger,
) -> Option<Vec<u8>> {
    registry
        .get_node_record(*node_id, *registry_version)
        .unwrap_or_else(|_| {
            info!(
                log,
                "Failed to retrieve registry record for node {}", node_id
            );
            None
        })
        .map(|r| r.node_operator_id)
}

/// Maps `StateManagerErrors` to their `XNetPayloadError` namesakes.
fn from_state_manager_error(e: StateManagerError) -> XNetPayloadValidationError {
    match e {
        StateManagerError::StateRemoved(height) => {
            ValidationError::ValidationFailed(XNetPayloadValidationFailure::StateRemoved(height))
        }
        StateManagerError::StateNotCommittedYet(height) => ValidationError::ValidationFailed(
            XNetPayloadValidationFailure::StateNotCommittedYet(height),
        ),
    }
}

/// Slice pool soft upper limit in bytes. Actual size may go over this limit, as
/// we're polling multiple subnets in parallel and we don't want to discard
/// slices that we've already pulled.
pub const POOL_BYTE_SIZE_SOFT_CAP: usize = 10 << 20;

/// Hard maximum slice size in bytes. We only pool up to 4 MB from any one
/// stream.
pub const POOL_SLICE_BYTE_SIZE_MAX: usize = 4 << 20;

/// Conservative minimum slice size in bytes. We stop trying to add slices to
/// the payload once we're this close to the payload size limit.
pub const SLICE_BYTE_SIZE_MIN: usize = 1 << 10;

/// An async task that refills the slice pool.
pub struct PoolRefillTask {
    /// A pool of slices, filled in the background by an async task.
    pool: Arc<Mutex<CertifiedSlicePool>>,

    endpoint_resolver: XNetEndpointResolver,

    /// Async client for querying `XNetEndpoints`.
    xnet_client: Arc<dyn XNetClient>,

    /// tokio runtime to be used for spawning async query tasks.
    runtime_handle: runtime::Handle,

    metrics: Arc<XNetPayloadBuilderMetrics>,

    log: ReplicaLogger,
}

impl PoolRefillTask {
    /// Starts an async task that fills the slice pool in the background.
    pub fn start(
        pool: Arc<Mutex<CertifiedSlicePool>>,
        endpoint_resolver: XNetEndpointResolver,
        xnet_client: Arc<dyn XNetClient>,
        runtime_handle: runtime::Handle,
        metrics: Arc<XNetPayloadBuilderMetrics>,
        log: ReplicaLogger,
    ) -> RefillTaskHandle {
        let (refill_trigger, mut refill_receiver) = mpsc::channel(1);
        let task = Self {
            pool,
            endpoint_resolver,
            xnet_client,
            runtime_handle: runtime_handle.clone(),
            metrics,
            log,
        };

        runtime_handle.spawn(async move {
            while let Some(registry_version) = refill_receiver.recv().await {
                task.refill_pool(
                    POOL_BYTE_SIZE_SOFT_CAP,
                    POOL_SLICE_BYTE_SIZE_MAX,
                    registry_version,
                )
                .await;
            }
        });

        RefillTaskHandle(Mutex::new(refill_trigger))
    }

    /// Queries all subnets for new slices and puts / appends them to the pool after
    /// validation against the given registry version.
    async fn refill_pool(
        &self,
        pool_byte_size_soft_cap: usize,
        slice_byte_size_max: usize,
        registry_version: RegistryVersion,
    ) {
        let pool_slice_stats = {
            let pool = self.pool.lock().unwrap();

            if pool.byte_size() > pool_byte_size_soft_cap {
                // Abort if pool is already full.
                return;
            }

            pool.peers()
                // Skip our own subnet, the loopback stream is routed separately.
                .filter(|&&subnet_id| subnet_id != self.endpoint_resolver.subnet_id)
                .map(|&subnet_id| (subnet_id, pool.slice_stats(subnet_id)))
                .collect::<BTreeMap<_, _>>()
        };

        for (subnet_id, slice_stats) in pool_slice_stats {
            let (stream_position, messages_begin, msg_count, byte_size) = match slice_stats {
                // Have a cached stream position.
                (Some(stream_position), messages_begin, msg_count, byte_size) => {
                    (stream_position, messages_begin, msg_count, byte_size)
                }

                // No cached stream position, no pooling / refill necessary.
                (None, _, _, _) => continue,
            };

            let (witness_begin, msg_begin, slice_byte_limit) = match messages_begin {
                // Existing pooled stream, pull partial slice and append.
                Some(messages_begin) if messages_begin == stream_position.message_index => (
                    stream_position.message_index,
                    stream_position.message_index + (msg_count as u64).into(),
                    slice_byte_size_max.saturating_sub(byte_size),
                ),

                // No pooled stream, or pooled stream does not begin at cached stream position, pull
                // complete slice from cached stream position.
                _ => (
                    stream_position.message_index,
                    stream_position.message_index,
                    slice_byte_size_max,
                ),
            };

            if slice_byte_limit < SLICE_BYTE_SIZE_MIN {
                // No more space left in the pool for this slice, bail out.
                continue;
            }

            // `XNetEndpoint` URL of a node on `subnet_id`.
            let endpoint_locator = match self.endpoint_resolver.xnet_endpoint_url(
                subnet_id,
                witness_begin,
                msg_begin,
                // XNetEndpoint only counts message bytes, allow some overhead (measuread: 350
                // bytes for certification plus base witness, 2% for large payloads).
                (slice_byte_limit.saturating_sub(350)) * 98 / 100,
            ) {
                Ok(endpoint_locator) => endpoint_locator,
                Err(e) => {
                    log!(self.log, e.log_level(), "{}", e);
                    self.metrics.observe_pull_attempt(e.to_label_value());
                    continue;
                }
            };

            // Spawn an async task to query the `XNetEndpoint` on `subnet_id`.
            let xnet_client = self.xnet_client.clone();
            let metrics = Arc::clone(&self.metrics);
            let pool = Arc::clone(&self.pool);
            let log = self.log.clone();
            self.runtime_handle.spawn(async move {
                let since = Instant::now();
                metrics.outstanding_queries.inc();
                let query_result = xnet_client.query(&endpoint_locator).await;
                metrics.outstanding_queries.dec();
                let proximity = endpoint_locator.proximity.into();

                match query_result {
                    Ok(slice) => {
                        let res = if witness_begin != msg_begin {
                            // Pulled a stream suffix, append to pooled slice.
                            pool.lock()
                                .unwrap()
                                .append(subnet_id, slice, registry_version, log)
                        } else {
                            // Pulled a complete stream, replace pooled slice (if any).
                            pool.lock()
                                .unwrap()
                                .put(subnet_id, slice, registry_version, log)
                        };
                        let status = match res {
                            Ok(()) => STATUS_SUCCESS,
                            Err(e) => e.to_label_value(),
                        };

                        metrics.observe_query_slice_duration(status, proximity, since);
                        metrics.observe_pull_attempt(status);
                    }

                    Err(e) => {
                        metrics.observe_query_slice_duration(&e.to_label_value(), proximity, since);
                        metrics.observe_pull_attempt(&e.to_label_value());
                        if let XNetClientError::NoContent = e {
                        } else if Self::pass_log_sampling() {
                            info!(
                                log,
                                "Failed to query stream slice for subnet {} from node {}: {}",
                                subnet_id,
                                endpoint_locator.node_id,
                                e
                            );
                        }
                    }
                }
            });
        }
    }

    fn pass_log_sampling() -> bool {
        /// The fraction of INFO logs related to stream pulls that XNet payload
        /// builder displays.  The logs become very polluted if we don't
        /// sample them.
        const LOG_PASS_THROUGH_RATE: f64 = 0.05;

        thread_rng().gen_bool(LOG_PASS_THROUGH_RATE)
    }
}

/// A handle for a `PoolRefillTask`to be used for triggering pool refills and
/// terminating the task (by dropping the handle).
pub struct RefillTaskHandle(pub Mutex<mpsc::Sender<RegistryVersion>>);

impl RefillTaskHandle {
    /// Triggers a slice pool refill, validating slices against the given registry
    /// version.
    pub fn trigger_refill(&self, registry_version: RegistryVersion) {
        // We don't care if the send succeeded or not. If it didn't, the refill task is
        // just behind.
        self.0.lock().unwrap().try_send(registry_version).ok();
    }
}

/// Wrapper around a `CertifiedSlicePool`, implementing the `XNetSlicePool` trait.
pub struct XNetSlicePoolImpl {
    /// A pool of slices, filled in the background by an async task.
    slice_pool: Arc<Mutex<CertifiedSlicePool>>,
}

impl XNetSlicePoolImpl {
    pub fn new(slice_pool: Arc<Mutex<CertifiedSlicePool>>) -> Self {
        Self { slice_pool }
    }
}

impl XNetSlicePool for XNetSlicePoolImpl {
    fn take_slice(
        &self,
        subnet_id: SubnetId,
        begin: Option<&ExpectedIndices>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<Option<(CertifiedStreamSlice, usize)>, CertifiedSliceError> {
        let mut slice_pool = self.slice_pool.lock().unwrap();
        slice_pool.take_slice(subnet_id, begin, msg_limit, byte_limit)
    }

    fn observe_pool_size_bytes(&self) {
        let slice_pool = self.slice_pool.lock().unwrap();
        slice_pool.observe_pool_size_bytes();
    }

    fn garbage_collect(&self, new_stream_positions: BTreeMap<SubnetId, ExpectedIndices>) {
        let mut slice_pool = self.slice_pool.lock().unwrap();
        slice_pool.garbage_collect(new_stream_positions);
    }

    fn garbage_collect_slice(&self, subnet_id: SubnetId, stream_position: ExpectedIndices) {
        let mut slice_pool = self.slice_pool.lock().unwrap();
        slice_pool.garbage_collect_slice(subnet_id, stream_position);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SignalsValidationResult {
    Valid,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SliceValidationResult {
    /// Slice is valid.
    Valid {
        messages_end: StreamIndex,
        signals_end: StreamIndex,
        byte_size: usize,
    },
    /// Slice is invalid for the given reason.
    Invalid(String),
    /// Slice is empty.
    Empty,
}

impl SliceValidationResult {
    /// Maps a `SliceValidationResult` to a value for the `pull_attempt_count`
    /// metric's `status` label.
    #[allow(dead_code)]
    fn to_label_value(&self) -> &'static str {
        match self {
            SliceValidationResult::Valid { .. } => "Valid",
            SliceValidationResult::Invalid(_) => "Invalid",
            SliceValidationResult::Empty => "Empty",
        }
    }
}

/// Internal error type, to simplify error handling.
#[derive(Debug)]
pub enum Error {
    GetStateFailed(Height, StateManagerError),
    RegistryGetSubnetsFailed(RegistryClientError),
    RegistryGetSubnetInfoFailed(SubnetId, RegistryClientError),
    MissingSubnet(SubnetId),
    RegistryGetNodeInfoFailed(NodeId, RegistryClientError),
    MissingXNetEndpoint(NodeId),
    InvalidXNetEndpoint(NodeId, String),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::GetStateFailed(_height, e) => Some(e),
            Error::RegistryGetSubnetsFailed(e) => Some(e),
            Error::RegistryGetSubnetInfoFailed(_subnet_id, e) => Some(e),
            Error::RegistryGetNodeInfoFailed(_node_id, e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::GetStateFailed(height, e) => {
                write!(f, "Error retrieving state at height {}: {}", height, e)
            }
            Error::RegistryGetSubnetsFailed(e) => {
                write!(f, "Failed to retrieve list of subnets: {}", e)
            }
            Error::RegistryGetSubnetInfoFailed(subnet_id, e) => write!(
                f,
                "Failed to retrieve registry info for subnet {}: {}",
                subnet_id, e
            ),
            Error::MissingSubnet(subnet_id) => write!(f, "No nodes in subnet {}", subnet_id),
            Error::RegistryGetNodeInfoFailed(node_id, e) => write!(
                f,
                "Failed to retrieve registry info for node {}: {}",
                node_id, e
            ),
            Error::MissingXNetEndpoint(node_id) => {
                write!(f, "No XNet endpoint info found for node {}", node_id)
            }
            Error::InvalidXNetEndpoint(node_id, e) => {
                write!(f, "Invalid XNet endpoint info for node {}: {}", node_id, e)
            }
        }
    }
}

impl Error {
    /// Returns the desired log level to be used with this `Error`.
    fn log_level(&self) -> slog::Level {
        match self {
            Error::InvalidXNetEndpoint(..) => slog::Level::Error,
            Error::GetStateFailed(..) => slog::Level::Warning,
            _ => slog::Level::Info,
        }
    }

    /// Maps the `Error` to a `status` label value.
    fn to_label_value(&self) -> &str {
        match self {
            Error::GetStateFailed(..) => "GetStateFailed",
            Error::RegistryGetSubnetsFailed(..) => "RegistryGetSubnetsFailed",
            Error::RegistryGetSubnetInfoFailed(..) => "RegistryGetSubnetInfoFailed",
            Error::MissingSubnet(..) => "MissingSubnet",
            Error::RegistryGetNodeInfoFailed(..) => "RegistryGetNodeInfoFailed",
            Error::MissingXNetEndpoint(..) => "MissingXNetEndpoint",
            Error::InvalidXNetEndpoint(..) => "InvalidXNetEndpoint",
        }
    }
}

/// An async `XNetEndpoint` client.
///
/// The `async_trait` attribute is necessary both here and on every
/// implementation because Rust does not have support for `async fn` in traits.
#[async_trait]
pub trait XNetClient: Sync + Send {
    /// Queries the given `XNetEndpoint` for a `CertifiedStreamSlice`.
    ///
    /// On success, returns the deserialized slice.
    async fn query(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError>;
}

/// The default `XNetClient` implementation, wrapping an HTTP client (for both
/// configuration and connection pooling).
struct XNetClientImpl {
    /// An HTTP client to be used for querying.
    http_client: Client<TlsConnector, Request<Body>>,

    /// Response body (encoded slice) size.
    response_body_size: HistogramVec,

    /// Proximity map to update after every query with the time-to-first-byte.
    proximity_map: Arc<ProximityMap>,
}

impl XNetClientImpl {
    /// Creates a new `XNetClientImpl` with a request timeout of 1 second and at
    /// most 1 idle connection per host.
    fn new(
        metrics_registry: &MetricsRegistry,
        runtime_handle: runtime::Handle,
        tls: Arc<dyn TlsConfig + Send + Sync>,
        proximity_map: Arc<ProximityMap>,
    ) -> XNetClientImpl {
        // TODO(MR-28) Make timeout configurable.
        let http_client: Client<TlsConnector, _> = Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(600)))
            .pool_max_idle_per_host(1)
            .executor(ExecuteOnRuntime(runtime_handle))
            .build(
                #[cfg(not(test))]
                TlsConnector::new(tls),
                #[cfg(test)]
                TlsConnector::new_for_tests(tls),
            );

        let response_body_size = metrics_registry.histogram_vec(
            METRIC_RESPONSE_BODY_SIZE,
            "Response body (encoded slice) size in bytes, by decode status.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
            &[LABEL_STATUS],
        );
        response_body_size.with_label_values(&[STATUS_SUCCESS]);
        response_body_size.with_label_values(&[STATUS_DECODE_ERROR]);

        XNetClientImpl {
            http_client,
            response_body_size,
            proximity_map,
        }
    }
}

#[async_trait]
impl XNetClient for XNetClientImpl {
    async fn query(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError> {
        // TODO(MR-28) Make timeout configurable.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let request_start = Instant::now();
            let result = self.http_client.get(endpoint.url.clone()).await;
            // While this is not exactly roundtrip time (it may include multiple roundtrips
            // e.g. if a TLS connection needs to be established first), it is a good enough
            // approximation. Else, we would have to use explicit pings to measure actual
            // roundtrip times.
            self.proximity_map.observe_roundtrip_time(
                endpoint.node_id,
                Instant::now().saturating_duration_since(request_start),
            );

            let response = result.map_err(|e| {
                if e.is_timeout() {
                    XNetClientError::Timeout
                } else {
                    XNetClientError::RequestFailed(e)
                }
            })?;

            let status = response.status();
            let content = receive_body_without_timeout(
                response.into_body(),
                (5 * POOL_SLICE_BYTE_SIZE_MAX).into(),
            )
            .await
            .map_err(XNetClientError::BodyReadError)?;
            Ok((status, content))
        })
        .await;

        let (status, bytes) = result.map_err(|_| XNetClientError::Timeout)??;

        match status {
            StatusCode::OK => match pb::CertifiedStreamSlice::proxy_decode(bytes.as_ref()) {
                Ok(slice) => {
                    self.response_body_size
                        .with_label_values(&[STATUS_SUCCESS])
                        .observe(bytes.len() as f64);
                    Ok(slice)
                }
                Err(err) => {
                    self.response_body_size
                        .with_label_values(&[STATUS_DECODE_ERROR])
                        .observe(bytes.len() as f64);
                    Err(XNetClientError::ProxyDecodeError(err))
                }
            },

            StatusCode::NO_CONTENT => Err(XNetClientError::NoContent),

            _ => Err(XNetClientError::ErrorResponse(
                status,
                String::from_utf8_lossy(bytes.as_ref()).to_string(),
            )),
        }
    }
}

#[derive(Debug)]
pub enum XNetClientError {
    Timeout,
    RequestFailed(hyper::Error),
    NoContent,
    ErrorResponse(hyper::StatusCode, String),
    BodyReadError(BodyReceiveError),
    ProxyDecodeError(ProxyDecodeError),
}

impl std::error::Error for XNetClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            XNetClientError::RequestFailed(e) => Some(e),
            XNetClientError::BodyReadError(e) => Some(e),
            XNetClientError::ProxyDecodeError(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for XNetClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XNetClientError::Timeout => write!(f, "XNet request timed out"),
            XNetClientError::RequestFailed(e) => write!(f, "XNet request failed: {}", e),
            XNetClientError::NoContent => write!(f, "No stream"),
            XNetClientError::ErrorResponse(status, msg) => write!(f, "HTTP {}: {}", status, msg),
            XNetClientError::BodyReadError(e) => write!(f, "Error reading response body: {}", e),
            XNetClientError::ProxyDecodeError(e) => {
                write!(f, "Error decoding XNet proto into Rust struct: {}", e)
            }
        }
    }
}

impl XNetClientError {
    /// Maps an `XNetClientError` to a `status` label value.
    fn to_label_value(&self) -> String {
        match self {
            XNetClientError::Timeout => "Timeout".to_string(),
            XNetClientError::RequestFailed(..) => "RequestFailed".to_string(),
            XNetClientError::NoContent => "NoContent".to_string(),
            XNetClientError::ErrorResponse(status, _) => format!("HTTP_{}", status.as_u16()),
            XNetClientError::BodyReadError(..) => "BodyReadError".to_string(),
            XNetClientError::ProxyDecodeError(..) => STATUS_DECODE_ERROR.to_string(),
        }
    }
}

/// Internal functionality, exposed for use by integration tests.
pub mod testing {
    pub use super::{
        EndpointLocator, GenRangeFn, PoolRefillTask, ProximityMap, RefillTaskHandle, XNetClient,
        XNetClientError, XNetEndpointResolver, XNetPayloadBuilderMetrics, LABEL_STATUS,
        METRIC_BUILD_PAYLOAD_DURATION, METRIC_SLICE_MESSAGES, METRIC_SLICE_PAYLOAD_SIZE,
        POOL_SLICE_BYTE_SIZE_MAX, STATUS_SUCCESS,
    };
}
