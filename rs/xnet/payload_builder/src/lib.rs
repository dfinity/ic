pub mod certified_slice_pool;
pub mod exchange;

#[cfg(test)]
mod impl_tests;
#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests;

use crate::certified_slice_pool::{
    CertifiedSlicePool, CertifiedSliceResult, certified_slice_count_bytes,
};
use crate::exchange::{
    AdvertTask, ProximityMap, PullTask, PullTaskHandle, XNetAdvertHandlerImpl, XNetClient,
    XNetClientImpl, XNetEndpointResolver,
};
use ic_config::message_routing::MAX_STREAM_MESSAGES;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::crypto::ErrorReproducibility;
use ic_interfaces::messaging::{
    InvalidXNetPayload, XNetAdvertHandler, XNetPayloadBuilder, XNetPayloadValidationError,
    XNetPayloadValidationFailure,
};
use ic_interfaces::validation::ValidationError;
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_limits::SYSTEM_SUBNET_STREAM_MSG_LIMIT;
use ic_logger::{ReplicaLogger, error, info, log, warn};
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{decimal_buckets, decimal_buckets_with_zero};
use ic_registry_client_helpers::subnet::{SubnetListRegistry, SubnetRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{ReplicatedState, replicated_state::ReplicatedStateMessageRouting};
use ic_types::batch::{ValidationContext, XNetPayload};
use ic_types::registry::RegistryClientError;
use ic_types::state_manager::StateManagerError;
use ic_types::xnet::{CertifiedStreamSlice, RejectSignal, StreamIndex};
use ic_types::{Height, NodeId, NumBytes, SubnetId};
use prometheus::{Histogram, HistogramVec, IntCounter};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::{BTreeMap, VecDeque};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;
use tokio::runtime;
use tokio::sync::watch;

/// A `StreamIndex` past every index a stream can reasonably hold, used as a
/// bound that nothing reaches.
pub const STREAM_INDEX_MAX: StreamIndex = StreamIndex::new(u64::MAX);

/// Message, signal and `header.begin()` indices into a XNet stream or stream
/// slice.
///
/// Used when computing the expected indices of a stream during payload building
/// and validation. And as cutoff points when trimming pooled stream slices.
///
/// The first two are the next indices we expect, the third the last one we have
/// no use for.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ExpectedIndices {
    /// Next expected message index. This is the most recent `messages.end()` in
    /// past payloads, when present; else `signals_end` of our outgoing stream.
    pub message_index: StreamIndex,

    /// Next expected signal index. This is the most recent `signals_end` in past
    /// payloads, when present; else `messages_begin()` of our outgoing stream.
    pub signal_index: StreamIndex,

    /// Highest `header.begin()` that would not let us garbage collect any reject
    /// signal: the index of the first reject signal we would still hold, after
    /// inducting the past payloads; `STREAM_INDEX_MAX` if we would hold none.
    ///
    /// A slice with a `header.begin()` past this is worth inducting even with no
    /// messages and no new signals.
    pub max_no_gc_header_begin: StreamIndex,
}

impl Default for ExpectedIndices {
    fn default() -> Self {
        Self {
            message_index: StreamIndex::from(0),
            signal_index: StreamIndex::from(0),
            // No reject signals to garbage collect.
            max_no_gc_header_begin: STREAM_INDEX_MAX,
        }
    }
}

pub struct XNetPayloadBuilderMetrics {
    /// Records the time it took to build the payload, by status.
    pub build_payload_duration: HistogramVec,
    /// Message count per valid slice.
    pub slice_messages: Histogram,
    /// Valid slice payload sizes.
    pub slice_payload_size: Histogram,
    /// Records the time it took to validate a payload, by status.
    pub validate_payload_duration: HistogramVec,
    /// Critical error: failed `count_bytes()` on valid slice.
    pub critical_error_slice_count_bytes_failed: IntCounter,
    /// Critical error: mismatch between the byte sizes computed by `take_slice()`,
    /// `certified_slice_count_bytes()` and `UnpackedStreamSlice::count_bytes()`.
    pub critical_error_slice_count_bytes_invalid: IntCounter,
}

pub const METRIC_BUILD_PAYLOAD_DURATION: &str = "xnet_builder_build_payload_duration_seconds";
pub const METRIC_SLICE_MESSAGES: &str = "xnet_builder_slice_messages";
pub const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_builder_slice_payload_size_bytes";
pub const METRIC_VALIDATE_PAYLOAD_DURATION: &str = "xnet_builder_validate_payload_duration_seconds";

pub const CRITICAL_ERROR_SLICE_COUNT_BYTES_FAILED: &str = "xnet_slice_count_bytes_failed";
pub const CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES: &str = "xnet_slice_count_bytes_invalid";

pub const LABEL_STATUS: &str = "status";

pub const STATUS_SUCCESS: &str = "success";

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

    /// Records the status and duration of a `validate_xnet_payload()` call.
    fn observe_validate_duration(&self, status: &str, since: Instant) {
        self.validate_payload_duration
            .with_label_values(&[status])
            .observe(since.elapsed().as_secs_f64());
    }
}

/// The maximum number of signals a stream header can have before pulling messages from the reverse
/// stream stops. This limit prevents one-sided traffic by insisting the other subnet make progress
/// after at most `MAX_SIGNALS` have been pulled.
///
/// More than `MAX_STREAM_MESSAGES` doesn't make sense because an honest subnet needs to garbage
/// collect messages before it can push more messages into a stream, which it can only do by
/// observing the signals in the reverse direction, thus advancing its `begin` and allowing for
/// garbage collecting the signals in turn.
///
/// For the case of `MAX_STREAM_MESSAGES` this acts as a dishonest subnet guard, for a smaller number
/// it acts as an ensurance that the flow of incoming traffic and that of outgoing traffic does not
/// diverge too far.
pub const MAX_SIGNALS: usize = MAX_STREAM_MESSAGES;

/// Implementation of `XNetPayloadBuilder` that uses a `StateManager`;
/// `RegistryClient`; and a slice pool populated by background tasks; to build
/// and validate `XNetPayloads`.
pub struct XNetPayloadBuilderImpl {
    /// Used for retrieving the execution state, for both payload building and
    /// validation.
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,

    /// Used for decoding certified streams.
    certified_stream_store: Arc<dyn CertifiedStreamStore>,

    /// Used for retrieving the registered subnets and their types.
    registry: Arc<dyn RegistryClient>,

    /// A pool of slices, filled in the background by an async task.
    slice_pool: Arc<Mutex<CertifiedSlicePool>>,

    /// Advert handling logic, shared by `XNetEndpoint` and `AdvertTask`.
    advert_handler: Arc<XNetAdvertHandlerImpl>,

    /// Handle to the pull task, used to trigger a refill after every garbage
    /// collection.
    pull_task_handle: PullTaskHandle,

    /// Function to be used for calculating deterministic `CertifiedStreamSlice`
    /// byte sizes. Always
    /// `crate::certified_slice_pool::certified_slice_count_bytes()` in
    /// production code, only replaced in unit tests.
    count_bytes_fn: fn(&CertifiedStreamSlice) -> CertifiedSliceResult<usize>,

    /// Conservative minimum slice size in bytes. We stop trying to add slices to
    /// the payload once we're this close to the payload size limit.
    ///
    /// Always `SLICE_BYTE_SIZE_MIN` in production, can be overridden for testing.
    slice_byte_size_min: usize,

    /// A deterministic pseudo-random number generator, for testing only.
    deterministic_rng_for_testing: Option<Mutex<StdRng>>,

    metrics: Arc<XNetPayloadBuilderMetrics>,

    log: ReplicaLogger,
}

impl XNetPayloadBuilderImpl {
    /// Creates a new `XNetPayloadBuilderImpl` for a node on `subnet_id`, using
    /// the given `StateManager`, `CertifiedStreamStore` and `RegistryClient`.
    ///
    /// Also starts the pull task; and the advert task, advertising on every
    /// certified height received from `max_certified_height_rx`.
    ///
    /// # Panics
    ///
    /// Panics if reading the node's own `node_operator_id` from the registry
    /// fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        tls_config: Arc<dyn TlsConfig>,
        registry: Arc<dyn RegistryClient>,
        runtime_handle: runtime::Handle,
        node_id: NodeId,
        subnet_id: SubnetId,
        max_certified_height_rx: watch::Receiver<Height>,
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
            tls_config,
            proximity_map.clone(),
        ));

        let slice_pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            metrics_registry,
            log.clone(),
        )));
        let endpoint_resolver = Arc::new(XNetEndpointResolver::new(
            Arc::clone(&registry),
            node_id,
            subnet_id,
            proximity_map,
            log.clone(),
        ));
        let pull_task_handle = PullTask::start(
            Arc::clone(&slice_pool),
            Arc::clone(&endpoint_resolver),
            Arc::clone(&xnet_client),
            Arc::clone(&certified_stream_store),
            Arc::clone(&state_manager),
            Arc::clone(&registry),
            runtime_handle.clone(),
            metrics_registry,
            log.clone(),
        );
        let payload_builder = Self::new_from_components(
            state_manager,
            certified_stream_store,
            registry,
            slice_pool,
            pull_task_handle,
            Arc::new(XNetPayloadBuilderMetrics::new(metrics_registry)),
            log.clone(),
        );
        AdvertTask::new(
            Arc::clone(&payload_builder.advert_handler),
            endpoint_resolver,
            xnet_client,
            metrics_registry,
            log,
        )
        .start(max_certified_height_rx, &runtime_handle);

        payload_builder
    }

    /// Same as `new` except that this constructor uses the provided `slice_pool`;
    /// and starts no pull or advert tasks.
    pub fn new_from_components(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        registry: Arc<dyn RegistryClient>,
        slice_pool: Arc<Mutex<CertifiedSlicePool>>,
        pull_task_handle: PullTaskHandle,
        metrics: Arc<XNetPayloadBuilderMetrics>,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        let advert_handler = Arc::new(XNetAdvertHandlerImpl::new(
            Arc::clone(&state_manager),
            Arc::clone(&certified_stream_store),
            Arc::clone(&registry),
            Arc::clone(&slice_pool),
            pull_task_handle.clone(),
            log.clone(),
        ));
        Self {
            state_manager,
            certified_stream_store,
            registry,
            slice_pool,
            advert_handler,
            pull_task_handle,
            count_bytes_fn: certified_slice_count_bytes,
            slice_byte_size_min: SLICE_BYTE_SIZE_MIN,
            deterministic_rng_for_testing: None,
            metrics,
            log,
        }
    }

    /// The handler for adverts posted to the `XNetEndpoint`.
    pub fn advert_handler(&self) -> Arc<dyn XNetAdvertHandler> {
        Arc::clone(&self.advert_handler) as Arc<_>
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
    /// The maximum no-GC `header.begin()` is the first reject signal at or beyond
    /// the most recent `header.begin()` from `subnet_id` in `payloads`.
    ///
    /// Returns `ExpectedIndices::default()` when no stream to or slices from the
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

        // For the maximum no-GC `header.begin()`, start with the most recent (max)
        // `header.begin()` of any slice from `payloads` (or else, zero). Then find the
        // first reject signal at or beyond that index, if any.
        let mut max_header_begin = StreamIndex::from(0);

        let stream = state.streams().get(&subnet_id);

        // Look for the most recent stream slice from `subnet_id`, if any.
        for payload in payloads.iter() {
            if let Some(certified_stream) = payload.stream_slices.get(&subnet_id) {
                let slice = self
                    .certified_stream_store
                    .decode_valid_certified_stream_slice(certified_stream)
                    .expect("failed to decode past certified stream");
                most_recent_signal_index.get_or_insert_with(|| slice.header().signals_end());
                max_header_begin = max_header_begin.max(slice.header().begin());
                if let Some(messages) = slice.messages() {
                    return ExpectedIndices {
                        message_index: messages.end(),
                        signal_index: most_recent_signal_index.unwrap(),
                        max_no_gc_header_begin: stream
                            .and_then(|s| s.next_reject_signal_index(max_header_begin))
                            .unwrap_or(STREAM_INDEX_MAX),
                    };
                }
            }
        }

        // No stream slice from `subnet_id` in `payloads`, look in `state`.
        let Some(stream) = stream else {
            return ExpectedIndices::default();
        };
        ExpectedIndices {
            message_index: stream.signals_end(),
            signal_index: most_recent_signal_index.unwrap_or_else(|| stream.messages_begin()),
            max_no_gc_header_begin: stream
                .next_reject_signal_index(max_header_begin)
                .unwrap_or(STREAM_INDEX_MAX),
        }
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
    ///     signals_end`;
    ///
    ///  2. signals must only refer to past and current messages, i.e.
    ///     `signals_end <= stream.messages_end()`;
    ///
    ///  3. `signals_end - reject_signals[0] <= 2 * MAX_SIGNALS`; and
    ///
    ///  4. `concat(reject_signals, [signals_end])` must be strictly increasing.
    ///
    /// Because this code is used both for validating slices before inclusion into a
    /// payload; and for validating proposed payloads; validation errors are logged
    /// at configurable levels (e.g. `info` at selection, `warn` at validation).
    fn validate_signals(
        &self,
        subnet_id: SubnetId,
        signals_end: StreamIndex,
        reject_signals: &VecDeque<RejectSignal>,
        expected: StreamIndex,
        state: &ReplicatedState,
        log_level: slog::Level,
    ) -> SignalsValidationResult {
        // `messages_begin()` and `messages_end()` of the outgoing stream.
        let (self_messages_begin, self_messages_end) = state
            .streams()
            .get(&subnet_id)
            .map(|s| (s.messages_begin(), s.messages_end()))
            .unwrap_or_default();

        // Must expect signal for existing message (or just beyond last message).
        assert!(
            self_messages_begin <= expected && expected <= self_messages_end,
            "Subnet {subnet_id}: invalid expected signal; messages_begin() ({self_messages_begin}) <= expected ({expected}) <= messages_end() ({self_messages_end})"
        );

        if expected > signals_end || signals_end > self_messages_end {
            log!(
                self.log,
                log_level,
                "Invalid stream from {}: expected ({}) <= signals_end ({}) <= self.messages_end() ({})",
                subnet_id,
                expected,
                signals_end,
                self_messages_end
            );
            return SignalsValidationResult::Invalid;
        }

        if !reject_signals.is_empty() {
            // A stream can never have more than `MAX_SIGNALS` signals by design,
            // since we stop pulling messages after reaching this limit. Any subnet with
            // more than this number of signals can therefore be classified as dishonest.
            // The factor of 2 allows for wiggle room in increasing this constant without
            // touching this, but is still good enough as a guard against dishonest subnets.
            // Furthermore, an honest subnet will only produce signals for the messages in
            // the incoming stream (i.e. no signals for future messages; and all signals for
            // past messages have been GC-ed).
            let signals_begin = reject_signals.front().unwrap();
            if signals_end.get() - signals_begin.index.get() > 2 * MAX_SIGNALS as u64 {
                log!(
                    self.log,
                    log_level,
                    "Too old reject signal in stream from {}: signals_begin {}, signals_end {}",
                    subnet_id,
                    signals_begin.index,
                    signals_end
                );
                return SignalsValidationResult::Invalid;
            }

            let mut next = signals_end;
            for signal in reject_signals.iter().rev() {
                if signal.index >= next {
                    log!(
                        self.log,
                        log_level,
                        "Invalid signals in stream from {}: reject_signals {:?}, signals_end {}",
                        subnet_id,
                        reject_signals,
                        signals_end
                    );
                    return SignalsValidationResult::Invalid;
                }
                next = signal.index;
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
    ///
    /// Because this code is used both for validating slices before inclusion into a
    /// payload; and for validating proposed payloads; validation errors are logged
    /// at configurable levels (e.g. `info` at selection, `warn` at validation).
    fn validate_slice(
        &self,
        subnet_id: SubnetId,
        certified_slice: &CertifiedStreamSlice,
        expected: &ExpectedIndices,
        validation_context: &ValidationContext,
        state: &ReplicatedState,
        log_level: slog::Level,
    ) -> SliceValidationResult {
        // Do not accept loopback stream slices. Those are inducted separately, entirely
        // within the DSM.
        if subnet_id == state.metadata.own_subnet_id {
            return SliceValidationResult::Invalid(
                "Loopback stream is inducted separately".to_string(),
            );
        }

        // Do not accept slices from subnets whose type cannot be determined.
        match self
            .registry
            .get_subnet_type(subnet_id, validation_context.registry_version)
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return SliceValidationResult::Invalid(format!(
                    "No subnet type for subnet {}",
                    subnet_id
                ));
            }
            Err(err) => {
                let msg = format!(
                    "Unable to determine subnet type of subnet {}: Err({})",
                    subnet_id, err
                );
                if err.is_reproducible() {
                    return SliceValidationResult::Invalid(msg);
                } else {
                    return SliceValidationResult::Transient(msg);
                }
            }
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
                    "Invalid stream from {subnet_id}: {err}"
                ));
            }
        };

        // Valid stream message bounds.
        if slice.header().begin() > slice.header().end() {
            log!(
                self.log,
                log_level,
                "Stream from {}: begin index ({}) after end index ({})",
                subnet_id,
                slice.header().begin(),
                slice.header().end()
            );
            return SliceValidationResult::Invalid(format!(
                "Invalid stream bounds in stream from {subnet_id}"
            ));
        }

        // Expected message index within stream message bounds (always present in the
        // header, even for empty slices).
        if expected.message_index < slice.header().begin()
            || slice.header().end() < expected.message_index
        {
            log!(
                self.log,
                log_level,
                "Stream from {}: expecting message {}, outside of stream bounds [{}, {})",
                subnet_id,
                expected.message_index,
                slice.header().begin(),
                slice.header().end()
            );
            return SliceValidationResult::Invalid(format!(
                "Unexpected messages in stream from {subnet_id}"
            ));
        }

        if slice.messages().is_none()
            && slice.header().signals_end() == expected.signal_index
            && slice.header().begin() <= expected.max_no_gc_header_begin
        {
            // Empty slice: no messages, no additional signals and no newly GC-ed messages
            // that would allow us to GC any reject signals (in addition to what we have in
            // the intervening payloads). Not actually invalid, but we don't want it in a
            // payload.
            return SliceValidationResult::Empty;
        }

        if let Some(messages) = slice.messages() {
            // Messages in slice within stream message bounds.
            if messages.begin() < slice.header().begin() || messages.end() > slice.header().end() {
                log!(
                    self.log,
                    log_level,
                    "Stream from {}: slice bounds [{}, {}) outside of stream bounds [{}, {})",
                    subnet_id,
                    messages.begin(),
                    messages.end(),
                    slice.header().begin(),
                    slice.header().end()
                );
                return SliceValidationResult::Invalid(format!(
                    "Invalid slice bounds in stream from {subnet_id}"
                ));
            }

            // Messages begin exactly at the expected message index.
            if messages.begin() != expected.message_index {
                log!(
                    self.log,
                    log_level,
                    "Stream from {}: expecting message with index {}, found {}",
                    subnet_id,
                    expected.message_index,
                    messages.begin()
                );
                return SliceValidationResult::Invalid(format!(
                    "Unexpected messages in stream from {subnet_id}"
                ));
            }

            // Ensure the message limit (dictated e.g. by the backlog size) is respected.
            if let Some(msg_limit) = get_msg_limit(subnet_id, state)
                && messages.len() > msg_limit
            {
                log!(
                    self.log,
                    log_level,
                    "Stream from {}: slice length ({}) above limit ({})",
                    subnet_id,
                    messages.len(),
                    msg_limit
                );
                return SliceValidationResult::Invalid(format!(
                    "Stream from {subnet_id}: slice length above limit"
                ));
            }

            // Ensure the signal limit is respected.
            let max_message_index = max_message_index(slice.header().begin());
            if messages.end() > max_message_index {
                log!(
                    self.log,
                    log_level,
                    "Stream from {}: slice end ({}) exceeds max index ({})",
                    subnet_id,
                    messages.end(),
                    max_message_index
                );
                return SliceValidationResult::Invalid(format!(
                    "Stream from {subnet_id}: inducting slice would produce too many signals"
                ));
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
                    "Failed to compute CertifiedStreamSlice byte size: {e}"
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
            log_level,
        ) {
            SignalsValidationResult::Valid => SliceValidationResult::Valid {
                messages_end: slice
                    .messages()
                    .map_or(expected.message_index, |messages| messages.end()),
                signals_end: slice.header().signals_end(),
                max_no_gc_header_begin: state
                    .streams()
                    .get(&subnet_id)
                    .and_then(|stream| stream.next_reject_signal_index(slice.header().begin()))
                    .unwrap_or(STREAM_INDEX_MAX),
                message_count: slice.messages().map_or(0, |messages| messages.len()),
                byte_size,
            },

            SignalsValidationResult::Invalid => SliceValidationResult::Invalid(format!(
                "Unexpected signals in stream from {subnet_id}"
            )),
        }
    }

    /// Shuffles the provided `Vec` using `self.deterministic_rng_for_testing` when
    /// set, `thread_rng()` otherwise.
    fn random_shuffle<T>(&self, vec: &mut [T]) {
        match self.deterministic_rng_for_testing {
            None => vec.shuffle(&mut thread_rng()),
            Some(ref rng) => vec.shuffle(rng.lock().unwrap().deref_mut()),
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

        // Random shuffle, so all slices have equal chances to be picked if `byte_limit`
        // would be exceeded.
        let mut shuffled_stream_positions: Vec<_> = stream_positions.clone().into_iter().collect();
        self.random_shuffle(&mut shuffled_stream_positions);

        let mut bytes_left = byte_limit.get() as usize;
        let mut stream_slices = BTreeMap::new();

        {
            let mut slice_pool = self.slice_pool.lock().unwrap();
            slice_pool.observe_pool_size_bytes();

            // Trim off messages in the state or past payloads.
            slice_pool.garbage_collect(stream_positions);
        }

        {
            // Takes from the pool a slice of the stream from `subnet_id` starting at
            // `begin`, of at most `msg_limit` messages and `byte_limit` bytes.
            //
            // If the slice is valid, returns it, its message count and its byte size.
            // If no slice is available or the slice is empty / invalid, returns `None`.
            let take_valid_slice = |subnet_id, begin, msg_limit, byte_limit| {
                let (slice, slice_bytes) = match self.slice_pool.lock().unwrap().take_slice(
                    subnet_id,
                    Some(&begin),
                    msg_limit,
                    Some(byte_limit),
                ) {
                    Ok(Some(slice)) => slice,
                    Ok(None) => return None,
                    Err(_) => return None,
                };
                debug_assert!(slice_bytes <= byte_limit);

                // Filter out invalid slices.
                let validation_result = self.validate_slice(
                    subnet_id,
                    &slice,
                    &begin,
                    validation_context,
                    &state,
                    slog::Level::Info,
                );
                match validation_result {
                    SliceValidationResult::Valid { byte_size, .. }
                        if byte_size != slice_bytes || byte_size > byte_limit =>
                    {
                        // This is a bug: inconsistent size estimate between packed and unpacked slice.
                        let message = format!(
                            "Slice from {subnet_id} has packed byte size {byte_size}, unpacked byte size {slice_bytes}, limit was {byte_limit}"
                        );
                        debug_assert!(false, "{}", message);
                        error!(
                            self.log,
                            "{}: {}", CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES, message
                        );
                        self.metrics.critical_error_slice_count_bytes_invalid.inc();
                    }

                    SliceValidationResult::Valid { message_count, .. } => {
                        return Some((slice, message_count, slice_bytes));
                    }

                    SliceValidationResult::Invalid(_) | SliceValidationResult::Transient(_) => {
                        info!(
                            self.log,
                            "Invalid slice from {}: {:?}. Referenced certified height {}. Gap to chain tip {}.",
                            subnet_id,
                            validation_result,
                            validation_context.certified_height,
                            past_payloads.len()
                        );
                    }

                    // No messages and no new signals. Skip it.
                    SliceValidationResult::Empty => {}
                }

                None
            };

            // Observes slice metrics. We only call this for slices that will make it into
            // the payload.
            let observe_slice = |message_count: usize, size_bytes: usize| {
                self.metrics.slice_messages.observe(message_count as f64);
                self.metrics.slice_payload_size.observe(size_bytes as f64);
            };

            // Prioritize signals over messages, as signals are orders of magnitude smaller;
            // they unblock reverse streams; and may contain reject signals, equivalent to a
            // reject response.
            //
            // To do that, we add header-only slices in a first iteration. Then, we replace
            // as many of them as possible with slices containing messages, until we run out
            // of space.
            //
            // Note that if a stream only consists of signals, taking the header-only slice
            // will remove it from the pool, so a second `take_slice()` call with non-zero
            // message limit will return `None`. Hence we must actually add the header-only
            // slices first; and then replace them with message slices, where available.
            let mut header_sizes = BTreeMap::new();
            for (subnet_id, begin) in shuffled_stream_positions.iter() {
                if bytes_left < self.slice_byte_size_min {
                    // Byte limit reached.
                    break;
                }
                if let Some((header_only_slice, _, size_bytes)) =
                    take_valid_slice(*subnet_id, begin.clone(), Some(0), bytes_left)
                {
                    header_sizes.insert(*subnet_id, size_bytes);
                    bytes_left = bytes_left.saturating_sub(size_bytes);
                    stream_slices.insert(*subnet_id, header_only_slice);
                }
            }

            // Replace with / add "message slices" until we run out of payload space.
            for (subnet_id, begin) in shuffled_stream_positions {
                if bytes_left < self.slice_byte_size_min {
                    break;
                }

                let header_bytes = header_sizes.get(&subnet_id).cloned().unwrap_or_default();
                let msg_limit = get_msg_limit(subnet_id, &state);
                if let Some((slice, message_count, slice_bytes)) =
                    take_valid_slice(subnet_id, begin, msg_limit, bytes_left + header_bytes)
                {
                    debug_assert!(slice_bytes >= header_bytes);
                    header_sizes.remove(&subnet_id);
                    bytes_left = (bytes_left + header_bytes).saturating_sub(slice_bytes);
                    stream_slices.insert(subnet_id, slice);
                    observe_slice(message_count, slice_bytes);
                }
            }

            // Also observe all the header-only slices that we have not replaced.
            for header_bytes in header_sizes.values() {
                observe_slice(0, *header_bytes);
            }
        }

        // Collect all successfully queried slices into an `XNetPayload`.
        Ok((
            XNetPayload { stream_slices },
            byte_limit.get().saturating_sub(bytes_left as u64).into(),
        ))
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

        self.pull_task_handle.trigger_refill();

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
                slog::Level::Warning,
            ) {
                SliceValidationResult::Invalid(reason) => {
                    self.metrics
                        .observe_validate_duration(VALIDATION_STATUS_INVALID, since);
                    return Err(ValidationError::InvalidArtifact(
                        InvalidXNetPayload::InvalidSlice(reason),
                    ));
                }
                SliceValidationResult::Transient(reason) => {
                    self.metrics
                        .observe_validate_duration(VALIDATION_STATUS_ERROR, since);
                    return Err(ValidationError::ValidationFailed(
                        XNetPayloadValidationFailure::Transient(reason),
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
                    max_no_gc_header_begin,
                    message_count,
                    byte_size,
                } => {
                    self.metrics.slice_messages.observe(message_count as f64);
                    self.metrics
                        .slice_payload_size
                        .observe(certified_slice.payload.len() as f64);
                    new_stream_positions.push((
                        *subnet_id,
                        messages_end,
                        signals_end,
                        max_no_gc_header_begin,
                    ));
                    payload_byte_size += byte_size;
                }
            }
        }

        // Garbage collect payload contents from the pool.
        {
            let mut slice_pool = self.slice_pool.lock().unwrap();
            slice_pool.observe_pool_size_bytes();

            for (subnet_id, message_index, signal_index, max_no_gc_header_begin) in
                new_stream_positions
            {
                slice_pool.garbage_collect_slice(
                    subnet_id,
                    ExpectedIndices {
                        message_index,
                        signal_index,
                        max_no_gc_header_begin,
                    },
                );
            }
        }
        // And trigger a pool refill.
        self.pull_task_handle.trigger_refill();

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, since);
        Ok(NumBytes::new(payload_byte_size as u64))
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
        Application | VerifiedApplication | CloudEngine => None,

        System => {
            // If this is not the NNS subnet and the remote subnet is a system subnet, don't enforce the limit.
            if state.metadata.own_subnet_id != state.metadata.network_topology.nns_subnet_id {
                let remote_subnet_type = state
                    .metadata
                    .network_topology
                    .subnets()
                    .get(&subnet_id)
                    // The lookup may fail if the subnet is new and the context state still uses an
                    // old registry version. Default to `Application` in that case.
                    .map_or(Application, |subnet| subnet.subnet_type);
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

/// The stream index up to which messages can be inducted while limiting the
/// number of signals in the reverse stream to `MAX_SIGNALS`.
///
/// `stream_begin` is the `begin` in the `StreamHeader` contained in the (same) stream slice.
///  It reflects the status on the remote subnet as far as we know at present. Up to this index
///  signals can be gc'ed in the reverse stream.
pub fn max_message_index(stream_begin: StreamIndex) -> StreamIndex {
    stream_begin + (MAX_SIGNALS as u64).into()
}

/// Maps `StateManagerErrors` to the equivalent `XNetPayloadValidationError`.
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

/// Conservative minimum slice size in bytes. We stop trying to add slices to
/// the payload once we're this close to the payload size limit.
pub const SLICE_BYTE_SIZE_MIN: usize = 1 << 10;

#[derive(Clone, Eq, PartialEq, Debug)]
enum SignalsValidationResult {
    Valid,
    Invalid,
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum SliceValidationResult {
    /// Slice is valid.
    Valid {
        messages_end: StreamIndex,
        signals_end: StreamIndex,
        /// See `ExpectedIndices::max_no_gc_header_begin`, computed as if this slice
        /// had been inducted.
        max_no_gc_header_begin: StreamIndex,
        message_count: usize,
        byte_size: usize,
    },
    /// Slice is invalid for the given reason.
    Invalid(String),
    /// Validation could not be completed due to a transient error.
    Transient(String),
    /// Slice is empty.
    Empty,
}

/// Internal error type, to simplify error handling.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Error retrieving state at height {0}: {1}")]
    GetStateFailed(Height, StateManagerError),
    #[error("Failed to retrieve list of subnets: {0}")]
    RegistryGetSubnetsFailed(RegistryClientError),
}

impl Error {
    /// Returns the desired log level to be used with this `Error`.
    fn log_level(&self) -> slog::Level {
        match self {
            Error::GetStateFailed(..) => slog::Level::Warning,
            Error::RegistryGetSubnetsFailed(..) => slog::Level::Info,
        }
    }

    /// Maps the `Error` to a `status` label value.
    fn to_label_value(&self) -> &str {
        match self {
            Error::GetStateFailed(..) => "GetStateFailed",
            Error::RegistryGetSubnetsFailed(..) => "RegistryGetSubnetsFailed",
        }
    }
}

/// Internal functionality, exposed for use by integration tests.
pub mod testing {
    pub use super::exchange::{
        EndpointLocator, GenRangeFn, ProximityMap, PullTask, PullTaskHandle, XNetClient,
        XNetClientError, XNetEndpointResolver,
    };
    pub use super::{
        LABEL_STATUS, METRIC_BUILD_PAYLOAD_DURATION, METRIC_SLICE_MESSAGES,
        METRIC_SLICE_PAYLOAD_SIZE, STATUS_SUCCESS, XNetPayloadBuilderMetrics,
    };

    use super::*;

    /// Overrides of `XNetPayloadBuilderImpl` defaults, for testing.
    pub trait XNetPayloadBuilderTesting {
        /// Replaces the function to be used for calculating `CertifiedStreamSlice`
        /// byte sizes with the provided one.
        fn with_count_bytes_fn(
            self,
            count_bytes_fn: fn(&CertifiedStreamSlice) -> CertifiedSliceResult<usize>,
        ) -> Self;

        /// Replaces `SLICE_BYTE_SIZE_MIN` with the provided value.
        fn with_slice_byte_size_min(self, slice_byte_size_min: usize) -> Self;

        /// Shuffles stream positions using the provided RNG instead of
        /// `thread_rng()`.
        fn with_deterministic_rng(self, rng: StdRng) -> Self;
    }

    impl XNetPayloadBuilderTesting for XNetPayloadBuilderImpl {
        fn with_count_bytes_fn(
            mut self,
            count_bytes_fn: fn(&CertifiedStreamSlice) -> CertifiedSliceResult<usize>,
        ) -> Self {
            self.count_bytes_fn = count_bytes_fn;
            self
        }

        fn with_slice_byte_size_min(mut self, slice_byte_size_min: usize) -> Self {
            self.slice_byte_size_min = slice_byte_size_min;
            self
        }

        fn with_deterministic_rng(mut self, rng: StdRng) -> Self {
            self.deterministic_rng_for_testing = Some(Mutex::new(rng));
            self
        }
    }
}
