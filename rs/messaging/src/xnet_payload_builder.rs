#[cfg(test)]
mod impl_tests;
#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod xnet_client_tests;

use crate::{
    certified_slice_pool::CertifiedSlicePool,
    hyper::{ExecuteOnRuntime, TlsConnector},
    xnet_uri::XNetAuthority,
};
use async_trait::async_trait;
use hyper::{client::Client, Body, Request, StatusCode, Uri};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::{
    certified_stream_store::CertifiedStreamStore,
    messaging::{
        InvalidXNetPayload, XNetPayloadBuilder, XNetPayloadError, XNetPayloadValidationError,
        XNetTransientValidationError,
    },
    registry::RegistryClient,
    state_manager::{StateManager, StateManagerError},
    validation::{ValidationError, ValidationResult},
};
use ic_logger::{info, log, warn, ReplicaLogger};
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero},
    MetricsRegistry, Timer,
};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_registry_client::helper::{
    node::NodeRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{ValidationContext, XNetPayload},
    registry::{connection_endpoint::ConnectionEndpoint, RegistryClientError},
    xnet::{CertifiedStreamSlice, StreamIndex},
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
};
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGauge};
use rand::{thread_rng, Rng};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{runtime, sync::mpsc};

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
        .get_transport_info(*node_id, *registry_version)
        .unwrap_or_else(|_| {
            info!(
                log,
                "Failed to retrieve registry record for node {}", node_id
            );
            None
        })
        .map(|r| r.node_operator_id)
}

pub struct XNetPayloadBuilderMetrics {
    /// Records the time it took to build the payload, by status.
    pub build_payload_duration: HistogramVec,
    /// Records pull atempts, by status. Orthogonal to to slice queries, as some
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
}

pub const METRIC_BUILD_PAYLOAD_DURATION: &str = "xnet_builder_build_payload_duration_seconds";
pub const METRIC_PULL_ATTEMPT_COUNT: &str = "xnet_builder_pull_attempt_count";
pub const METRIC_QUERY_SLICE_DURATION: &str = "xnet_builder_query_slice_duration_seconds";
pub const METRIC_RESPONSE_BODY_SIZE: &str = "xnet_builder_response_body_size_bytes";
pub const METRIC_SLICE_MESSAGES: &str = "xnet_builder_slice_messages";
pub const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_builder_slice_payload_size_bytes";
pub const METRIC_VALIDATE_PAYLOAD_DURATION: &str = "xnet_builder_validate_payload_duration_seconds";
pub const METRIC_OUTSTANDING_XNET_QUERIES: &str = "xnet_builder_outstanding_queries";

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
        }
    }

    /// Records the status and duration of a `get_xnet_payload()` call.
    fn observe_build_duration(&self, status: &str, timer: Timer) {
        self.build_payload_duration
            .with_label_values(&[status])
            .observe(timer.elapsed());
    }

    /// Increments the `pull_attempt_count` counter for the given status.
    fn observe_pull_attempt(&self, status: &str) {
        self.pull_attempt_count.with_label_values(&[status]).inc();
    }

    /// Observes the elapsed `query_slice_duration` under the given status.
    fn observe_query_slice_duration(&self, status: &str, proximity: &str, timer: Timer) {
        self.query_slice_duration
            .with_label_values(&[status, proximity])
            .observe(timer.elapsed());
    }

    /// Records the status and duration of a `validate_xnet_payload()` call.
    fn observe_validate_duration(&self, status: &str, timer: Timer) {
        self.validate_payload_duration
            .with_label_values(&[status])
            .observe(timer.elapsed());
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

    /// A pool of slices, filled in the background by an async task.
    slice_pool: Arc<Mutex<CertifiedSlicePool>>,

    /// Handle to the pool refill task, used to asynchronously trigger refill.
    refill_task_handle: RefillTaskHandle,

    metrics: Arc<XNetPayloadBuilderMetrics>,

    log: ReplicaLogger,
}

/// Represents the location of a peer
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
pub struct EndpointLocator {
    /// The ID of the node hosting the replica.
    node_id: NodeId,

    /// The endpoint URL.
    pub url: Uri,

    /// The proximity of the peer.
    proximity: PeerLocation,
}

/// Message and signal indices into a XNet stream or stream slice.
///
/// Used when computing the expected indices of a stream during payload building
/// and validation. Or as cutoff points when dealing with stream slices.
#[derive(Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct ExpectedIndices {
    pub message_index: StreamIndex,
    pub signal_index: StreamIndex,
}

/// Message count limit for `System` subnet outgoing streams used for throttling
/// the matching input stream.
pub const SYSTEM_SUBNET_STREAM_MSG_LIMIT: usize = 100;

impl XNetPayloadBuilderImpl {
    /// Creates a new `XNetPayloadBuilderImpl` for a node on `subnet_id`, using
    /// the given `StateManager`, `CertifiedStreamStore` and`RegistryClient`.
    ///
    /// # Panics
    ///
    ///  Panics if reading the node's own `node_operator_id` from the registry
    /// fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
        registry: Arc<dyn RegistryClient>,
        runtime_handle: runtime::Handle,
        node_id: NodeId,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        let xnet_client: Arc<dyn XNetClient> = Arc::new(XNetClientImpl::new(
            metrics_registry,
            runtime_handle.clone(),
            tls_handshake,
        ));

        Self::with_xnet_client(
            xnet_client,
            state_manager,
            certified_stream_store,
            registry,
            runtime_handle,
            node_id,
            subnet_id,
            metrics_registry,
            log,
        )
    }

    /// Test helper for creating a `XNetPayloadBuilder` around a provided
    /// `XNetClient`.
    #[allow(clippy::too_many_arguments)]
    fn with_xnet_client(
        xnet_client: Arc<dyn XNetClient>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        registry: Arc<dyn RegistryClient>,
        runtime_handle: runtime::Handle,
        node_id: NodeId,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        let slice_pool = Arc::new(Mutex::new(CertifiedSlicePool::new(metrics_registry)));
        let metrics = Arc::new(XNetPayloadBuilderMetrics::new(metrics_registry));
        let endpoint_resolver =
            XNetEndpointResolver::new(Arc::clone(&registry), node_id, subnet_id, log.clone());
        let refill_task_handle = PoolRefillTask::start(
            Arc::clone(&slice_pool),
            endpoint_resolver,
            Arc::clone(&xnet_client),
            runtime_handle,
            Arc::clone(&metrics),
            log.clone(),
        );

        Self {
            state_manager,
            certified_stream_store,
            registry,
            slice_pool,
            refill_task_handle,
            metrics,
            log,
        }
    }

    /// Calculates the next expected message and signal indices for a given
    /// stream, based on `state` and the subsequent `payloads`.
    ///
    /// The next expected message index is the most recent `messages.end()` from
    /// `subnet_id` in `payloads`, when that exists; or `signals_end` of the
    /// outgoing `Stream` to `subnet_id` in `state`. The next expected signal
    /// index is the most recent `signals_end` from `subnet_id` in `payloads`,
    /// when that exists; or `messages.begin()` of the outgoing `Stream` to
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
                            .unwrap_or_else(|| slice.header().signals_end),
                    };
                }
                most_recent_signal_index.get_or_insert_with(|| slice.header().signals_end);
            }
        }

        // No stream slice from `subnet_id` in `payloads`, look in `state`.
        state
            .streams()
            .get(&subnet_id)
            .map(|stream| ExpectedIndices {
                message_index: stream.signals_end,
                signal_index: most_recent_signal_index.unwrap_or_else(|| stream.messages.begin()),
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
            .unwrap_or_else(Vec::new);

        let expected_indices = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                (
                    subnet_id,
                    self.expected_indices_for_stream(subnet_id, &state, past_payloads),
                )
            })
            .collect::<BTreeMap<SubnetId, ExpectedIndices>>();
        Ok(expected_indices)
    }

    /// Validates the `signals_end` of the incoming `StreamSlice` from
    /// `subnet_id` with respect to `expected` (the expected signal index);
    /// and to `messages.end()` of the outgoing `Stream` to `subnet_id`.
    ///
    /// In particular:
    ///
    ///  1. `signals_end` must be monotonically increasing, i.e. `expected <=
    /// signals_end`; and
    ///
    ///  2. signals must only refer to past and current messages, i.e.
    /// `signals_end <= stream.messages.end()`.
    fn validate_signals(
        &self,
        subnet_id: SubnetId,
        signals_end: StreamIndex,
        expected: StreamIndex,
        state: &ReplicatedState,
    ) -> SignalsValidationResult {
        // `messages.end()` of the outgoing stream.
        let (self_messages_begin, self_messages_end) = state
            .streams()
            .get(&subnet_id)
            .map(|s| (s.messages.begin(), s.messages.end()))
            .unwrap_or_default();

        // Must expect signal for existing message (or just beyond last message).
        assert!(
            self_messages_begin <= expected && expected <= self_messages_end,
            "Subnet {}: invalid expected signal; messages.begin() ({}) <= expected ({}) <= messages.end() ({})",
            subnet_id,
            self_messages_begin,
            expected,
            self_messages_end
        );

        if expected <= signals_end && signals_end <= self_messages_end {
            SignalsValidationResult::Valid
        } else {
            warn!(
                self.log,
                "Invalid stream from {}: expected ({}) <= signals_end ({}) <= self.messages.end() ({})",
                subnet_id,
                expected,
                signals_end,
                self_messages_end
            );
            SignalsValidationResult::Invalid
        }
    }

    /// Validates the `certified_slice` received from `subnet_id`:
    ///  * checks its signature against the public key of `subnet_id`;
    ///  * ensures stream message bounds are valid and slice message bounds are
    ///    within stream message bounds;
    ///  * looks for gaps/duplicates in its `messages` w.r.t. `expected`
    ///    indices;
    ///  * and ensures signals advance monotonically and only refer to current
    ///    messages.
    fn validate_slice(
        &self,
        subnet_id: SubnetId,
        certified_slice: &CertifiedStreamSlice,
        expected: &ExpectedIndices,
        validation_context: &ValidationContext,
        state: &ReplicatedState,
    ) -> SliceValidationResult {
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
        if slice.header().begin > slice.header().end {
            warn!(
                self.log,
                "Stream from {}: begin index ({}) after end index ({})",
                subnet_id,
                slice.header().begin,
                slice.header().end
            );
            return SliceValidationResult::Invalid(format!(
                "Invalid stream bounds in stream from {}",
                subnet_id
            ));
        }

        // Expected message index within stream message bounds (always present in the
        // header, even for empty slices).
        if expected.message_index < slice.header().begin
            || slice.header().end < expected.message_index
        {
            warn!(
                self.log,
                "Stream from {}: expecting message {}, outside of stream bounds [{}, {})",
                subnet_id,
                expected.message_index,
                slice.header().begin,
                slice.header().end
            );
            return SliceValidationResult::Invalid(format!(
                "Unexpected messages in stream from {}",
                subnet_id
            ));
        }

        if slice.messages().is_none() && slice.header().signals_end == expected.signal_index {
            // Empty slice: no messages and no additional signals (in addition to what we
            // have in state and any intervening payloads). Not actually invalid, but
            // we don't want it in a payload.
            return SliceValidationResult::Empty;
        }

        if let Some(messages) = slice.messages() {
            // Messages in slice within stream message bounds.
            if messages.begin() < slice.header().begin || messages.end() > slice.header().end {
                warn!(
                    self.log,
                    "Stream from {}: slice bounds [{}, {}) outside of stream bounds [{}, {})",
                    subnet_id,
                    messages.begin(),
                    messages.end(),
                    slice.header().begin,
                    slice.header().end
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
            if let Some(msg_limit) = self.get_msg_limit(subnet_id, state) {
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

        // `signals_end` must point to a message in the stream (or just past the last
        // message).
        match self.validate_signals(
            subnet_id,
            slice.header().signals_end,
            expected.signal_index,
            &state,
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
                    signals_end: slice.header().signals_end,
                }
            }

            SignalsValidationResult::Invalid => SliceValidationResult::Invalid(format!(
                "Unexpected signals in stream from {}",
                subnet_id
            )),
        }
    }

    /// Implementation of `get_xnet_payload()` that returns a `Result`, so it
    /// can use the `?` operator internally for clean and simple error handling.
    fn get_xnet_payload_impl(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> Result<XNetPayload, Error> {
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
            return Ok(XNetPayload::default());
        }

        // Random rotation so all slices have equal chances if `byte_limit` is reached.
        let mut rotated_stream_positions: Vec<_> = stream_positions.clone().into_iter().collect();
        let first_subnet = thread_rng().gen_range(0, rotated_stream_positions.len());
        rotated_stream_positions.rotate_left(first_subnet);

        let mut bytes_left = byte_limit.get() as usize;
        let mut stream_slices = BTreeMap::new();

        {
            let mut slice_pool = self.slice_pool.lock().unwrap();
            slice_pool.observe_pool_size_bytes();

            // Trim off messages in the state or past payloads.
            slice_pool.garbage_collect(stream_positions);

            // Keep adding slices until we run out of payload space.
            for (subnet_id, begin) in rotated_stream_positions {
                if !stream_slices.is_empty() && bytes_left < SLICE_BYTE_SIZE_MIN {
                    // Byte limit reached.
                    break;
                }

                let msg_limit = self.get_msg_limit(subnet_id, &state);
                let slice = match slice_pool.take_slice(
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

                // Filter out invalid slices.
                let validation_result =
                    self.validate_slice(subnet_id, &slice, &begin, validation_context, &state);
                // TODO(MR-6): Record valid/invalid slice.
                if let SliceValidationResult::Valid { .. } = validation_result {
                    bytes_left = bytes_left.saturating_sub(slice.count_bytes());
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
        Ok(XNetPayload { stream_slices })
    }

    /// Calculates an upper bound for how many messages can be included into a
    /// block based on the size of the reverse stream, in an attempt to limit
    /// the in-flight requests from and responses to a given subnet. Only
    /// applies to `System` subnets.
    fn get_msg_limit(&self, subnet_id: SubnetId, state: &ReplicatedState) -> Option<usize> {
        match state.metadata.own_subnet_type {
            // No limits for now on application subnets.
            SubnetType::Application | SubnetType::VerifiedApplication => None,

            // Stay below limit on system subnet(s).
            SubnetType::System => state
                .streams()
                .get(&subnet_id)
                .map(|stream| stream.messages.len())
                .or(Some(0))
                .map(|len| SYSTEM_SUBNET_STREAM_MSG_LIMIT.saturating_sub(len)),
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

    log: ReplicaLogger,
}

impl XNetEndpointResolver {
    pub fn new(
        registry: Arc<dyn RegistryClient>,
        node_id: NodeId,
        subnet_id: SubnetId,
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
            log,
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

        // Retrieve `subnet_id`'s nodes.
        let nodes = self
            .registry
            .get_node_ids_on_subnet(subnet_id, version)
            .map_err(|e| Error::RegistryGetSubnetInfoFailed(subnet_id, e))?
            .filter(|nodes| !nodes.is_empty())
            .ok_or_else(|| Error::MissingSubnet(subnet_id))?;

        // Attempt to pick a node under the same node operator, if such a node exists.
        // TODO(MR-27) select node based on proximity.
        let mut same_node_operator_nodes: Vec<NodeId> = Vec::new();

        for n in nodes.iter() {
            if let Some(node_operator_id) =
                get_node_operator_id(n, self.registry.as_ref(), &version, &self.log)
            {
                if self.node_operator_id == node_operator_id {
                    same_node_operator_nodes.push(*n);
                }
            }
        }

        let (nodes, proximity) = if same_node_operator_nodes.is_empty() {
            (nodes, PeerLocation::Remote)
        } else {
            (same_node_operator_nodes, PeerLocation::Local)
        };
        // Pick a random node from among the candidates, to spread the load.
        let node = nodes.get(thread_rng().gen_range(0, nodes.len())).unwrap();

        let node_record = self
            .registry
            .get_transport_info(*node, version)
            .map_err(|e| Error::RegistryGetNodeInfoFailed(*node, e))?;

        // TODO(OR4-18): Handle more than one xnet endpoint if given. This
        // prefers the first entry in .xnet_endpoint, or the only entry in
        let xnet_endpoint = match node_record {
            Some(node_record) => {
                if node_record.xnet_api.is_empty() {
                    node_record
                        .xnet
                        .ok_or_else(|| Error::MissingXNetEndpoint(*node))
                } else {
                    Ok(node_record.xnet_api[0].clone())
                }
            }
            None => Err(Error::MissingXNetEndpoint(*node)),
        }?;

        let xnet_endpoint = ConnectionEndpoint::try_from(xnet_endpoint)
            .map_err(|e| Error::InvalidXNetEndpoint(*node, e.to_string()))?;

        let socket_addr = SocketAddr::from(&xnet_endpoint);

        let authority = XNetAuthority {
            node_id: *node,
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
                node_id: *node,
                url,
                proximity,
            })
    }
}

impl XNetPayloadBuilder for XNetPayloadBuilderImpl {
    fn get_xnet_payload(
        &self,
        _: Height,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> Result<XNetPayload, XNetPayloadError> {
        let timer = Timer::start();
        let payload =
            match self.get_xnet_payload_impl(validation_context, past_payloads, byte_limit) {
                Ok(payload) => {
                    self.metrics.observe_build_duration(STATUS_SUCCESS, timer);
                    payload
                }

                Err(e) => {
                    log!(self.log, e.log_level(), "{}", e);
                    self.metrics
                        .observe_build_duration(&e.to_label_value(), timer);

                    XNetPayload::default()
                }
            };

        // We don't care if the send succeeded or not. If it didn't, the refill task is
        // just behind.
        self.refill_task_handle.trigger_refill();

        Ok(payload)
    }

    fn validate_xnet_payload(
        &self,
        payload: &XNetPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        _byte_limit: NumBytes,
    ) -> ValidationResult<XNetPayloadValidationError> {
        let timer = Timer::start();
        let state = match self
            .state_manager
            .get_state_at(validation_context.certified_height)
        {
            Ok(state) => state.take(),
            Err(err) => {
                self.metrics
                    .observe_validate_duration(VALIDATION_STATUS_ERROR, timer);
                return Err(from_state_manager_error(err));
            }
        };

        // For every slice in `payload`, check certification and gaps/duplicates.
        let mut new_stream_positions = Vec::new();
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
                        .observe_validate_duration(VALIDATION_STATUS_INVALID, timer);
                    return Err(ValidationError::Permanent(
                        InvalidXNetPayload::InvalidSlice(reason),
                    ));
                }
                SliceValidationResult::Empty => {
                    self.metrics
                        .observe_validate_duration(VALIDATION_STATUS_EMPTY_SLICE, timer);
                    return Err(ValidationError::Permanent(
                        InvalidXNetPayload::InvalidSlice("Empty slice".to_string()),
                    ));
                }
                SliceValidationResult::Valid {
                    messages_end,
                    signals_end,
                } => new_stream_positions.push((*subnet_id, messages_end, signals_end)),
            }
        }

        // Garbage collect payload contents from the pool.
        {
            let mut slice_pool = self.slice_pool.lock().unwrap();
            slice_pool.observe_pool_size_bytes();

            for (subnet_id, message_index, signal_index) in new_stream_positions {
                slice_pool.garbage_collect_slice(
                    subnet_id,
                    ExpectedIndices {
                        message_index,
                        signal_index,
                    },
                );
            }
        }
        // And trigger a pool refill.
        self.refill_task_handle.trigger_refill();

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, timer);
        Ok(())
    }
}

/// Maps `StateManagerErrors` to their `XNetPayloadError` namesakes.
fn from_state_manager_error(e: StateManagerError) -> XNetPayloadValidationError {
    match e {
        StateManagerError::StateRemoved(height) => {
            ValidationError::Permanent(InvalidXNetPayload::StateRemoved(height))
        }
        StateManagerError::StateNotCommittedYet(height) => {
            ValidationError::Transient(XNetTransientValidationError::StateNotCommittedYet(height))
        }
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
            while refill_receiver.recv().await.is_some() {
                task.refill_pool(POOL_BYTE_SIZE_SOFT_CAP, POOL_SLICE_BYTE_SIZE_MAX)
                    .await;
            }
        });

        RefillTaskHandle(Mutex::new(refill_trigger))
    }

    /// Queries all subnets for new slices and puts / appends them to the pool.
    async fn refill_pool(&self, pool_byte_size_soft_cap: usize, slice_byte_size_max: usize) {
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
                    self.metrics.observe_pull_attempt(&e.to_label_value());
                    continue;
                }
            };

            // Spawn an async task to query the `XNetEndpoint` on `subnet_id`.
            let xnet_client = self.xnet_client.clone();
            let metrics = Arc::clone(&self.metrics);
            let pool = Arc::clone(&self.pool);
            let log = self.log.clone();
            self.runtime_handle.spawn(async move {
                let proximity = endpoint_locator.proximity.into();
                let timer = Timer::start();
                metrics.outstanding_queries.inc();
                let query_result = xnet_client.query(endpoint_locator.url.clone()).await;
                metrics.outstanding_queries.dec();

                match query_result {
                    Ok(slice) => {
                        let res = if witness_begin != msg_begin {
                            // Pulled a stream suffix, append to pooled slice.
                            pool.lock().unwrap().append(subnet_id, slice)
                        } else {
                            // Pulled a complete stream, replace polled slice (if any).
                            pool.lock().unwrap().put(subnet_id, slice)
                        };
                        let status = match res {
                            Ok(()) => STATUS_SUCCESS,
                            Err(e) => e.to_label_value(),
                        };

                        metrics.observe_query_slice_duration(status, proximity, timer);
                        metrics.observe_pull_attempt(status);
                    }

                    Err(e) => {
                        metrics.observe_query_slice_duration(&e.to_label_value(), proximity, timer);
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
pub struct RefillTaskHandle(Mutex<mpsc::Sender<()>>);

impl RefillTaskHandle {
    /// Triggers a slice pool refill.
    pub fn trigger_refill(&self) {
        // We don't care if the send succeeded or not. If it didn't, the refill task is
        // just behind.
        self.0.lock().unwrap().try_send(()).ok();
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
    /// Queries the given `XNetEndpoint` URL for a `CertifiedStreamSlice`.
    ///
    /// On success, returns the deserialized slice and its (serialized) size.
    async fn query(&self, url: Uri) -> Result<CertifiedStreamSlice, XNetClientError>;
}

/// The default `XNetClient` implementation, wrapping an HTTP client (for both
/// configuration and connection pooling).
struct XNetClientImpl {
    /// An HTTP client to be used for querying.
    http_client: Client<TlsConnector, Request<Body>>,

    /// Response body (encoded slice) size.
    response_body_size: HistogramVec,
}

impl XNetClientImpl {
    /// Creates a new `XNetClientImpl` with a request timeout of 1 second and at
    /// most 1 idle connection per host.
    fn new(
        metrics_registry: &MetricsRegistry,
        runtime_handle: runtime::Handle,
        tls: Arc<dyn TlsHandshake + Send + Sync>,
    ) -> XNetClientImpl {
        // TODO(MR-28) Make timeout configurable.
        let http_client: Client<TlsConnector, _> = Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(600)))
            .pool_max_idle_per_host(1)
            .executor(ExecuteOnRuntime(runtime_handle))
            .build(TlsConnector::new(tls));

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
        }
    }
}

#[async_trait]
impl XNetClient for XNetClientImpl {
    async fn query(&self, url: Uri) -> Result<CertifiedStreamSlice, XNetClientError> {
        // TODO(MR-28) Make timeout configurable.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let response = self.http_client.get(url.clone()).await.map_err(|e| {
                if e.is_timeout() {
                    XNetClientError::Timeout
                } else {
                    XNetClientError::RequestFailed(e)
                }
            })?;
            let status = response.status();
            let content = hyper::body::to_bytes(response.into_body())
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
    BodyReadError(hyper::Error),
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
    use super::*;

    pub use super::{
        PoolRefillTask, RefillTaskHandle, XNetClient, XNetClientError, XNetEndpointResolver,
        XNetPayloadBuilderMetrics, LABEL_STATUS, METRIC_BUILD_PAYLOAD_DURATION,
        METRIC_SLICE_MESSAGES, METRIC_SLICE_PAYLOAD_SIZE, POOL_SLICE_BYTE_SIZE_MAX, STATUS_SUCCESS,
        SYSTEM_SUBNET_STREAM_MSG_LIMIT,
    };

    /// Puts the provided slice into the payload builder's slice pool.
    pub fn pool_slice(
        payload_builder: &XNetPayloadBuilderImpl,
        subnet_id: SubnetId,
        slice: CertifiedStreamSlice,
    ) {
        payload_builder
            .slice_pool
            .lock()
            .unwrap()
            .put(subnet_id, slice)
            .unwrap();
    }

    /// Test helper for creating a `XNetPayloadBuilder` around a provided
    /// `XNetClient`.
    #[allow(clippy::too_many_arguments)]
    pub fn xnet_payload_builder_with_xnet_client(
        xnet_client: Arc<dyn XNetClient>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        registry: Arc<dyn RegistryClient>,
        runtime_handle: runtime::Handle,
        node_id: NodeId,
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        XNetPayloadBuilderImpl::with_xnet_client(
            xnet_client,
            state_manager,
            certified_stream_store,
            registry,
            runtime_handle,
            node_id,
            subnet_id,
            metrics_registry,
            log,
        )
    }
}
