use super::test_fixtures::*;
use super::*;
use crate::certified_slice_pool::CertifiedSliceError;
use assert_matches::assert_matches;
use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
use ic_interfaces::messaging::{InvalidXNetPayload, XNetPayloadValidationFailure};
use ic_interfaces_certified_stream_store::DecodeStreamError;
use ic_interfaces_certified_stream_store_mocks::MockCertifiedStreamStore;
use ic_interfaces_state_manager::StateReader;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_replicated_state::Stream;
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_consensus::fake::Fake;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    HistogramStats, MetricVec, fetch_histogram_stats, fetch_histogram_vec_count,
    fetch_int_counter_vec, metric_vec,
};
use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5};
use ic_types::CryptoHashOfPartialState;
use ic_types::consensus::certification::{Certification, CertificationContent};
use ic_types::crypto::{CryptoHash, Signed};
use ic_types::signature::ThresholdSignature;
use ic_types::state_manager::StateManagerError;
use ic_types::xnet::RejectReason;
use maplit::btreemap;
use mockall::predicate::eq;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn build_payload_no_subnets() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);

        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        assert_eq!(
            (
                XNetPayload {
                    stream_slices: Default::default()
                },
                0.into()
            ),
            xnet_payload_builder.get_xnet_payload(
                &fixture.validation_context,
                &fixture.past_payloads(),
                PAYLOAD_BYTES_LIMIT,
            )
        );
        assert_eq!(
            metric_vec(&[(&[("status", "success")], 1)]),
            fixture.build_payload_counts()
        );
        // No pull attempts, and thus no queries, messages, signals or payloads.
        assert!(fixture.pull_attempt_counts().is_empty());
        assert!(fixture.query_slice_counts().is_empty());
        assert_eq!(0, fixture.slice_messages_stats().count);
        assert_eq!(0, fixture.slice_payload_size_stats().count);
    });
}

/// Creates an `XNetEndpointResolver` around a `ProximityMap` that resolves to
/// the remote node of the given index; and calls `xnet_endpoint_url()` on it.
fn resolve_xnet_endpoint(remote_node_index: u64, log: ReplicaLogger) -> EndpointLocator {
    let registry = create_xnet_endpoint_url_test_fixture();
    let metrics = MetricsRegistry::new();

    let proximity_map = Arc::new(ProximityMap::with_rng(
        mock_gen_range_low(remote_node_index, 3),
        LOCAL_NODE,
        registry.clone(),
        Arc::new(UnhealthyNodes::new(UNHEALTHY_NODE_TTL, &metrics)),
        &metrics,
        log.clone(),
    ));
    let endpoint_resolver = XNetEndpointResolver::new(
        registry,
        LOCAL_NODE_1_OPERATOR_1,
        LOCAL_SUBNET,
        proximity_map,
        log,
    );

    endpoint_resolver
        .xnet_endpoint_url(REMOTE_SUBNET, 1.into(), 2.into(), 1000)
        .unwrap()
}

#[tokio::test]
async fn xnet_endpoint_url_node_same_operator() {
    with_test_replica_logger(|log| {
        assert_eq!(
            EndpointLocator {
                node_id: REMOTE_NODE_1_OPERATOR_1,
                url: "http://gfvbo-licaa-aaaaa-aaaap-2ai.169@192.168.1.1:2197/api/v1/stream/fscpm-uiaaa-aaaaa-aaaap-yai?msg_begin=2&witness_begin=1&byte_limit=1000"
                    .parse::<Uri>()
                    .unwrap(),
                proximity: PeerLocation::Local
            },
            resolve_xnet_endpoint(0, log)
        );
    });
}

#[tokio::test]
async fn xnet_endpoint_url_node_other_operator() {
    with_test_replica_logger(|log| {
        assert_eq!(
            EndpointLocator {
                node_id: REMOTE_NODE_3_OPERATOR_2,
                url: "http://hr2go-2qeaa-aaaaa-aaaap-2ai.169@192.168.1.3:2197/api/v1/stream/fscpm-uiaaa-aaaaa-aaaap-yai?msg_begin=2&witness_begin=1&byte_limit=1000"
                    .parse::<Uri>()
                    .unwrap(),
                proximity: PeerLocation::Remote
            },
            resolve_xnet_endpoint(2, log)
        );
    });
}

#[tokio::test]
async fn validate_empty_payload() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        let payload = XNetPayload {
            stream_slices: Default::default(),
        };

        // Empty payload is valid after `state` + `past_payloads`.
        assert_eq!(
            NumBytes::from(0),
            xnet_payload_builder
                .validate_xnet_payload(
                    &payload,
                    &fixture.validation_context,
                    &fixture.past_payloads()
                )
                .unwrap()
        );

        // Empty payload is valid after `state` with no `past_payloads`.
        assert_eq!(
            NumBytes::from(0),
            xnet_payload_builder
                .validate_xnet_payload(&payload, &fixture.validation_context, &[])
                .unwrap()
        );
    });
}

// tokio runtime is required to use timeout & threads in xnet payload builder.
#[tokio::test]
async fn validate_valid_payload() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Validate newest `XNetPayload` in `payloads` against previous ones + state.
        let payloads = fixture.past_payloads();
        let (payload, past_payloads) = payloads.split_first().unwrap();

        assert_eq!(
            NumBytes::from(payload.stream_slices.len() as u64),
            xnet_payload_builder
                .validate_xnet_payload(payload, &fixture.validation_context, past_payloads)
                .unwrap()
        );
    });
}

#[tokio::test]
async fn validate_valid_payload_against_state_only() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);
        let payload = fixture.payloads.last().unwrap();

        // Validate oldest payload against state and no intermediate payloads.
        assert_eq!(
            NumBytes::from(payload.stream_slices.len() as u64),
            xnet_payload_builder
                .validate_xnet_payload(payload, &fixture.validation_context, &[])
                .unwrap()
        );
    });
}

#[tokio::test]
async fn validate_duplicate_messages() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Simulate duplicate messages by validating the last `XNetPayload` on top of
        // itself.
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                fixture.payloads.last().unwrap(),
                &fixture.validation_context,
                &fixture.past_payloads(),
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(_)
            ))
        );
    });
}

#[tokio::test]
async fn validate_duplicate_messages_against_state_only() {
    with_test_replica_logger(|log| {
        // A `ReplicatedState` with existing streams for `SUBNET_1` and `SUBNET_2`.
        let state_manager = FakeStateManager::new();
        let stream_1 = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: 0,
            signal_end: 17,
        });
        let stream_2 = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: 0,
            signal_end: 5,
        });

        put_replicated_state_for_testing(
            &state_manager,
            btreemap![SUBNET_1 => stream_1, SUBNET_2 => stream_2],
        );

        // An `XNetPayload` with an overlapping `CertifiedStreamSlice` from `SUBNET_1`.
        let slice = make_certified_stream_slice(
            SUBNET_1,
            StreamConfig {
                message_begin: 16,
                message_end: 18,
                signal_end: 0,
            },
        );
        let payload = XNetPayload {
            stream_slices: btreemap![SUBNET_1 => slice],
        };
        let state_manager = Arc::new(state_manager);
        let registry = get_simple_registry_for_test();
        let tls_handshake = Arc::new(MockTlsConfig::new());
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            state_manager,
            tls_handshake as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        );

        let validation_context = get_validation_context_for_test();

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(&payload, &validation_context, &[],),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(_)
            ))
        );
    });
}

#[tokio::test]
async fn validate_missing_messages() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Split `payloads` into `past_payloads` and `payload`.
        let mut past_payloads: Vec<&XNetPayload> = fixture.past_payloads();
        let payload = past_payloads.pop().unwrap();

        // Simulate missing messages by removing the last `XNetPayload` in `payloads`.
        past_payloads.pop().unwrap();
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                payload,
                &fixture.validation_context,
                &past_payloads,
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(_)
            ))
        );
    });
}

#[tokio::test]
async fn validate_missing_messages_against_state_only() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Validate the second `XNetPayload` against `state` only.
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                fixture.payloads.get(1).unwrap(),
                &fixture.validation_context,
                &[],
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(_)
            ))
        );
    });
}

#[tokio::test]
async fn validate_state_removed() {
    with_test_replica_logger(|log| {
        let certified_stream_store = MockCertifiedStreamStore::new();
        let certified_stream_store = Arc::new(certified_stream_store);
        let mut state_manager = MockStateManager::new();
        state_manager
            .expect_get_state_at()
            .with(eq(CERTIFIED_HEIGHT))
            .return_const(Err(StateManagerError::StateRemoved(CERTIFIED_HEIGHT)));
        let state_manager = Arc::new(state_manager);
        let registry = get_simple_registry_for_test();
        let tls_handshake = Arc::new(MockTlsConfig::new());
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            certified_stream_store,
            tls_handshake as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        );

        let payload = XNetPayload {
            stream_slices: Default::default(),
        };
        let validation_context = get_validation_context_for_test();

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &payload,
                &validation_context,
                &[]
            ),
            Err(ValidationError::ValidationFailed(XNetPayloadValidationFailure::StateRemoved(h)))
            if h == CERTIFIED_HEIGHT
        );
    });
}

#[tokio::test]
async fn validate_state_not_yet_committed() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let state_manager = Arc::new(state_manager);

        let registry = get_simple_registry_for_test();
        let tls_handshake = Arc::new(MockTlsConfig::new());
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            state_manager,
            tls_handshake as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        );

        let payload = XNetPayload {
            stream_slices: Default::default(),
        };
        let validation_context = get_validation_context_for_test();

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &payload,
                &validation_context,
                &[]
            ),
            Err(ValidationError::ValidationFailed(XNetPayloadValidationFailure::StateNotCommittedYet(h)))
            if h == CERTIFIED_HEIGHT
        );
    });
}

/// Have `count_bytes_fn` return an error while validating a payload. This is
/// unexpected behavior, so ensure that the relevant critical error counter is
/// bumped accordingly.
#[tokio::test]
async fn validate_broken_count_bytes_fn() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture
            .new_xnet_payload_builder_impl(log)
            .with_count_bytes_fn(|_| {
                Err(CertifiedSliceError::DecodeFailed(
                    ProxyDecodeError::MissingField("test"),
                ))
            });

        // Validate newest `XNetPayload` in `payloads` against previous ones + state.
        let payloads = fixture.past_payloads();
        let (payload, past_payloads) = payloads.split_first().unwrap();

        assert!(
            xnet_payload_builder
                .validate_xnet_payload(payload, &fixture.validation_context, past_payloads)
                .is_err()
        );

        assert_eq!(
            metric_vec(&[
                (&[("error", &CRITICAL_ERROR_SLICE_INVALID_COUNT_BYTES)], 0),
                (&[("error", &CRITICAL_ERROR_SLICE_COUNT_BYTES_FAILED)], 1),
            ]),
            fetch_int_counter_vec(&fixture.metrics, "critical_errors")
        );
    });
}

/// A test fixture that sets up a `FakeStateManager` and matching
/// `RegistryClient` with valid payloads and expected indices.
pub(crate) struct PayloadBuilderTestFixture {
    pub state_manager: Arc<FakeStateManager>,
    pub tls_handshake: Arc<MockTlsConfig>,
    pub registry: Arc<dyn RegistryClient>,
    pub validation_context: ValidationContext,
    pub metrics: MetricsRegistry,

    pub payloads: Vec<XNetPayload>,
}

impl PayloadBuilderTestFixture {
    /// Creates a fixture with state provided by `get_xnet_state_for_testing()`,
    /// and registry entries plus matching URLs for the given number of subnets.
    pub fn with_xnet_state(subnet_count: u8) -> Self {
        Self::with_xnet_state_and_subnet_types(subnet_count, btreemap![], None)
    }

    /// Like `with_xnet_state`, but with configurable subnet types. Subnets not
    /// present in `subnet_types` default to `SubnetType::Application`.
    /// `own_subnet_type` overrides the own subnet type in the replicated state.
    pub fn with_xnet_state_and_subnet_types(
        subnet_count: u8,
        subnet_types: BTreeMap<SubnetId, SubnetType>,
        own_subnet_type: Option<SubnetType>,
    ) -> Self {
        let state_manager = Arc::new(FakeStateManager::new());
        let tls_handshake = Arc::new(MockTlsConfig::new());

        let (payloads, expected_indices) =
            get_xnet_state_for_testing_with_subnet_type(&state_manager, own_subnet_type);
        // Register subnet types for all subnets used in payloads (SUBNET_1
        // through SUBNET_4) as Application by default.
        let mut all_subnet_types = btreemap![
            SUBNET_1 => SubnetType::Application,
            SUBNET_2 => SubnetType::Application,
            SUBNET_3 => SubnetType::Application,
            SUBNET_4 => SubnetType::Application,
        ];
        all_subnet_types.extend(subnet_types);
        let (registry, _) = get_registry_and_urls_for_test_with_subnet_types(
            subnet_count,
            expected_indices,
            all_subnet_types,
        );

        PayloadBuilderTestFixture {
            state_manager,
            tls_handshake,
            registry,
            validation_context: get_validation_context_for_test(),
            metrics: MetricsRegistry::new(),

            payloads,
        }
    }

    /// Constructs an `XNetPayloadBuilderImpl` using the fixture's
    /// `state_manager`, `registry` and `metrics`.
    pub fn new_xnet_payload_builder_impl(&self, log: ReplicaLogger) -> XNetPayloadBuilderImpl {
        XNetPayloadBuilderImpl::new(
            Arc::clone(&self.state_manager) as Arc<_>,
            Arc::clone(&self.state_manager) as Arc<_>,
            Arc::clone(&self.tls_handshake) as Arc<_>,
            Arc::clone(&self.registry) as Arc<_>,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &self.metrics,
            log,
        )
        // Any slice, empty or not, has byte size 1.
        .with_count_bytes_fn(|_| Ok(1))
    }

    /// Helper to create a vector of references from `self.payloads`.
    pub fn past_payloads(&self) -> Vec<&XNetPayload> {
        self.payloads.iter().collect()
    }

    /// Fetches the values of the `METRIC_BUILD_PAYLOAD_DURATION` histograms'
    /// `_count` fields for all label value combinations.
    pub fn build_payload_counts(&self) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.metrics, METRIC_BUILD_PAYLOAD_DURATION)
    }

    /// Fetches the values of the `METRIC_PULL_ATTEMPT_COUNT` counters for all
    /// label value combinations.
    pub fn pull_attempt_counts(&self) -> MetricVec<u64> {
        fetch_int_counter_vec(&self.metrics, METRIC_PULL_ATTEMPT_COUNT)
    }

    /// Fetches the values of the `METRIC_PULL_SLICE_DURATION` histograms'
    /// `_count` fields for all label value combinations.
    pub fn query_slice_counts(&self) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.metrics, METRIC_QUERY_SLICE_DURATION)
    }

    /// Fetches the `METRIC_SLICE_MESSAGES` histogram's stats.
    pub fn slice_messages_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_SLICE_MESSAGES).unwrap()
    }

    /// Fetches the `METRIC_SLICE_PAYLOAD_SIZE` histogram's stats.
    pub fn slice_payload_size_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_SLICE_PAYLOAD_SIZE).unwrap()
    }
}

/// A minimal `XNetSlicePool` for testing: stores one slice per subnet and
/// never garbage collects (neither `garbage_collect` nor `garbage_collect_slice`
/// removes or trims slices).
struct TestSlicePool(Mutex<BTreeMap<SubnetId, CertifiedStreamSlice>>);

impl XNetSlicePool for TestSlicePool {
    fn take_slice(
        &self,
        subnet_id: SubnetId,
        _begin: Option<&ExpectedIndices>,
        _msg_limit: Option<usize>,
        _byte_limit: Option<usize>,
    ) -> CertifiedSliceResult<Option<(CertifiedStreamSlice, usize)>> {
        Ok(self.0.lock().unwrap().remove(&subnet_id).map(|s| (s, 1)))
    }

    fn observe_pool_size_bytes(&self) {}

    fn garbage_collect(&self, _: BTreeMap<SubnetId, ExpectedIndices>) {}

    fn garbage_collect_slice(&self, _: SubnetId, _: ExpectedIndices) {}

    fn classify_advert(
        &self,
        _: SubnetId,
        _: &StreamHeader,
        _: &dyn Fn(StreamIndex, StreamIndex) -> bool,
    ) -> XNetAdvertOutcome {
        XNetAdvertOutcome::Actionable
    }

    fn record_peer_header(&self, _: SubnetId, _: &StreamHeader, _: Height) {}
}

/// `get_xnet_payload` must not include a slice from a deleted subnet even if
/// the pool contains one (e.g., populated just before deletion). The deleted
/// subnet is absent from `expected_stream_indices`, so it is never iterated
/// over during payload assembly and never appears in the result.
#[tokio::test]
async fn get_xnet_payload_excludes_deleted_subnet_slice() {
    with_test_replica_logger(|log| {
        // State with an outgoing stream to SUBNET_2 committed at CERTIFIED_HEIGHT.
        let state_manager = Arc::new(FakeStateManager::new());
        put_replicated_state_for_testing(
            state_manager.as_ref(),
            btreemap! {
                SUBNET_2 => generate_stream(&StreamConfig {
                    message_begin: 0,
                    message_end: 5,
                    signal_end: 3,
                }),
            },
        );

        // Seed the pool with SUBNET_2's slice, simulating a pool populated just
        // before SUBNET_2 was deleted from the registry.
        let slice = make_certified_stream_slice(
            SUBNET_2,
            StreamConfig {
                message_begin: 3,
                message_end: 5,
                signal_end: 3,
            },
        );
        let slice_pool = Box::new(TestSlicePool(Mutex::new(btreemap! { SUBNET_2 => slice })));

        // Registry with only SUBNET_1; SUBNET_2 is absent (deleted).
        let (registry, _) = get_registry_and_urls_for_test(1, btreemap![]);

        let metrics_registry = MetricsRegistry::new();
        let (refill_trigger, _refill_receiver) = tokio::sync::mpsc::channel(1);
        let xnet_payload_builder = XNetPayloadBuilderImpl::new_from_components(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            registry as Arc<_>,
            Arc::new(None),
            None,
            slice_pool,
            RefillTaskHandle(Mutex::new(refill_trigger)),
            Arc::new(XNetPayloadBuilderMetrics::new(&metrics_registry)),
            log,
        )
        .with_count_bytes_fn(|_| Ok(1));

        let validation_context = get_validation_context_for_test();
        let (payload, _) =
            xnet_payload_builder.get_xnet_payload(&validation_context, &[], PAYLOAD_BYTES_LIMIT);

        assert!(
            !payload.stream_slices.contains_key(&SUBNET_2),
            "deleted SUBNET_2's slice must not appear in the payload"
        );
    });
}

/// A payload containing a certified stream slice from a deleted subnet (absent
/// from the registry at the block's registry version) must be rejected by
/// `validate_xnet_payload`, even if the deleted subnet still had a non-empty
/// stream of messages to deliver.
///
/// This is the key invariant that makes `discard_streams_for_deleted_subnets`
/// safe: no block can carry a certified slice from the deleted subnet after
/// deletion takes effect, so after the outgoing stream is discarded, no new
/// certified stream slices from the deleted subnet can be pulled and refer to
/// the deleted outgoing stream.
#[tokio::test]
async fn validate_xnet_payload_rejects_slice_from_deleted_subnet() {
    with_test_replica_logger(|log| {
        // State with an outgoing stream to SUBNET_2 (prior communication before
        // its deletion) committed at CERTIFIED_HEIGHT.
        let state_manager = FakeStateManager::new();
        put_replicated_state_for_testing(
            &state_manager,
            btreemap! {
                SUBNET_2 => generate_stream(&StreamConfig {
                    message_begin: 0,
                    message_end: 5,
                    signal_end: 3,
                }),
            },
        );

        // Registry with only SUBNET_1; SUBNET_2 is absent (deleted).
        let (registry, _) = get_registry_and_urls_for_test(1, btreemap![]);
        let state_manager = Arc::new(state_manager);
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::new(MockTlsConfig::new()) as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        )
        .with_count_bytes_fn(|_| Ok(1));

        let validation_context = get_validation_context_for_test();

        // Payload with SUBNET_2's certified slice: messages 3..5 still to deliver
        // (it GCed 0..3 after A sent signals), signals_end = 3.
        let payload = XNetPayload {
            stream_slices: btreemap! {
                SUBNET_2 => make_certified_stream_slice(
                    SUBNET_2,
                    StreamConfig {
                        message_begin: 3,
                        message_end: 5,
                        signal_end: 3,
                    },
                ),
            },
        };

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(&payload, &validation_context, &[]),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(_)
            ))
        );
    });
}

/// CloudEngine subnets now participate in XNet. At the unit level this checks
/// that `expected_stream_indices` returns entries for an engine's Application
/// peers (no filter excluding them), so the engine will attempt to pull from
/// them. The end-to-end behavior — that a CloudEngine subnet actually builds and
/// validates XNet payloads and completes a best-effort cross-subnet call (which
/// requires `get_xnet_payload`/`validate_xnet_payload` to no longer short-circuit
/// for engines) — is covered by `xnet_cloud_engine_isolation_test`.
#[tokio::test]
async fn cloud_engine_get_xnet_payload_participates() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
            4,
            btreemap![],
            Some(SubnetType::CloudEngine),
        );
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        let state = fixture
            .state_manager
            .get_state_at(fixture.validation_context.certified_height)
            .unwrap()
            .take();
        let past_payloads = fixture.past_payloads();
        let stream_positions = xnet_payload_builder
            .expected_stream_indices(
                &fixture.validation_context,
                state.as_ref(),
                past_payloads.as_slice(),
            )
            .unwrap();

        // The engine produces non-empty stream positions — it will try to pull
        // from peers (Application subnets SUBNET_1..SUBNET_4 are all present).
        assert!(!stream_positions.is_empty());
        for subnet in &[SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4] {
            assert!(
                stream_positions.contains_key(subnet),
                "CloudEngine should pull from Application subnet {subnet:?}"
            );
        }
    });
}

/// CloudEngine subnets must accept non-empty XNet payloads during validation.
#[tokio::test]
async fn cloud_engine_validate_accepts_non_empty_payload() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
            0,
            btreemap![],
            Some(SubnetType::CloudEngine),
        );
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Use a pre-built payload from the fixture — indices are consistent with
        // the state, so validation passes for any subnet type including CloudEngine.
        let payload = fixture.payloads.last().unwrap();
        assert!(
            !payload.stream_slices.is_empty(),
            "fixture payload must be non-empty for this test to be meaningful"
        );

        assert!(
            xnet_payload_builder
                .validate_xnet_payload(payload, &fixture.validation_context, &[])
                .is_ok(),
            "CloudEngine subnet should accept non-empty XNet payloads"
        );
    });
}

/// Non-CloudEngine subnets must accept slices originating from a CloudEngine subnet.
#[tokio::test]
async fn validate_accepts_slice_from_cloud_engine_subnet() {
    with_test_replica_logger(|log| {
        let cloud_engine_subnet = SUBNET_1;
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
            0,
            btreemap![cloud_engine_subnet => SubnetType::CloudEngine],
            None,
        );

        // This is an Application subnet validating an incoming payload.
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Use a pre-built payload from the fixture. SUBNET_1 is the CloudEngine
        // subnet; a slice from it must now be accepted by a non-engine subnet.
        let payload = fixture.payloads.last().unwrap();
        assert!(
            payload.stream_slices.contains_key(&cloud_engine_subnet),
            "fixture payload must contain a slice from the CloudEngine subnet"
        );

        assert!(
            xnet_payload_builder
                .validate_xnet_payload(payload, &fixture.validation_context, &[])
                .is_ok(),
            "Application subnet should accept slices from a CloudEngine subnet"
        );
    });
}

/// Non-CloudEngine subnets must reject slices from subnets whose type cannot be determined.
#[tokio::test]
async fn validate_rejects_slice_from_unknown_subnet() {
    with_test_replica_logger(|log| {
        let unknown_subnet = SUBNET_5;
        // SUBNET_5 is not registered in the registry (only SUBNET_1-4 are).
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);

        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        let slice = make_certified_stream_slice(
            unknown_subnet,
            StreamConfig {
                message_begin: 0,
                message_end: 2,
                signal_end: 0,
            },
        );
        let payload = XNetPayload {
            stream_slices: btreemap![unknown_subnet => slice],
        };

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &payload,
                &fixture.validation_context,
                &[],
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidXNetPayload::InvalidSlice(msg)
            )) if msg.contains("No subnet type for subnet")
        );
    });
}

/// An Application subnet with a registered CloudEngine peer must pull from it.
#[tokio::test]
async fn build_payload_includes_cloud_engine_subnet() {
    with_test_replica_logger(|log| {
        // Register 2 subnets: SUBNET_1 as CloudEngine, SUBNET_2 as Application.
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
            2,
            btreemap![SUBNET_1 => SubnetType::CloudEngine, SUBNET_2 => SubnetType::Application],
            None,
        );

        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        let state = fixture
            .state_manager
            .get_state_at(fixture.validation_context.certified_height)
            .unwrap()
            .take();
        let past_payloads = fixture.past_payloads();
        let stream_positions = xnet_payload_builder
            .expected_stream_indices(
                &fixture.validation_context,
                state.as_ref(),
                past_payloads.as_slice(),
            )
            .unwrap();

        // Both SUBNET_1 (CloudEngine) and SUBNET_2 (Application) are included.
        assert!(stream_positions.contains_key(&SUBNET_1));
        assert!(stream_positions.contains_key(&SUBNET_2));
    });
}

/// Our outgoing stream to `REMOTE_SUBNET` across the advert tests: we have
/// inducted its messages up to `OWN_SIGNALS_END`; it has signalled ours up to
/// `OWN_MESSAGES_BEGIN`, where the messages we still hold for it begin.
///
/// An advert is thus new to us iff it ends past `OWN_SIGNALS_END`, signals past
/// `OWN_MESSAGES_BEGIN`, or begins past a reject signal of ours.
const OWN_SIGNALS_END: u64 = 3;
const OWN_MESSAGES_BEGIN: u64 = 5;
const OWN_MESSAGES_END: u64 = 10;

fn own_stream_for_advert_tests() -> Stream {
    generate_stream(&StreamConfig {
        message_begin: OWN_MESSAGES_BEGIN,
        message_end: OWN_MESSAGES_END,
        signal_end: OWN_SIGNALS_END,
    })
}

/// Builds an `XNetPayloadBuilderImpl` around `certified_stream_store`, with a
/// registry that only knows `REMOTE_SUBNET` and a pool that actually records
/// peer headers; plus said pool.
fn advert_handler_and_pool(
    certified_stream_store: MockCertifiedStreamStore,
    log: ReplicaLogger,
) -> (XNetPayloadBuilderImpl, Arc<Mutex<CertifiedSlicePool>>) {
    advert_handler_and_pool_for(own_stream_for_advert_tests(), certified_stream_store, log)
}

/// Like `advert_handler_and_pool()`, but with the given outgoing stream to
/// `REMOTE_SUBNET`.
fn advert_handler_and_pool_for(
    own_stream: Stream,
    certified_stream_store: MockCertifiedStreamStore,
    log: ReplicaLogger,
) -> (XNetPayloadBuilderImpl, Arc<Mutex<CertifiedSlicePool>>) {
    let state_manager = Arc::new(FakeStateManager::new());
    put_replicated_state_for_testing(
        state_manager.as_ref(),
        btreemap! { REMOTE_SUBNET => own_stream },
    );
    // `FakeStateManager` only reports a height as certified once a certification
    // for it has been delivered, and advert classification reads certified state.
    state_manager.deliver_state_certification(Certification {
        height: CERTIFIED_HEIGHT,
        height_witness: None,
        signed: Signed {
            content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(vec![]))),
            signature: ThresholdSignature::fake(),
        },
    });
    let (registry, _) = get_registry_and_urls_for_test(1, btreemap![]);

    let metrics_registry = MetricsRegistry::new();
    let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(&metrics_registry)));
    let (refill_trigger, _refill_receiver) = tokio::sync::mpsc::channel(1);
    let payload_builder = XNetPayloadBuilderImpl::new_from_components(
        state_manager as Arc<_>,
        Arc::new(certified_stream_store) as Arc<_>,
        registry as Arc<_>,
        Arc::new(None),
        None,
        Box::new(XNetSlicePoolImpl::new(Arc::clone(&pool))),
        RefillTaskHandle(Mutex::new(refill_trigger)),
        Arc::new(XNetPayloadBuilderMetrics::new(&metrics_registry)),
        log,
    );

    (payload_builder, pool)
}

/// A mock store expecting exactly `verifications` verifying decodes of an advert
/// carrying `advertised`'s header. Only adverts classified as `NothingNew` or
/// `Actionable` are verified, so the count is what each test is really asserting;
/// the classifying decode is real, off the advert's own bytes.
fn advert_store(advertised: &Stream, verifications: usize) -> MockCertifiedStreamStore {
    let decoded = advertised.slice(advertised.messages_begin(), Some(0));
    let mut store = MockCertifiedStreamStore::new();
    store
        .expect_decode_certified_stream_slice()
        .times(verifications)
        .returning(move |_, _, _| Ok(decoded.clone()));
    store
}

/// The peer header on record for `REMOTE_SUBNET`, if any.
fn recorded_peer_header(pool: &Mutex<CertifiedSlicePool>) -> Option<(Arc<StreamHeader>, Height)> {
    pool.lock()
        .unwrap()
        .peer_header(REMOTE_SUBNET)
        .map(|(header, height)| (header.clone(), height))
}

/// An advert offering messages we have not inducted is actionable, and its
/// header is recorded.
#[tokio::test]
async fn handle_advert_actionable() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END + 4,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        let header = advertised.header();
        let (payload_builder, pool) = advert_handler_and_pool(advert_store(&advertised, 1), log);

        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Actionable)
        );
        assert_eq!(
            Some((Arc::new(header), CERTIFIED_HEIGHT)),
            recorded_peer_header(&pool)
        );

        // Redundant copies of the same advert are classified as duplicates
        // and not verified again.
        for _ in 0..2 {
            assert_matches!(
                payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
                Ok(XNetAdvertOutcome::Duplicate)
            );
        }
    });
}

/// An advert offering only messages already accounted for by the cached stream
/// position, i.e. included into blocks, is dropped without being verified.
#[tokio::test]
async fn handle_advert_in_payload() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END + 4,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        let (payload_builder, pool) = advert_handler_and_pool(advert_store(&advertised, 0), log);

        // A past payload already covers all of it.
        pool.lock().unwrap().garbage_collect(btreemap! {
            REMOTE_SUBNET => ExpectedIndices {
                message_index: (OWN_SIGNALS_END + 4).into(),
                signal_index: OWN_MESSAGES_BEGIN.into(),
                ..Default::default()
            }
        });

        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
            Ok(XNetAdvertOutcome::InPayload)
        );
        // The advertised header was not (verified and) recorded.
        assert_eq!(None, recorded_peer_header(&pool));
    });
}

/// An advert bringing signals we have not acted on is actionable even with no
/// messages we have not inducted: only those signals let us garbage collect the
/// messages we hold for `REMOTE_SUBNET`.
#[tokio::test]
async fn handle_advert_new_signals() {
    with_test_replica_logger(|log| {
        // Nothing we have not inducted, but signals past those we have acted on.
        let advertised = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN + 2,
        });
        let header = advertised.header();
        let (payload_builder, pool) = advert_handler_and_pool(advert_store(&advertised, 1), log);

        // A header on record covering everything except the new signals.
        let recorded = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        pool.lock().unwrap().record_peer_header(
            REMOTE_SUBNET,
            &recorded.header(),
            CERTIFIED_HEIGHT.decrement(),
        );

        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Actionable)
        );
        assert_eq!(
            Some((Arc::new(header), CERTIFIED_HEIGHT)),
            recorded_peer_header(&pool)
        );
    });
}

/// An advert whose content we have already recorded, but at a lower certified
/// height, is classified as a duplicate without being verified.
#[tokio::test]
async fn handle_advert_duplicate_content() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END + 4,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        let header = advertised.header();
        let (payload_builder, pool) = advert_handler_and_pool(advert_store(&advertised, 0), log);

        pool.lock().unwrap().record_peer_header(
            REMOTE_SUBNET,
            &header,
            CERTIFIED_HEIGHT.decrement(),
        );

        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Duplicate)
        );
    });
}

/// An advert offering nothing we do not already have is answered with our own
/// certified header, so its sender can observe our stream's `begin`.
#[tokio::test]
async fn handle_advert_nothing_new() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        // The header-only reply, as encoded from our own stream.
        let own_header = make_certified_stream_slice(
            LOCAL_SUBNET,
            StreamConfig {
                message_begin: OWN_MESSAGES_BEGIN,
                message_end: OWN_MESSAGES_BEGIN,
                signal_end: OWN_SIGNALS_END,
            },
        );

        // Two copies, as from two nodes of the source subnet at the same certified
        // height: each is answered, or only one of the peer's nodes would learn our
        // header per height.
        let mut store = advert_store(&advertised, 2);
        let expected_reply = own_header.clone();
        store
            .expect_encode_certified_stream_slice()
            .times(2)
            .returning(move |_, _, _, msg_limit, _| {
                assert_eq!(msg_limit, Some(0));
                Ok(own_header.clone())
            });
        let (payload_builder, pool) = advert_handler_and_pool(store, log);

        for _ in 0..2 {
            assert_matches!(
                payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
                Ok(XNetAdvertOutcome::NothingNew)
            );
            // Advertised header was recorded regardless.
            assert_eq!(
                Some((Arc::new(advertised.header()), CERTIFIED_HEIGHT)),
                recorded_peer_header(&pool)
            );
            assert_eq!(
                Some(expected_reply.clone()),
                payload_builder.certified_header(REMOTE_SUBNET)
            );
        }
    });
}

/// An advert whose `begin` is past a reject signal of ours brings something even
/// when all of its messages and signals are accounted for: inducting it lets us
/// garbage collect that signal.
#[tokio::test]
async fn handle_advert_collecting_reject_signal() {
    with_test_replica_logger(|log| {
        // As `own_stream_for_advert_tests()`, except that we rejected the last message
        // we inducted, leaving a reject signal at `REJECT_SIGNAL`.
        const REJECT_SIGNAL: u64 = OWN_SIGNALS_END - 1;
        let mut own_stream = generate_stream(&StreamConfig {
            message_begin: OWN_MESSAGES_BEGIN,
            message_end: OWN_MESSAGES_END,
            signal_end: REJECT_SIGNAL,
        });
        own_stream.push_reject_signal(RejectReason::CanisterMigrating);

        // A stream whose messages and signals we've inducted; only its `begin` differs.
        let advertised = |begin| {
            generate_stream(&StreamConfig {
                message_begin: begin,
                message_end: OWN_SIGNALS_END,
                signal_end: OWN_MESSAGES_BEGIN,
            })
        };

        // A `begin` at the reject signal leaves it uncollected.
        let (payload_builder, _pool) = advert_handler_and_pool_for(
            own_stream.clone(),
            advert_store(&advertised(REJECT_SIGNAL), 1),
            log.clone(),
        );
        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised(REJECT_SIGNAL))),
            Ok(XNetAdvertOutcome::NothingNew)
        );

        // One past it collects it, so there is something to fetch after all.
        let (payload_builder, _pool) = advert_handler_and_pool_for(
            own_stream,
            advert_store(&advertised(REJECT_SIGNAL + 1), 1),
            log,
        );
        assert_matches!(
            payload_builder
                .handle_advert(REMOTE_SUBNET, make_advert(&advertised(REJECT_SIGNAL + 1))),
            Ok(XNetAdvertOutcome::Actionable)
        );
    });
}

/// An advert offering new content whose certification does not verify is
/// rejected and not recorded.
#[tokio::test]
async fn handle_advert_invalid_signature() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END + 4,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        let mut store = MockCertifiedStreamStore::new();
        store
            .expect_decode_certified_stream_slice()
            .times(1)
            .return_once(|_, _, _| Err(DecodeStreamError::InvalidSignature(REMOTE_SUBNET)));
        let (payload_builder, pool) = advert_handler_and_pool(store, log);

        assert_matches!(
            payload_builder.handle_advert(REMOTE_SUBNET, make_advert(&advertised)),
            Err(XNetAdvertError::InvalidSignature)
        );
        assert_eq!(None, recorded_peer_header(&pool));
    });
}
