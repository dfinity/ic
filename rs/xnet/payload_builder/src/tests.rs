use super::test_fixtures::*;
use super::*;
use assert_matches::assert_matches;
use ic_interfaces::messaging::{InvalidXNetPayload, XNetTransientValidationError};
use ic_interfaces_state_manager::StateManagerError;
use ic_test_utilities::{
    certified_stream_store::MockCertifiedStreamStore,
    crypto::fake_tls_handshake::FakeTlsHandshake,
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, fetch_int_counter_vec, metric_vec,
        HistogramStats, MetricVec,
    },
    state_manager::{FakeStateManager, MockStateManager},
    types::ids::{SUBNET_1, SUBNET_2},
    with_test_replica_logger,
};
use maplit::btreemap;
use mockall::predicate::eq;

#[tokio::test]
async fn build_payload_no_subnets() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);

        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        assert_eq!(
            XNetPayload {
                stream_slices: Default::default()
            },
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
            Err(ValidationError::Permanent(
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
        let registry = get_empty_registry_for_test();
        let tls_handshake = Arc::new(FakeTlsHandshake::new());
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
            Err(ValidationError::Permanent(
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
            Err(ValidationError::Permanent(
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
            Err(ValidationError::Permanent(
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
        let registry = get_empty_registry_for_test();
        let tls_handshake = Arc::new(FakeTlsHandshake::new());
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
            Err(ValidationError::Permanent(InvalidXNetPayload::StateRemoved(h)))
            if h == CERTIFIED_HEIGHT
        );
    });
}

#[tokio::test]
async fn validate_state_not_yet_committed() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let state_manager = Arc::new(state_manager);

        let registry = get_empty_registry_for_test();
        let tls_handshake = Arc::new(FakeTlsHandshake::new());
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
            Err(ValidationError::Transient(XNetTransientValidationError::StateNotCommittedYet(h)))
            if h == CERTIFIED_HEIGHT
        );
    });
}

/// A test fixture that sets up a `FakeStateManager` and matching
/// `RegistryClient` with valid payloads and expected indices.
pub(crate) struct PayloadBuilderTestFixture {
    pub state_manager: Arc<FakeStateManager>,
    pub tls_handshake: Arc<FakeTlsHandshake>,
    pub registry: Arc<dyn RegistryClient>,
    pub validation_context: ValidationContext,
    pub metrics: MetricsRegistry,

    pub payloads: Vec<XNetPayload>,
}

impl PayloadBuilderTestFixture {
    /// Creates a fixture with state provided by `get_xnet_state_for_testing()`,
    /// and registry entries plus matching URLs for the given number of subnets.
    pub fn with_xnet_state(subnet_count: u8) -> Self {
        let state_manager = Arc::new(FakeStateManager::new());
        let tls_handshake = Arc::new(FakeTlsHandshake::new());

        let (payloads, expected_indices) = get_xnet_state_for_testing(&*state_manager);
        let (registry, _) = get_registry_and_urls_for_test(subnet_count, expected_indices);

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
