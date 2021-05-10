use super::test_fixtures::*;
use super::*;
use assert_matches::assert_matches;
use ic_interfaces::{
    messaging::{InvalidXNetPayload, XNetTransientValidationError},
    state_manager::StateManagerError,
};
use ic_test_utilities::{
    certified_stream_store::MockCertifiedStreamStore,
    consensus::assert_result_invalid,
    crypto::fake_tls_handshake::FakeTlsHandshake,
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, fetch_int_counter_vec, metric_vec,
        HistogramStats, MetricVec,
    },
    state_manager::{FakeStateManager, MockStateManager},
    types::ids::subnet_test_id,
    types::ids::{SUBNET_1, SUBNET_2},
    with_test_replica_logger,
};
use maplit::btreemap;
use mockall::predicate::eq;
use std::collections::BTreeMap;

#[tokio::test]
async fn build_payload_no_subnets() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);

        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        assert_matches!(
            xnet_payload_builder.get_xnet_payload(
                Height::from(0),
                &fixture.validation_context,
                &fixture.past_payloads(),
                PAYLOAD_BYTES_LIMIT,
            ),
            Ok(payload) if payload.stream_slices == Default::default()
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

fn resolve_xnet_endpoint_url(local_node: NodeId, log: ReplicaLogger) -> NodeId {
    let registry = create_xnet_endpoint_url_test_fixture();

    let endpoint_resolver = XNetEndpointResolver::new(registry, local_node, subnet_test_id(1), log);

    endpoint_resolver
        .xnet_endpoint_url(subnet_test_id(2), 0.into(), 0.into(), 1000)
        .unwrap()
        .node_id
}

#[tokio::test]
async fn xnet_endpoint_url_node_in_node_operator_1() {
    with_test_replica_logger(|log| {
        let expected = vec![REMOTE_NODE_1_NO_1, REMOTE_NODE_2_NO_1];

        for _ in 0..10 {
            let res = resolve_xnet_endpoint_url(LOCAL_NODE_NO_1, log.clone());

            assert!(
                expected.contains(&res),
                "Expected one of {:?}, got {:?}",
                expected,
                res
            );
        }
    });
}

#[tokio::test]
async fn xnet_endpoint_url_node_in_node_operator_2() {
    with_test_replica_logger(|log| {
        let expected = vec![REMOTE_NODE_3_NO_2, REMOTE_NODE_4_NO_2];

        for _ in 0..10 {
            let res = resolve_xnet_endpoint_url(LOCAL_NODE_NO_2, log.clone());

            assert!(
                expected.contains(&res),
                "Expected one of {:?}, got {:?}",
                expected,
                res
            );
        }
    });
}

#[tokio::test]
async fn xnet_endpoint_url_node_in_node_operator_3() {
    with_test_replica_logger(|log| {
        let expected = vec![
            REMOTE_NODE_1_NO_1,
            REMOTE_NODE_2_NO_1,
            REMOTE_NODE_3_NO_2,
            REMOTE_NODE_4_NO_2,
        ];

        for _ in 0..10 {
            let res = resolve_xnet_endpoint_url(LOCAL_NODE_NO_3, log.clone());

            assert!(
                expected.contains(&res),
                "Expected one of {:?}, got {:?}",
                expected,
                res
            );
        }
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
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &payload,
                &fixture.validation_context,
                &fixture.past_payloads(),
                PAYLOAD_BYTES_LIMIT
            ),
            Ok(_)
        );

        // Empty payload is valid after `state` with no `past_payloads`.
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &payload,
                &fixture.validation_context,
                &[],
                PAYLOAD_BYTES_LIMIT
            ),
            Ok(_)
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

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                payload,
                &fixture.validation_context,
                &past_payloads,
                PAYLOAD_BYTES_LIMIT
            ),
            Ok(_)
        );
    });
}

#[tokio::test]
async fn validate_valid_payload_against_state_only() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Validate oldest payload against state and no intermediate payloads.
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                &fixture.payloads.last().unwrap(),
                &fixture.validation_context,
                &[],
                PAYLOAD_BYTES_LIMIT
            ),
            Ok(_)
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
        assert_result_invalid(xnet_payload_builder.validate_xnet_payload(
            fixture.payloads.last().unwrap(),
            &fixture.validation_context,
            &fixture.past_payloads(),
            PAYLOAD_BYTES_LIMIT,
        ));
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

        assert_result_invalid(xnet_payload_builder.validate_xnet_payload(
            &payload,
            &validation_context,
            &[],
            PAYLOAD_BYTES_LIMIT,
        ));
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
        assert_result_invalid(xnet_payload_builder.validate_xnet_payload(
            payload,
            &fixture.validation_context,
            &past_payloads,
            PAYLOAD_BYTES_LIMIT,
        ));
    });
}

#[tokio::test]
async fn validate_missing_messages_against_state_only() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state(0);
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Validate the second `XNetPayload` against `state` only.
        assert_result_invalid(xnet_payload_builder.validate_xnet_payload(
            &fixture.payloads.get(1).unwrap(),
            &fixture.validation_context,
            &[],
            PAYLOAD_BYTES_LIMIT,
        ));
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
                &[],
                PAYLOAD_BYTES_LIMIT,
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
                &[],
                PAYLOAD_BYTES_LIMIT,
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
    pub expected_indices: BTreeMap<SubnetId, ExpectedIndices>,
    pub subnet_urls: Vec<String>,
}

impl PayloadBuilderTestFixture {
    /// Creates a fixture with state provided by `get_xnet_state_for_testing()`,
    /// and registry entries plus matching URLs for the given number of subnets.
    pub fn with_xnet_state(subnet_count: u8) -> Self {
        let state_manager = Arc::new(FakeStateManager::new());
        let tls_handshake = Arc::new(FakeTlsHandshake::new());

        let (payloads, expected_indices) = get_xnet_state_for_testing(&*state_manager);
        let (registry, subnet_urls) =
            get_registry_and_urls_for_test(subnet_count, expected_indices.clone());

        PayloadBuilderTestFixture {
            state_manager,
            tls_handshake,
            registry,
            validation_context: get_validation_context_for_test(),
            metrics: MetricsRegistry::new(),

            payloads,
            expected_indices,
            subnet_urls,
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
    }

    /// Constructs an `XNetPayloadBuilderImpl` using the provided `XNetClient`
    /// and the fixture's `state_manager`, `registry` and `metrics`.
    #[allow(dead_code)]
    pub fn new_xnet_payload_builder_with_xnet_client(
        &self,
        xnet_client: Arc<dyn XNetClient>,
        log: ReplicaLogger,
    ) -> XNetPayloadBuilderImpl {
        XNetPayloadBuilderImpl::with_xnet_client(
            xnet_client,
            Arc::clone(&self.state_manager) as Arc<_>,
            Arc::clone(&self.state_manager) as Arc<_>,
            Arc::clone(&self.registry) as Arc<_>,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &self.metrics,
            log,
        )
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
