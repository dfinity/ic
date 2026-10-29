use super::test_fixtures::*;
use super::*;
use crate::certified_slice_pool::{CRITICAL_ERROR_INCOMPARABLE_PEER_HEADER, CertifiedSliceError};
use crate::exchange::{METRIC_PULL_ATTEMPT_COUNT, METRIC_QUERY_SLICE_DURATION};
use crate::testing::XNetPayloadBuilderTesting;
use assert_matches::assert_matches;
use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
use ic_interfaces::messaging::{InvalidXNetPayload, XNetPayloadValidationFailure};
use ic_interfaces_certified_stream_store_mocks::MockCertifiedStreamStore;
use ic_interfaces_state_manager::StateReader;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    HistogramStats, MetricVec, fetch_histogram_stats, fetch_histogram_vec_count,
    fetch_int_counter_vec, metric_vec,
};
use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5};
use ic_types::state_manager::StateManagerError;
use maplit::btreemap;
use mockall::predicate::eq;
use std::sync::Arc;

#[tokio::test]
async fn build_payload_empty_pool() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state();

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

#[tokio::test]
async fn validate_empty_payload() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
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

#[tokio::test]
async fn validate_valid_payload() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);
        let payload = fixture.oldest_payload();

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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Simulate duplicate messages by validating the newest `XNetPayload` on top of
        // itself.
        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                fixture.newest_payload(),
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
            already_closed_receiver(),
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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Most recent payload.
        let payload = fixture.newest_payload();
        let past_payloads = fixture.past_payloads();

        assert_matches!(
            xnet_payload_builder.validate_xnet_payload(
                payload,
                &fixture.validation_context,
                // Simulate missing messages by skipping the oldest payload.
                &past_payloads[1..2],
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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
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
            already_closed_receiver(),
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
            already_closed_receiver(),
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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
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
                (&[("error", &CRITICAL_ERROR_INCOMPARABLE_PEER_HEADER)], 0),
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
    /// and registry entries for the subnets in its payloads (`SUBNET_1` through
    /// `SUBNET_4`, as `Application`).
    pub fn with_xnet_state() -> Self {
        Self::with_xnet_state_and_subnet_types(btreemap![], None)
    }

    /// Like `with_xnet_state`, but with `subnet_types` overriding the types of
    /// (or adding to) the registered subnets. `own_subnet_type` overrides the own
    /// subnet type in the replicated state.
    pub fn with_xnet_state_and_subnet_types(
        subnet_types: BTreeMap<SubnetId, SubnetType>,
        own_subnet_type: Option<SubnetType>,
    ) -> Self {
        let state_manager = Arc::new(FakeStateManager::new());
        let tls_handshake = Arc::new(MockTlsConfig::new());

        let (payloads, _) =
            get_xnet_state_for_testing_with_own_subnet_type(&state_manager, own_subnet_type);
        let mut all_subnet_types = btreemap![
            SUBNET_1 => SubnetType::Application,
            SUBNET_2 => SubnetType::Application,
            SUBNET_3 => SubnetType::Application,
            SUBNET_4 => SubnetType::Application,
        ];
        all_subnet_types.extend(subnet_types);
        let registry = get_registry_for_test_with_subnet_types(all_subnet_types);

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
            already_closed_receiver(),
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

    /// Returns the newest payload in `self.payloads`.
    pub fn newest_payload(&self) -> &XNetPayload {
        self.payloads.first().unwrap()
    }

    /// Returns the oldest payload in `self.payloads`.
    pub fn oldest_payload(&self) -> &XNetPayload {
        self.payloads.last().unwrap()
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

    /// Fetches the values of the `METRIC_QUERY_SLICE_DURATION` histograms'
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
        let registry = get_registry_for_test(&[SUBNET_1]);
        let state_manager = Arc::new(state_manager);
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::new(MockTlsConfig::new()) as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            already_closed_receiver(),
            &MetricsRegistry::new(),
            log,
        )
        .with_count_bytes_fn(|_| Ok(1));

        let validation_context = get_validation_context_for_test();

        // Payload with SUBNET_2's (matching) certified slice.
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

/// CloudEngine subnets participate in XNet. At the unit level this checks
/// that `expected_stream_indices` returns entries for an engine's Application
/// peers (no filter excluding them), so the engine will attempt to pull from
/// them. The end-to-end behavior — that a CloudEngine subnet actually builds and
/// validates XNet payloads and completes a best-effort cross-subnet call (which
/// requires `get_xnet_payload`/`validate_xnet_payload` to not short-circuit
/// for engines) — is covered by `xnet_cloud_engine_isolation_test`.
#[tokio::test]
async fn cloud_engine_expected_stream_indices_populated() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
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
            btreemap![],
            Some(SubnetType::CloudEngine),
        );
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Use a pre-built payload from the fixture — indices are consistent with
        // the state, so validation passes for any subnet type including CloudEngine.
        let payload = fixture.oldest_payload();
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
            btreemap![cloud_engine_subnet => SubnetType::CloudEngine],
            None,
        );

        // This is an Application subnet validating an incoming payload.
        let xnet_payload_builder = fixture.new_xnet_payload_builder_impl(log);

        // Use a pre-built payload from the fixture. SUBNET_1 is the CloudEngine
        // subnet; a slice from it must be accepted by a non-engine subnet.
        let payload = fixture.oldest_payload();
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
        let fixture = PayloadBuilderTestFixture::with_xnet_state();

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

/// Building and validating payloads both garbage collect the pool, so both
/// trigger a refill.
#[tokio::test]
async fn garbage_collection_triggers_refill() {
    with_test_replica_logger(|log| {
        let fixture = PayloadBuilderTestFixture::with_xnet_state();
        let (pull_task_handle, mut refill_triggers, _) = PullTaskHandle::new();
        let metrics_registry = MetricsRegistry::new();
        let xnet_payload_builder = XNetPayloadBuilderImpl::new_from_components(
            Arc::clone(&fixture.state_manager) as Arc<_>,
            Arc::clone(&fixture.state_manager) as Arc<_>,
            Arc::clone(&fixture.registry) as Arc<_>,
            Arc::new(Mutex::new(CertifiedSlicePool::new(
                &metrics_registry,
                log.clone(),
            ))),
            pull_task_handle,
            Arc::new(XNetPayloadBuilderMetrics::new(&metrics_registry)),
            log,
        )
        // Any slice, empty or not, has byte size 1.
        .with_count_bytes_fn(|_| Ok(1));

        xnet_payload_builder.get_xnet_payload(
            &fixture.validation_context,
            &fixture.past_payloads(),
            PAYLOAD_BYTES_LIMIT,
        );
        assert_eq!(Ok(()), refill_triggers.try_recv());

        let payloads = fixture.past_payloads();
        let (payload, past_payloads) = payloads.split_first().unwrap();
        xnet_payload_builder
            .validate_xnet_payload(payload, &fixture.validation_context, past_payloads)
            .unwrap();
        assert_eq!(Ok(()), refill_triggers.try_recv());
    });
}

/// An Application subnet with a registered CloudEngine peer must track its
/// stream indices.
#[tokio::test]
async fn expected_stream_indices_includes_cloud_engine_subnet() {
    with_test_replica_logger(|log| {
        // Override `SUBNET_1` as `CloudEngine`.
        let fixture = PayloadBuilderTestFixture::with_xnet_state_and_subnet_types(
            btreemap![SUBNET_1 => SubnetType::CloudEngine],
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
