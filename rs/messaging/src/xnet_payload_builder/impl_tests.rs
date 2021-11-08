//! Tests for `XNetPayloadBuilder` private methods.

use super::test_fixtures::*;
use super::*;
use assert_matches::assert_matches;
use ic_interfaces::{certified_stream_store::DecodeStreamError, state_manager::StateReader};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::testing::ReplicatedStateTesting;
use ic_test_utilities::{
    certified_stream_store::MockCertifiedStreamStore,
    crypto::fake_tls_handshake::FakeTlsHandshake,
    state_manager::FakeStateManager,
    types::ids::{subnet_test_id, SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5},
    with_test_replica_logger,
};
use maplit::btreemap;

#[tokio::test]
async fn expected_indices_for_stream() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let (payloads, mut expected_indices) = get_xnet_state_for_testing(&state_manager);
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager.clone(), log);

        let validation_context = get_validation_context_for_test();
        let past_payloads: Vec<&XNetPayload> = payloads.iter().collect();

        let state = state_manager
            .get_state_at(validation_context.certified_height)
            .unwrap()
            .take();

        for subnet in &[SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5] {
            let expected = expected_indices.remove(subnet).unwrap_or_default();
            assert_eq!(
                expected,
                xnet_payload_builder.expected_indices_for_stream(*subnet, &state, &past_payloads)
            );
        }
    });
}

#[tokio::test]
async fn expected_stream_indices() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let (payloads, expected_indices) = get_xnet_state_for_testing(&state_manager);

        // A registry that has entries for `SUBNET_1` through `SUBNET_5`.
        let (registry, _urls) = get_registry_and_urls_for_test(5, expected_indices.clone());
        let tls_handshake = Arc::new(FakeTlsHandshake::new());
        let state_manager = Arc::new(state_manager);
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            tls_handshake as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        );

        let validation_context = get_validation_context_for_test();
        let past_payloads: Vec<&XNetPayload> = payloads.iter().collect();

        let state = state_manager
            .get_state_at(validation_context.certified_height)
            .unwrap()
            .take();

        let computed_indices = xnet_payload_builder
            .expected_stream_indices(
                &validation_context,
                state.as_ref(),
                past_payloads.as_slice(),
            )
            .unwrap();
        assert_eq!(expected_indices, computed_indices);
    });
}

#[tokio::test]
async fn validate_signals() {
    use SignalsValidationResult::*;

    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager, log);

        // Shortcut for `xnet_payload_builder.validate_signals(SUBNET_1, _, _, _)`.
        let validate = |signals_end, expected, state| {
            xnet_payload_builder.validate_signals(
                SUBNET_1,
                StreamIndex::new(signals_end),
                StreamIndex::new(expected),
                state,
            )
        };

        // Empty state (no stream for `SUBNET_1`).
        let empty_state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );

        // With no stream present, only default signals are valid.
        assert_eq!(Valid, validate(0, 0, &empty_state));
        // Signal for non-existent message.
        assert_eq!(Invalid, validate(1, 0, &empty_state));

        // State with `messages.end() == 7` for `SUBNET_1`.
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        state.with_streams(btreemap! {
            SUBNET_1 => generate_stream(&StreamConfig {
                message_begin: 4,
                message_end: 7,
                signal_end: 107,
            }),
        });

        // No longer valid: `signals_end < expected`.
        assert_eq!(Invalid, validate(4, 5, &state));

        // All combinations with `expected <= signals_end <= stream.messages.end()` are
        // valid.
        assert_eq!(Valid, validate(5, 5, &state));
        assert_eq!(Valid, validate(6, 5, &state));
        assert_eq!(Valid, validate(7, 5, &state));

        // Signal for nonexistent message (8).
        assert_eq!(Invalid, validate(8, 5, &state));
    });
}

#[tokio::test]
#[should_panic(expected = "Subnet yndj2-3ybaa-aaaaa-aaaap-yai: invalid expected signal")]
async fn validate_signals_expected_before_messages_begin() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager, log);

        // State with `messages.end() == 7` for `SUBNET_1`.
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        state.with_streams(btreemap! {
            SUBNET_1 => generate_stream(&StreamConfig {
                message_begin: 4,
                message_end: 7,
                signal_end: 107,
            }),
        });
        // Valid `signals_end`.
        let signals_end = StreamIndex::new(4);

        let expected = StreamIndex::new(2);
        xnet_payload_builder.validate_signals(SUBNET_1, signals_end, expected, &state);
    });
}

#[tokio::test]
#[should_panic(expected = "Subnet yndj2-3ybaa-aaaaa-aaaap-yai: invalid expected signal")]
async fn validate_signals_expected_after_messages_begin() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager, log);

        // Empty state (no stream for `SUBNET_1`).
        let state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        // Valid `signals_end`.
        let signals_end = StreamIndex::new(0);

        let expected = StreamIndex::new(2);
        xnet_payload_builder.validate_signals(SUBNET_1, signals_end, expected, &state);
    });
}

#[tokio::test]
async fn validate_slice() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager, log);
        let validation_context = get_validation_context_for_test();

        // Message and slice begin and end indices for stream to `SUBNET_1`.
        const MESSAGE_BEGIN: StreamIndex = StreamIndex::new(4);
        const MESSAGE_END: StreamIndex = StreamIndex::new(7);
        const SIGNAL_END: StreamIndex = StreamIndex::new(107);

        // Expected indices for messages and signals from `SUBNET_1`.
        const EXPECTED: ExpectedIndices = ExpectedIndices {
            message_index: SIGNAL_END,   // Assume no intervening payloads.
            signal_index: MESSAGE_BEGIN, // Assume we no signals for existing messages.
        };

        // State with stream for `SUBNET_1`.
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        state.with_streams(btreemap! {
            SUBNET_1 => generate_stream(&StreamConfig {
                message_begin: MESSAGE_BEGIN.get(),
                message_end: MESSAGE_END.get(),
                signal_end: SIGNAL_END.get(),
            }),
        });

        // Helper for generating a slice from `SUBNET_1` with valid signals; and with
        // messages between the given indices indices; and validating it.
        let validate_slice_with_messages = |message_begin, message_end| {
            let certified_slice = make_certified_stream_slice(
                SUBNET_1,
                StreamConfig {
                    message_begin,
                    message_end,
                    signal_end: EXPECTED.signal_index.get(),
                },
            );
            xnet_payload_builder.validate_slice(
                SUBNET_1,
                &certified_slice,
                &EXPECTED,
                &validation_context,
                &state,
            )
        };

        let expected_message = EXPECTED.message_index.get();
        assert_matches!(
            validate_slice_with_messages(expected_message - 1, expected_message,),
            SliceValidationResult::Invalid(_)
        );
        assert_eq!(
            SliceValidationResult::Empty,
            validate_slice_with_messages(expected_message, expected_message)
        );
        assert_eq!(
            SliceValidationResult::Valid {
                messages_end: EXPECTED.message_index.increment(),
                signals_end: EXPECTED.signal_index,
                byte_size: 1
            },
            validate_slice_with_messages(expected_message, expected_message + 1)
        );
        // Empty slice, but invalid because the stream bounds do not include the
        // expected message index.
        assert_matches!(
            validate_slice_with_messages(expected_message + 1, expected_message + 1),
            SliceValidationResult::Invalid(_)
        );
        assert_matches!(
            validate_slice_with_messages(expected_message + 1, expected_message + 2),
            SliceValidationResult::Invalid(_)
        );

        // Validate a slice with invalid signals (signals end before expected index).
        // Detailed signal validation is done by the `validate_signals` tests.
        let certified_slice = make_certified_stream_slice(
            SUBNET_1,
            StreamConfig {
                message_begin: EXPECTED.message_index.get(),
                message_end: EXPECTED.message_index.get() + 1,
                signal_end: EXPECTED.signal_index.get() - 1,
            },
        );
        assert_matches!(
            xnet_payload_builder.validate_slice(
                SUBNET_1,
                &certified_slice,
                &EXPECTED,
                &validation_context,
                &state,
            ),
            SliceValidationResult::Invalid(_)
        );
    });
}

#[tokio::test]
async fn validate_slice_invalid_signature() {
    with_test_replica_logger(|log| {
        // A `CertifiedStreamStore` that returns `Err(DecodeStreamError)`.
        let mut certified_stream_store = MockCertifiedStreamStore::new();
        certified_stream_store
            .expect_decode_certified_stream_slice()
            .returning(|_, _, _| Err(DecodeStreamError::InvalidSignature(SUBNET_1)));

        let certified_stream_store = Arc::new(certified_stream_store);

        let state_manager = FakeStateManager::new();
        let state_manager = Arc::new(state_manager);
        let tls_handshake = Arc::new(FakeTlsHandshake::new());
        let registry = get_empty_registry_for_test();
        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            state_manager,
            certified_stream_store,
            tls_handshake as Arc<_>,
            registry,
            tokio::runtime::Handle::current(),
            LOCAL_NODE,
            LOCAL_SUBNET,
            &MetricsRegistry::new(),
            log,
        );

        // A valid combination of state, certified slice and expected indices.
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        state.with_streams(btreemap! {
            SUBNET_1 => generate_stream(&StreamConfig {
                message_begin: 3,
                message_end: 4,
                signal_end: 1,
            }),
        });
        let certified_slice = make_certified_stream_slice(
            SUBNET_1,
            StreamConfig {
                message_begin: 1,
                message_end: 2,
                signal_end: 4,
            },
        );
        let expected = ExpectedIndices {
            message_index: StreamIndex::new(2),
            signal_index: StreamIndex::new(3),
        };

        let validation_context = get_validation_context_for_test();

        assert_matches!(
            xnet_payload_builder.validate_slice(
                SUBNET_1,
                &certified_slice,
                &expected,
                &validation_context,
                &state,
            ),
            SliceValidationResult::Invalid(_)
        );
    });
}

#[tokio::test]
async fn validate_slice_above_msg_limit() {
    with_test_replica_logger(|log| {
        let state_manager = FakeStateManager::new();
        let xnet_payload_builder = get_xnet_payload_builder_for_test(state_manager, log);
        let validation_context = get_validation_context_for_test();

        // Message and slice begin and end indices for outgoing stream to `SUBNET_1`.
        // Output stream has exactly `SYSTEM_SUBNET_STREAM_MSG_LIMIT` messages, which
        // should prevent any new messages from being included into blocks.
        const MESSAGE_BEGIN: u64 = 13;
        const MESSAGE_END: u64 = MESSAGE_BEGIN + SYSTEM_SUBNET_STREAM_MSG_LIMIT as u64;
        const SIGNAL_END: u64 = 107;

        // Expected indices for messages and signals from `SUBNET_1`.
        const EXPECTED: ExpectedIndices = ExpectedIndices {
            message_index: StreamIndex::new(SIGNAL_END), // Assume no intervening payloads.
            signal_index: StreamIndex::new(MESSAGE_BEGIN), // Assume no signals for existing msgs.
        };

        // State of a `System` subnet with a stream for `SUBNET_1`.
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::System,
            "NOT_USED".into(),
        );
        state.with_streams(btreemap! {
            SUBNET_1 => generate_stream(&StreamConfig {
                message_begin: MESSAGE_BEGIN,
                message_end: MESSAGE_END,
                signal_end: SIGNAL_END,
            }),
        });

        // Helper for validating a generated slice from `SUBNET_1` with messages between
        // the given indices indices and the given `signals_end` index.
        let validate_slice = |message_begin, message_end, signal_end, state| {
            let certified_slice = make_certified_stream_slice(
                SUBNET_1,
                StreamConfig {
                    message_begin,
                    message_end,
                    signal_end,
                },
            );
            xnet_payload_builder.validate_slice(
                SUBNET_1,
                &certified_slice,
                &EXPECTED,
                &validation_context,
                state,
            )
        };

        let expected_message = EXPECTED.message_index.get();
        let signal_index = EXPECTED.signal_index.get();

        // Sanity check: empty slice is rejected.
        assert_matches!(
            validate_slice(expected_message, expected_message, signal_index, &state),
            SliceValidationResult::Empty
        );
        // Sanity check: empty slice with higher signals_end is valid.
        assert_eq!(
            SliceValidationResult::Valid {
                messages_end: expected_message.into(),
                signals_end: (signal_index + 1).into(),
                byte_size: 1
            },
            validate_slice(expected_message, expected_message, signal_index + 1, &state),
        );

        // Non-empty slice has too many messages for a `System` subnet...
        assert_matches!(
            validate_slice(expected_message, expected_message + 1, signal_index, &state),
            SliceValidationResult::Invalid(_)
        );

        // ...but would be valid on an `Application` subnet.
        #[allow(clippy::redundant_clone)]
        let mut state = state.clone();
        state.metadata.own_subnet_type = SubnetType::Application;
        assert_eq!(
            SliceValidationResult::Valid {
                messages_end: (expected_message + 1).into(),
                signals_end: signal_index.into(),
                byte_size: 1
            },
            validate_slice(expected_message, expected_message + 1, signal_index, &state),
        );
    });
}

/// Constructs an `XNetPayloadBuilder` around `state_manager`, `log` and an
/// empty registry.
fn get_xnet_payload_builder_for_test(
    state_manager: FakeStateManager,
    log: ReplicaLogger,
) -> XNetPayloadBuilderImpl {
    let registry = get_empty_registry_for_test();
    let state_manager = Arc::new(state_manager);
    let tls_handshake = Arc::new(FakeTlsHandshake::new());
    XNetPayloadBuilderImpl::new(
        Arc::clone(&state_manager) as Arc<_>,
        state_manager,
        tls_handshake,
        registry,
        tokio::runtime::Handle::current(),
        LOCAL_NODE,
        LOCAL_SUBNET,
        &MetricsRegistry::new(),
        log,
    )
    // Any slice, empty or not, has byte size 1.
    .with_count_bytes_fn(|_| Ok(1))
}
