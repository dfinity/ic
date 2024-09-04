use super::*;
use crate::message_routing::{LABEL_REMOTE, METRIC_TIME_IN_BACKLOG, METRIC_TIME_IN_STREAM};
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_interfaces::messaging::LABEL_VALUE_CANISTER_NOT_FOUND;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    metadata_state::StreamMap, replicated_state::LABEL_VALUE_OUT_OF_MEMORY,
    testing::ReplicatedStateTesting, CanisterStatus, ReplicatedState, Stream,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    fetch_histogram_stats, fetch_histogram_vec_count, fetch_int_counter, fetch_int_counter_vec,
    fetch_int_gauge_vec, metric_vec, nonzero_values, HistogramStats, MetricVec,
};
use ic_test_utilities_state::{new_canister_state, register_callback};
use ic_test_utilities_types::ids::{user_test_id, SUBNET_12, SUBNET_23, SUBNET_27};
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_test_utilities_types::xnet::StreamHeaderBuilder;
use ic_types::{
    messages::{CallbackId, Payload, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE},
    time::UNIX_EPOCH,
    xnet::{RejectReason, RejectSignal, StreamFlags, StreamIndexedQueue},
    CanisterId, CountBytes, Cycles,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use pretty_assertions::assert_eq;
use std::convert::TryFrom;
use MessageBuilder::*;

const LOCAL_SUBNET: SubnetId = SUBNET_12; // g24bn-xymaa-aaaaa-aaaap-yai
const REMOTE_SUBNET: SubnetId = SUBNET_23; // 5h3gz-qaxaa-aaaaa-aaaap-yai
const CANISTER_MIGRATION_SUBNET: SubnetId = SUBNET_27; // 6pfiy-tq3aa-aaaaa-aaaap-yai
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref LOCAL_CANISTER: CanisterId = CanisterId::from(0x34); // v32cj-3iaaa-aaaaa-aaa2a-cai
    static ref OTHER_LOCAL_CANISTER: CanisterId = CanisterId::from(0x56); // 4wttx-iyaaa-aaaaa-aabla-cai
    static ref REMOTE_CANISTER: CanisterId = CanisterId::from(0x134); // czeeh-caaaa-aaaaa-aae2a-cai
    static ref OTHER_REMOTE_CANISTER: CanisterId = CanisterId::from(0x156); // lunvz-rqaaa-aaaaa-aafla-cai
    static ref UNKNOWN_CANISTER: CanisterId = CanisterId::from(0x234); // at66y-zqaaa-aaaaa-aai2a-cai
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

/// Tests that a message for a reject response does not exceed an upper bounds.
#[test]
fn oversized_reject_message_is_truncated() {
    fn assert_correct_truncation(msg_len: usize, len_after_truncation: usize) {
        let reject_response = generate_reject_response(
            &RequestBuilder::new().build(),
            RejectCode::SysTransient,
            (0..msg_len).map(|_| "a").collect(),
        );
        assert_matches!(
            reject_response,
            RequestOrResponse::Response(response) if matches!(
                &response.response_payload,
                Payload::Reject(context) if context.message().len() == len_after_truncation
            )
        );
    }

    assert_correct_truncation(
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN - 1,
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN - 1,
    );
    assert_correct_truncation(
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
    );
    assert_correct_truncation(
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN + 1,
        MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
    );
}

/// Tests that inducting a loopback stream with signals panics.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet g24bn-xymaa-aaaaa-aaaap-yai: messages begin (21) != stream signals_end (22)"
)]
fn induct_loopback_stream_with_signals_panics() {
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 22,
            ..StreamConfig::default()
        }],
        |stream_handler, state, _| {
            stream_handler.induct_loopback_stream(state, &mut (i64::MAX / 2));
        },
    );
}

/// Tests that inducting a loopback stream where `signals_end` < `begin` panics: messages are always
/// garbage collected up to `signals_end` and `signals_end` is monotonically increasing.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet g24bn-xymaa-aaaaa-aaaap-yai: messages begin (21) != stream signals_end (20)"
)]
fn induct_loopback_stream_signals_end_before_messages_begin_panics() {
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 20,
            ..StreamConfig::default()
        }],
        |stream_handler, state, _| {
            stream_handler.induct_loopback_stream(state, &mut (i64::MAX / 2));
        },
    );
}

/// Tests that inducting an empty loopback stream leaves the state untouched.
#[test]
fn induct_loopback_stream_empty_loopback_stream() {
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            signals_end: 21,
            ..StreamConfig::default()
        }],
        |stream_handler, state, metrics| {
            let expected_state = state.clone();

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                available_guaranteed_response_memory,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            metrics.assert_inducted_xnet_messages_eq(&[]);
            assert_eq!(0, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that inducting a loopback stream containing a request to a non-existant canister results
/// in a reject response addressed to `LOCAL_CANISTER` inducted into the state.
///
/// Note that `induct_loopback_stream()` first inducts the loopback stream as a stream slice, which
/// produces a reject signal for this request. In a second step the loopback stream is gc'ed,
/// which collects the signal and triggers generating and then inducting a corrsponding reject response.
#[test]
fn induct_loopback_stream_reject_response() {
    // A loopback stream with 1 message addressed to an unknown canister.
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER)],
            signals_end: 21,
            ..StreamConfig::default()
        }],
        |stream_handler, state, metrics| {
            let mut expected_state = state.clone();
            // Expecting a state with reject response inducted for the request @21.
            push_input(
                &mut expected_state,
                generate_reject_response_for(
                    RejectReason::CanisterNotFound,
                    request_in_stream(state.get_stream(&LOCAL_SUBNET), 21),
                ),
            );

            // Expecting an empty loopback stream with begin advanced.
            let loopback_stream = stream_from_config(StreamConfig {
                begin: 22,
                signals_end: 22,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);

            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_NOT_FOUND, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            assert_eq!(1, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that messages in the loopback stream on a subnet where `OTHER_LOCAL_CANISTER` has been
/// migrated to `CANISTER_MIGRATION_SUBNET`
/// - are inducted successfully when addressed to the non-migrating canister `LOCAL_CANISTER`.
/// - requests trigger a reject response when addressed the migrating canister
///   `OTHER_LOCAL_CANISTER` that is inducted into the state.
/// - responses are rerouted into the stream to `CANISTER_MIGRATION_SUBNET` when addressed to the
///   migrating canister `OTHER_LOCAL_CANISTER`.
#[test]
fn induct_loopback_stream_reroute_response() {
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Response(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER),
                Response(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER),
            ],
            signals_end: 21,
            ..StreamConfig::default()
        }],
        |stream_handler, state, metrics| {
            // `OTHER_LOCAL_CANISTER` was hosted by the `LOCAL_SUBNET` but then migrated.
            let state = simulate_canister_migration(
                state,
                *OTHER_LOCAL_CANISTER,
                LOCAL_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // The request @21 and the response @22 are expected to be inducted successfully;
            // the request @23 is expected to trigger a reject response which is inducted
            // successfully.
            let inducted_response = message_in_stream(state.get_stream(&LOCAL_SUBNET), 22);
            let inducted_response_count_bytes = inducted_response.count_bytes();
            push_inputs(
                &mut expected_state,
                [
                    message_in_stream(state.get_stream(&LOCAL_SUBNET), 21),
                    inducted_response,
                    &generate_reject_response_for(
                        RejectReason::CanisterMigrating,
                        request_in_stream(state.get_stream(&LOCAL_SUBNET), 23),
                    ),
                ],
            );

            // The loopback stream is expected to be empty, with signals advanced.
            let loopback_stream = stream_from_config(StreamConfig {
                begin: 25,
                signals_end: 25,
                ..StreamConfig::default()
            });

            // A new outgoing stream is generated with the response @24 rerouted into it.
            let migration_stream = stream_from_config(StreamConfig {
                messages: vec![message_in_stream(state.get_stream(&LOCAL_SUBNET), 24).clone()],
                ..StreamConfig::default()
            });

            expected_state.with_streams(btreemap![
                LOCAL_SUBNET => loopback_stream,
                CANISTER_MIGRATION_SUBNET => migration_stream,
            ]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);

            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            // `available_guaranteed_response_memory` does not keep track of gc'ing
            // the response @22 in the loopback stream after inducting it.
            assert_eq!(
                available_guaranteed_response_memory + inducted_response_count_bytes as i64,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_MIGRATED, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 2),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_CANISTER_MIGRATED, 1),
            ]);
            assert_eq!(3, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that inducting a loopback stream containing a valid request and a valid response to and from
/// `LOCAL_CANISTER` results in both messages inducted successfully.
#[test]
fn induct_loopback_stream_success() {
    with_local_test_setup(
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Response(*LOCAL_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 21,
            ..StreamConfig::default()
        }],
        |stream_handler, state, metrics| {
            let mut expected_state = state.clone();

            let loopback_stream = state.get_stream(&LOCAL_SUBNET);
            // Both messages are expected to be inducted successfully.
            push_inputs(
                &mut expected_state,
                messages_in_stream(loopback_stream, 21..=22),
            );
            let response_count_bytes = response_in_stream(loopback_stream, 22).count_bytes();

            // The loopback stream should be empty with `begin` and `signals_end` advanced.
            let loopback_stream = stream_from_config(StreamConfig {
                begin: 23,
                signals_end: 23,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            // `available_guaranteed_response_memory` is a lower bound as it doesn't include garbage
            // collecting responses from streams, therefore it is off by `response_count_bytes`.
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory + response_count_bytes as i64,
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            assert_eq!(2, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_loopback_stream()`.
#[test]
fn induct_loopback_stream_with_subnet_message_memory_limit() {
    // A stream handler with a subnet message memory limit that only allows up to 3 reservations.
    induct_loopback_stream_with_memory_limit_impl(HypervisorConfig {
        subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        ..Default::default()
    });
}

/// Tests that wasm custom sections memory capacity does not affect
/// `StreamHandlerImpl::induct_loopback_stream()`.
#[test]
fn induct_loopback_stream_with_zero_subnet_wasm_custom_sections_limit() {
    // A stream handler with a subnet message memory limit that only allows up to 3 reservations
    // and no allowance for wasm custom sections.
    induct_loopback_stream_with_memory_limit_impl(HypervisorConfig {
        subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        subnet_wasm_custom_sections_memory_capacity: NumBytes::new(0),
        ..Default::default()
    });
}

/// Tests that canister memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_canister_memory_limit() {
    // A stream handler with a canister memory limit that only allows up to 3 reservations.
    induct_loopback_stream_ignores_memory_limit_impl(HypervisorConfig {
        max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        ..Default::default()
    });
}

/// Tests that subnet memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_subnet_memory_limit() {
    // A stream handler with a subnet memory limit that only allows up to 3 reservations.
    induct_loopback_stream_ignores_memory_limit_impl(HypervisorConfig {
        subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        ..Default::default()
    });
}

/// Tests that subnet message memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_subnet_message_memory_limit() {
    // A stream handler with a subnet message memory limit that only allows up to 3 reservations.
    induct_loopback_stream_ignores_memory_limit_impl(HypervisorConfig {
        subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        ..Default::default()
    });
}

/// Tests that subnet wasm custom sections memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_subnet_wasm_custom_sections_memory_limit() {
    // A stream handler with a subnet message memory limit that only allows up to 3 reservations.
    induct_loopback_stream_ignores_memory_limit_impl(HypervisorConfig {
        subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
        subnet_wasm_custom_sections_memory_capacity: NumBytes::new(0),
        ..Default::default()
    });
}

/// Common initial state setup for `StreamHandlerImpl::induct_loopback_stream()`
/// memory limit tests.
fn with_induct_loopback_stream_setup(
    config: HypervisorConfig,
    subnet_type: SubnetType,
    test_impl: impl FnOnce(StreamHandlerImpl, ReplicatedState, MetricsFixture),
) {
    with_local_test_setup_and_config(
        config,
        subnet_type,
        btreemap![LOCAL_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 21,
            ..StreamConfig::default()
        }],
        test_impl,
    );
}

/// Common implementation for `StreamHandlerImpl::induct_loopback_stream()`
/// memory limit tests. Expects a `StreamHandlerImpl` with canister; subnet; or
/// subnet message; memory limits only large enough for 3 in-flight requests
/// plus epsilon at a time. Ensures that the limits are enforced when inducting
/// the loopback stream.
///
/// Sets up a canister with two input queue reservations for two in-flight
/// loopback requests and a loopback stream containing said requests. Tries to
/// induct the loopback stream and expects the first request to be inducted; and
/// the second request to fail to be inducted due to lack of memory.
fn induct_loopback_stream_with_memory_limit_impl(config: HypervisorConfig) {
    with_induct_loopback_stream_setup(
        config,
        SubnetType::Application,
        |stream_handler, state, metrics| {
            let mut expected_state = state.clone();
            // Expecting a canister state with... the first message and a reject response for the
            // request @22 inducted...
            push_inputs(
                &mut expected_state,
                [
                    message_in_stream(state.get_stream(&LOCAL_SUBNET), 21),
                    &generate_reject_response_for(
                        RejectReason::OutOfMemory,
                        request_in_stream(state.get_stream(&LOCAL_SUBNET), 22),
                    ),
                ],
            );

            // ...and an empty loopback stream with indices advanced.
            let loopback_stream = stream_from_config(StreamConfig {
                begin: 23,
                signals_end: 23,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );
            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_OUT_OF_MEMORY, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            assert_eq!(2, metrics.fetch_inducted_payload_sizes_stats().count);
        },
    );
}

/// Common implementation for `StreamHandlerImpl::induct_loopback_stream()`
/// memory limit tests. Expects a `StreamHandlerImpl` with canister; subnet; or
/// subnet message; memory limits only large enough for 3 in-flight requests
/// plus epsilon at a time. Ensures that the limit is ignored when inducting
/// the loopback stream.
///
/// Sets up a canister with two input queue reservations for two in-flight
/// loopback requests and a loopback stream containing said requests. Tries to
/// induct the loopback stream and expects both requests to be inducted
/// successfully.
fn induct_loopback_stream_ignores_memory_limit_impl(config: HypervisorConfig) {
    with_induct_loopback_stream_setup(
        config,
        SubnetType::System,
        |stream_handler, state, metrics| {
            let mut expected_state = state.clone();
            // Expecting a canister state with the 2 requests inducted...
            push_inputs(
                &mut expected_state,
                messages_in_stream(state.get_stream(&LOCAL_SUBNET), 21..=22),
            );
            // ...and an empty loopback stream with begin indices advanced.
            let loopback_stream = stream_from_config(StreamConfig {
                begin: 23,
                signals_end: 23,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler
                .induct_loopback_stream(state, &mut available_guaranteed_response_memory);

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );
            metrics.assert_inducted_xnet_messages_eq(&[(
                LABEL_VALUE_TYPE_REQUEST,
                LABEL_VALUE_SUCCESS,
                2,
            )]);
            assert_eq!(2, metrics.fetch_inducted_payload_sizes_stats().count);
        },
    );
}

/// Tests that messages are gc'ed according to the `signals_end` provided. Since there are no
/// reject signals for existing messages, no gc'ed messages should be returned.
#[test]
fn garbage_collect_messages_success() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with 3 messages.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // A `signals_end` that triggers gc'ing the first two messages;
        // reject signals for already GC-ed messages should not affect gc'ing.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 33,
            reject_signals: vec![
                RejectSignal::new(CanisterMigrating, 29.into()),
                RejectSignal::new(CanisterMigrating, 30.into()),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, metrics| {
            let mut streams = state.take_streams();

            // The expected stream has the first 2 messages garbage collected.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 33,
                messages: vec![message_in_stream(streams.get(&REMOTE_SUBNET), 33).clone()],
                signals_end: 43,
                ..StreamConfig::default()
            });

            let slice = slices.get(&REMOTE_SUBNET).unwrap();
            let rejected_messages = stream_handler.garbage_collect_messages(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slice.header().signals_end(),
                slice.header().reject_signals(),
            );

            assert!(rejected_messages.is_empty());
            assert_eq!(Some(&expected_stream), streams.get(&REMOTE_SUBNET));
            assert_eq!(
                Some(2),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
        },
    );
}

/// Tests that messages are gc'ed according to the `signals_end` provided. Messages for which
/// a reject signal is given must be returned.
#[test]
fn garbage_collect_messages_with_reject_signals_success() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with 3 messages.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming `StreamSlice` with a `signals_end` that should trigger gc'ing the first two
        // messages; reject signals for the messages @31 and @32.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 33,
            reject_signals: vec![
                RejectSignal::new(CanisterNotFound, 31.into()),
                RejectSignal::new(CanisterMigrating, 32.into()),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, metrics| {
            let mut streams = state.take_streams();

            // The expected stream has the first 2 messages garbage collected.
            let outgoing_stream = streams.get(&REMOTE_SUBNET);
            let expected_stream = stream_from_config(StreamConfig {
                begin: 33,
                messages: vec![message_in_stream(outgoing_stream, 33).clone()],
                signals_end: 43,
                ..StreamConfig::default()
            });

            // The expected rejected messages are @31 and @32.
            let expected_rejected_messages = vec![
                (
                    CanisterNotFound,
                    message_in_stream(outgoing_stream, 31).clone(),
                ),
                (
                    CanisterMigrating,
                    message_in_stream(outgoing_stream, 32).clone(),
                ),
            ];

            let slice = slices.get(&REMOTE_SUBNET).unwrap();
            let rejected_messages = stream_handler.garbage_collect_messages(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slice.header().signals_end(),
                slice.header().reject_signals(),
            );

            assert_eq!(expected_rejected_messages, rejected_messages);
            assert_eq!(Some(&expected_stream), streams.get(&REMOTE_SUBNET));
            assert_eq!(
                Some(2),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
        },
    );
}

/// Tests `garbage_collect_signals`; signals are garbage collected based off of
/// `begin` in the `StreamHeader` in `StreamSlice`.
#[test]
fn garbage_collect_signals_success() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with reject signals.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 23,
            messages: vec![Request(*LOCAL_CANISTER, *REMOTE_CANISTER)],
            signals_end: 153,
            reject_signals: vec![
                RejectSignal::new(CanisterMigrating, 138.into()),
                RejectSignal::new(CanisterNotFound, 139.into()),
                RejectSignal::new(OutOfMemory, 142.into()),
                RejectSignal::new(QueueFull, 145.into()),
            ],
            ..StreamConfig::default()
        }],
        // A `StreamSlice` with a `header_begin` that should gc the first two reject signals.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            header_begin: Some(142),
            messages_begin: 153,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, metrics| {
            let mut streams = state.take_streams();

            // The expected stream is identical except the first two signals are gc'ed.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 23,
                messages: vec![message_in_stream(streams.get(&REMOTE_SUBNET), 23).clone()],
                signals_end: 153,
                reject_signals: vec![
                    RejectSignal::new(OutOfMemory, 142.into()),
                    RejectSignal::new(QueueFull, 145.into()),
                ],
                ..StreamConfig::default()
            });

            stream_handler.garbage_collect_signals(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slices.get(&REMOTE_SUBNET).unwrap(),
            );

            assert_eq!(Some(&expected_stream), streams.get(&REMOTE_SUBNET));
            // 2 reject signals from `initial_stream` (138, 139) were GC-ed.
            assert_eq!(
                Some(2),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS),
            );
        },
    );
}

/// Tests that garbage collecting reject signals that are out of order panics.
#[test]
#[should_panic(
    expected = "Invalid signal indices in stream to subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, signals [RejectSignal { reason: CanisterMigrating, index: 138 }, RejectSignal { reason: CanisterNotFound, index: 139 }, RejectSignal { reason: CanisterStopped, index: 145 }, RejectSignal { reason: CanisterStopping, index: 142 }]"
)]
fn garbage_collect_signals_in_wrong_order() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with reject signals out of order.
        btreemap![REMOTE_SUBNET => StreamConfig {
            signals_end: 153,
            reject_signals: vec![
                RejectSignal::new(CanisterMigrating, 138.into()),
                RejectSignal::new(CanisterNotFound, 139.into()),
                RejectSignal::new(CanisterStopped, 145.into()),
                RejectSignal::new(CanisterStopping, 142.into()),
            ],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with `header_begin` such that some reject signals
        // are garbage collected.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            header_begin: Some(142),
            messages_begin: 153,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, _| {
            let mut streams = state.take_streams();

            stream_handler.garbage_collect_signals(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slices.get(&REMOTE_SUBNET).unwrap(),
            );
        },
    );
}

/// Tests that garbage collecting signals with a `StreamSlice` whose `message_begin` does not correspond
/// to the `signals_end` of the Stream panics.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, messages [142, 145)"
)]
fn garbage_collect_signals_with_invalid_slice_messages() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with reject signals.
        btreemap![REMOTE_SUBNET => StreamConfig {
            signals_end: 153,
            reject_signals: vec![
                RejectSignal::new(QueueFull, 138.into()),
                RejectSignal::new(Unknown, 139.into()),
                RejectSignal::new(CanisterMigrating, 142.into()),
                RejectSignal::new(CanisterStopped, 145.into()),
            ],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with `messages_begin` != `signals_end` in the stream.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            header_begin: Some(142),
            messages_begin: 143,
            messages: vec![
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, _| {
            let mut streams = state.take_streams();

            stream_handler.garbage_collect_signals(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slices.get(&REMOTE_SUBNET).unwrap(),
            );
        },
    );
}

/// Tests that garbage collecting signals with an empty `StreamSlice` whose `message_begin` does not correspond
/// to the `signals_end` of the Stream panics.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, messages [142, 143)"
)]
fn garbage_collect_signals_with_invalid_empty_slice() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with reject signals.
        btreemap![REMOTE_SUBNET => StreamConfig {
            signals_end: 153,
            reject_signals: vec![
                RejectSignal::new(CanisterNotFound, 138.into()),
                RejectSignal::new(CanisterMigrating, 139.into()),
                RejectSignal::new(QueueFull, 142.into()),
                RejectSignal::new(OutOfMemory, 145.into()),
            ],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a `messages_begin` < `signals_end` in the stream.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            header_begin: Some(142),
            messages_begin: 143,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, _| {
            let mut streams = state.take_streams();

            stream_handler.garbage_collect_signals(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slices.get(&REMOTE_SUBNET).unwrap(),
            );
        },
    );
}

/// Tests that garbage collecting messages with a `signals_end` in an incoming slice before the `begin`
/// of the Stream panics.
#[test]
#[should_panic(
    expected = "Invalid signal indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_before_first_message() {
    use RejectReason::*;
    with_test_setup(
        // An outgoing stream with 3 messages.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a `signals_end` < `begin` in the stream.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 24,
            reject_signals: vec![
                RejectSignal::new(CanisterStopped, 19.into()),
                RejectSignal::new(CanisterMigrating, 20.into()),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, _| {
            let mut streams = state.take_streams();

            let slice = slices.get(&REMOTE_SUBNET).unwrap();
            stream_handler.garbage_collect_messages(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slice.header().signals_end(),
                slice.header().reject_signals(),
            );
        },
    );
}

/// Tests that garbage collecting messages with a `signals_end` in an incoming slice after the index
/// of the last message in the Stream panics.
#[test]
#[should_panic(
    expected = "Invalid signal indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_after_last_message() {
    with_test_setup(
        // An outgoing stream with 3 messages.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a `signals_end` < `begin` in the stream.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 35,
            reject_signals: vec![
                RejectSignal::new(RejectReason::CanisterNotFound, 30.into()),
                RejectSignal::new(RejectReason::QueueFull, 31.into()),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, mut state, slices, _| {
            let mut streams = state.take_streams();

            let slice = slices.get(&REMOTE_SUBNET).unwrap();
            stream_handler.garbage_collect_messages(
                &mut streams.get_mut(&REMOTE_SUBNET).unwrap(),
                REMOTE_SUBNET,
                slice.header().signals_end(),
                slice.header().reject_signals(),
            );
        },
    );
}

/// Tests that we panic if we attempt to garbage collect messages in an
/// inexistent stream (from a subnet that we haven't talked to before).
///
/// Garbage collection is triggered for a slice with `signals_end` > 0.
#[test]
#[should_panic(
    expected = "Cannot garbage collect a stream for subnet 5h3gz-qaxaa-aaaaa-aaaap-yai that does not exist"
)]
fn garbage_collect_local_state_signals_for_inexistent_stream() {
    with_test_setup(
        btreemap![],
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 1,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, _| {
            stream_handler.garbage_collect_local_state(state, &mut (i64::MAX / 2), &slices);
        },
    );
}

/// Tests that nothing happens if we attempt to garbage collect an inexistent
/// stream (from a subnet that we haven't talked to before).
///
/// Garbage collection is not triggered for a slice with `signals_end` == 0.
#[test]
fn garbage_collect_local_state_inexistent_stream() {
    with_test_setup(
        btreemap![],
        btreemap![REMOTE_SUBNET => StreamSliceConfig::default()],
        |stream_handler, state, slices, metrics| {
            // Stream state should be unchanged.
            let expected_state = state.clone();

            let pruned_state =
                stream_handler.garbage_collect_local_state(state, &mut (i64::MAX / 2), &slices);

            assert_eq!(expected_state, pruned_state);
            assert_eq!(
                Some(0),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
            assert_eq!(
                Some(0),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS)
            );
        },
    );
}

/// Tests that garbage collecting a provided `ReplicatedState` results in all
/// messages with matching signals being garbage collected appropriately;
/// that message memory usage is updated correctly; and checks that stream flags
/// were observed.
#[test]
fn garbage_collect_local_state_success() {
    with_test_setup(
        // An outgoing stream with 3 messages.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            flags: StreamFlags {
                deprecated_responses_only: false,
            },
            ..StreamConfig::default()
        }],
        // An incoming stream slice with stream flags set.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 33,
            messages_begin: 43,
            flags: StreamFlags {
                deprecated_responses_only: true,
            },
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected stream has the first two messages gc'ed and the stream flags set.
            let outgoing_stream = state.get_stream(&REMOTE_SUBNET);
            let response_count_bytes = response_in_stream(outgoing_stream, 32).count_bytes();
            let expected_stream = stream_from_config(StreamConfig {
                begin: 33,
                messages: vec![message_in_stream(outgoing_stream, 33).clone()],
                signals_end: 43,
                flags: StreamFlags {
                    deprecated_responses_only: true,
                },
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let initial_available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let pruned_state =
                stream_handler.garbage_collect_local_state(state, &mut (i64::MAX / 2), &slices);

            assert_eq!(pruned_state, expected_state);
            // `available_guaranteed_response_memory` is a lower bound as it doesn't include garbage
            // collecting responses from streams, therefore it is off by `response_count_bytes`.
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&pruned_state),
                initial_available_guaranteed_response_memory + response_count_bytes as i64,
            );

            assert_eq!(
                Some(2),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
            assert_eq!(
                Some(0),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS),
            );
            assert_eq!(
                Some(1),
                metrics.fetch_int_counter(METRIC_STREAM_FLAGS_CHANGES),
            );
            // No critical errors were raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that garbage collecting a provided `ReplicatedState` results in all
/// messages with matching signals being garbage collected or rerouted, as
/// appropriate.
fn garbage_collect_local_state_with_reject_signals_for_response_success_impl(
    reason: RejectReason,
    expected_critical_error_counts: CriticalErrorCounts,
) {
    with_test_setup(
        // A stream with 4 messages, responses @32 and @33.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // A stream slice with a reject signal for the response @33.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 34,
            reject_signals: vec![RejectSignal::new(reason, 33.into())],
            messages_begin: 43,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let state = simulate_canister_migration(
                state,
                *REMOTE_CANISTER,
                REMOTE_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let outgoing_stream = state.get_stream(&REMOTE_SUBNET);
            // The expected stream has indices advanced and the first 3 messages gc'ed.
            let pruned_stream = stream_from_config(StreamConfig {
                begin: 34,
                messages: vec![message_in_stream(outgoing_stream, 34).clone()],
                signals_end: 43,
                ..StreamConfig::default()
            });
            // The response @33 is rerouted into a new stream.
            let rerouted_stream = stream_from_config(StreamConfig {
                messages: vec![message_in_stream(outgoing_stream, 33).clone()],
                ..StreamConfig::default()
            });

            let mut expected_state = state.clone();
            expected_state.with_streams(
                btreemap![REMOTE_SUBNET => pruned_stream, CANISTER_MIGRATION_SUBNET => rerouted_stream],
            );

            let pruned_state =
                stream_handler.garbage_collect_local_state(state, &mut (i64::MAX / 2), &slices);

            assert_eq!(pruned_state, expected_state);
            assert_eq!(
                Some(3),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
            assert_eq!(
                Some(0),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS),
            );
            metrics.assert_eq_critical_errors(expected_critical_error_counts);
        },
    );
}

/// Tests that garbage collecting with a legal reject signal does not raise a critical error.
#[test]
fn garbage_collect_local_state_with_legal_reject_signal_for_response_success() {
    garbage_collect_local_state_with_reject_signals_for_response_success_impl(
        RejectReason::CanisterMigrating,
        // No critical errors raised.
        CriticalErrorCounts::default(),
    );
}

/// Tests that garbage collecting with a legal reject signal does raise a critical error.
#[test]
fn garbage_collect_local_state_with_illegal_reject_signal_for_response_success() {
    garbage_collect_local_state_with_reject_signals_for_response_success_impl(
        RejectReason::CanisterNotFound,
        CriticalErrorCounts {
            bad_reject_signal_for_response: 1,
            ..CriticalErrorCounts::default()
        },
    );
}

/// Tests tha tan incoming reject signal for a request from `LOCAL_CANISTER` in the stream to
/// `REMOTE_SUBNET` triggers locally generating and successfully inducting a corresponding
/// reject response.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_request_success() {
    with_test_setup(
        // An outgoing stream with one request @21 in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*LOCAL_CANISTER, *REMOTE_CANISTER)],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with one reject signal for the request @21.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 22,
            reject_signals: vec![RejectSignal::new(RejectReason::QueueFull, 21.into())],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected state has 1 reject response for the request @21 successfully inducted.
            let reject_response = generate_reject_response_for(
                RejectReason::QueueFull,
                request_in_stream(state.get_stream(&REMOTE_SUBNET), 21),
            );
            push_input(&mut expected_state, reject_response);
            // The expected outgoing stream is empty with `begin` avanced.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 22,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            // Act and compare to expected.
            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.garbage_collect_local_state(
                state,
                &mut available_guaranteed_response_memory,
                &slices,
            );
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                available_guaranteed_response_memory,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            // 1 reject response successfully inducted.
            metrics.assert_inducted_xnet_messages_eq(&[(
                LABEL_VALUE_TYPE_RESPONSE,
                LABEL_VALUE_SUCCESS,
                1,
            )]);

            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that an incoming reject signal for a request from `OTHER_LOCAL_CANISTER` in the stream
/// to `REMOTE_SUBNET` triggers locally generating a reject response but raises a critical error
/// due to induction failure because no such canister is installed on `LOCAL_SUBNET`.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_request_from_absent_canister() {
    with_test_setup(
        // An outgoing stream with one request from an absent `OTHER_LOCAL_CANISTER` @21 in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*OTHER_LOCAL_CANISTER, *REMOTE_CANISTER)],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with one reject signal for the request @21.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 22,
            reject_signals: vec![RejectSignal::new(RejectReason::CanisterStopped, 21.into())],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected outgoing stream is empty with `begin` avanced.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 22,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            // Act and compare to expected.
            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.garbage_collect_local_state(
                state,
                &mut available_guaranteed_response_memory,
                &slices,
            );
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                available_guaranteed_response_memory,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            // 1 reject response failed to induct.
            metrics.assert_inducted_xnet_messages_eq(&[(
                LABEL_VALUE_TYPE_RESPONSE,
                LABEL_VALUE_CANISTER_NOT_FOUND,
                1,
            )]);

            // One critical error raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts {
                induct_response_failed: 1,
                ..CriticalErrorCounts::default()
            });
        },
    );
}

/// Tests that an incoming reject signal for a request to and from `LOCAL_CANISTER` in the stream
/// to `REMOTE_SUBNET` triggers locally generating a reject response that is successfully inducted
/// but the misrouted request (it should be in the loopback stream) raises a critical error.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_misrouted_request() {
    with_test_setup(
        // An outgoing stream with one misrouted loopback request @21 in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*LOCAL_CANISTER, *LOCAL_CANISTER)],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with one reject signal for the request @21.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 22,
            reject_signals: vec![RejectSignal::new(RejectReason::CanisterStopping, 21.into())],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected state has 1 reject response for the request @21 successfully inducted.
            let reject_response = generate_reject_response_for(
                RejectReason::CanisterStopping,
                request_in_stream(state.get_stream(&REMOTE_SUBNET), 21),
            );
            push_input(&mut expected_state, reject_response);
            // The expected outgoing stream is empty with `begin` avanced.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 22,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            // Act and compare to expected.
            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.garbage_collect_local_state(
                state,
                &mut available_guaranteed_response_memory,
                &slices,
            );
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                available_guaranteed_response_memory,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            // 1 reject response for a misrouted request successfully inducted.
            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_REQUEST_MISROUTED, 1),
            ]);

            // One critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts {
                request_misrouted: 1,
                ..CriticalErrorCounts::default()
            });
        },
    );
}

/// Tests that an incoming reject signal for a request from `LOCAL_CANISTER` in the stream
/// to `REMOTE_SUBNET` triggers locally generating a reject response that is rerouted into
/// the stream to `CANISTER_MIGRATION_SUBNET` when `LOCAL_CANISTER` has since been migrated.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_request_from_migrating_canister() {
    with_test_setup(
        // An outgoing stream with one request @21 in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*LOCAL_CANISTER, *REMOTE_CANISTER)],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with one reject signal for the request @21.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 22,
            reject_signals: vec![RejectSignal::new(RejectReason::OutOfMemory, 21.into())],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // Mark `LOCAL_CANISTER` as migrated from `LOCAL_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
            let state = simulate_canister_migration(
                state,
                *LOCAL_CANISTER,
                LOCAL_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // The expected outgoing stream is empty with `begin` avanced.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 22,
                ..StreamConfig::default()
            });
            // The stream to the migration subnet is new and has 1 reject response in it
            // due to the other reject signal.
            let migration_stream = stream_from_config(StreamConfig {
                messages: vec![generate_reject_response_for(
                    RejectReason::OutOfMemory,
                    request_in_stream(state.get_stream(&REMOTE_SUBNET), 21),
                )],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![
                REMOTE_SUBNET => expected_stream,
                CANISTER_MIGRATION_SUBNET => migration_stream,
            ]);

            // Act and compare to expected.
            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.garbage_collect_local_state(
                state,
                &mut available_guaranteed_response_memory,
                &slices,
            );
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                available_guaranteed_response_memory,
                stream_handler.available_guaranteed_response_memory(&inducted_state),
            );

            // 1 reject response failed to induct.
            metrics.assert_inducted_xnet_messages_eq(&[(
                LABEL_VALUE_TYPE_RESPONSE,
                LABEL_VALUE_CANISTER_MIGRATED,
                1,
            )]);

            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Calls `induct_stream_slices()` with one stream slice coming from `CANISTER_MIGRATION_SUBNET`
/// as input containing 3 messages:
/// - a reject response for a request sent to `REMOTE_CANISTER` from `LOCAL_CANISTER`,
/// - a data response with the same recipients.
/// - and a request with the same recipients.
///
/// `LOCAL_CANISTER` is marked as having migrated from `CANISTER_MIGRATION_SUBNET` to
/// `LOCAL_SUBNET`.
///
/// All of these messages are apparently misrouted, but since we cannot migrate reject signals,
/// there is an exception for reject responses (but only reject responses) coming from a former
/// host-subnet of a migrating canister.
///
/// The purpose of this test is to ensure that reject responses are accepted and inducted and
/// everything else is treated as a misrouted message, i.e. accepted but dropped.
#[test]
fn induct_stream_slices_reject_response_from_old_host_subnet_is_accepted() {
    with_test_setup(
        // A stream slice with 3 messages in it...
        btreemap![],
        btreemap![CANISTER_MIGRATION_SUBNET => StreamSliceConfig {
            messages_begin: 0,
            messages: vec![
                // ...a reject response for a request sent to `REMOTE_CANISTER` @0...
                RejectResponse(*REMOTE_CANISTER, *LOCAL_CANISTER, RejectReason::QueueFull),
                // ...a data response @1...
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
                // ...and a request from @2.
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // Mark `LOCAL_CANISTER` as having migrated from `CANISTER_MIGRATION_SUBNET` to `LOCAL_SUBNET`.
            let state = simulate_canister_migration(
                state,
                *LOCAL_CANISTER,
                CANISTER_MIGRATION_SUBNET,
                LOCAL_SUBNET,
            );

            // Expect a state, where the reject response was successfully inducted...
            let mut expected_state = state.clone();
            push_input(
                &mut expected_state,
                message_in_slice(slices.get(&CANISTER_MIGRATION_SUBNET), 0).clone(),
            );
            // ...and a stream to `CANISTER_MIGRATION_SUBNET` with all 3 messages accepted.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 0,
                signals_end: 3,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![CANISTER_MIGRATION_SUBNET => expected_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            // Compare inducted to expected.
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            // Expect the reject response was inducted, the response and request got rejected.
            metrics.assert_inducted_xnet_messages_eq(&[
                (
                    LABEL_VALUE_TYPE_RESPONSE,
                    LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                    1,
                ),
                (
                    LABEL_VALUE_TYPE_REQUEST,
                    LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                    1,
                ),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            metrics.assert_eq_critical_errors(CriticalErrorCounts {
                sender_subnet_mismatch: 2,
                ..CriticalErrorCounts::default()
            });
        },
    );
}

/// Common implementation for tests checking reject responses generated locally by the
/// `StreamHandler` directly.
fn check_stream_handler_locally_generated_reject_response_impl(
    reason: RejectReason,
    expected_reject_code: RejectCode,
    expected_message: String,
) {
    with_test_setup(
        // An outgoing stream with one request @21 in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![Request(*LOCAL_CANISTER, *REMOTE_CANISTER)],
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a reject signal for the request @21 in it.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            signals_end: 22,
            reject_signals: vec![RejectSignal::new(reason, 21.into())],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, _| {
            // Generate the expected reject response for the request in `outgoing_stream`.
            let request = request_in_stream(state.get_stream(&REMOTE_SUBNET), 21);
            let reject_response = ic_types::messages::Response {
                originator: request.sender,
                respondent: request.receiver,
                originator_reply_callback: request.sender_reply_callback,
                refund: request.payment,
                response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
                    expected_reject_code,
                    expected_message,
                    MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
                )),
                deadline: request.deadline,
            };

            // The expected state has this reject response inducted.
            let mut expected_state = state.clone();
            push_input(&mut expected_state, reject_response.into());

            // The expected stream is gc'ed.
            let expected_stream = stream_from_config(StreamConfig {
                begin: 22,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let inducted_state = stream_handler.process_stream_slices(state, slices);

            assert_eq!(inducted_state, expected_state);
        },
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_canister_migrating() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::CanisterMigrating,
        RejectCode::SysTransient,
        format!("Canister {} is migrating", *REMOTE_CANISTER),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_canister_not_found() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::CanisterNotFound,
        RejectCode::DestinationInvalid,
        format!("Canister {} not found", *REMOTE_CANISTER),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_canister_stopped() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::CanisterStopped,
        RejectCode::CanisterError,
        format!("Canister {} is stopped", *REMOTE_CANISTER),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_canister_stopping() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::CanisterStopping,
        RejectCode::CanisterError,
        format!("Canister {} is stopping", *REMOTE_CANISTER),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_queue_full() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::QueueFull,
        RejectCode::SysTransient,
        format!("Canister {} input queue is full", *REMOTE_CANISTER),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_out_of_memory() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::OutOfMemory,
        RejectCode::CanisterError,
        format!(
            "Cannot induct request. Out of memory: requested {}",
            MAX_RESPONSE_COUNT_BYTES,
        ),
    );
}

#[test]
fn check_stream_handler_locally_generated_reject_response_unknown() {
    check_stream_handler_locally_generated_reject_response_impl(
        RejectReason::Unknown,
        RejectCode::SysFatal,
        "Inducting request failed due to an unknown error".to_string(),
    );
}

/// Common implementation for tests checking reject responses generated by the `StreamHandler`
/// directly.
fn check_stream_handler_generated_reject_response_impl(
    mut available_guaranteed_response_memory: i64,
    // This function will be fed with a replicated state that has one `LOCAL_CANISTER` installed.
    // It's purpose is to set the stage as required such that inducting the `loopback_stream`
    // induces the type of reject response that will be be compared against a reference given
    // by `expected_reject_code` and `expected_state_error`.
    setup_state: &dyn Fn(&mut ReplicatedState),
    reason: RejectReason,
) {
    with_local_test_setup(
        // A loopback stream with one request in it.
        btreemap![LOCAL_SUBNET => StreamConfig {
            messages: vec![Request(*LOCAL_CANISTER, *LOCAL_CANISTER)],
            ..StreamConfig::default()
        }],
        |stream_handler, mut state, _| {
            // Call the state setup function.
            setup_state(&mut state);

            // A reject signal gets pushed into the loopback stream.
            let mut expected_state = state.clone();
            let mut expected_stream = state.get_stream(&LOCAL_SUBNET).unwrap().clone();
            expected_stream.push_reject_signal(reason);
            expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_stream]);

            // Induct the loopback stream as a stream slice.
            let loopback_stream_slice: StreamSlice =
                state.get_stream(&LOCAL_SUBNET).unwrap().clone().into();
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                btreemap![LOCAL_SUBNET => loopback_stream_slice],
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
        },
    );
}

#[test]
fn check_stream_handler_generated_reject_response_canister_not_found() {
    check_stream_handler_generated_reject_response_impl(
        i64::MAX / 2, // `available_guaranteed_response_memory`
        &|state| {
            state.canister_states.remove(&LOCAL_CANISTER).unwrap();
        },
        RejectReason::CanisterNotFound,
    );
}

#[test]
fn check_stream_handler_generated_reject_response_canister_stopped() {
    check_stream_handler_generated_reject_response_impl(
        i64::MAX / 2, // `available_guaranteed_response_memory`
        &|state| {
            state
                .canister_states
                .get_mut(&LOCAL_CANISTER)
                .unwrap()
                .system_state
                .status = CanisterStatus::Stopped;
        },
        RejectReason::CanisterStopped,
    );
}

#[test]
fn check_stream_handler_generated_reject_response_canister_stopping() {
    check_stream_handler_generated_reject_response_impl(
        i64::MAX / 2, // `available_guaranteed_response_memory`
        &|state| {
            state
                .canister_states
                .get_mut(&LOCAL_CANISTER)
                .unwrap()
                .system_state
                .status = CanisterStatus::Stopping {
                call_context_manager: Default::default(),
                stop_contexts: Default::default(),
            };
        },
        RejectReason::CanisterStopping,
    );
}

#[test]
fn check_stream_handler_generated_reject_response_queue_full() {
    check_stream_handler_generated_reject_response_impl(
        i64::MAX / 2, // `available_guaranteed_response_memory`
        &|state| {
            let mut callback_id = 2;
            while let Ok(()) = state.push_input(
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER)
                    .build_with(CallbackId::new(callback_id), 0),
                &mut (i64::MAX / 2),
            ) {
                callback_id += 1;
            }
        },
        RejectReason::QueueFull,
    );
}

#[test]
fn check_stream_handler_generated_reject_response_out_of_memory() {
    check_stream_handler_generated_reject_response_impl(
        0, // `available_guaranteed_response_memory`
        &|_| {},
        RejectReason::OutOfMemory,
    );
}

#[test]
fn check_stream_handler_generated_reject_response_canister_migrating() {
    check_stream_handler_generated_reject_response_impl(
        i64::MAX / 2, // `available_guaranteed_response_memory`
        &|state| {
            *state = simulate_canister_migration(
                state.clone(),
                *LOCAL_CANISTER,
                LOCAL_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );
        },
        RejectReason::CanisterMigrating,
    );
}

/// Tests that inducting stream slices results in signals appended to `StreamHeaders`;
/// and messages included into canister `InputQueues` or reject `Responses` on output streams
/// as appropriate.
#[test]
fn induct_stream_slices_partial_success() {
    with_test_setup(
        // An outgoing stream with one request and one response in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with...
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                // ...two incoming request @43 and @44...
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                // ...an incoming response @45...
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
                // ...a request to a missing canister @46 (on this subnet according to the
                // routing table); this is expected to trigger a reject response...
                Request(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
                // ..a request not from `REMOTE_SUBNET` @47...
                Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                // ...a request from a missing canister @48 (not anywhere according to the routing
                // table); this is expected to be accepted but dropped...
                Request(*UNKNOWN_CANISTER, *LOCAL_CANISTER),
                // ...and a response to a missing canister @49 (on this subnet according to the
                // routing table); this expected to be accepted but dropped.
                Response(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
            ],
            // ...and two accept signals.
            signals_end: 33,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected state has the first 3 messages inducted.
            push_inputs(
                &mut expected_state,
                messages_in_slice(slices.get(&REMOTE_SUBNET), 43..=45),
            );
            let response_count_bytes =
                response_in_slice(slices.get(&REMOTE_SUBNET), 45).count_bytes();

            // The expected stream has...
            let expected_stream = stream_from_config(StreamConfig {
                begin: 31,
                // ...the two initial messages as `induct_stream_slices` does not gc,
                // a reject response for the request to a missing canister @46...
                messages: vec![
                    message_in_stream(state.get_stream(&REMOTE_SUBNET), 31).clone(),
                    message_in_stream(state.get_stream(&REMOTE_SUBNET), 32).clone(),
                ],
                // ...6 accept signals for the messages in the stream slice...
                signals_end: 50,
                reject_signals: vec![
                    // ...and a reject signal for the request @46 due to a missing canister.
                    RejectSignal::new(RejectReason::CanisterNotFound, 46.into()),
                ],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let initial_available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let mut available_guaranteed_response_memory =
                initial_available_guaranteed_response_memory;

            // Act
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
            // 2 requests and one response inducted (consuming 2 - 1 reservations).
            assert_eq!(
                initial_available_guaranteed_response_memory
                    - MAX_RESPONSE_COUNT_BYTES as i64
                    - response_count_bytes as i64,
                available_guaranteed_response_memory
            );
            // Not equal, because the computed available memory does not account for the
            // reject response (since it's from a nonexistent canister).
            assert!(
                stream_handler.available_guaranteed_response_memory(&inducted_state)
                    >= available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                // Requests @43 and @44 successfully inducted.
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 2),
                // Request @46 not inducted because of missing canister.
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_NOT_FOUND, 1),
                // Request @47 not inducted because of canister not on `REMOTE_SUBNET`.
                // Request @48 not inducted becaue of unknown canister sender.
                (
                    LABEL_VALUE_TYPE_REQUEST,
                    LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                    2,
                ),
                // Response @45 successfully inducted.
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
                // Response @49 not inducted because of missing canister.
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_CANISTER_NOT_FOUND, 1),
            ]);
            assert_eq!(3, metrics.fetch_inducted_payload_sizes_stats().count);
            // Three critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts {
                induct_response_failed: 1,
                sender_subnet_mismatch: 2,
                ..CriticalErrorCounts::default()
            });
        },
    );
}

/// Tests that a message addressed to a canister that is not currently hosted by
/// this subnet; and is not being migrated on a path containing both this subnet
/// and its known host; is dropped, incrementing the respective critical error
/// count.
#[test]
fn induct_stream_slices_receiver_subnet_mismatch() {
    with_test_setup(
        // An outgoing stream with one request and one response in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with...
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                // ...a request addressed to a canister hosted by another subnet...
                Request(*REMOTE_CANISTER, *OTHER_REMOTE_CANISTER),
                // ...a response addressed to a canister hosted by another subnet...
                Response(*REMOTE_CANISTER, *OTHER_REMOTE_CANISTER),
                // ...a request addressed to a canister not mapped to any subnet in the routing
                // table...
                Request(*REMOTE_CANISTER, *UNKNOWN_CANISTER),
                // ...a response addressed to a canister not mapped to any subnet in the routing
                // table.
                Response(*REMOTE_CANISTER, *UNKNOWN_CANISTER),
            ],
            signals_end: 21,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // Throw in a canister migration with a path that does not include this subnet.
            let state = prepare_canister_migration(
                state,
                *OTHER_REMOTE_CANISTER,
                REMOTE_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            // The expected state should be unchanged...
            let mut expected_state = state.clone();

            // ...except that the stream should have `signals_end` incremented for the 2 dropped messages.
            let outgoing_stream = state.get_stream(&REMOTE_SUBNET);
            let expected_stream = stream_from_config(StreamConfig {
                begin: 21,
                messages: vec![
                    message_in_stream(outgoing_stream, 21).clone(),
                    message_in_stream(outgoing_stream, 22).clone(),
                ],
                signals_end: 47,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (
                    LABEL_VALUE_TYPE_REQUEST,
                    LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                    2,
                ),
                (
                    LABEL_VALUE_TYPE_RESPONSE,
                    LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                    2,
                ),
            ]);
            assert_eq!(0, metrics.fetch_inducted_payload_sizes_stats().count);
            metrics.assert_eq_critical_errors(CriticalErrorCounts {
                receiver_subnet_mismatch: 4,
                ..CriticalErrorCounts::default()
            });
        },
    );
}

/// Tests that inducting stream slices containing messages to a canister that is
/// known to be in the process of migration but has not yet been migrated to
/// this subnet results in reject signals for responses and reject `Responses`
/// for requests on output streams.
#[test]
fn induct_stream_slices_with_messages_to_migrating_canister() {
    with_test_setup(
        // An outgoing stream with one request and one response in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a request addressed to `REMOTE_CANISTER` @43 and a response
        // woth the same recipients @44.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                Request(*OTHER_REMOTE_CANISTER, *REMOTE_CANISTER),
                Response(*OTHER_REMOTE_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 21,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // `REMOTE_CANISTER` is hosted by `CANISTER_MIGRATION_SUBNET` but in the process
            // of being migrated to `LOCAL_SUBNET`.
            let state =
                complete_canister_migration(state, *REMOTE_CANISTER, CANISTER_MIGRATION_SUBNET);
            let state = prepare_canister_migration(
                state,
                *REMOTE_CANISTER,
                CANISTER_MIGRATION_SUBNET,
                LOCAL_SUBNET,
            );

            let mut expected_state = state.clone();
            // Expecting a stream with...
            let outgoing_stream = state.get_stream(&REMOTE_SUBNET);
            let expected_stream = stream_from_config(StreamConfig {
                begin: 21,
                messages: vec![
                    // ...the initial messages still in it...
                    message_in_stream(outgoing_stream, 21).clone(),
                    message_in_stream(outgoing_stream, 22).clone(),
                ],
                // ... a `signals_end` advanced by 2...
                signals_end: 45,
                // ...and a reject signals for the request @43 and the response @44.
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 43.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 44.into()),
                ],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);

            // Act.
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_MIGRATED, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_CANISTER_MIGRATED, 1),
            ]);
            assert_eq!(0, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that inducting stream slices containing messages to a migrated
/// canister results in reject signals for responses and reject `Responses` for
/// requests on output streams.
#[test]
fn induct_stream_slices_with_messages_to_migrated_canister() {
    with_test_setup(
        // An outgoing stream with one request and one response in it.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a request @43 and a response @44.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 21,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // `LOCAL_CANISTER` was hosted by the `LOCAL_SUBNET` but then migrated.
            let state = simulate_canister_migration(
                state,
                *LOCAL_CANISTER,
                LOCAL_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // Expecting a stream with...
            let outgoing_stream = state.get_stream(&REMOTE_SUBNET);
            let expected_stream = stream_from_config(StreamConfig {
                begin: 21,
                messages: vec![
                    // ...the initial messages still in it...
                    message_in_stream(outgoing_stream, 21).clone(),
                    message_in_stream(outgoing_stream, 22).clone(),
                ],
                // ... a `signals_end` advanced by 2...
                signals_end: 45,
                // ...and reject signals for the request @43 and the response @44.
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 43.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 44.into()),
                ],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);

            // Act
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_MIGRATED, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_CANISTER_MIGRATED, 1),
            ]);
            assert_eq!(0, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests the induction of stream slices containing messages from a canister
/// that is known to be in the process of migration but not yet known to have
/// been migrated.
#[test]
fn induct_stream_slices_with_messages_from_migrating_canister() {
    with_test_setup(
        // An outgoing stream with one request and one response to `REMOTE_CANISTER` in it.
        btreemap![CANISTER_MIGRATION_SUBNET => StreamConfig {
            begin: 21,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a request @43 and a response @44.
        btreemap![CANISTER_MIGRATION_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 21,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            // `REMOTE_CANISTER` is migrating from `REMOTE_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
            let state = prepare_canister_migration(
                state,
                *REMOTE_CANISTER,
                REMOTE_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // The expected state has the two messages inducted...
            push_inputs(
                &mut expected_state,
                messages_in_slice(slices.get(&CANISTER_MIGRATION_SUBNET), 43..=44),
            );
            // ...and a stream with...
            let migration_stream = state.get_stream(&CANISTER_MIGRATION_SUBNET);
            let expected_stream = stream_from_config(StreamConfig {
                begin: 21,
                messages: vec![
                    // ...the initial messages still in it...
                    message_in_stream(migration_stream, 21).clone(),
                    message_in_stream(migration_stream, 22).clone(),
                ],
                // ...and a `signals_end` incremented by 2.
                signals_end: 45,
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![CANISTER_MIGRATION_SUBNET => expected_stream]);

            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );

            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            assert_eq!(2, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Common implementation for memory limit tests setup such the subnet has
/// only enough message memory for one reservation (plus epsilon).
///
/// Ensures that the limits are enforced when inducting stream slices.
///
/// Tries to induct a slice consisting of `[request1, response, request2]`:
///  * `request1` will fail to be inducted due to lack of memory;
///  * `response` will be inducted and consume the existing reservation;
///  * `request2` will be inducted successfully, as there is now available
///    guaranteed response memory for one request.
fn induct_stream_slices_with_memory_limit_impl(subnet_type: SubnetType) {
    with_test_setup_and_config(
        // A config with only enough subnet message memory for one request + epsilon.
        HypervisorConfig {
            subnet_message_memory_capacity: NumBytes::new(
                MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10,
            ),
            ..Default::default()
        },
        subnet_type,
        // An empty outgoing stream.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with [request1 @43, response @44, request2 @45] in it.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 43,
            messages: vec![
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 31,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            let mut expected_state = state.clone();
            // The expected state must have `response` and `request2` inducted.
            push_inputs(
                &mut expected_state,
                messages_in_slice(slices.get(&REMOTE_SUBNET), 44..=45),
            );
            // The expected stream is empty with advanced...
            let expected_stream = stream_from_config(StreamConfig {
                begin: 31,
                signals_end: 46,
                reject_signals: vec![
                    // ...and a reject signal for request1 @43 was appended.
                    RejectSignal::new(RejectReason::OutOfMemory, 43.into()),
                ],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

            // Act
            let mut available_guaranteed_response_memory =
                stream_handler.available_guaranteed_response_memory(&state);
            let inducted_state = stream_handler.induct_stream_slices(
                state,
                slices,
                &mut available_guaranteed_response_memory,
            );

            // Assert
            assert_eq!(expected_state, inducted_state);
            assert_eq!(
                stream_handler.available_guaranteed_response_memory(&inducted_state),
                available_guaranteed_response_memory
            );
            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 1),
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_OUT_OF_MEMORY, 1),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 1),
            ]);
            assert_eq!(2, metrics.fetch_inducted_payload_sizes_stats().count);
            // No critical errors raised.
            metrics.assert_eq_critical_errors(CriticalErrorCounts::default());
        },
    );
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()`.
#[test]
fn induct_stream_slices_with_subnet_message_memory_limit() {
    induct_stream_slices_with_memory_limit_impl(SubnetType::Application);
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()` on system subnets.
#[test]
fn system_subnet_induct_stream_slices_with_subnet_message_memory_limit() {
    induct_stream_slices_with_memory_limit_impl(SubnetType::System);
}

/// Tests that messages in the loopback stream and incoming slices are inducted
/// (with signals added appropriately); and messages present in the initial
/// state are garbage collected or rerouted as appropriate.
#[test]
fn process_stream_slices_with_reject_signals_partial_success() {
    with_test_setup(
        btreemap![
            // A loopback stream with 3 requests in it.
            LOCAL_SUBNET => StreamConfig {
                begin: 21,
                messages: vec![
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                ],
                signals_end: 21,
                ..StreamConfig::default()
            },
            // An outgoing stream with 4 messages and reject signals in it.
            REMOTE_SUBNET => StreamConfig {
                begin: 31,
                messages: vec![
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER), // request @31
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER), // request @32
                    Response(*LOCAL_CANISTER, *REMOTE_CANISTER), // response @33
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER), // request @34
                ],
                signals_end: 153,
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 138.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 139.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 145.into()),
                ],
                ..StreamConfig::default()
            },
        ],
        // An incoming stream slice with...
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            // ...a `begin` in the header that will gc the first two reject signals @138 and @139...
            header_begin: Some(142),
            messages_begin: 153,
            messages: vec![
                // ...a valid request from the remote subnet @153...
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                // ...a request from an unknown canister @154...
                Request(*UNKNOWN_CANISTER, *LOCAL_CANISTER),
            ],
            // ...a `signals_end` that will leave one request @34 after gc'ing...
            signals_end: 34,
            // ...and a reject signal for the response @33.
            reject_signals: vec![RejectSignal::new(
                RejectReason::CanisterMigrating,
                33.into(),
            )],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            stream_handler
                .time_in_stream_metrics
                .lock()
                .unwrap()
                .record_header(
                    REMOTE_SUBNET,
                    &state.get_stream(&REMOTE_SUBNET).unwrap().header(),
                );

            // `REMOTE_CANISTER` is marked as migrating from `REMOTE_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
            let state = simulate_canister_migration(
                state,
                *REMOTE_CANISTER,
                REMOTE_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // The expected state has the 3 loopback messages inducted...
            push_inputs(
                &mut expected_state,
                messages_in_stream(state.get_stream(&LOCAL_SUBNET), 21..=23),
            );
            // ...and the first request from the incoming slice (the 2nd is dropped).
            push_input(
                &mut expected_state,
                message_in_slice(slices.get(&REMOTE_SUBNET), 153).clone(),
            );

            // The expected loopback stream is gc'ed.
            let expected_loopback_stream = stream_from_config(StreamConfig {
                begin: 24,
                signals_end: 24,
                ..StreamConfig::default()
            });
            // The expected outgoing stream has some of its constituents gc'ed.
            let expected_outgoing_stream = stream_from_config(StreamConfig {
                begin: 34,
                messages: vec![message_in_stream(state.get_stream(&REMOTE_SUBNET), 34).clone()],
                signals_end: 155,
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 145.into()),
                ],
                ..StreamConfig::default()
            });
            // The expected stream to `CANISTER_MIGRATION_SUBNET` has the reject response @33 rerouted.
            let rerouted_stream = stream_from_config(StreamConfig {
                messages: vec![message_in_stream(state.get_stream(&REMOTE_SUBNET), 33).clone()],
                ..StreamConfig::default()
            });
            expected_state.with_streams(btreemap![
                LOCAL_SUBNET => expected_loopback_stream,
                REMOTE_SUBNET => expected_outgoing_stream,
                CANISTER_MIGRATION_SUBNET => rerouted_stream,
            ]);

            // Act.
            let inducted_state = stream_handler.process_stream_slices(state, slices);

            assert_eq!(expected_state, inducted_state);
            metrics.assert_inducted_xnet_messages_eq(&[
                // The request from an unknown canister @154 is dropped.
                (
                    LABEL_VALUE_TYPE_REQUEST,
                    LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                    1,
                ),
                // Three loopback and one incoming requests successfully inducted.
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 4),
            ]);
            // 4 messages inducted.
            assert_eq!(4, metrics.fetch_inducted_payload_sizes_stats().count);
            // 3 messages GC-ed from loopback stream, 3 from outgoing stream.
            assert_eq!(
                Some(6),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
            // 2 reject signals from `initial_stream` (138, 139) were GC-ed.
            assert_eq!(
                Some(2),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS),
            );
            assert_eq!(
                metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
                metrics.fetch_int_gauge_vec(METRIC_XNET_MESSAGE_BACKLOG),
            );
            assert_eq!(
                metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 3)]),
                metrics.fetch_histogram_vec_count(METRIC_TIME_IN_STREAM),
            );
            assert_eq!(
                metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 2)]),
                metrics.fetch_histogram_vec_count(METRIC_TIME_IN_BACKLOG),
            );
        },
    );
}

/// Tests that when canister migration happens in both sending and receiving subnets,
/// messages in the loopback stream and incoming slices are inducted
/// (with signals added appropriately); and messages present in the initial
/// state are garbage collected or rerouted as appropriate.
#[test]
fn process_stream_slices_canister_migration_in_both_subnets_success() {
    with_test_setup(
        btreemap![
            // A loopback stream with...
            LOCAL_SUBNET => StreamConfig {
                begin: 21,
                messages: vec![
                    // ...3 messages to and from `LOCAL_CANISTER` @21..=23...
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                    Request(*LOCAL_CANISTER, *LOCAL_CANISTER),
                    // ...a request @24 and a response @25 to `LOCAL_CANISTER` from `OTHER_LOCAL_CANISTER`...
                    Request(*OTHER_LOCAL_CANISTER, *LOCAL_CANISTER),
                    Response(*OTHER_LOCAL_CANISTER, *LOCAL_CANISTER),
                    // ...a request @26 from `LOCAL_CANISTER` to `OTHER_LOCAL_CANISTER (a reject response
                    // should be generated for it)...
                    Request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER),
                    // ...and a response @27 from `LOCAL_CANISTER` to `OTHER_LOCAL_CANISTER` (a reject
                    // signal will be generated during induction; the response will be rerouted; and then
                    // the reject signal is gc'ed; i.e. the signal is never visible).
                    Response(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER),
                ],
                signals_end: 21,
                ..StreamConfig::default()
            },
            // An outgoing stream with...
            REMOTE_SUBNET => StreamConfig {
                begin: 31,
                messages: vec![
                    // ...4 messages from `LOCAL_CANISTER` to `REMOTE_CANISTER`... @31..=34, with a
                    // response @33...
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                    Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                    Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                ],
                signals_end: 153,
                // ...and 4 reject signals.
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 138.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 139.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 145.into()),
                ],
                ..StreamConfig::default()
            }
        ],
        // An incoming stream slice with...
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            header_begin: Some(142),
            messages_begin: 153,
            messages: vec![
                // ...a request @153 from `REMOTE_CANISTER` to `LOCAL_CANISTER`...
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                // ...one request @154 to the migrated canister...
                Request(*OTHER_REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
                // ...one response @155 to the migrated canister...
                Response(*OTHER_REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
                // ...one request @156 between the two migrated canisters...
                Request(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
                // ...one response @157 between the two migrated canisters...
                Response(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER),
            ],
            signals_end: 34,
            // ..and a reject signal for the response @33.
            reject_signals: vec![RejectSignal::new(
                RejectReason::CanisterMigrating,
                33.into(),
            )],
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, metrics| {
            stream_handler
                .time_in_stream_metrics
                .lock()
                .unwrap()
                .record_header(
                    REMOTE_SUBNET,
                    &state.get_stream(&REMOTE_SUBNET).unwrap().header(),
                );

            // `OTHER_LOCAL_CANISTER` is marked as migrating from `LOCAL_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
            let state = simulate_canister_migration(
                state,
                *OTHER_LOCAL_CANISTER,
                LOCAL_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            // `REMOTE_CANISTER` is marked as migrating from `REMOTE_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
            let state = simulate_canister_migration(
                state,
                *REMOTE_CANISTER,
                REMOTE_SUBNET,
                CANISTER_MIGRATION_SUBNET,
            );

            let mut expected_state = state.clone();
            // The expected state has the first 5 loopback messages @21..=25 inducted...
            push_inputs(
                &mut expected_state,
                messages_in_stream(state.get_stream(&LOCAL_SUBNET), 21..=25),
            );
            // ...and the first incoming message @153 and a reject response for the request @26.
            push_inputs(
                &mut expected_state,
                [
                    message_in_slice(slices.get(&REMOTE_SUBNET), 153),
                    &generate_reject_response_for(
                        RejectReason::CanisterMigrating,
                        request_in_stream(state.get_stream(&LOCAL_SUBNET), 26),
                    ),
                ],
            );

            // The expected loopback stream has all initial messages gc'ed.
            let expected_loopback_stream = stream_from_config(StreamConfig {
                begin: 28,
                signals_end: 28,
                ..StreamConfig::default()
            });

            // The expected outgoing stream is pruned and has reject signals for the messages
            // @154..=157.
            let pruned_outgoing_stream = stream_from_config(StreamConfig {
                begin: 34,
                messages: vec![
                    // ...one message @34 not gc'ed...
                    message_in_stream(state.get_stream(&REMOTE_SUBNET), 34).clone(),
                ],
                signals_end: 158,
                reject_signals: vec![
                    RejectSignal::new(RejectReason::CanisterMigrating, 142.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 145.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 154.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 155.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 156.into()),
                    RejectSignal::new(RejectReason::CanisterMigrating, 157.into()),
                ],
                ..StreamConfig::default()
            });

            // The expected stream to `CANISTER_MIGRATION_SUBNET` has...
            let rerouted_stream = stream_from_config(StreamConfig {
                messages: vec![
                    // ...the response @27 rerouted...
                    message_in_stream(state.get_stream(&LOCAL_SUBNET), 27).clone(),
                    // ...and the response @33 rerouted.
                    message_in_stream(state.get_stream(&REMOTE_SUBNET), 33).clone(),
                ],
                ..StreamConfig::default()
            });

            expected_state.with_streams(btreemap![
                LOCAL_SUBNET => expected_loopback_stream,
                REMOTE_SUBNET => pruned_outgoing_stream,
                CANISTER_MIGRATION_SUBNET => rerouted_stream,
            ]);

            // Act
            let inducted_state = stream_handler.process_stream_slices(state, slices);

            assert_eq!(expected_state, inducted_state);

            // 2 incoming messages discarded and 3 loopback +1 incoming inducted.
            metrics.assert_inducted_xnet_messages_eq(&[
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_CANISTER_MIGRATED, 3),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_CANISTER_MIGRATED, 3),
                (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_SUCCESS, 5),
                (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_SUCCESS, 2),
            ]);
            // 7 messages inducted, compare above.
            assert_eq!(7, metrics.fetch_inducted_payload_sizes_stats().count);
            // 7 messages GC-ed from loopback stream, 3 from outgoing stream.
            assert_eq!(
                Some(10),
                metrics.fetch_int_counter(METRIC_GCED_XNET_MESSAGES),
            );
            // 3 reject signals from outgoing stream (138, 139, 142) were gc-ed;
            // and 1 reject signal for the rejected request in the loopback stream.
            assert_eq!(
                Some(4),
                metrics.fetch_int_counter(METRIC_GCED_XNET_REJECT_SIGNALS),
            );
            assert_eq!(
                metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
                metrics.fetch_int_gauge_vec(METRIC_XNET_MESSAGE_BACKLOG),
            );
            // Check the number of GC-ed messages in the stream for the remote subnet.
            assert_eq!(
                metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 3)]),
                metrics.fetch_histogram_vec_count(METRIC_TIME_IN_STREAM),
            );
            // Check the number of inducted messages in the slice from the remote subnet.
            assert_eq!(
                metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 5)]),
                metrics.fetch_histogram_vec_count(METRIC_TIME_IN_BACKLOG),
            );
        },
    );
}

/// Tests that attempting to induct a slice with messages for which we have
/// already produced signals panics.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: messages begin (42) != stream signals_end (43)"
)]
fn process_stream_slices_with_invalid_messages() {
    with_test_setup(
        // An outgoing stream with a `signals_end` of 43.
        btreemap![REMOTE_SUBNET => StreamConfig {
            begin: 31,
            messages: vec![
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Response(*LOCAL_CANISTER, *REMOTE_CANISTER),
                Request(*LOCAL_CANISTER, *REMOTE_CANISTER),
            ],
            signals_end: 43,
            ..StreamConfig::default()
        }],
        // An incoming stream slice with a `messages_begin` < `signals_end` in the stream config above.
        btreemap![REMOTE_SUBNET => StreamSliceConfig {
            messages_begin: 42,
            messages: vec![
                Request(*REMOTE_CANISTER, *LOCAL_CANISTER),
                Response(*REMOTE_CANISTER, *LOCAL_CANISTER),
            ],
            signals_end: 33,
            ..StreamSliceConfig::default()
        }],
        |stream_handler, state, slices, _| {
            stream_handler.process_stream_slices(state, slices);
        },
    );
}

/// Generates a test setup. For details see `with_test_setup_and_config()`.
fn with_test_setup(
    stream_configs: BTreeMap<SubnetId, StreamConfig<Vec<MessageBuilder>>>,
    slice_configs: BTreeMap<SubnetId, StreamSliceConfig<Vec<MessageBuilder>>>,
    test_impl: impl FnOnce(
        StreamHandlerImpl,
        ReplicatedState,
        BTreeMap<SubnetId, StreamSlice>,
        MetricsFixture,
    ),
) {
    with_test_setup_and_config(
        HypervisorConfig::default(),
        SubnetType::Application,
        stream_configs,
        slice_configs,
        test_impl,
    )
}

/// Generates a test setup using a custom hypervisor config. The setup consists of a `LOCAL_SUBNET`
/// with only `LOCAL_CANISTER` installed. Streams are generated according to `stream_configs`,
/// requests from `LOCAL_CANISTER` and responses to `LOCAL_CANISTER` have registered callback IDs and
/// input queue reservations are made such that the state is equivalent to how it would be had the full
/// API been used to arrive at it, i.e. responses and (reject) responses generated from these requests
/// can be successfully inducted into the state. Same for the generated stream slices.
fn with_test_setup_and_config(
    hypervisor_config: HypervisorConfig,
    subnet_type: SubnetType,
    stream_configs: BTreeMap<SubnetId, StreamConfig<Vec<MessageBuilder>>>,
    slice_configs: BTreeMap<SubnetId, StreamSliceConfig<Vec<MessageBuilder>>>,
    test_impl: impl FnOnce(
        StreamHandlerImpl,
        ReplicatedState,
        BTreeMap<SubnetId, StreamSlice>,
        MetricsFixture,
    ),
) {
    with_test_replica_logger(|log| {
        // Generate an empty `ReplicatedState` for `LOCAL_SUBNET`.
        let mut state = ReplicatedState::new(LOCAL_SUBNET, subnet_type);
        state.metadata.certification_version =
            ic_certification_version::CURRENT_CERTIFICATION_VERSION;
        let metrics_registry = MetricsRegistry::new();
        let stream_handler = StreamHandlerImpl::new(
            LOCAL_SUBNET,
            hypervisor_config,
            &metrics_registry,
            Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
                &metrics_registry,
            ))),
            log.clone(),
        );

        // Ensure the routing table maps `LOCAL_CANISTER` to `LOCAL_SUBNET`,
        // `REMOTE_CANISTER` to `REMOTE_SUBNET` and `UNKNOWN_CANISTER` to `None`.
        let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => LOCAL_SUBNET,
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => REMOTE_SUBNET,
        }).unwrap());
        assert_eq!(
            Some(LOCAL_SUBNET),
            routing_table.route(LOCAL_CANISTER.get())
        );
        assert_eq!(
            Some(REMOTE_SUBNET),
            routing_table.route(REMOTE_CANISTER.get())
        );
        assert!(routing_table.route(UNKNOWN_CANISTER.get()).is_none());
        state.metadata.network_topology.routing_table = routing_table;

        // Generate testing canister using `LOCAL_CANISTER` as the canister ID.
        let mut canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );

        // Generates messages from `MessageBuilder`, makes a reservation for message in
        // the input queue and registers a `CallbackId` in the `canister_state` if it is
        // a request sent by `LOCAL_CANISTER` or a response sent to `LOCAL_CANISTER`,
        // i.e. it produces a `CallContextManager` that you'd have if the full API for
        // sending messages were used.
        //
        // For all other messages a `other_callback_id` is used, i.e. something that
        // simulates callback IDs generated in a different canister.
        let mut other_callback_id = 0_u64;
        let mut messages_from_builders = |builders: Vec<MessageBuilder>| -> Vec<RequestOrResponse> {
            builders
                .into_iter()
                .enumerate()
                .map(|(payload_size_bytes, builder)| {
                    let (respondent, originator) = match builder {
                        Request(sender, receiver) => (receiver, sender),
                        Response(respondent, originator) => (respondent, originator),
                        RejectResponse(respondent, originator, _) => (respondent, originator),
                    };

                    // Register a callback and make an input queue reservation if `msg_config`
                    // corresponds to `LOCAL_CANISTER`; else use a dummy callback id.
                    if originator == *LOCAL_CANISTER {
                        // Register a `Callback` and get a `CallbackId`.
                        let callback_id = register_callback(
                            &mut canister_state,
                            originator,
                            respondent,
                            NO_DEADLINE,
                        );

                        // Make an input queue reservation.
                        canister_state
                            .push_output_request(
                                RequestBuilder::new()
                                    .sender(originator)
                                    .receiver(respondent)
                                    .sender_reply_callback(callback_id)
                                    .build()
                                    .into(),
                                UNIX_EPOCH,
                            )
                            .unwrap();

                        // Empty output queues.
                        canister_state.output_into_iter().count();

                        builder.build_with(callback_id, payload_size_bytes)
                    } else {
                        // Message will not be inducted, use a replacement
                        other_callback_id += 1;
                        builder.build_with(CallbackId::new(other_callback_id), payload_size_bytes)
                    }
                })
                .collect()
        };

        // Generate streams.
        let mut streams = StreamMap::new();
        for (subnet_id, stream_config) in stream_configs.into_iter() {
            // Convert from `StreamConfig<MessageBuilder>` to `StreamConfig<RequestOrResponse>`
            // then use `stream_from_config()` to generate the `Stream`.
            let stream = stream_from_config(StreamConfig {
                begin: stream_config.begin,
                messages: messages_from_builders(stream_config.messages),
                signals_end: stream_config.signals_end,
                reject_signals: stream_config.reject_signals,
                flags: stream_config.flags,
            });
            streams.insert(subnet_id, stream);
        }

        // Generate stream slices.
        let mut slices = BTreeMap::<SubnetId, StreamSlice>::new();
        for (subnet_id, slice_config) in slice_configs.into_iter() {
            // Convert from `StreamSliceConfig<MessageBuilder>` to `StreamSliceConfig<RequestOrResponse>`
            // then use `stream_slice_from_config()` to generate the `StreamSlice`.
            let slice = stream_slice_from_config(StreamSliceConfig {
                header_begin: slice_config.header_begin,
                header_end: slice_config.header_end,
                signals_end: slice_config.signals_end,
                reject_signals: slice_config.reject_signals,
                flags: slice_config.flags,
                messages_begin: slice_config.messages_begin,
                messages: messages_from_builders(slice_config.messages),
            });
            slices.insert(subnet_id, slice);
        }

        // Insert the canister with ID `LOCAL_CANISTER` and the generated streams into the state.
        state.put_canister_state(canister_state);
        state.with_streams(streams);

        // Call test function.
        test_impl(
            stream_handler,
            state,
            slices,
            MetricsFixture {
                registry: metrics_registry,
            },
        );
    });
}

/// Generates a local test setup, i.e. without incoming stream slices.
/// For details see `with_test_setup_and_config()`.
fn with_local_test_setup(
    stream_configs: BTreeMap<SubnetId, StreamConfig<Vec<MessageBuilder>>>,
    test_impl: impl FnOnce(StreamHandlerImpl, ReplicatedState, MetricsFixture),
) {
    with_test_setup(
        stream_configs,
        btreemap![],
        |stream_handler, state, _, metrics| test_impl(stream_handler, state, metrics),
    );
}

/// Generates a local test setup, i.e. without incoming stream slices.
/// For details see `with_test_setup_and_config()`.
fn with_local_test_setup_and_config(
    hypervisor_config: HypervisorConfig,
    subnet_type: SubnetType,
    stream_configs: BTreeMap<SubnetId, StreamConfig<Vec<MessageBuilder>>>,
    test_impl: impl FnOnce(StreamHandlerImpl, ReplicatedState, MetricsFixture),
) {
    with_test_setup_and_config(
        hypervisor_config,
        subnet_type,
        stream_configs,
        btreemap![],
        |stream_handler, state, _, metrics| test_impl(stream_handler, state, metrics),
    );
}

/// A config used to generate a `Stream`.
///
/// The generic parameter `C` is either `Vec<MessageBuilder>` or `Vec<RequestOrResponse>`.
/// The whole container is used rather than the type inside the vector because Rust insists
/// `T` must implement `Default` to use an empty `Vec<T>::new()` as the default.
#[derive(Default)]
struct StreamConfig<C: IntoIterator + Default> {
    begin: u64,
    messages: C,
    signals_end: u64,
    reject_signals: Vec<RejectSignal>,
    flags: StreamFlags,
}

/// Generates a `Stream` from a `StreamConfig<RequestOrResponse>`
fn stream_from_config(config: StreamConfig<Vec<RequestOrResponse>>) -> Stream {
    let mut queue = StreamIndexedQueue::<RequestOrResponse>::with_begin(config.begin.into());
    for msg in config.messages {
        queue.push(msg.clone());
    }
    let mut stream = Stream::with_signals(
        queue,
        config.signals_end.into(),
        config.reject_signals.into(),
    );
    stream.set_reverse_stream_flags(config.flags);
    stream
}

/// A config to generate a `StreamSlice`.
///
/// The generic parameter `C` is either `Vec<MessageBuilder>` or `Vec<RequestOrResponse>`.
/// The whole container is used rather than the type inside the vector because Rust insists
/// `T` must implement `Default` to use an empty `Vec<T>::new()` as the default.
///
/// Note:
/// - `messages_begin` is used for `header_begin` if it is `None`.
/// - `messages_begin` + `messages.len()` is used for `header_end` if it is `None`.
#[derive(Default)]
struct StreamSliceConfig<C: IntoIterator + Default> {
    header_begin: Option<u64>,
    header_end: Option<u64>,
    signals_end: u64,
    reject_signals: Vec<RejectSignal>,
    flags: StreamFlags,
    messages_begin: u64,
    messages: C,
}

/// Generates a `StreamSlice` from a `StreamSliceConfig`.
fn stream_slice_from_config(config: StreamSliceConfig<Vec<RequestOrResponse>>) -> StreamSlice {
    let header_begin = match config.header_begin {
        Some(header_begin) => header_begin,
        None => config.messages_begin,
    };
    let header_end = match config.header_end {
        Some(header_end) => header_end,
        None => config.messages_begin + config.messages.len() as u64,
    };

    let header = StreamHeaderBuilder::new()
        .begin(header_begin.into())
        .end(header_end.into())
        .signals_end(config.signals_end.into())
        .reject_signals(config.reject_signals.into())
        .flags(config.flags)
        .build();
    let mut queue =
        StreamIndexedQueue::<RequestOrResponse>::with_begin(config.messages_begin.into());
    for msg in config.messages.into_iter() {
        queue.push(msg);
    }

    StreamSlice::new(header, queue)
}

/// Returns a reference to a request in a stream at `stream_index`.
///
/// Panics if no such request exists.
fn request_in_stream(
    opt_stream: Option<&Stream>,
    stream_index: u64,
) -> &ic_types::messages::Request {
    match opt_stream.and_then(|stream| stream.messages().get(stream_index.into())) {
        Some(RequestOrResponse::Request(request)) => request,
        _ => unreachable!(),
    }
}

/// Returns a reference to a response in a stream at `stream_index`.
///
/// Panics if no such response exists.
fn response_in_stream(
    opt_stream: Option<&Stream>,
    stream_index: u64,
) -> &ic_types::messages::Response {
    match opt_stream.and_then(|stream| stream.messages().get(stream_index.into())) {
        Some(RequestOrResponse::Response(response)) => response,
        _ => unreachable!(),
    }
}

/// Returns a reference to a response in the stream slice at `stream_index`.
///
/// Panics if no such response exists.
fn response_in_slice(
    opt_slice: Option<&StreamSlice>,
    stream_index: u64,
) -> &ic_types::messages::Response {
    match opt_slice.and_then(|slice| {
        slice
            .messages()
            .and_then(|msgs| msgs.get(stream_index.into()))
    }) {
        Some(RequestOrResponse::Response(response)) => response,
        _ => unreachable!(),
    }
}

/// Returns a reference to the message at `stream_index` in the stream.
///
/// Panics if no such message exists.
fn message_in_stream(opt_stream: Option<&Stream>, stream_index: u64) -> &RequestOrResponse {
    opt_stream
        .and_then(|stream| stream.messages().get(stream_index.into()))
        .unwrap()
}

/// Returns a reference to the message at `stream_index` in the stream slice.
///
/// Panics if no such message exists.
fn message_in_slice(opt_slice: Option<&StreamSlice>, stream_index: u64) -> &RequestOrResponse {
    opt_slice
        .and_then(|slice| {
            slice
                .messages()
                .and_then(|msgs| msgs.get(stream_index.into()))
        })
        .unwrap()
}

/// Pushes a message into the `state` using an infinite memory pool.
fn push_input(state: &mut ReplicatedState, msg: RequestOrResponse) {
    state.push_input(msg, &mut (i64::MAX / 2)).unwrap();
}

/// Returns an iterator over messages in a stream over the `stream_index_range`.
///
/// Panics if any of the messages in `stream_index_range` does not exist.
fn messages_in_stream(
    opt_stream: Option<&Stream>,
    stream_index_range: std::ops::RangeInclusive<u64>,
) -> impl Iterator<Item = &RequestOrResponse> {
    match opt_stream {
        // Not the `unwrap()`s here ensure that the code panics when the whole range was not
        // available rather than just silently terminating the iterator prematurely. This behaviour
        // is important to ensure we actually test as intended.
        Some(stream) => stream_index_range
            .map(|stream_index| stream.messages().get(stream_index.into()).unwrap()),
        None => unreachable!(),
    }
}

/// Returns an iterator over messages in a stream slice over the `stream_index_range`.
///
/// Panics if any of the messages in `stream_index_range` does not exist.
fn messages_in_slice(
    opt_slice: Option<&StreamSlice>,
    stream_index_range: std::ops::RangeInclusive<u64>,
) -> impl Iterator<Item = &RequestOrResponse> {
    match opt_slice {
        // Not the `unwrap()`s here ensure that the code panics when the whole range was not
        // available rather than just silently terminating the iterator prematurely. This behaviour
        // is important to ensure we actually test as intended.
        Some(slice) => stream_index_range
            .map(|stream_index| slice.messages().unwrap().get(stream_index.into()).unwrap()),
        None => unreachable!(),
    }
}

/// Pushes the messages yielded by `iter` into the `state`.
fn push_inputs<'a>(
    state: &mut ReplicatedState,
    iter: impl IntoIterator<Item = &'a RequestOrResponse>,
) {
    for msg in iter {
        state.push_input(msg.clone(), &mut (i64::MAX / 2)).unwrap();
    }
}

/// Instructions for building various kinds of messages; essentially a wrapper for
/// `RequestBuilder`, `ResponseBuilder`.
#[derive(Copy, Clone)]
enum MessageBuilder {
    // `(sender, receiver)`.
    Request(CanisterId, CanisterId),
    // `(respondent, originator)`
    Response(CanisterId, CanisterId),
    // `(respondent, originator, reason)`
    RejectResponse(CanisterId, CanisterId, RejectReason),
}

impl MessageBuilder {
    fn build_with(self, callback_id: CallbackId, payload_size_bytes: usize) -> RequestOrResponse {
        match self {
            Self::Request(sender, receiver) => RequestBuilder::new()
                .sender(sender)
                .receiver(receiver)
                .sender_reply_callback(callback_id)
                .method_payload(vec![0_u8; payload_size_bytes])
                .build()
                .into(),
            Self::Response(respondent, originator) => ResponseBuilder::new()
                .respondent(respondent)
                .originator(originator)
                .originator_reply_callback(callback_id)
                .response_payload(Payload::Data(vec![0_u8; payload_size_bytes]))
                .build()
                .into(),
            Self::RejectResponse(respondent, originator, reason) => generate_reject_response_for(
                reason,
                &RequestBuilder::new()
                    .sender(originator)
                    .receiver(respondent)
                    .sender_reply_callback(callback_id)
                    .build(),
            ),
        }
    }
}

struct MetricsFixture {
    pub registry: MetricsRegistry,
}

impl MetricsFixture {
    /// Retrieves an int counter.
    fn fetch_int_counter(&self, name: &str) -> Option<u64> {
        fetch_int_counter(&self.registry, name)
    }

    /// Retrieves an int gauge vec.
    fn fetch_int_gauge_vec(&self, name: &str) -> MetricVec<u64> {
        fetch_int_gauge_vec(&self.registry, name)
    }

    /// Retrieves a histogram vec count.
    fn fetch_histogram_vec_count(&self, name: &str) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.registry, name)
    }

    /// Retrieves the `METRIC_INDUCTED_XNET_PAYLOAD_SIZES` histogram's stats.
    fn fetch_inducted_payload_sizes_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.registry, METRIC_INDUCTED_XNET_PAYLOAD_SIZES).unwrap_or_else(
            || {
                panic!(
                    "Histogram not found: {}",
                    METRIC_INDUCTED_XNET_PAYLOAD_SIZES
                )
            },
        )
    }

    /// Asserts that the values of the `METRIC_INDUCTED_XNET_MESSAGES` metric
    /// match for the given statuses and are zero for all other statuses.
    fn assert_inducted_xnet_messages_eq(&self, expected: &[(&str, &str, u64)]) {
        // Using a slice directly inside the `map` function would return a reference
        // to a temporary object.
        let vec = expected
            .iter()
            .map(|(type_identifier, status_identifier, count)| {
                (
                    [
                        (LABEL_TYPE, type_identifier),
                        (LABEL_STATUS, status_identifier),
                    ],
                    *count,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            metric_vec(
                vec.iter()
                    .map(|(labels, count)| (labels.as_slice(), *count))
                    .collect::<Vec<_>>()
                    .as_slice()
            ),
            nonzero_values(fetch_int_counter_vec(
                &self.registry,
                METRIC_INDUCTED_XNET_MESSAGES
            ))
        );
    }

    fn assert_eq_critical_errors(&self, counts: CriticalErrorCounts) {
        assert_eq!(
            metric_vec(&[
                (
                    &[("error", &CRITICAL_ERROR_INDUCT_RESPONSE_FAILED.to_string())],
                    counts.induct_response_failed
                ),
                (
                    &[(
                        "error",
                        &CRITICAL_ERROR_BAD_REJECT_SIGNAL_FOR_RESPONSE.to_string()
                    )],
                    counts.bad_reject_signal_for_response
                ),
                (
                    &[("error", &CRITICAL_ERROR_SENDER_SUBNET_MISMATCH.to_string())],
                    counts.sender_subnet_mismatch
                ),
                (
                    &[("error", &CRITICAL_ERROR_REQUEST_MISROUTED.to_string())],
                    counts.request_misrouted
                ),
                (
                    &[(
                        "error",
                        &CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH.to_string()
                    )],
                    counts.receiver_subnet_mismatch
                )
            ]),
            fetch_int_counter_vec(&self.registry, "critical_errors")
        );
    }
}

#[derive(Default)]
struct CriticalErrorCounts {
    pub induct_response_failed: u64,
    pub bad_reject_signal_for_response: u64,
    pub sender_subnet_mismatch: u64,
    pub receiver_subnet_mismatch: u64,
    pub request_misrouted: u64,
}

/// Populates the given `state`'s canister migrations with a single entry,
/// recording the given migration trace for the given canister.
fn prepare_canister_migration(
    mut state: ReplicatedState,
    migrated_canister: CanisterId,
    from_subnet: SubnetId,
    to_subnet: SubnetId,
) -> ReplicatedState {
    let canister_id_ranges = CanisterIdRanges::try_from(vec![CanisterIdRange {
        start: migrated_canister,
        end: migrated_canister,
    }])
    .unwrap();

    let mut canister_migrations = (*state.metadata.network_topology.canister_migrations).clone();
    canister_migrations
        .insert_ranges(canister_id_ranges, from_subnet, to_subnet)
        .unwrap();
    state.metadata.network_topology.canister_migrations = Arc::new(canister_migrations);

    state
}

/// Updates the routing table in `state` to assign the given canister to the
/// `destination` subnet.
fn complete_canister_migration(
    mut state: ReplicatedState,
    migrated_canister: CanisterId,
    destination: SubnetId,
) -> ReplicatedState {
    let canister_id_ranges = CanisterIdRanges::try_from(vec![CanisterIdRange {
        start: migrated_canister,
        end: migrated_canister,
    }])
    .unwrap();

    let mut routing_table = (*state.metadata.network_topology.routing_table).clone();
    routing_table
        .assign_ranges(canister_id_ranges, destination)
        .unwrap();
    state.metadata.network_topology.routing_table = Arc::new(routing_table);

    state
}

/// Simulates the migration of the given canister between `from_subnet` and
/// `to_subnet` by recording the corresponding entry in `state`'s
/// `canister_migrations` and updating its routing table.
fn simulate_canister_migration(
    state: ReplicatedState,
    migrated_canister: CanisterId,
    from_subnet: SubnetId,
    to_subnet: SubnetId,
) -> ReplicatedState {
    let state = prepare_canister_migration(state, migrated_canister, from_subnet, to_subnet);
    complete_canister_migration(state, migrated_canister, to_subnet)
}
