// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]

use super::*;
use crate::message_routing::{LABEL_REMOTE, METRIC_TIME_IN_BACKLOG, METRIC_TIME_IN_STREAM};
use ic_base_types::NumSeconds;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{
    CanisterIdRange, CanisterIdRanges, CanisterMigrations, RoutingTable,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    replicated_state::{LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_OUT_OF_MEMORY},
    testing::ReplicatedStateTesting,
    CanisterState, ReplicatedState, Stream,
};
use ic_test_utilities::{
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, fetch_int_counter, fetch_int_counter_vec,
        fetch_int_gauge_vec, metric_vec, nonzero_values, HistogramStats, MetricVec,
    },
    state::{new_canister_state, register_callback},
    types::ids::{user_test_id, SUBNET_12, SUBNET_23, SUBNET_27},
    types::messages::{RequestBuilder, ResponseBuilder},
    types::xnet::{StreamHeaderBuilder, StreamSliceBuilder},
    with_test_replica_logger,
};
use ic_types::{
    messages::{CallbackId, Payload, Request, MAX_RESPONSE_COUNT_BYTES},
    xnet::{testing::StreamSliceTesting, StreamIndex, StreamIndexedQueue},
    CanisterId, Cycles,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::convert::TryFrom;

const LOCAL_SUBNET: SubnetId = SUBNET_12;
const REMOTE_SUBNET: SubnetId = SUBNET_23;
const CANISTER_MIGRATION_SUBNET: SubnetId = SUBNET_27;
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref LOCAL_CANISTER: CanisterId = CanisterId::from(0x34);
    static ref OTHER_LOCAL_CANISTER: CanisterId = CanisterId::from(0x56);
    static ref REMOTE_CANISTER: CanisterId = CanisterId::from(0x134);
    static ref OTHER_REMOTE_CANISTER: CanisterId = CanisterId::from(0x156);
    static ref UNKNOWN_CANISTER: CanisterId = CanisterId::from(0x234);
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet g24bn-xymaa-aaaaa-aaaap-yai: messages begin (21) != stream signals_end (22)"
)]
fn induct_loopback_stream_with_signals_panics() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut state, _) = new_fixture(&log);

        // A loopback stream containing 2 messages and 1 signal.
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 2,
            signals_end: 22,
            reject_signals: None,
        });
        state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

        stream_handler.induct_loopback_stream(state);
    });
}

#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet g24bn-xymaa-aaaaa-aaaap-yai: messages begin (21) != stream signals_end (20)"
)]
fn induct_loopback_stream_signals_end_before_messages_begin_panics() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut state, _) = new_fixture(&log);

        // A loopback stream with signals().end() != messages().begin().
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 2,
            signals_end: 20,
            reject_signals: None,
        });
        state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

        stream_handler.induct_loopback_stream(state);
    });
}

#[test]
fn induct_loopback_stream_empty_loopback_stream() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // An empty loopback stream.
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 0,
            signals_end: 21,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

        let expected_state = initial_state.clone();

        let inducted_state = stream_handler.induct_loopback_stream(initial_state);

        assert_eq!(expected_state, inducted_state);
        assert_inducted_xnet_messages_eq(MetricVec::new(), &metrics_registry);
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

#[test]
fn induct_loopback_stream_reject_response() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // A loopback stream with 1 message addressed to an unknown canister.
        let loopback_stream = generate_stream(
            MessageConfig {
                sender: *LOCAL_CANISTER,
                receiver: *OTHER_LOCAL_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig {
                end: 21,
                reject_signals: None,
            },
        );
        let msg = loopback_stream.messages().iter().next().unwrap().1.clone();
        initial_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

        // Expecting an unchanged canister state...
        let mut expected_state = initial_state.clone();

        // ...and a loopback stream with begin indices advanced...
        let mut expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 22,
            message_count: 0,
            signals_end: 22,
            reject_signals: None,
        });
        // ...plus a reject response.
        let context = RejectContext::new(
            RejectCode::DestinationInvalid,
            StateError::CanisterNotFound(*OTHER_LOCAL_CANISTER).to_string(),
        );
        expected_loopback_stream.push(generate_reject_response(msg, context));
        expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_loopback_stream]);

        let inducted_state = stream_handler.induct_loopback_stream(initial_state);

        assert_eq!(expected_state, inducted_state);
        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_CANISTER_NOT_FOUND),
                ],
                1,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

#[test]
fn induct_loopback_stream_reroute_response() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // `OTHER_LOCAL_CANISTER` was hosted by the `LOCAL_SUBNET` but then migrated.
        initial_state = simulate_canister_migration(
            initial_state,
            *OTHER_LOCAL_CANISTER,
            LOCAL_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        let mut loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 21,
            reject_signals: None,
        });

        // `LOCAL_CANISTER` sent a request to `OTHER_LOCAL_CANISTER`, which is no longer hosted by the `LOCAL_SUBNET`.
        // A reject response should be generated for it.
        loopback_stream.push(test_request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // `LOCAL_CANISTER` sent a response to `OTHER_LOCAL_CANISTER`, which is no longer hosted by the `LOCAL_SUBNET`.
        // A reject signal will be generated during induction; the response will be rerouted; and the reject signal garbage collected.
        loopback_stream.push(test_response(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into());

        let inducted_msg = loopback_stream.messages().get(21.into()).unwrap().clone();
        let rejected_msg = loopback_stream.messages().get(22.into()).unwrap().clone();
        let rerouted_msg = loopback_stream.messages().get(23.into()).unwrap().clone();

        initial_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream.clone()]);

        let mut expected_state = initial_state.clone();

        // The `inducted_msg` is expected to be inducted to the input queue of the local canister.
        expected_state
            .push_input(
                QUEUE_INDEX_NONE,
                inducted_msg,
                (u64::MAX / 2).into(),
                &mut (i64::MAX / 2),
            )
            .unwrap();

        // A reject signal is generated at index 23 and then garbage-collected.
        let mut expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 24,
            message_count: 0,
            signals_end: 24,
            reject_signals: None,
        });

        let context = RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "Canister {} is being migrated to/from {}",
                *OTHER_LOCAL_CANISTER, CANISTER_MIGRATION_SUBNET
            ),
        );
        expected_loopback_stream.push(generate_reject_response(rejected_msg, context));

        let mut expected_outgoing_stream = generate_stream(
            MessageConfig {
                sender: *LOCAL_CANISTER,
                receiver: *OTHER_LOCAL_CANISTER,
                begin: 0,
                count: 0,
            },
            SignalConfig {
                end: 0,
                reject_signals: None,
            },
        );
        expected_outgoing_stream.push(rerouted_msg);

        expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_loopback_stream, CANISTER_MIGRATION_SUBNET => expected_outgoing_stream]);

        let state_after_induction = stream_handler.induct_loopback_stream(initial_state);

        assert_eq!(expected_state, state_after_induction);
        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            1,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

#[test]
fn induct_loopback_stream_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        let mut expected_state = initial_state.clone();

        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // A loopback stream with 2 messages.
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 2,
            signals_end: 21,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream.clone()]);

        // Expecting a canister state with the 2 messages inducted...
        let expected_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        expected_state.put_canister_state(expected_canister_state);
        push_inputs(&mut expected_state, loopback_stream.messages().iter());

        // ...and an empty loopback stream with begin indices advanced by 2.
        let expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 23,
            message_count: 0,
            signals_end: 23,
            reject_signals: None,
        });
        expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_loopback_stream]);

        let inducted_state = stream_handler.induct_loopback_stream(initial_state);

        assert_eq!(expected_state, inducted_state);
        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                ],
                2,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            2,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests that canister memory limit is enforced by
/// `StreamHandlerImpl::induct_loopback_stream()`.
#[test]
fn induct_loopback_stream_with_canister_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a canister memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            induct_loopback_stream_with_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        } else {
            induct_loopback_stream_ignores_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        }
    });
}

/// Tests that subnet memory limit is enforced by
/// `StreamHandlerImpl::induct_loopback_stream()`.
#[test]
fn induct_loopback_stream_with_subnet_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a subnet memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            induct_loopback_stream_with_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        } else {
            induct_loopback_stream_ignores_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        }
    });
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_loopback_stream()`.
#[test]
fn induct_loopback_stream_with_subnet_message_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a subnet message memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            induct_loopback_stream_with_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        } else {
            induct_loopback_stream_ignores_memory_limit_impl(
                stream_handler,
                initial_state,
                metrics_registry,
            );
        }
    });
}

/// Tests that canister memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_canister_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a canister memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, mut initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_loopback_stream_ignores_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_subnet_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a subnet memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, mut initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_loopback_stream_ignores_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet message memory limit is ignored by
/// `StreamHandlerImpl::induct_loopback_stream()` for system subnets.
#[test]
fn system_subnet_induct_loopback_stream_ignores_subnet_message_memory_limit() {
    with_test_replica_logger(|log| {
        // A stream handler with a subnet message memory limit that only allows up to 3 reservations.
        let config = HypervisorConfig {
            subnet_message_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 7 / 2),
            ..Default::default()
        };
        let (stream_handler, mut initial_state, metrics_registry) =
            new_fixture_with_config(&log, config);
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_loopback_stream_ignores_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
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
fn induct_loopback_stream_with_memory_limit_impl(
    stream_handler: StreamHandlerImpl,
    mut initial_state: ReplicatedState,
    metrics_registry: MetricsRegistry,
) {
    let mut expected_state = initial_state.clone();

    let (loopback_stream, expected_canister_state) =
        induct_loopback_stream_with_memory_limit_setup(&mut initial_state);

    // Expecting a canister state with the first message inducted...
    expected_state.put_canister_state(expected_canister_state);
    push_inputs(
        &mut expected_state,
        loopback_stream.messages().iter().take(1),
    );

    // ...and a loopback stream with begin indices advanced...
    let mut expected_loopback_stream = generate_loopback_stream(StreamConfig {
        messages_begin: 23,
        message_count: 0,
        signals_end: 23,
        reject_signals: None,
    });
    // ...plus a reject response.
    let context = RejectContext::new(
        RejectCode::SysTransient,
        StateError::OutOfMemory {
            requested: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
            available: MAX_RESPONSE_COUNT_BYTES as i64 / 2,
        }
        .to_string(),
    );
    let msg = loopback_stream.messages().iter().nth(1).unwrap().1;
    expected_loopback_stream.push(generate_reject_response(msg.clone(), context));
    expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_loopback_stream]);

    let inducted_state = stream_handler.induct_loopback_stream(initial_state);

    assert_eq!(expected_state, inducted_state);
    assert_inducted_xnet_messages_eq(
        metric_vec(&[
            (
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                ],
                1,
            ),
            (
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_OUT_OF_MEMORY),
                ],
                1,
            ),
        ]),
        &metrics_registry,
    );
    assert_eq!(
        1,
        fetch_inducted_payload_sizes_stats(&metrics_registry).count
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
fn induct_loopback_stream_ignores_memory_limit_impl(
    stream_handler: StreamHandlerImpl,
    mut initial_state: ReplicatedState,
    metrics_registry: MetricsRegistry,
) {
    let mut expected_state = initial_state.clone();

    let (loopback_stream, expected_canister_state) =
        induct_loopback_stream_with_memory_limit_setup(&mut initial_state);

    // Expecting a canister state with the 2 requests inducted...
    expected_state.put_canister_state(expected_canister_state);
    push_inputs(&mut expected_state, loopback_stream.messages().iter());

    // ...and a loopback stream with begin indices advanced.
    let expected_loopback_stream = generate_loopback_stream(StreamConfig {
        messages_begin: 23,
        message_count: 0,
        signals_end: 23,
        reject_signals: None,
    });
    expected_state.with_streams(btreemap![LOCAL_SUBNET => expected_loopback_stream]);

    let inducted_state = stream_handler.induct_loopback_stream(initial_state);

    assert_eq!(expected_state, inducted_state);
    assert_inducted_xnet_messages_eq(
        metric_vec(&[(
            &[
                (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                (LABEL_STATUS, LABEL_VALUE_SUCCESS),
            ],
            2,
        )]),
        &metrics_registry,
    );
    assert_eq!(
        2,
        fetch_inducted_payload_sizes_stats(&metrics_registry).count
    );
}

/// Common initial state setup for `StreamHandlerImpl::induct_loopback_stream()`
/// memory limit tests.
fn induct_loopback_stream_with_memory_limit_setup(
    initial_state: &mut ReplicatedState,
) -> (Stream, CanisterState) {
    // The initial state has a loopback stream with 2 requests...
    let loopback_stream = generate_loopback_stream(StreamConfig {
        messages_begin: 21,
        message_count: 2,
        signals_end: 21,
        reject_signals: None,
    });
    initial_state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream.clone()]);

    // ...and a canister with 2 input queue reservations (for the 2 requests in the stream).
    let mut initial_canister_state = new_canister_state(
        *LOCAL_CANISTER,
        user_test_id(24).get(),
        *INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    make_input_queue_reservations(&mut initial_canister_state, 2, *LOCAL_CANISTER);
    initial_state.put_canister_state(initial_canister_state.clone());

    (loopback_stream, initial_canister_state)
}

/// Simple test to verify that a specified message is removed from the
/// outgoing Stream.
#[test]
fn garbage_collect_messages_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, metrics_registry) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });

        let slice_signals_end = 33.into();
        // Reject signals for already GC-ed messages.
        let slice_reject_signals = vec![29.into(), 30.into()].into();

        // The expected state must contain a stream that does not contain the specified
        // messages; the stream header should be unmodified from the input (and is not
        // consistent with the contained messages).
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });

        let mut stats = Default::default();
        let rejected_messages = stream_handler.garbage_collect_messages(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            slice_signals_end,
            &slice_reject_signals,
        );

        assert!(rejected_messages.is_empty());
        assert_eq!(expected_stream, stream);
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
    });
}

/// Simple test to verify that a specified message is removed from the
/// outgoing Stream and messages with reject signals are returned.
#[test]
fn garbage_collect_messages_with_reject_signals_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, metrics_registry) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });

        let slice_signals_end = 33.into();
        let slice_reject_signals = vec![32.into()].into();

        // The expected state must contain a stream that does not contain the specified
        // messages; the stream header should be unmodified from the input (and is not
        // consistent with the contained messages).
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });

        let expected_rejected_messages = vec![stream.messages().get(32.into()).unwrap().clone()];

        let mut stats = Default::default();
        let rejected_messages = stream_handler.garbage_collect_messages(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            slice_signals_end,
            &slice_reject_signals,
        );

        assert_eq!(rejected_messages, expected_rejected_messages);
        assert_eq!(expected_stream, stream);
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
    });
}

/// Simple test to confirm that signals in the base state are removed based
/// off of messages.
/// Tests `garbage_collect_signals()`.
#[test]
fn garbage_collect_signals_success() {
    with_test_replica_logger(|log| {
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 153,
            reject_signals: Some(vec![138, 139, 142, 145]),
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 153,
            message_count: 10,
            signals_end: 33,
            reject_signals: None,
        });

        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 153,
            reject_signals: Some(vec![142, 145]),
        });

        let mut stats = Default::default();
        let (stream_handler, _, metrics_registry) = new_fixture(&log);
        stream_handler.garbage_collect_signals(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );

        assert_eq!(expected_stream, stream);
        // 2 reject signals from `initial_stream` (138, 139) were GC-ed.
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid signal indices in stream to subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, signals [138, 139, 145, 142]"
)]
fn garbage_collect_signals_in_wrong_order() {
    with_test_replica_logger(|log| {
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 153,
            // Reject signals not in order.
            reject_signals: Some(vec![138, 139, 145, 142]),
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 153,
            message_count: 10,
            signals_end: 33,
            reject_signals: None,
        });

        let mut stats = Default::default();
        let (stream_handler, _, _) = new_fixture(&log);
        stream_handler.garbage_collect_signals(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, messages [142, 148)"
)]
fn garbage_collect_signals_with_invalid_slice_messages() {
    with_test_replica_logger(|log| {
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 153,
            reject_signals: Some(vec![138, 139, 142, 145]),
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 143,
            // `signals_end` in the stream is 153 and beyond the range of messages in the stream slice.
            message_count: 5,
            signals_end: 33,
            reject_signals: None,
        });

        let mut stats = Default::default();
        let (stream_handler, _, _) = new_fixture(&log);
        stream_handler.garbage_collect_signals(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: signals_end 153, messages [142, 143)"
)]
fn garbage_collect_signals_with_invalid_empty_slice() {
    with_test_replica_logger(|log| {
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 153,
            reject_signals: Some(vec![138, 139, 142, 145]),
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 143,
            // `signals_end` in the stream is 153 and beyond the range of messages in the stream slice.
            message_count: 0,
            signals_end: 33,
            reject_signals: None,
        });

        let mut stats = Default::default();
        let (stream_handler, _, _) = new_fixture(&log);
        stream_handler.garbage_collect_signals(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid signal indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_before_first_message() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, _) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });

        let slice_signals_end = 24.into();
        let slice_reject_signals = vec![19.into(), 20.into()].into();

        let mut stats = Default::default();
        stream_handler.garbage_collect_messages(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            slice_signals_end,
            &slice_reject_signals,
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid signal indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_after_last_message() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, _) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });

        let slice_signals_end = 35.into();
        let slice_reject_signals = vec![30.into(), 31.into()].into();

        let mut stats = Default::default();
        stream_handler.garbage_collect_messages(
            &mut StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            slice_signals_end,
            &slice_reject_signals,
        );
    });
}

/// Tests that we panic if we attempt to garbage collect messages in an
/// inexistent stream (from a subnet that we haven't talked to before).
#[test]
#[should_panic(
    expected = "Cannot garbage collect a stream for subnet 5h3gz-qaxaa-aaaaa-aaaap-yai that does not exist"
)]
fn garbage_collect_local_state_signals_for_inexistent_stream() {
    with_test_replica_logger(|log| {
        let (stream_handler, state, _) = new_fixture(&log);

        // Incoming stream with some messages and signals.
        let incoming_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 0,
            header_end: None,
            messages_begin: 0,
            message_count: 2,
            signals_end: 1,
            reject_signals: None,
        });

        stream_handler
            .garbage_collect_local_state(state, &btreemap![REMOTE_SUBNET => incoming_slice]);
    });
}

/// Tests that nothing happens if we attempt to garbage collect an inexistent
/// stream (from a subnet that we haven't talked to before).
#[test]
fn garbage_collect_local_state_inexistent_stream() {
    with_test_replica_logger(|log| {
        let (stream_handler, initial_state, metrics_registry) = new_fixture(&log);

        // Incoming stream with some messages but no signals.
        let incoming_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 0,
            header_end: None,
            messages_begin: 0,
            message_count: 2,
            signals_end: 0,
            reject_signals: None,
        });

        // Stream state should be unchanged.
        let expected_state = initial_state.clone();

        let pruned_state = stream_handler.garbage_collect_local_state(
            initial_state,
            &btreemap![REMOTE_SUBNET => incoming_slice],
        );

        assert_eq!(pruned_state, expected_state);
        assert_eq!(
            0,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
        assert_eq!(
            0,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );
    });
}

/// Tests that garbage collecting a provided `ReplicatedState` results in all
/// messages with matching signals being garbage collected appropriately.
#[test]
fn garbage_collect_local_state_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        let mut expected_state = initial_state.clone();

        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        // 2 incoming messages, 2 new incoming signals.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
            reject_signals: None,
        });

        // The expected state must contain only messages past the last signal (index
        // 33).
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });
        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

        let pruned_state = stream_handler
            .garbage_collect_local_state(initial_state, &btreemap![REMOTE_SUBNET => stream_slice]);

        assert_eq!(pruned_state, expected_state);
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
        assert_eq!(
            0,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );
        assert_eq_critical_error_reject_signals_for_request(0, &metrics_registry);
    });
}

/// Tests that garbage collecting a provided `ReplicatedState` results in all
/// messages with matching signals being garbage collected  or rerouted, as
/// appropriate.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_response_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        // `initial_stream` has 4 messages and the message at index 33 is a response.
        let mut initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 2,
            signals_end: 43,
            reject_signals: None,
        });
        initial_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());
        initial_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        // 2 incoming messages, 3 new incoming signals including a reject signal @33.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 34,
            reject_signals: Some(vec![33]),
        });

        let mut pruned_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 34,
            message_count: 0,
            signals_end: 43,
            reject_signals: None,
        });
        pruned_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        let mut rerouted_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 0,
            message_count: 0,
            signals_end: 0,
            reject_signals: None,
        });
        rerouted_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        initial_state = simulate_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        let mut expected_state = initial_state.clone();
        expected_state.with_streams(
            btreemap![REMOTE_SUBNET => pruned_stream, CANISTER_MIGRATION_SUBNET => rerouted_stream],
        );

        let pruned_state = stream_handler
            .garbage_collect_local_state(initial_state, &btreemap![REMOTE_SUBNET => stream_slice]);

        assert_eq!(pruned_state, expected_state);
        assert_eq!(
            3,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
        assert_eq!(
            0,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );
        assert_eq_critical_error_reject_signals_for_request(0, &metrics_registry);
    });
}

/// Tests that garbage collecting a provided `ReplicatedState` against reject signals for requests causes a critical error.
#[test]
fn garbage_collect_local_state_with_reject_signals_for_request() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        // `initial_stream` has 2 requests.
        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 2,
            signals_end: 43,
            reject_signals: None,
        });

        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        // 2 incoming messages, 3 new incoming signals including a reject signal @33.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
            reject_signals: Some(vec![31]),
        });

        initial_state = simulate_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        stream_handler
            .garbage_collect_local_state(initial_state, &btreemap![REMOTE_SUBNET => stream_slice]);

        assert_eq_critical_error_reject_signals_for_request(1, &metrics_registry);
    });
}

#[test]
fn reroute_rejected_messages_success() {
    with_test_replica_logger(|log| {
        // Empty initial state.
        let (stream_handler, mut initial_state, _) = new_fixture(&log);

        // Response to be rerouted.
        let response: RequestOrResponse = test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into();

        // Expected state has a stream to `REMOTE_SUBNET` containing the rerouted response.
        let mut expected_state = initial_state.clone();
        let mut rerouted_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 0,
            message_count: 0,
            signals_end: 0,
            reject_signals: None,
        });
        rerouted_stream.push(response.clone());
        expected_state.with_streams(btreemap![REMOTE_SUBNET => rerouted_stream]);

        // Act
        let mut streams = initial_state.take_streams();
        stream_handler.reroute_rejected_messages(
            vec![response],
            &mut streams,
            initial_state
                .metadata
                .network_topology
                .routing_table
                .as_ref(),
            REMOTE_SUBNET,
        );

        // Assert
        assert_eq!(streams, expected_state.take_streams());
    });
}

#[test]
fn generate_reject_response_queue_full() {
    // Arbitrary initial output stream.
    let mut stream = generate_outgoing_stream(StreamConfig {
        messages_begin: 31,
        message_count: 3,
        signals_end: 42,
        reject_signals: None,
    });

    // A request that failed to be inducted due to a `QueueFull` error.
    let msg = test_request(*REMOTE_CANISTER, *LOCAL_CANISTER);
    let msg_clone = msg.clone();
    let err = StateError::QueueFull { capacity: 13 };

    // The expected output stream should have an extra reject `Response` appended.
    let mut expected_stream = stream.clone();
    expected_stream.push(
        Response {
            originator: msg.sender,
            respondent: msg.receiver,
            originator_reply_callback: msg.sender_reply_callback,
            refund: msg.payment,
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::SysTransient,
                err.to_string(),
            )),
        }
        .into(),
    );

    stream.push(generate_reject_response(
        msg_clone.into(),
        RejectContext::new(RejectCode::SysTransient, err.to_string()),
    ));

    assert_eq!(expected_stream, stream);
}

#[test]
fn generate_reject_response_canister_not_found() {
    // Arbitrary initial output stream.
    let mut stream = generate_outgoing_stream(StreamConfig {
        messages_begin: 31,
        message_count: 3,
        signals_end: 42,
        reject_signals: None,
    });

    // A request that failed to be inducted due to a `CanisterNotFound` error.
    let msg = test_request(*REMOTE_CANISTER, *LOCAL_CANISTER);
    let msg_clone = msg.clone();
    let err = StateError::CanisterNotFound(*LOCAL_CANISTER);

    // The expected output stream should have an extra reject `Response` appended.
    let mut expected_stream = stream.clone();
    expected_stream.push(
        Response {
            originator: msg.sender,
            respondent: msg.receiver,
            originator_reply_callback: msg.sender_reply_callback,
            refund: msg.payment,
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::DestinationInvalid,
                err.to_string(),
            )),
        }
        .into(),
    );

    stream.push(generate_reject_response(
        msg_clone.into(),
        RejectContext::new(RejectCode::DestinationInvalid, err.to_string()),
    ));

    assert_eq!(expected_stream, stream);
}

/// Tests that inducting stream slices results in signals appended to
/// `StreamHeaders`; and messages included into canister `InputQueues` or
/// reject `Responses` on output streams as appropriate.
#[test]
fn induct_stream_slices_partial_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        // Canister with a reservation for one incoming response.
        let mut initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        make_input_queue_reservations(&mut initial_canister_state, 1, *REMOTE_CANISTER);
        initial_state.put_canister_state(initial_canister_state);

        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        let mut expected_state = initial_state.clone();
        // 2 incoming requests, 2 signals...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
            reject_signals: None,
        });

        // ...and one incoming response.
        let response: RequestOrResponse = test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into();
        stream_slice.push_message(response);

        // The expected canister state must contain the 3 inducted messages...
        if let Some(messages) = stream_slice.messages() {
            push_inputs(&mut expected_state, messages.iter());
        }
        // ...and signals for the 3 inducted messages in the stream.
        let mut expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 46,
            reject_signals: None,
        });

        // Push a request addressed to a missing canister into the input stream.
        let request_to_missing_canister: RequestOrResponse =
            test_request(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into();
        stream_slice.push_message(request_to_missing_canister.clone());

        // And expect one signal and one reject Response in the output stream.
        expected_stream.increment_signals_end();
        expected_stream.push(generate_reject_response(
            request_to_missing_canister,
            RejectContext::new(
                RejectCode::DestinationInvalid,
                StateError::CanisterNotFound(*OTHER_LOCAL_CANISTER).to_string(),
            ),
        ));

        // Push a request from a canister not on the remote subnet.
        let request_from_mismatched_subnet: RequestOrResponse =
            test_request(*LOCAL_CANISTER, *LOCAL_CANISTER).into();
        stream_slice.push_message(request_from_mismatched_subnet);
        // And expect one signal only (no reject Response) in the output stream.
        expected_stream.increment_signals_end();

        // Push a request from a canister not on any known subnet.
        let request_from_mismatched_subnet: RequestOrResponse =
            test_request(*UNKNOWN_CANISTER, *LOCAL_CANISTER).into();
        stream_slice.push_message(request_from_mismatched_subnet);
        // And expect one signal only (no reject Response) in the output stream.
        expected_stream.increment_signals_end();

        // Push a response addressed to a missing canister into the input stream.
        let response_to_missing_canister: RequestOrResponse =
            test_response(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into();
        stream_slice.push_message(response_to_missing_canister);
        // And expect one signal in the output stream.
        expected_stream.increment_signals_end();

        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

        // Act
        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );

        assert_eq!(
            expected_state.canister_state(&LOCAL_CANISTER),
            inducted_state.canister_state(&LOCAL_CANISTER),
        );

        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    2,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_NOT_FOUND),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SENDER_SUBNET_MISMATCH),
                    ],
                    2,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_NOT_FOUND),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            3,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests that a response to a missing canister is dropped, incrementing the
/// respective critical error count.
#[test]
fn induct_stream_slices_response_to_missing_canister() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        let mut expected_state = initial_state.clone();

        // Initial state with no canisters and one stream.
        let outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 0,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Incoming slice with one response addressed to a missing canister.
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 43,
            header_end: None,
            messages_begin: 43,
            message_count: 0,
            signals_end: 21,
            reject_signals: None,
        });
        stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());

        // The expected stream should have `signals_end` incremented for the 1 dropped message.
        let expected_outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 0,
            signals_end: 44,
            reject_signals: None,
        });
        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );
        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                    (LABEL_STATUS, LABEL_VALUE_CANISTER_NOT_FOUND),
                ],
                1,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        assert_eq_critical_error_induct_response_failed(1, &metrics_registry);
    });
}

/// Tests that a message from a sender that is not currently and has not
/// recently (according to `canister_migrations`) been hosted by the remote
/// subnet is dropped, incrementing the respective critical error count.
#[test]
fn induct_stream_slices_sender_subnet_mismatch() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        // Initial state with one canister...
        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // ...and one stream.
        let outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Incoming slice with requests from canisters not hosted by the remote subnet.
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 43,
            header_end: None,
            messages_begin: 43,
            message_count: 0,
            signals_end: 21,
            reject_signals: None,
        });
        // Canister hosted by some other subnet (this one).
        stream_slice.push_message(test_request(*OTHER_LOCAL_CANISTER, *LOCAL_CANISTER).into());
        // Canister not mapped to any subnet in the routing table.
        stream_slice.push_message(test_request(*UNKNOWN_CANISTER, *LOCAL_CANISTER).into());

        // The expected state should be unchanged...
        let mut expected_state = initial_state.clone();

        // ...except that the stream should have `signals_end` incremented for the 2 dropped messages.
        let expected_outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 45,
            reject_signals: None,
        });
        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );
        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_SENDER_SUBNET_MISMATCH),
                ],
                2,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        assert_eq_critical_error_sender_subnet_mismatch(2, &metrics_registry);
    });
}

/// Tests that a message adressed to a canister that is not currently hosted by
/// this subnet; and is not being migrated on a path containing both this subnet
/// and its known host; is dropped, incrementing the respective critical error
/// count.
#[test]
fn induct_stream_slices_receiver_subnet_mismatch() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);

        // Initial state with no canisters and one stream.
        let outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Throw in a canister migration with a path that does not include this subnet.
        initial_state = prepare_canister_migration(
            initial_state,
            *OTHER_REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        // Incoming slice with requests for canisters not hosted by this subnet.
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 43,
            header_end: None,
            messages_begin: 43,
            message_count: 0,
            signals_end: 21,
            reject_signals: None,
        });
        // Canister hosted by some other subnet.
        stream_slice.push_message(test_request(*REMOTE_CANISTER, *OTHER_REMOTE_CANISTER).into());
        // Canister not mapped to any subnet in the routing table.
        stream_slice.push_message(test_request(*REMOTE_CANISTER, *UNKNOWN_CANISTER).into());

        // The expected state should be unchanged...
        let mut expected_state = initial_state.clone();

        // ...except that the stream should have `signals_end` incremented for the 2 dropped messages.
        let expected_outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 45,
            reject_signals: None,
        });
        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );
        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_RECEIVER_SUBNET_MISMATCH),
                ],
                2,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        assert_eq_critical_error_receiver_subnet_mismatch(2, &metrics_registry);
    });
}

/// Tests that inducting stream slices containing messages to a canister that is
/// known to be in the process of migration but has not yet been migrated to
/// this subnet results in reject signals for responses and reject `Responses`
/// for requests on output streams.
#[test]
fn induct_stream_slices_with_messages_to_migrating_canister() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        // `REMOTE_CANISTER` is hosted by `CANISTER_MIGRATION_SUBNET` but in the process
        // of being migrated to `LOCAL_SUBNET`.
        initial_state =
            complete_canister_migration(initial_state, *REMOTE_CANISTER, CANISTER_MIGRATION_SUBNET);
        initial_state = prepare_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            CANISTER_MIGRATION_SUBNET,
            LOCAL_SUBNET,
        );
        let mut expected_state = initial_state.clone();

        let outgoing_stream = generate_stream(
            MessageConfig {
                sender: *LOCAL_CANISTER,
                receiver: *OTHER_REMOTE_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig {
                end: 43,
                reject_signals: None,
            },
        );
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Incoming slice...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 43,
            header_end: None,
            messages_begin: 43,
            message_count: 0,
            signals_end: 21,
            reject_signals: None,
        });
        // ...with one incoming request...
        stream_slice.push_message(test_request(*OTHER_REMOTE_CANISTER, *REMOTE_CANISTER).into());
        // ...and one incoming response.
        stream_slice.push_message(test_response(*OTHER_REMOTE_CANISTER, *REMOTE_CANISTER).into());

        // Expecting an outgoing stream with a reject signal @44 for the
        // incoming response...
        let mut expected_outgoing_stream = generate_stream(
            MessageConfig {
                sender: *LOCAL_CANISTER,
                receiver: *OTHER_REMOTE_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig {
                end: 45,
                reject_signals: Some(vec![44]),
            },
        );
        // ...and a reject response for the incoming request.
        let rejected_request = stream_slice
            .messages()
            .unwrap()
            .get(43.into())
            .unwrap()
            .clone();
        let context = RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "Canister {} is being migrated to/from {}",
                *REMOTE_CANISTER, CANISTER_MIGRATION_SUBNET
            ),
        );
        expected_outgoing_stream.push(generate_reject_response(rejected_request, context));

        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        // Act
        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );

        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests that inducting stream slices containing messages to a migrated
/// canister results in reject signals for responses and reject `Responses` for
/// requests on output streams.
#[test]
fn induct_stream_slices_with_messages_to_migrated_canister() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        // `LOCAL_CANISTER` was hosted by the `LOCAL_SUBNET` but then migrated.
        initial_state = simulate_canister_migration(
            initial_state,
            *LOCAL_CANISTER,
            LOCAL_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );
        let mut expected_state = initial_state.clone();

        let outgoing_stream = generate_stream(
            MessageConfig {
                sender: *OTHER_LOCAL_CANISTER,
                receiver: *REMOTE_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig {
                end: 43,
                reject_signals: None,
            },
        );
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Incoming slice with one incoming request...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 1,
            signals_end: 21,
            reject_signals: None,
        });
        // ...and one incoming response.
        stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());

        // Expecting an outgoing stream with a reject signal @44 for the
        // incoming response...
        let mut expected_outgoing_stream = generate_stream(
            MessageConfig {
                sender: *OTHER_LOCAL_CANISTER,
                receiver: *REMOTE_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig {
                end: 45,
                reject_signals: Some(vec![44]),
            },
        );

        // ...and a reject response for the incoming request.
        let rejected_request = stream_slice
            .messages()
            .unwrap()
            .get(43.into())
            .unwrap()
            .clone();
        let context = RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "Canister {} is being migrated to/from {}",
                *LOCAL_CANISTER, CANISTER_MIGRATION_SUBNET
            ),
        );
        expected_outgoing_stream.push(generate_reject_response(rejected_request, context));

        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        // Act
        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );

        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests the induction of stream slices containing messages from a canister
/// that is known to be in the process of migration but not yet known to have
/// been migrated.
#[test]
fn induct_stream_slices_with_messages_from_migrating_canister() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        // Canister with a reservation for one incoming response.
        let mut initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        make_input_queue_reservations(&mut initial_canister_state, 1, *REMOTE_CANISTER);
        initial_state.put_canister_state(initial_canister_state);

        // `REMOTE_CANISTER` is migrating from `REMOTE_SUBNET` to `CANISTER_MIGRATION_SUBNET`.
        initial_state = prepare_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        let mut expected_state = initial_state.clone();

        let outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![CANISTER_MIGRATION_SUBNET => outgoing_stream]);

        // Slice consisting of one incoming request...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 1,
            signals_end: 21,
            reject_signals: None,
        });
        // ...and one incoming response.
        stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());

        // The expected canister state must contain the 2 inducted messages...
        if let Some(messages) = stream_slice.messages() {
            push_inputs(&mut expected_state, messages.iter());
        }
        // ...and `signals_end` incremented for the 2 inducted messages in the stream.
        let expected_outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 45,
            reject_signals: None,
        });

        expected_state
            .with_streams(btreemap![CANISTER_MIGRATION_SUBNET => expected_outgoing_stream]);

        let inducted_state = stream_handler.induct_stream_slices(
            initial_state,
            btreemap![CANISTER_MIGRATION_SUBNET => stream_slice],
        );

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );

        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            2,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests the induction of stream slices containing messages from a canister
/// known to have been be migrated.
#[test]
fn induct_stream_slices_with_messages_from_migrated_canister() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        // Canister with a reservation for one incoming response.
        let mut initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        make_input_queue_reservations(&mut initial_canister_state, 1, *REMOTE_CANISTER);
        initial_state.put_canister_state(initial_canister_state);

        // `REMOTE_CANISTER` was hosted by the `REMOTE_SUBNET` but then migrated.
        initial_state = simulate_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        let mut expected_state = initial_state.clone();

        let outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => outgoing_stream]);

        // Slice consisting of one incoming request...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 1,
            signals_end: 21,
            reject_signals: None,
        });
        // ...and one incoming response.
        stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());

        // The expected canister state must contain the 2 inducted messages...
        if let Some(messages) = stream_slice.messages() {
            push_inputs(&mut expected_state, messages.iter());
        }
        // ...and `signals_end` incremented for the 2 inducted messages in the stream.
        let expected_outgoing_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 21,
            message_count: 1,
            signals_end: 45,
            reject_signals: None,
        });

        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_outgoing_stream]);

        let inducted_state = stream_handler
            .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );

        assert_eq!(expected_state, inducted_state);

        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            2,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
    });
}

/// Tests that canister memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()`.
#[test]
fn induct_stream_slices_with_canister_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Canister memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                ..Default::default()
            },
        );

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()`.
#[test]
fn induct_stream_slices_with_subnet_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Subnet memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                ..Default::default()
            },
        );

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()`.
#[test]
fn induct_stream_slices_with_subnet_message_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Subnet message memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_message_memory_capacity: NumBytes::new(
                    MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10,
                ),
                ..Default::default()
            },
        );

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that canister memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()` on system subnets.
#[test]
fn system_subnet_induct_stream_slices_with_canister_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Canister memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                ..Default::default()
            },
        );
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()` on system subnets.
#[test]
fn system_subnet_induct_stream_slices_with_subnet_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Subnet memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                ..Default::default()
            },
        );
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Tests that subnet message memory limit is enforced by
/// `StreamHandlerImpl::induct_stream_slices()` on system subnets.
#[test]
fn system_subnet_induct_stream_slices_with_subnet_message_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Subnet message memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_message_memory_capacity: NumBytes::new(
                    MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10,
                ),
                ..Default::default()
            },
        );
        initial_state.metadata.own_subnet_type = SubnetType::System;

        induct_stream_slices_with_memory_limit_impl(
            stream_handler,
            initial_state,
            metrics_registry,
        );
    });
}

/// Common implementation for memory limit tests. Expects a `StreamHandlerImpl`
/// with canister, subnet or subnet message memory limits only large enough for
/// one in-flight request (plus epsilon) at a time. Ensures that the limits are
/// enforced when inducting stream slices.
///
/// Sets up a canister with one input queue reservation for one in-flight
/// (outgoing) request. Tries to induct a slice consisting of `[request1,
/// response, request2]`:
///  * `request1` will fail to be inducted due to lack of memory;
///  * `response` will be inducted and consume the existing reservation;
///  * `request2` will be inducted successfully, as there is now available
///    memory for one request.
fn induct_stream_slices_with_memory_limit_impl(
    stream_handler: StreamHandlerImpl,
    mut initial_state: ReplicatedState,
    metrics_registry: MetricsRegistry,
) {
    let (mut expected_state, mut expected_stream, stream_slice, request1) =
        induct_stream_slices_with_memory_limit_setup(&mut initial_state);

    // The expected canister state must contain the response and `request2`...
    if let Some(messages) = stream_slice.messages() {
        push_inputs(&mut expected_state, messages.iter().skip(1));
    }
    // ...and signals for the 3 messages plus one reject response for `request1` in
    // the output stream.
    expected_stream.increment_signals_end();
    expected_stream.increment_signals_end();
    expected_stream.increment_signals_end();
    expected_stream.push(generate_reject_response(
        request1,
        RejectContext::new(
            RejectCode::SysTransient,
            StateError::OutOfMemory {
                requested: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
                available: MAX_RESPONSE_COUNT_BYTES as i64 / 2,
            }
            .to_string(),
        ),
    ));
    expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

    // Act
    let inducted_state = stream_handler
        .induct_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

    // Assert
    assert_eq!(expected_state, inducted_state);

    assert_inducted_xnet_messages_eq(
        metric_vec(&[
            (
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                ],
                1,
            ),
            (
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_OUT_OF_MEMORY),
                ],
                1,
            ),
            (
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                    (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                ],
                1,
            ),
        ]),
        &metrics_registry,
    );
    assert_eq!(
        2,
        fetch_inducted_payload_sizes_stats(&metrics_registry).count
    );
}

/// Common initial state setup for `StreamHandlerImpl::induct_stream_slices()`
/// memory limit tests.
fn induct_stream_slices_with_memory_limit_setup(
    initial_state: &mut ReplicatedState,
) -> (ReplicatedState, Stream, StreamSlice, RequestOrResponse) {
    fn request_with_callback(callback_id: u64) -> RequestOrResponse {
        let mut request = test_request(*REMOTE_CANISTER, *LOCAL_CANISTER);
        // Set a callback ID that will allow us to identify the request.
        request.sender_reply_callback = CallbackId::new(callback_id);
        request.into()
    }

    // Canister with a reservation for one incoming response.
    let mut initial_canister_state = new_canister_state(
        *LOCAL_CANISTER,
        user_test_id(24).get(),
        *INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    make_input_queue_reservations(&mut initial_canister_state, 1, *REMOTE_CANISTER);
    initial_state.put_canister_state(initial_canister_state);
    let expected_state = initial_state.clone();

    let initial_stream = generate_outgoing_stream(StreamConfig {
        messages_begin: 31,
        message_count: 3,
        signals_end: 43,
        reject_signals: None,
    });
    let expected_stream = initial_stream.clone();
    initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

    // Incoming slice: `[request1, response, request2]`.
    let mut stream_slice = generate_stream_slice(StreamSliceConfig {
        header_begin: 43,
        header_end: None,
        messages_begin: 43,
        message_count: 0,
        signals_end: 31,
        reject_signals: None,
    });
    let request1 = request_with_callback(13);
    stream_slice.push_message(request1.clone());
    stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());
    let request2 = request_with_callback(14);
    stream_slice.push_message(request2);

    (expected_state, expected_stream, stream_slice, request1)
}

/// Tests that messages in the loopback stream and incoming slices are inducted
/// (with signals added appropriately); and messages present in the initial
/// state are garbage collected or rerouted as appropriate.
#[test]
fn process_stream_slices_with_reject_signals_partial_success() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;
        let mut expected_state = initial_state.clone();

        // The initial state consists of a blank CanisterState...
        let initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        initial_state.put_canister_state(initial_canister_state);

        // ...a loopback stream containing 3 messages...
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 3,
            signals_end: 21,
            reject_signals: None,
        });

        // ...and an outgoing stream containing 4 messages, with the message @33 a response.
        let mut initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 2,
            signals_end: 153,
            reject_signals: Some(vec![138, 139, 142, 145]),
        });
        initial_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());
        initial_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        stream_handler
            .time_in_stream_metrics
            .lock()
            .unwrap()
            .record_header(REMOTE_SUBNET, &initial_stream.header());
        initial_state.with_streams(
            btreemap![LOCAL_SUBNET => loopback_stream.clone(), REMOTE_SUBNET => initial_stream],
        );

        //
        // The incoming stream slice has 1 message and 3 signals (including a reject signal for the response @33)...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 153,
            message_count: 1,
            signals_end: 34,
            reject_signals: Some(vec![33]),
        });
        // ...and a second message from a canister not mapped in the routing table.
        stream_slice.push_message(test_request(*UNKNOWN_CANISTER, *LOCAL_CANISTER).into());

        //
        // The expected `CanisterState` has...
        let expected_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        expected_state.put_canister_state(expected_canister_state);

        // ...the 3 loopback messages...
        push_inputs(&mut expected_state, loopback_stream.messages().iter());
        // ...and the first incoming message (2nd is silently dropped).
        push_inputs(
            &mut expected_state,
            stream_slice.messages().unwrap().iter().take(1),
        );

        //
        // The expected `Streams` have all loopback messages consumed and garbage collected...
        let expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 24,
            message_count: 0,
            signals_end: 24,
            reject_signals: None,
        });

        // ...one message left in the `pruned_stream`, one message rerouted to the
        // `rerouted_stream`. `signals_end` is incremented and `reject_signals`
        // are garbage collected.
        let mut pruned_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 34,
            message_count: 0,
            signals_end: 155,
            reject_signals: Some(vec![142, 145]),
        });
        pruned_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        let mut rerouted_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 0,
            message_count: 0,
            signals_end: 0,
            reject_signals: None,
        });
        rerouted_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        initial_state = simulate_canister_migration(
            initial_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        expected_state = simulate_canister_migration(
            expected_state,
            *REMOTE_CANISTER,
            REMOTE_SUBNET,
            CANISTER_MIGRATION_SUBNET,
        );

        expected_state.with_streams(
            btreemap![LOCAL_SUBNET => expected_loopback_stream, REMOTE_SUBNET => pruned_stream, CANISTER_MIGRATION_SUBNET => rerouted_stream],
        );

        let inducted_state = stream_handler
            .process_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );
        assert_eq!(
            expected_state.canister_state(&LOCAL_CANISTER),
            inducted_state.canister_state(&LOCAL_CANISTER),
        );
        assert_eq!(expected_state, inducted_state);

        // 1 incoming messages discarded; 3 loopback + 1 incoming messages inducted.
        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SENDER_SUBNET_MISMATCH),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    4,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            4,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        // 3 messages GC-ed from loopback stream, 3 from outgoing stream.
        assert_eq!(
            6,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
        // 2 reject signals from `initial_stream` (138, 139) were GC-ed.
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );

        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_XNET_MESSAGE_BACKLOG)
        );
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 3)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_STREAM),
        );
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &&*REMOTE_SUBNET.to_string().as_str())], 2)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_BACKLOG),
        );
    });
}

/// Tests that when canister migration happens in both sending and receiving subnets,
/// messages in the loopback stream and incoming slices are inducted
/// (with signals added appropriately); and messages present in the initial
/// state are garbage collected or rerouted as appropriate.
#[test]
fn process_stream_slices_canister_migration_in_both_subnets_success() {
    with_test_replica_logger(|log| {
        let (mut stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        stream_handler.testing_flag_generate_reject_signals = true;

        //
        // Initial state with canister migrations happening in both sending and
        // receiving subnets...
        initial_state.metadata.network_topology.canister_migrations = Arc::new(
            CanisterMigrations::try_from(btreemap! {
                CanisterIdRange{ start: *OTHER_LOCAL_CANISTER, end: *OTHER_LOCAL_CANISTER } => vec![LOCAL_SUBNET, CANISTER_MIGRATION_SUBNET],
                CanisterIdRange{ start: *REMOTE_CANISTER, end: *REMOTE_CANISTER } => vec![REMOTE_SUBNET, CANISTER_MIGRATION_SUBNET],
            }).unwrap()
        );
        initial_state = complete_canister_migration(
            initial_state,
            *OTHER_LOCAL_CANISTER,
            CANISTER_MIGRATION_SUBNET,
        );
        initial_state =
            complete_canister_migration(initial_state, *REMOTE_CANISTER, CANISTER_MIGRATION_SUBNET);

        // ...a canister with a reservation for one incoming response...
        let mut initial_canister_state = new_canister_state(
            *LOCAL_CANISTER,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        make_input_queue_reservations(&mut initial_canister_state, 1, *OTHER_LOCAL_CANISTER);
        initial_state.put_canister_state(initial_canister_state);

        let mut expected_state = initial_state.clone();

        // ...a loopback stream containing 3 messages...
        let mut loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 3,
            signals_end: 21,
            reject_signals: None,
        });
        // ...one request and one response from `OTHER_LOCAL_CANISTER` to `LOCAL_CANISTER`...
        loopback_stream.push(test_request(*OTHER_LOCAL_CANISTER, *LOCAL_CANISTER).into());
        loopback_stream.push(test_response(*OTHER_LOCAL_CANISTER, *LOCAL_CANISTER).into());

        // ...a request from `LOCAL_CANISTER` to `OTHER_LOCAL_CANISTER`...
        // (A reject response should be generated for it.)
        loopback_stream.push(test_request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // ...a response from `LOCAL_CANISTER` to `OTHER_LOCAL_CANISTER`...
        // (A reject signal will be generated during induction; the response will be
        // rerouted; and the reject signal garbage collected.)
        loopback_stream.push(test_response(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // ...and an outgoing stream containing 4 messages, with the message @33 a response.
        let mut initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 2,
            signals_end: 153,
            reject_signals: Some(vec![138, 139, 142, 145]),
        });
        initial_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());
        initial_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        stream_handler
            .time_in_stream_metrics
            .lock()
            .unwrap()
            .record_header(REMOTE_SUBNET, &initial_stream.header());
        initial_state.with_streams(
            btreemap![LOCAL_SUBNET => loopback_stream.clone(), REMOTE_SUBNET => initial_stream],
        );

        //
        // The incoming stream slice has 1 message and 3 signals (including a reject signal for the response @33)...
        let mut stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 142,
            header_end: None,
            messages_begin: 153,
            message_count: 1,
            signals_end: 34,
            reject_signals: Some(vec![33]),
        });
        // ...one incoming request to the migrated canister....
        stream_slice
            .push_message(test_request(*OTHER_REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // ...one incoming response to the migrated canister....
        stream_slice
            .push_message(test_response(*OTHER_REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // ...one incoming request between the two migrated canisters....
        stream_slice.push_message(test_request(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into());

        // ...and one incoming response between the two migrated canisters....
        stream_slice.push_message(test_response(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into());

        //
        // The expected `CanisterState` has the 5 loopback messages to `LOCAL_CANISTER`...
        push_inputs(
            &mut expected_state,
            loopback_stream.messages().iter().take(5),
        );
        // ...and the first incoming message to `LOCAL_CANISTER`.
        push_inputs(
            &mut expected_state,
            stream_slice.messages().unwrap().iter().take(1),
        );

        //
        // The expected `Streams` have all initial loopback messages consumed and garbage collected...
        let mut expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 28,
            message_count: 0,
            signals_end: 28,
            reject_signals: None,
        });
        // ...a reject response for the local request to `OTHER_LOCAL_CANISTER`...
        let context = RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "Canister {} is being migrated to/from {}",
                *OTHER_LOCAL_CANISTER, CANISTER_MIGRATION_SUBNET
            ),
        );
        expected_loopback_stream.push(generate_reject_response(
            test_request(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into(),
            context,
        ));

        // ...5 new signals including 2 reject signals...
        let mut pruned_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 34,
            message_count: 0,
            // `signals_end` is incremented and `reject_signals` are garbage collected.
            signals_end: 158,
            reject_signals: Some(vec![142, 145, 155, 157]),
        });
        // ...one initial message left in the `pruned_stream`...
        pruned_stream.push(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        // ...two reject responses for the two remote requests to `OTHER_LOCAL_CANISTER`...
        let context = RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "Canister {} is being migrated to/from {}",
                *OTHER_LOCAL_CANISTER, CANISTER_MIGRATION_SUBNET
            ),
        );
        pruned_stream.push(generate_reject_response(
            test_request(*OTHER_REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into(),
            context.clone(),
        ));
        pruned_stream.push(generate_reject_response(
            test_request(*REMOTE_CANISTER, *OTHER_LOCAL_CANISTER).into(),
            context,
        ));

        // ...and two rerouted responses for the two migrated canisters.
        let mut rerouted_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 0,
            message_count: 0,
            signals_end: 0,
            reject_signals: None,
        });
        rerouted_stream.push(test_response(*LOCAL_CANISTER, *OTHER_LOCAL_CANISTER).into());
        rerouted_stream.push(test_response(*LOCAL_CANISTER, *REMOTE_CANISTER).into());

        expected_state.with_streams(
            btreemap![LOCAL_SUBNET => expected_loopback_stream, REMOTE_SUBNET => pruned_stream, CANISTER_MIGRATION_SUBNET => rerouted_stream],
        );

        // Act
        let inducted_state = stream_handler
            .process_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);

        // Assert
        assert_eq!(
            expected_state.system_metadata(),
            inducted_state.system_metadata(),
        );
        assert_eq!(
            expected_state.canister_state(&LOCAL_CANISTER),
            inducted_state.canister_state(&LOCAL_CANISTER),
        );
        assert_eq!(expected_state, inducted_state);

        // 2 incoming messages discarded and 3 loopback +1 incoming inducted.
        assert_inducted_xnet_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    3,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_CANISTER_MIGRATED),
                    ],
                    3,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    5,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                    ],
                    1,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            6,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        // 7 messages GC-ed from loopback stream, 3 from outgoing stream.
        assert_eq!(
            10,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
        // 3 reject signals from `initial_stream` (138, 139, 142) were GC-ed.
        assert_eq!(
            3,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_REJECT_SIGNALS).unwrap()
        );

        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_XNET_MESSAGE_BACKLOG)
        );
        // Check the number of GC-ed messages in the stream for the remote subnet.
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 3)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_STREAM),
        );
        // Check the number of inducted messages in the slice from the remote subnet.
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &&*REMOTE_SUBNET.to_string().as_str())], 5)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_BACKLOG),
        );
    });
}

/// Tests that attempting to induct a slice with messages for which we have
/// already produced signals panics.
#[test]
#[should_panic(
    expected = "Invalid message indices in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai: messages begin (42) != stream signals_end (43)"
)]
fn process_stream_slices_with_invalid_messages() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, _) = new_fixture(&log);

        // The initial state consists of an output stream with signals_end 43.
        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
            reject_signals: None,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        // The incoming stream slice has 2 messages starting at index 42.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 40,
            header_end: Some(50),
            messages_begin: 42,
            message_count: 2,
            signals_end: 33,
            reject_signals: None,
        });

        stream_handler
            .process_stream_slices(initial_state, btreemap![REMOTE_SUBNET => stream_slice]);
    });
}

/// Sets up the `StreamHandlerImpl`, `ReplicatedState` and `MetricsRegistry` to
/// be used by a test.
fn new_fixture(log: &ReplicaLogger) -> (StreamHandlerImpl, ReplicatedState, MetricsRegistry) {
    new_fixture_with_config(log, HypervisorConfig::default())
}

/// Sets up the `StreamHandlerImpl`, `ReplicatedState` and `MetricsRegistry` to
/// be used by a test, using the provided `HypervisorConfig` to construct the
/// `StreamHandlerImpl`.
fn new_fixture_with_config(
    log: &ReplicaLogger,
    hypervisor_config: HypervisorConfig,
) -> (StreamHandlerImpl, ReplicatedState, MetricsRegistry) {
    let mut state =
        ReplicatedState::new_rooted_at(LOCAL_SUBNET, SubnetType::Application, "NOT_USED".into());
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

    (stream_handler, state, metrics_registry)
}

/// Pushes `messages` into `state` as inputs.
fn push_inputs<'a, I>(state: &mut ReplicatedState, messages: I)
where
    I: std::iter::Iterator<Item = (StreamIndex, &'a RequestOrResponse)>,
{
    for (_stream_index, msg) in messages {
        assert_eq!(
            Ok(()),
            state.push_input(
                QUEUE_INDEX_NONE,
                msg.clone(),
                (u64::MAX / 2).into(),
                &mut (i64::MAX / 2)
            )
        );
    }
}

/// Makes `count` input queue reservations for responses from `remote`.
fn make_input_queue_reservations(canister: &mut CanisterState, count: usize, remote: CanisterId) {
    for _ in 0..count {
        let msg = test_request(*LOCAL_CANISTER, remote);
        register_callback(
            canister,
            msg.sender,
            msg.receiver,
            msg.sender_reply_callback,
        );
        canister.push_output_request(msg).unwrap();
    }
    canister.output_into_iter().count();
}

#[derive(Clone)]
struct SignalConfig {
    end: u64,
    reject_signals: Option<Vec<u64>>,
}

#[derive(Clone)]
struct MessageConfig {
    sender: CanisterId,
    receiver: CanisterId,
    begin: u64,
    count: u64,
}

fn generate_stream(msg_config: MessageConfig, signal_config: SignalConfig) -> Stream {
    let stream_header_builder = StreamHeaderBuilder::new()
        .begin(StreamIndex::from(msg_config.begin))
        .end(StreamIndex::from(msg_config.begin + msg_config.count))
        .signals_end(StreamIndex::from(signal_config.end));

    let msg_begin = StreamIndex::from(msg_config.begin);

    let slice = StreamSliceBuilder::new()
        .header(stream_header_builder.build())
        .generate_messages(
            msg_begin,
            msg_config.count,
            msg_config.sender,
            msg_config.receiver,
        )
        .build();

    let messages = slice
        .messages()
        .cloned()
        .unwrap_or_else(|| StreamIndexedQueue::with_begin(msg_begin));

    if let Some(reject_signals) = signal_config.reject_signals {
        let reject_signals: VecDeque<StreamIndex> = reject_signals
            .iter()
            .map(|x| StreamIndex::from(*x))
            .collect();
        Stream::with_signals(messages, slice.header().signals_end, reject_signals)
    } else {
        Stream::new(messages, slice.header().signals_end)
    }
}

#[derive(Clone)]
struct StreamConfig {
    messages_begin: u64,
    message_count: u64,
    signals_end: u64,
    reject_signals: Option<Vec<u64>>,
}

fn generate_outgoing_stream(config: StreamConfig) -> Stream {
    generate_stream(
        MessageConfig {
            sender: *LOCAL_CANISTER,
            receiver: *REMOTE_CANISTER,
            begin: config.messages_begin,
            count: config.message_count,
        },
        SignalConfig {
            end: config.signals_end,
            reject_signals: config.reject_signals,
        },
    )
}

fn generate_loopback_stream(config: StreamConfig) -> Stream {
    generate_stream(
        MessageConfig {
            sender: *LOCAL_CANISTER,
            receiver: *LOCAL_CANISTER,
            begin: config.messages_begin,
            count: config.message_count,
        },
        SignalConfig {
            end: config.signals_end,
            reject_signals: config.reject_signals,
        },
    )
}

#[derive(Clone)]
struct StreamSliceConfig {
    header_begin: u64,
    header_end: Option<u64>,
    messages_begin: u64,
    message_count: u64,
    signals_end: u64,
    reject_signals: Option<Vec<u64>>,
}

fn generate_stream_slice(config: StreamSliceConfig) -> StreamSlice {
    let stream = generate_stream(
        MessageConfig {
            sender: *REMOTE_CANISTER,
            receiver: *LOCAL_CANISTER,
            begin: config.messages_begin,
            count: config.message_count,
        },
        SignalConfig {
            end: config.signals_end,
            reject_signals: config.reject_signals,
        },
    );
    let mut slice: StreamSlice = stream.into();
    slice.header_mut().begin = StreamIndex::from(config.header_begin);
    if let Some(end) = config.header_end {
        slice.header_mut().end = StreamIndex::from(end);
    }
    slice
}

fn test_request(sender: CanisterId, receiver: CanisterId) -> Request {
    RequestBuilder::new()
        .receiver(receiver)
        .sender(sender)
        .sender_reply_callback(CallbackId::from(1))
        .payment(Cycles::zero())
        .method_name("name".to_string())
        .method_payload(Vec::new())
        .build()
}

fn test_response(respondent: CanisterId, originator: CanisterId) -> Response {
    ResponseBuilder::new()
        .respondent(respondent)
        .originator(originator)
        .originator_reply_callback(CallbackId::from(1))
        .refund(Cycles::zero())
        .response_payload(Payload::Data(Vec::new()))
        .build()
}

/// Asserts that the values of the `METRIC_INDUCTED_XNET_MESSAGES` metric
/// match for the given statuses and are zero for all other statuses.
fn assert_inducted_xnet_messages_eq(expected: MetricVec<u64>, metrics_registry: &MetricsRegistry) {
    assert_eq!(
        expected,
        nonzero_values(fetch_int_counter_vec(
            metrics_registry,
            METRIC_INDUCTED_XNET_MESSAGES
        ))
    );
}

/// Retrieves the `METRIC_INDUCTED_XNET_PAYLOAD_SIZES` histogram's stats.
fn fetch_inducted_payload_sizes_stats(metrics_registry: &MetricsRegistry) -> HistogramStats {
    fetch_histogram_stats(metrics_registry, METRIC_INDUCTED_XNET_PAYLOAD_SIZES).unwrap_or_else(
        || {
            panic!(
                "Histogram not found: {}",
                METRIC_INDUCTED_XNET_PAYLOAD_SIZES
            )
        },
    )
}

/// Populates the given `state`'s canister migrations with a single entry,
/// recording the given migration trace for the given canister.
fn prepare_canister_migration(
    mut state: ReplicatedState,
    migrated_canister: CanisterId,
    from_subnet: SubnetId,
    to_subnet: SubnetId,
) -> ReplicatedState {
    state.metadata.network_topology.canister_migrations = Arc::new(
        CanisterMigrations::try_from(btreemap! {
            CanisterIdRange{ start: migrated_canister, end: migrated_canister } => vec![from_subnet, to_subnet],
        })
        .unwrap(),
    );
    state
}

/// Updates the routing table in `state` to assign the given canister to the
/// `destination` subnet.
fn complete_canister_migration(
    mut state: ReplicatedState,
    migrated_canister: CanisterId,
    destination: SubnetId,
) -> ReplicatedState {
    let mut routing_table = (*state.metadata.network_topology.routing_table).clone();
    routing_table
        .assign_ranges(
            CanisterIdRanges::try_from(vec![CanisterIdRange {
                start: migrated_canister,
                end: migrated_canister,
            }])
            .unwrap(),
            destination,
        )
        .expect("ranges are not well formed");
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

fn assert_eq_critical_error_induct_response_failed(count: u64, metrics_registry: &MetricsRegistry) {
    assert_eq_critical_errors(count, 0, 0, 0, metrics_registry);
}

fn assert_eq_critical_error_reject_signals_for_request(
    count: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq_critical_errors(0, count, 0, 0, metrics_registry);
}

fn assert_eq_critical_error_sender_subnet_mismatch(count: u64, metrics_registry: &MetricsRegistry) {
    assert_eq_critical_errors(0, 0, count, 0, metrics_registry);
}

fn assert_eq_critical_error_receiver_subnet_mismatch(
    count: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq_critical_errors(0, 0, 0, count, metrics_registry);
}

fn assert_eq_critical_errors(
    induct_response_failed: u64,
    reject_signals_for_request: u64,
    sender_subnet_mismatch: u64,
    receiver_subnet_mismatch: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        metric_vec(&[
            (
                &[("error", &CRITICAL_ERROR_INDUCT_RESPONSE_FAILED.to_string())],
                induct_response_failed
            ),
            (
                &[(
                    "error",
                    &CRITICAL_ERROR_REJECT_SIGNALS_FOR_REQUEST.to_string()
                )],
                reject_signals_for_request
            ),
            (
                &[("error", &CRITICAL_ERROR_SENDER_SUBNET_MISMATCH.to_string())],
                sender_subnet_mismatch
            ),
            (
                &[(
                    "error",
                    &CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH.to_string()
                )],
                receiver_subnet_mismatch
            )
        ]),
        fetch_int_counter_vec(metrics_registry, "critical_errors")
    );
}
