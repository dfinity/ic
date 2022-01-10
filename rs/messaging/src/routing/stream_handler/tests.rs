// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]

use super::*;
use crate::message_routing::{LABEL_REMOTE, METRIC_TIME_IN_BACKLOG, METRIC_TIME_IN_STREAM};
use ic_base_types::NumSeconds;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    replicated_state::{LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_OUT_OF_MEMORY},
    testing::ReplicatedStateTesting,
    ReplicatedState, Stream,
};
use ic_test_utilities::{
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, fetch_int_counter, fetch_int_counter_vec,
        fetch_int_gauge_vec, metric_vec, nonzero_values, HistogramStats, MetricVec,
    },
    state::new_canister_state,
    types::ids::{user_test_id, SUBNET_12, SUBNET_23},
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
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const MAX_CANISTER_MEMORY_SIZE: NumBytes = NumBytes::new(u64::MAX / 2);
const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(u64::MAX / 2);

lazy_static! {
    static ref LOCAL_CANISTER: CanisterId = CanisterId::from(0x34);
    static ref REMOTE_CANISTER: CanisterId = CanisterId::from(0x134);
    static ref UNKNOWN_CANISTER: CanisterId = CanisterId::from(0x234);
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

#[test]
#[should_panic(
    expected = "Expecting loopback stream signals to end (22) where messages begin (21)"
)]
fn induct_loopback_stream_with_signals_panics() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut state, _) = new_fixture(&log);

        // A loopback stream containing 2 messages and 1 signal.
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 2,
            signals_end: 22,
        });
        state.with_streams(btreemap![LOCAL_SUBNET => loopback_stream]);

        stream_handler.induct_loopback_stream(state);
    });
}

#[test]
#[should_panic(
    expected = "Expecting loopback stream signals to end (20) where messages begin (21)"
)]
fn induct_loopback_stream_signals_end_before_messages_begin_panics() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut state, _) = new_fixture(&log);

        // A loopback stream with signals().end() != messages().begin().
        let loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 21,
            message_count: 2,
            signals_end: 20,
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
                receiver: *REMOTE_CANISTER,
                begin: 21,
                count: 1,
            },
            SignalConfig { end: 21 },
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
        });
        // ...plus a reject response.
        let context = RejectContext::new(
            RejectCode::DestinationInvalid,
            StateError::CanisterNotFound(*REMOTE_CANISTER).to_string(),
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

        for (_stream_index, msg) in loopback_stream.messages().iter() {
            assert_eq!(
                Ok(()),
                expected_state.push_input(
                    QUEUE_INDEX_NONE,
                    msg.clone(),
                    (u64::MAX / 2).into(),
                    &mut (i64::MAX / 2)
                )
            );
        }

        // ...and an empty loopback stream with begin indices advanced by 2.
        let expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 23,
            message_count: 0,
            signals_end: 23,
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
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
        });

        // The expected state must contain a stream that does not contain the specified
        // messages; the stream header should be unmodified from the input (and is not
        // consistent with the contained messages).
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 43,
        });

        let mut stats = Default::default();
        stream_handler.garbage_collect_messages(
            StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );

        assert_eq!(expected_stream, stream);
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid signals in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_before_first_message() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, _) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 24,
        });

        let mut stats = Default::default();
        stream_handler.garbage_collect_messages(
            StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
        );
    });
}

#[test]
#[should_panic(
    expected = "Invalid signals in stream slice from subnet 5h3gz-qaxaa-aaaaa-aaaap-yai"
)]
fn assert_garbage_collect_messages_last_signal_after_last_message() {
    with_test_replica_logger(|log| {
        let (stream_handler, _, _) = new_fixture(&log);

        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
        });

        let slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 35,
        });

        let mut stats = Default::default();
        stream_handler.garbage_collect_messages(
            StreamHandle::new(&mut stream, &mut stats),
            REMOTE_SUBNET,
            &slice,
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
    });
}

/// Tests that a provided Stream results in all messages in the stream_state
/// being garbage collected appropriately.
#[test]
fn garbage_collect_local_state_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
        let mut expected_state = initial_state.clone();

        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
        });
        initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

        // 2 incoming messages, 3 partially overlapping incoming signals.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: None,
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
        });

        // The expected state must contain only messages past the last signal (index
        // 33).
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 43,
        });
        expected_state.with_streams(btreemap![REMOTE_SUBNET => expected_stream]);

        let pruned_state = stream_handler
            .garbage_collect_local_state(initial_state, &btreemap![REMOTE_SUBNET => stream_slice]);

        assert_eq!(pruned_state, expected_state);
        assert_eq!(
            2,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );
    });
}

#[test]
fn enqueue_reject_response_queue_full() {
    with_test_replica_logger(|log| {
        // Arbitrary initial output stream.
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 42,
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

        let (stream_handler, _, _) = new_fixture(&log);
        let mut stats = Default::default();
        stream_handler.try_enqueue_reject_response(
            msg_clone.into(),
            RejectCode::SysTransient,
            err.to_string(),
            &mut StreamHandle::new(&mut stream, &mut stats),
        );

        assert_eq!(expected_stream, stream);
    });
}

#[test]
fn enqueue_reject_response_canister_not_found() {
    with_test_replica_logger(|log| {
        // Arbitrary initial output stream.
        let mut stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 42,
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

        let (stream_handler, _, _) = new_fixture(&log);
        let mut stats = Default::default();
        stream_handler.try_enqueue_reject_response(
            msg_clone.into(),
            RejectCode::DestinationInvalid,
            err.to_string(),
            &mut StreamHandle::new(&mut stream, &mut stats),
        );

        assert_eq!(expected_stream, stream);
    });
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
        initial_canister_state
            .push_output_request(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER))
            .unwrap();
        initial_canister_state.output_into_iter().count();
        initial_state.put_canister_state(initial_canister_state);

        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
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
        });

        // ...and one incoming response.
        let response: RequestOrResponse = test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into();
        stream_slice.push_message(response);

        // The expected canister state must contain the 3 inducted messages...
        if let Some(messages) = stream_slice.messages() {
            for (_stream_index, msg) in messages.iter() {
                assert_eq!(
                    Ok(()),
                    expected_state.push_input(
                        QUEUE_INDEX_NONE,
                        msg.clone(),
                        (u64::MAX / 2).into(),
                        &mut (i64::MAX / 2)
                    )
                );
            }
        }
        // ...and signals for the 3 inducted messages in the stream.
        let mut expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 46,
        });

        // Push a request addressed to a missing canister into the input stream.
        let request_to_missing_canister: RequestOrResponse =
            test_request(*REMOTE_CANISTER, *REMOTE_CANISTER).into();
        stream_slice.push_message(request_to_missing_canister.clone());

        // And expect one signal and one reject Response in the output stream.
        expected_stream.increment_signals_end();
        expected_stream.push(generate_reject_response(
            request_to_missing_canister,
            RejectContext::new(
                RejectCode::DestinationInvalid,
                StateError::CanisterNotFound(*REMOTE_CANISTER).to_string(),
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
            test_response(*REMOTE_CANISTER, *REMOTE_CANISTER).into();
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
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_SENDER_SUBNET_UNKNOWN),
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

/// Tests that canister memory limit is enforced when inducting stream slices.
///
/// Sets up a stream handler with only enough canister memory for one in-flight
/// request (plus epsilon) at a time; and a canister with one in-flight
/// (outgoing) request. Tries to induct a slice consisting of `[request1,
/// response, request2]`: `request1` will fail due to lack of memory; `response`
/// will be inducted and consume the existing reservation; `request2` will be
/// inducted successfully, as there is now available memory for one request.
#[test]
fn induct_stream_slices_canister_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Canister memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_memory_capacity: SUBNET_MEMORY_CAPACITY,
                max_canister_memory_size: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                ..Default::default()
            },
        );

        induct_stream_slices_memory_limits_impl(stream_handler, initial_state, metrics_registry);
    });
}

/// Tests that subnet memory limit is enforced when inducting stream slices.
///
/// Sets up a stream handler with only enough subnet available memory for one
/// in-flight request (plus epsilon) at a time; and a canister with one
/// in-flight (outgoing) request. Tries to induct a slice consisting of
/// `[request1, response, request2]`: `request1` will fail due to lack of
/// memory; `response` will be inducted and consume the existing reservation;
/// `request2` will be inducted successfully, as there is now available memory
/// for one request.
#[test]
fn induct_stream_slices_subnet_memory_limit() {
    if !ENFORCE_MESSAGE_MEMORY_USAGE {
        return;
    }

    with_test_replica_logger(|log| {
        // Subnet memory limit only allows for one in-flight request (plus epsilon).
        let (stream_handler, initial_state, metrics_registry) = new_fixture_with_config(
            &log,
            HypervisorConfig {
                subnet_memory_capacity: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64 * 15 / 10),
                max_canister_memory_size: MAX_CANISTER_MEMORY_SIZE,
                ..Default::default()
            },
        );

        induct_stream_slices_memory_limits_impl(stream_handler, initial_state, metrics_registry);
    });
}

fn induct_stream_slices_memory_limits_impl(
    stream_handler: StreamHandlerImpl,
    mut initial_state: ReplicatedState,
    metrics_registry: MetricsRegistry,
) {
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
    initial_canister_state
        .push_output_request(test_request(*LOCAL_CANISTER, *REMOTE_CANISTER))
        .unwrap();
    initial_canister_state.output_into_iter().count();
    initial_state.put_canister_state(initial_canister_state);
    let mut expected_state = initial_state.clone();

    let initial_stream = generate_outgoing_stream(StreamConfig {
        messages_begin: 31,
        message_count: 3,
        signals_end: 43,
    });
    let mut expected_stream = initial_stream.clone();
    initial_state.with_streams(btreemap![REMOTE_SUBNET => initial_stream]);

    // Incoming slice: `request1`, response, `request2`.
    let mut stream_slice = generate_stream_slice(StreamSliceConfig {
        header_begin: 43,
        header_end: None,
        messages_begin: 43,
        message_count: 0,
        signals_end: 31,
    });
    let request1 = request_with_callback(13);
    stream_slice.push_message(request1.clone());
    stream_slice.push_message(test_response(*REMOTE_CANISTER, *LOCAL_CANISTER).into());
    let request2 = request_with_callback(14);
    stream_slice.push_message(request2);

    // The expected canister state must contain the response and `request2`...
    if let Some(messages) = stream_slice.messages() {
        for (_stream_index, msg) in messages.iter().skip(1) {
            assert_eq!(
                Ok(()),
                expected_state.push_input(
                    QUEUE_INDEX_NONE,
                    msg.clone(),
                    (u64::MAX / 2).into(),
                    &mut (i64::MAX / 2)
                )
            );
        }
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

/// Tests that given a loopback stream and a certified stream slice,
/// messages are inducted (with signals added appropriately), and
/// messages present in the initial state are removed as appropriate.
#[test]
fn process_certified_stream_slices_success() {
    with_test_replica_logger(|log| {
        let (stream_handler, mut initial_state, metrics_registry) = new_fixture(&log);
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
        });

        // ...and an output stream with 3 messages.
        let initial_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 31,
            message_count: 3,
            signals_end: 43,
        });

        stream_handler
            .time_in_stream_metrics
            .lock()
            .unwrap()
            .record_header(REMOTE_SUBNET, &initial_stream.header());
        initial_state.with_streams(
            btreemap![LOCAL_SUBNET => loopback_stream.clone(), REMOTE_SUBNET => initial_stream],
        );

        //
        // The incoming stream slice has 2 messages and 2 signals.
        let stream_slice = generate_stream_slice(StreamSliceConfig {
            header_begin: 42,
            header_end: Some(50),
            messages_begin: 43,
            message_count: 2,
            signals_end: 33,
        });

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
        for (_stream_index, msg) in loopback_stream.messages().iter() {
            assert_eq!(
                Ok(()),
                expected_state.push_input(
                    QUEUE_INDEX_NONE,
                    msg.clone(),
                    (u64::MAX / 2).into(),
                    &mut (i64::MAX / 2)
                )
            );
        }
        // ...and the 2 incoming messages inducted.
        if let Some(messages) = stream_slice.messages() {
            for (_stream_index, msg) in messages.iter() {
                assert_eq!(
                    Ok(()),
                    expected_state.push_input(
                        QUEUE_INDEX_NONE,
                        msg.clone(),
                        (u64::MAX / 2).into(),
                        &mut (i64::MAX / 2)
                    )
                );
            }
        }

        //
        // The expected `Streams` have...
        // ...all loopback messages consumed and garbage collected...
        let expected_loopback_stream = generate_loopback_stream(StreamConfig {
            messages_begin: 24,
            message_count: 0,
            signals_end: 24,
        });

        // ...one message left, and signals for the 2 inducted messages.
        let expected_stream = generate_outgoing_stream(StreamConfig {
            messages_begin: 33,
            message_count: 1,
            signals_end: 45,
        });

        expected_state.with_streams(
            btreemap![LOCAL_SUBNET => expected_loopback_stream, REMOTE_SUBNET => expected_stream],
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

        // 3 loopback + 2 incoming messages inducted.
        assert_inducted_xnet_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_SUCCESS),
                ],
                5,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            5,
            fetch_inducted_payload_sizes_stats(&metrics_registry).count
        );
        // 3 messages GC-ed from loopback stream, 2 from outgoing stream.
        assert_eq!(
            5,
            fetch_int_counter(&metrics_registry, METRIC_GCED_XNET_MESSAGES).unwrap()
        );

        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 5)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_XNET_MESSAGE_BACKLOG)
        );
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &REMOTE_SUBNET.to_string().as_str())], 2)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_STREAM),
        );
        assert_eq!(
            metric_vec(&[(&[(&LABEL_REMOTE, &&*REMOTE_SUBNET.to_string().as_str())], 2)]),
            fetch_histogram_vec_count(&metrics_registry, METRIC_TIME_IN_BACKLOG),
        );
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

#[derive(Clone)]
struct SignalConfig {
    end: u64,
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

    Stream::new(
        slice
            .messages()
            .cloned()
            .unwrap_or_else(|| StreamIndexedQueue::with_begin(msg_begin)),
        slice.header().signals_end,
    )
}

#[derive(Clone)]
struct StreamConfig {
    messages_begin: u64,
    message_count: u64,
    signals_end: u64,
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
        .sender_reply_callback(CallbackId::from(0))
        .payment(Cycles::zero())
        .method_name("name".to_string())
        .method_payload(Vec::new())
        .build()
}

fn test_response(respondent: CanisterId, originator: CanisterId) -> Response {
    ResponseBuilder::new()
        .respondent(respondent)
        .originator(originator)
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
