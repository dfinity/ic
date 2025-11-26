use crate::message_routing::MessageRoutingMetrics;

use super::*;
use ic_base_types::NumSeconds;
use ic_config::message_routing::{MAX_STREAM_MESSAGES, TARGET_STREAM_SIZE_BYTES};
use ic_error_types::RejectCode;
use ic_management_canister_types_private::Method;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, InputQueueType, ReplicatedState, Stream, SubnetTopology,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting, SystemStateTesting},
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    MetricVec, fetch_histogram_stats, fetch_int_counter_vec, fetch_int_gauge_vec, metric_vec,
    nonzero_values,
};
use ic_test_utilities_state::{new_canister_state, register_callback};
use ic_test_utilities_types::{
    ids::{SUBNET_27, SUBNET_42, canister_test_id, user_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    CanisterId, Cycles, SubnetId, Time,
    messages::{
        CallbackId, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, NO_DEADLINE, Payload, RejectContext,
        Request, RequestOrResponse, Response, StreamMessage,
    },
    time::{CoarseTime, UNIX_EPOCH},
    xnet::{StreamIndex, StreamIndexedQueue},
};
use lazy_static::lazy_static;
use maplit::btreemap;
use pretty_assertions::assert_eq;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{
    collections::{BTreeMap, VecDeque},
    convert::TryFrom,
    mem::size_of,
};

const LOCAL_SUBNET: SubnetId = SUBNET_27;
const REMOTE_SUBNET: SubnetId = SUBNET_42;

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const SOME_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(1);

lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

#[test]
fn test_signals_end_metric_exported() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut state, metrics_registry) = new_fixture(&log);

        let stream = Stream::new(
            StreamIndexedQueue::with_begin(StreamIndex::new(0)),
            StreamIndex::new(42),
        );

        state.with_streams(btreemap![LOCAL_SUBNET => stream]);

        stream_builder.build_streams(state);

        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &LOCAL_SUBNET.to_string())],
                StreamIndex::new(42).get()
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_SIGNALS_END)
        );
    });
}

#[test]
fn reject_local_request() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(3);
        let receiver = canister_test_id(4);

        let (stream_builder, mut state, _) = new_fixture(&log);

        // A CanisterState to test on.
        let canister_id = canister_test_id(3);
        let mut canister_state = new_canister_state(
            canister_id,
            user_test_id(1).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );

        // With a reservation on an input queue.
        let payment = Cycles::new(100);
        let callback_id = register_callback(&mut canister_state, sender, receiver, NO_DEADLINE);
        let msg = generate_message_for_test(
            sender,
            receiver,
            callback_id,
            "method".to_string(),
            payment,
            NO_DEADLINE,
        );

        canister_state
            .push_output_request(msg.clone().into(), UNIX_EPOCH)
            .unwrap();
        canister_state
            .system_state
            .queues_mut()
            .pop_canister_output(&msg.receiver)
            .unwrap();
        state.put_canister_state(canister_state);
        let mut expected_state = state.clone();

        // Reject the message.
        let reject_message = (0..MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN + 1)
            .map(|_| "a")
            .collect::<String>();
        stream_builder.reject_local_request(
            &mut state,
            &msg,
            RejectCode::SysFatal,
            reject_message.clone(),
        );

        // Which should result in a reject Response being enqueued onto the input queue.
        let expected_reject_context = RejectContext::new_with_message_length_limit(
            RejectCode::SysFatal,
            reject_message,
            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
        );
        assert_eq!(
            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
            expected_reject_context.message().len()
        );
        expected_state
            .push_input(
                Response {
                    originator: msg.sender,
                    respondent: msg.receiver,
                    originator_reply_callback: msg.sender_reply_callback,
                    refund: msg.payment,
                    response_payload: Payload::Reject(expected_reject_context),
                    deadline: msg.deadline,
                }
                .into(),
                &mut (i64::MAX / 2),
            )
            .unwrap();

        assert_eq!(
            expected_state.canister_state(&canister_id).unwrap(),
            state.canister_state(&canister_id).unwrap()
        );
    });
}

// Tests that the OutputQueues are fully drained.
#[test]
fn build_streams_success() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        //Set up the expected Stream from the messages.
        let expected_stream = Stream::new(
            requests_into_queue_round_robin(
                StreamIndex::from(0),
                msgs.clone(),
                None,
                provided_state.time(),
            ),
            Default::default(),
        );
        let expected_stream_bytes = expected_stream.count_bytes() as u64;
        let expected_stream_begin = expected_stream.messages_begin().get();
        let expected_signals_end = expected_stream.signals_end().get();

        // Set up the provided_canister_states.
        let provided_canister_states = canister_states_with_outputs(msgs);
        provided_state.put_canister_states(provided_canister_states);

        // Expect all canister outputs to have been consumed.
        let mut expected_state = consume_output_queues(&provided_state);

        // Establish the expected ReplicatedState that holds the expected_stream_state.
        expected_state.modify_streams(|streams| {
            streams.insert(REMOTE_SUBNET, expected_stream);
        });

        assert_eq!(
            btreemap! {},
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN)
        );

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(14, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 14)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                expected_stream_bytes
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                expected_stream_begin
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                expected_signals_end
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_SIGNALS_END)
        );
    });
}

// Tests that messages between local canisters get routed.
#[test]
fn build_streams_local_canisters() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        // The provided_canister_states contains the source canisters with outgoing
        // messages, but also the destination canisters of all messages.
        let mut provided_canister_states = canister_states_with_outputs(msgs.clone());
        for msg in &msgs {
            provided_canister_states
                .entry(msg.receiver)
                .or_insert_with(|| {
                    new_canister_state(
                        msg.receiver,
                        msg.sender.get(),
                        *INITIAL_CYCLES,
                        NumSeconds::from(100_000),
                    )
                });
        }

        // Establish that the provided_state has the provided_canister_states.
        provided_state.put_canister_states(provided_canister_states);

        // Ensure the routing table knows about the `LOCAL_SUBNET`.
        let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => LOCAL_SUBNET,
        }).unwrap());
        provided_state.metadata.network_topology.routing_table = Arc::clone(&routing_table);

        // Set up the expected Stream from the messages.
        let expected_stream = Stream::new(
            requests_into_queue_round_robin(
                StreamIndex::from(0),
                msgs,
                None,
                provided_state.time(),
            ),
            Default::default(),
        );
        let expected_stream_bytes = expected_stream.count_bytes() as u64;

        // The expected_canister_states contains both the source canisters with consumed
        // messages, but also the destination canisters of all messages.
        let mut expected_state = consume_output_queues(&provided_state);

        // Establish the expected ReplicatedState that holds the expected_stream_state
        // and expected_canister_states
        expected_state.modify_streams(|streams| {
            streams.insert(LOCAL_SUBNET, expected_stream);
        });

        expected_state.metadata.network_topology.routing_table = routing_table;

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(14, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &LOCAL_SUBNET.to_string())], 14)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &LOCAL_SUBNET.to_string())],
                expected_stream_bytes
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
    });
}

#[test]
fn build_streams_impl_at_message_limit_leaves_state_untouched() {
    build_streams_impl_at_limit_leaves_state_untouched_impl(0, usize::MAX);
}

#[test]
fn build_streams_impl_at_memory_limit_leaves_state_untouched() {
    build_streams_impl_at_limit_leaves_state_untouched_impl(usize::MAX, 0);
}

fn build_streams_impl_at_limit_leaves_state_untouched_impl(
    max_stream_messages: usize,
    target_stream_size_bytes: usize,
) {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) =
            new_fixture_with_limits(&log, max_stream_messages, target_stream_size_bytes);
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

        // We put an empty stream for the destination subnet into the state because
        // the implementation of stream builder will always allow one message if
        // the stream does not exist yet.
        let mut streams = provided_state.take_streams();
        streams.entry(REMOTE_SUBNET).or_default();
        provided_state.put_streams(streams);

        // Set up the provided_canister_states.
        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);
        let provided_canister_states = canister_states_with_outputs(msgs);
        provided_state.put_canister_states(provided_canister_states);

        let expected_state = provided_state.clone();

        // Act.
        let result_state = stream_builder.build_streams_impl(provided_state.clone());
        assert_eq!(result_state, expected_state);

        assert_eq!(
            btreemap! {},
            nonzero_values(fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN)),
        );
        assert_eq!(
            btreemap! {},
            nonzero_values(fetch_int_counter_vec(
                &metrics_registry,
                METRIC_ROUTED_MESSAGES
            ))
        );
        assert_eq!(0, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            btreemap! {},
            nonzero_values(fetch_int_gauge_vec(
                &metrics_registry,
                METRIC_STREAM_MESSAGES
            ))
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                Stream::new(StreamIndexedQueue::default(), Default::default()).count_bytes() as u64
            )]),
            nonzero_values(fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES))
        );
        assert_eq!(
            btreemap! {},
            nonzero_values(fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN))
        );
    });
}

/// Helper for testing `build_streams_impl()` with various message or byte size
/// limits.
///
/// `max_stream_messages` is passed to `build_streams_impl()` as the parameter
/// of the same name. `max_stream_messages_by_byte_size` is multiplied by the
/// generated message size and passed as the `target_stream_size_bytes`
/// parameter. `expected_messages` is the number of messages expected to have
/// been routed.
fn build_streams_impl_respects_limits(
    max_stream_messages: usize,
    max_stream_messages_by_byte_size: usize,
    expected_messages: u64,
) {
    with_test_replica_logger(|log| {
        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);
        let msg_count = msgs.len();
        // All messages returned by `generate_messages_for_test` are of the same size
        let msg_size = msgs.first().unwrap().count_bytes() as u64;

        // Target stream size: stream struct plus `max_stream_messages_by_byte_size - 1`
        // messages plus 1 byte. Since this is a target / soft limit, it should ensure
        // that exactly `max_stream_messages_by_byte_size` messages (or
        // `max_stream_messages_by_byte_size * msg_size` bytes) are routed.
        let target_stream_size_bytes =
            size_of::<Stream>() + (max_stream_messages_by_byte_size - 1) * msg_size as usize + 1;

        let (stream_builder, mut provided_state, metrics_registry) =
            new_fixture_with_limits(&log, max_stream_messages, target_stream_size_bytes);
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

        assert!(
            msg_count > expected_messages as usize,
            "Invalid test setup: msg_count ({msg_count}) must be greater than routed_messages ({expected_messages})"
        );

        // Set up the provided_canister_states.
        let provided_canister_states = canister_states_with_outputs(msgs.clone());
        provided_state.put_canister_states(provided_canister_states);

        // Expected state starts off from the provided state.
        let mut expected_state = provided_state.clone();

        // With `routed_messages` consumed from output queues.
        expected_state
            .output_into_iter()
            .take(expected_messages as usize)
            .count();

        // And the same `routed_messages` in the stream to `REMOTE_SUBNET`.
        let expected_stream = Stream::new(
            requests_into_queue_round_robin(
                StreamIndex::from(0),
                msgs,
                Some(expected_messages * msg_size),
                provided_state.time(),
            ),
            Default::default(),
        );
        expected_state.modify_streams(|streams| {
            streams.insert(REMOTE_SUBNET, expected_stream);
        });

        // Act.
        let result_state = stream_builder.build_streams_impl(provided_state);

        assert_eq!(expected_state.canister_states, result_state.canister_states);
        assert_eq!(expected_state.metadata, result_state.metadata);
        assert_eq!(expected_state, result_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                expected_messages,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            expected_messages,
            fetch_routed_payload_count(&metrics_registry)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                expected_messages
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                Stream::new(StreamIndexedQueue::default(), Default::default()).count_bytes() as u64
                    + expected_messages * msg_size
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN)
        );
    });
}

#[test]
fn build_streams_impl_respects_byte_size_limit() {
    build_streams_impl_respects_limits(1_000_000, 4, 4);
}

#[test]
fn build_streams_impl_respects_message_limit() {
    build_streams_impl_respects_limits(4, 1_000_000, 4);
}

// Tests that messages addressed to canisters not mapped to a known subnet
// result in reject Responses.
#[test]
fn build_streams_reject_response_on_unknown_destination_subnet() {
    with_test_replica_logger(|log| {
        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        // Set up the provided_canister_states.
        let provided_canister_states = canister_states_with_outputs(msgs.clone());
        provided_state.put_canister_states(provided_canister_states);

        // Expect all messages in canister output queues to have been consumed.
        let mut expected_state = consume_output_queues(&provided_state);

        // Build up the expected stream: one reject Response for each request.
        for msg in msgs {
            let receiver = msg.receiver;
            stream_builder.reject_local_request(
                &mut expected_state,
                &msg,
                RejectCode::DestinationInvalid,
                format!("No route to canister {receiver}"),
            );
        }

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_CANISTER_NOT_FOUND),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(0, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            btreemap! {},
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            btreemap! {},
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
    });
}

#[test]
fn build_streams_with_messages_targeted_to_other_subnets() {
    with_test_replica_logger(|log| {
        let msgs = vec![generate_message_for_test(
            canister_test_id(0),
            CanisterId::from(REMOTE_SUBNET),
            CallbackId::from(1),
            Method::CanisterStatus.to_string(),
            Cycles::new(0),
            NO_DEADLINE,
        )];

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        // Ensure the routing table knows about the `REMOTE_SUBNET`.
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());
        provided_state
            .metadata
            .network_topology
            .subnets
            .insert(REMOTE_SUBNET, Default::default());

        // Set up the provided_canister_states.
        let provided_canister_states = canister_states_with_outputs(msgs.clone());
        provided_state.put_canister_states(provided_canister_states);

        // Set up the expected Stream from the messages.
        let expected_stream = Stream::new(
            requests_into_queue_round_robin(
                StreamIndex::from(0),
                msgs,
                None,
                provided_state.time(),
            ),
            Default::default(),
        );
        let expected_stream_bytes = expected_stream.count_bytes() as u64;

        // Expected ReplicatedState has the message routed from the canister output
        // queue into the remote stream.
        let mut expected_state = consume_output_queues(&provided_state);
        expected_state.modify_streams(|streams| {
            streams.insert(REMOTE_SUBNET, expected_stream);
        });

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                1,
            )]),
            &metrics_registry,
        );
        assert_eq!(1, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 1)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                expected_stream_bytes
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
    });
}

fn build_streams_with_best_effort_messages_impl(
    local_subnet_type: SubnetType,
    remote_subnet_type: SubnetType,
) {
    let local_canister_id = canister_test_id(0);
    let remote_canister_id = canister_test_id(1);
    with_test_replica_logger(|log| {
        // Two best-effort requests: one local and one remote.
        let msgs = vec![
            RequestBuilder::new()
                .sender(local_canister_id)
                .receiver(local_canister_id)
                .sender_reply_callback(CallbackId::from(1))
                .deadline(SOME_DEADLINE)
                .build(),
            RequestBuilder::new()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .sender_reply_callback(CallbackId::from(2))
                .deadline(SOME_DEADLINE)
                .build(),
        ];

        let (stream_builder, mut provided_state, _) = new_fixture(&log);

        // Set the subnet types of the local and remote subnets.
        provided_state.metadata.network_topology.subnets = btreemap! {
            LOCAL_SUBNET => SubnetTopology {subnet_type: local_subnet_type, ..Default::default()},
            REMOTE_SUBNET => SubnetTopology {subnet_type: remote_subnet_type, ..Default::default()},
        };
        // Ensure that the routing table knows about `LOCAL_SUBNET` and `REMOTE_SUBNET`.
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: local_canister_id, end: local_canister_id } => LOCAL_SUBNET,
                CanisterIdRange{ start: remote_canister_id, end: remote_canister_id } => REMOTE_SUBNET,
            },
        ).unwrap());

        // Set up a canister with `msgs` in its output queues.
        let provided_canister_states = canister_states_with_outputs(msgs.clone());
        provided_state.put_canister_states(provided_canister_states);

        let result_state = stream_builder.build_streams(provided_state);

        // Local best-effort request was routed.
        assert!(
            !result_state
                .streams()
                .get(&LOCAL_SUBNET)
                .unwrap()
                .messages()
                .is_empty(),
            "Local subnet type: {local_subnet_type:?}, Remote subnet type: {remote_subnet_type:?}",
        );

        // Remote best-effort request was routed.
        assert!(
            !result_state
                .streams()
                .get(&REMOTE_SUBNET)
                .unwrap()
                .messages()
                .is_empty(),
            "Local subnet type: {local_subnet_type:?}, Remote subnet type: {remote_subnet_type:?}",
        );

        // No reject response was enqueued.
        let maybe_reject_response = result_state
            .canister_state(&local_canister_id)
            .unwrap()
            .clone()
            .pop_input();
        assert!(
            maybe_reject_response.is_none(),
            "Local subnet type: {local_subnet_type:?}, Remote subnet type: {remote_subnet_type:?}",
        );
    });
}

#[test]
fn build_streams_with_best_effort_messages() {
    for local_subnet_type in &[
        SubnetType::Application,
        SubnetType::System,
        SubnetType::VerifiedApplication,
    ] {
        for remote_subnet_type in &[
            SubnetType::Application,
            SubnetType::System,
            SubnetType::VerifiedApplication,
        ] {
            build_streams_with_best_effort_messages_impl(*local_subnet_type, *remote_subnet_type);
        }
    }
}

// Tests that remote requests and all responses with oversized payloads are rejected.
#[test]
fn build_streams_with_oversized_payloads() {
    with_test_replica_logger(|log| {
        let local_canister = canister_test_id(0);
        let remote_canister = canister_test_id(1);
        let method_name: String = ['a'; 13].iter().collect();

        // Payloads/error message that result in `get_payload_size()` returning exactly
        // `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 + 1`.
        let oversized_request_payload: Vec<u8> = std::iter::repeat_n(
            0u8,
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize - method_name.len() + 1,
        )
        .collect();
        let oversized_response_payload: Vec<u8> =
            std::iter::repeat_n(0u8, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 1)
                .collect();
        let oversized_error_message: String =
            "x".repeat(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize);

        // Oversized local request: will be routed normally, we allow oversized local
        // requests for installing canisters with large Wasm binaries.
        let local_request = Request {
            sender: local_canister,
            receiver: local_canister,
            sender_reply_callback: CallbackId::from(1),
            payment: Cycles::new(1),
            method_name: method_name.clone(),
            method_payload: oversized_request_payload.clone(),
            metadata: Default::default(),
            deadline: NO_DEADLINE,
        };
        assert!(local_request.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);

        // Oversized remote request: will be rejected locally.
        let remote_request = Request {
            sender: local_canister,
            receiver: remote_canister,
            sender_reply_callback: CallbackId::from(2),
            payment: Cycles::new(2),
            method_name,
            method_payload: oversized_request_payload,
            metadata: Default::default(),
            deadline: NO_DEADLINE,
        };
        assert!(remote_request.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);
        let remote_request_reject = Response {
            originator: local_canister,
            respondent: remote_canister,
            originator_reply_callback: CallbackId::from(2),
            refund: Cycles::new(2),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!(
                    "Canister {} violated contract: attempted to send a message of size {} exceeding the limit {}",
                    local_canister,
                    remote_request.payload_size_bytes(),
                    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
                ),
            )),
            deadline: NO_DEADLINE,
        };

        // Oversized response: will be replaced with a reject response.
        let data_response = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(3),
            response_payload: Payload::Data(oversized_response_payload),
            deadline: NO_DEADLINE,
        };
        assert!(data_response.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);
        let data_response_reject = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(3),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!(
                    "Canister {} violated contract: attempted to send a message of size {} exceeding the limit {}",
                    local_canister,
                    data_response.payload_size_bytes(),
                    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
                ),
            )),
            deadline: NO_DEADLINE,
        };

        // Oversized reject response: will be replaced with a reject response.
        let reject_response = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(4),
            refund: Cycles::new(4),
            // Abuse `RejectContext::from_canonical()`, as it doesn't truncate the message.
            response_payload: Payload::Reject(RejectContext::from_canonical(
                RejectCode::SysTransient,
                oversized_error_message,
            )),
            deadline: NO_DEADLINE,
        };
        assert!(reject_response.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);
        let reject_response_reject = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(4),
            refund: Cycles::new(4),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::SysTransient,
                // Long enough message to be properly truncated by the constructor.
                "x".repeat(10 * 1024),
            )),
            deadline: NO_DEADLINE,
        };

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        // Map local canister to `LOCAL_SUBNET` and remote canister to `REMOTE_SUBNET`.
        provided_state.metadata.network_topology.routing_table = Arc::new(
            RoutingTable::try_from(btreemap! {
                CanisterIdRange{ start: local_canister, end: local_canister } => LOCAL_SUBNET,
                CanisterIdRange{ start: remote_canister, end: remote_canister } => REMOTE_SUBNET,
            })
            .unwrap(),
        );

        // Provided_canister_states with oversized payload messages as outputs.
        let provided_canister_states = canister_states_with_outputs::<RequestOrResponse>(vec![
            local_request.clone().into(),
            remote_request.into(),
            data_response.into(),
            reject_response.into(),
        ]);
        provided_state.put_canister_states(provided_canister_states);

        // Expecting all canister outputs to have been consumed.
        let mut expected_state = consume_output_queues(&provided_state);

        // Expecting a reject response for the remote request.
        let local_canister = expected_state.canister_state_mut(&local_canister).unwrap();
        push_input(local_canister, remote_request_reject.into());

        // Expecting a loopback stream consisting of:
        //  * successfully routed local request;
        //  * no remote request routed;
        //  * responses replaced with reject responses.
        let mut expected_stream_messages = StreamIndexedQueue::with_begin(0.into());
        expected_stream_messages.push(local_request.into());
        expected_stream_messages.push(data_response_reject.into());
        expected_stream_messages.push(reject_response_reject.into());
        let expected_stream = Stream::new(expected_stream_messages, Default::default());
        let expected_stream_bytes = expected_stream.count_bytes() as u64;
        expected_state.modify_streams(|streams| {
            streams.insert(LOCAL_SUBNET, expected_stream);
        });

        // Act
        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(expected_state.canister_states, result_state.canister_states);
        assert_eq!(expected_state.metadata, result_state.metadata);
        assert_eq!(expected_state, result_state);

        assert_routed_messages_eq(
            metric_vec(&[
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                        (LABEL_STATUS, LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE),
                    ],
                    1,
                ),
                (
                    &[
                        (LABEL_TYPE, LABEL_VALUE_TYPE_RESPONSE),
                        (LABEL_STATUS, LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE),
                    ],
                    2,
                ),
            ]),
            &metrics_registry,
        );
        assert_eq!(1, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &LOCAL_SUBNET.to_string())], 3)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &LOCAL_SUBNET.to_string())],
                expected_stream_bytes
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
        assert_eq_critical_errors(2, 0, &metrics_registry);
    });
}

/// Sets up the `StreamHandlerImpl`, `ReplicatedState` and `MetricsRegistry` to
/// be used by a test using specific stream limits.
fn new_fixture_with_limits(
    log: &ReplicaLogger,
    max_stream_messages: usize,
    target_stream_size_bytes: usize,
) -> (StreamBuilderImpl, ReplicatedState, MetricsRegistry) {
    let mut state = ReplicatedState::new(LOCAL_SUBNET, SubnetType::Application);
    state.metadata.batch_time = Time::from_nanos_since_unix_epoch(5);
    let metrics_registry = MetricsRegistry::new();
    let stream_builder = StreamBuilderImpl::new(
        LOCAL_SUBNET,
        max_stream_messages,
        target_stream_size_bytes,
        &metrics_registry,
        &MessageRoutingMetrics::new(&metrics_registry),
        Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
            &metrics_registry,
        ))),
        log.clone(),
    );

    (stream_builder, state, metrics_registry)
}

/// Sets up the `StreamHandlerImpl`, `ReplicatedState` and `MetricsRegistry` to
/// be used by a test using default stream limits.
fn new_fixture(log: &ReplicaLogger) -> (StreamBuilderImpl, ReplicatedState, MetricsRegistry) {
    new_fixture_with_limits(log, MAX_STREAM_MESSAGES, TARGET_STREAM_SIZE_BYTES)
}

/// Simulates routing the given requests into a `StreamIndexedQueue` with the
/// given `start` index, until `byte_limit` is reached or exceeded.
///
/// It takes into account the pseudorandom rotation of the canisters thats done
/// based on the batch time, but assumes that there are no messages in subnet
/// queues.
fn requests_into_queue_round_robin(
    start: StreamIndex,
    requests: Vec<Request>,
    byte_limit: Option<u64>,
    time: Time,
) -> StreamIndexedQueue<StreamMessage> {
    let mut queue = StreamIndexedQueue::with_begin(start);

    let mut request_map: BTreeMap<CanisterId, BTreeMap<CanisterId, VecDeque<Request>>> =
        BTreeMap::new();
    for request in requests {
        request_map
            .entry(request.sender)
            .or_default()
            .entry(request.receiver)
            .or_default()
            .push_back(request);
    }

    type CanistersWithQueues = VecDeque<(CanisterId, VecDeque<Request>)>;
    let mut request_ring: VecDeque<(CanisterId, CanistersWithQueues)> = request_map
        .into_iter()
        .map(|(canister, requests)| (canister, requests.into_iter().collect()))
        .collect();

    let mut rng = ChaChaRng::seed_from_u64(time.as_nanos_since_unix_epoch());
    let rotation = rng.random_range(0..request_ring.len().max(1));
    request_ring.rotate_left(rotation);

    let mut bytes_routed = 0;
    while let Some((src, mut requests)) = request_ring.pop_front() {
        if let Some((dst, mut req_queue)) = requests.pop_front() {
            if let Some(request) = req_queue.pop_front() {
                if let Some(limit) = byte_limit
                    && bytes_routed >= limit
                {
                    break;
                }
                let req: StreamMessage = request.into();
                bytes_routed += req.count_bytes() as u64;
                queue.push(req);
                requests.push_back((dst, req_queue));
            }
            request_ring.push_back((src, requests));
        }
    }

    queue
}

/// Generates a collection of messages for test purposes based on the number of
/// canisters that should send/receive messages.
fn generate_messages_for_test(senders: u64, receivers: u64) -> Vec<Request> {
    let mut messages = Vec::new();
    for snd in 3..(3 + senders) {
        let sender = canister_test_id(snd);
        let mut next_callback_id = 0;
        let payment = Cycles::new(100);
        // Round robin across receivers, to emulate the ordering of `output_into_iter()`.
        for i in snd..2 * snd {
            for rcv in 700..(700 + receivers) {
                let receiver = canister_test_id(rcv);
                next_callback_id += 1;
                messages.push(generate_message_for_test(
                    sender,
                    receiver,
                    CallbackId::from(next_callback_id),
                    format!("req_{snd}_{rcv}_{i}"),
                    payment,
                    NO_DEADLINE,
                ));
            }
        }
    }
    messages
}

fn generate_message_for_test(
    sender: CanisterId,
    receiver: CanisterId,
    callback_id: CallbackId,
    method_name: String,
    payment: Cycles,
    deadline: CoarseTime,
) -> Request {
    RequestBuilder::default()
        .sender(sender)
        .receiver(receiver)
        .sender_reply_callback(callback_id)
        .method_name(method_name)
        .payment(payment)
        .deadline(deadline)
        .build()
}

// Generates `CanisterStates` with the given messages in output queues.
fn canister_states_with_outputs<M: Into<RequestOrResponse>>(
    msgs: Vec<M>,
) -> BTreeMap<CanisterId, CanisterState> {
    let mut canister_states = BTreeMap::<CanisterId, CanisterState>::new();

    for msg in msgs {
        let msg = msg.into();
        let canister_state = canister_states.entry(msg.sender()).or_insert_with(|| {
            new_canister_state(
                msg.sender(),
                msg.sender().get(),
                *INITIAL_CYCLES,
                NumSeconds::from(100_000),
            )
        });

        match msg {
            RequestOrResponse::Request(req) => {
                let callback_id =
                    register_callback(canister_state, req.sender, req.receiver, req.deadline);
                // Check the implicit assumption that the test messages were generated with a
                // `sender_reply_callback` that is consistent with the callback IDs that the
                // `CallContextManager` generates and registers.
                assert_eq!(req.sender_reply_callback, callback_id);

                canister_state.push_output_request(req, UNIX_EPOCH).unwrap();
            }

            RequestOrResponse::Response(rep) => {
                // First push then pop a matching input request, to create a reservation.
                let req = generate_message_for_test(
                    rep.originator,
                    rep.respondent,
                    rep.originator_reply_callback,
                    "".to_string(),
                    Cycles::new(0),
                    NO_DEADLINE,
                );
                push_input(canister_state, req.into());
                canister_state.system_state.pop_input().unwrap();

                canister_state.push_output_response(rep);
            }
        }
    }

    canister_states
}

/// Returns a clone of the provided state with all output messages consumed.
fn consume_output_queues(state: &ReplicatedState) -> ReplicatedState {
    let mut state = state.clone();
    state.output_into_iter().count();
    state
}

/// Pushes the message into the given canister's corresponding input queue.
fn push_input(canister_state: &mut CanisterState, msg: RequestOrResponse) {
    let mut subnet_available_memory = 1 << 30;
    assert!(
        canister_state
            .push_input(
                msg,
                &mut subnet_available_memory,
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
}

/// Asserts that the values of the `METRIC_ROUTED_MESSAGES` metric
/// match for the given statuses and are zero for all other statuses.
fn assert_routed_messages_eq(expected: MetricVec<u64>, metrics_registry: &MetricsRegistry) {
    assert_eq!(
        expected,
        nonzero_values(fetch_int_counter_vec(
            metrics_registry,
            METRIC_ROUTED_MESSAGES
        ))
    );
}

/// Retrieves the `METRIC_ROUTED_PAYLOAD_SIZES` histogram's count.
fn fetch_routed_payload_count(metrics_registry: &MetricsRegistry) -> u64 {
    fetch_histogram_stats(metrics_registry, METRIC_ROUTED_PAYLOAD_SIZES)
        .unwrap_or_else(|| panic!("Histogram not found: {METRIC_ROUTED_PAYLOAD_SIZES}"))
        .count
}

fn assert_eq_critical_errors(
    payload_too_large: u64,
    response_destination_not_found: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        nonzero_values(metric_vec(&[
            (&[("error", &CRITICAL_ERROR_INFINITE_LOOP)], 0),
            (
                &[("error", &CRITICAL_ERROR_PAYLOAD_TOO_LARGE)],
                payload_too_large
            ),
            (
                &[("error", &CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND)],
                response_destination_not_found
            )
        ])),
        nonzero_values(fetch_int_counter_vec(metrics_registry, "critical_errors"))
    );
}
