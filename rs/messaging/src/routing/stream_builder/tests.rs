use super::*;
use ic_base_types::NumSeconds;
use ic_error_types::RejectCode;
use ic_ic00_types::Method;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting, SystemStateTesting},
    CanisterState, InputQueueType, ReplicatedState, Stream, SubnetTopology,
};
use ic_test_utilities::{
    metrics::{
        fetch_histogram_stats, fetch_int_counter_vec, fetch_int_gauge_vec, metric_vec,
        nonzero_values, MetricVec,
    },
    state::{new_canister_state, register_callback},
    types::{
        ids::{canister_test_id, user_test_id, SUBNET_27, SUBNET_42},
        messages::RequestBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
    },
    xnet::{StreamIndex, StreamIndexedQueue},
    CanisterId, Cycles, SubnetId, Time,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{
    collections::{BTreeMap, VecDeque},
    convert::TryFrom,
};

const LOCAL_SUBNET: SubnetId = SUBNET_27;
const REMOTE_SUBNET: SubnetId = SUBNET_42;

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
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
        let payment = Cycles::from(100);
        let msg = generate_message_for_test(
            sender,
            receiver,
            CallbackId::from(1),
            "method".to_string(),
            payment,
        );
        register_callback(
            &mut canister_state,
            msg.sender,
            msg.receiver,
            msg.sender_reply_callback,
        );

        canister_state.push_output_request(msg.clone()).unwrap();
        canister_state
            .system_state
            .queues_mut()
            .pop_canister_output(&msg.receiver)
            .unwrap();
        state.put_canister_state(canister_state);
        let mut expected_state = state.clone();

        // Reject the message.
        let reject_message = "Reject response";
        stream_builder.reject_local_request(
            &mut state,
            msg.clone(),
            RejectCode::SysFatal,
            reject_message.to_string(),
        );

        // Which should result in a reject Response being enqueued onto the input queue.
        expected_state
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: msg.sender,
                    respondent: msg.receiver,
                    originator_reply_callback: msg.sender_reply_callback,
                    refund: msg.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: RejectCode::SysFatal,
                        message: reject_message.to_string(),
                    }),
                }
                .into(),
                (u64::MAX / 2).into(),
                &mut (i64::MAX / 2),
            )
            .unwrap();

        assert_eq!(
            expected_state.canister_state(&canister_id).unwrap(),
            state.canister_state(&canister_id).unwrap()
        );
    });
}

#[test]
fn reject_local_request_for_subnet() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut state, _) = new_fixture(&log);

        // With a reservation on the subnet input queue.
        let payment = Cycles::from(100);
        let subnet_id = state.metadata.own_subnet_id;
        let subnet_id_as_canister_id = CanisterId::from(subnet_id);
        let msg = generate_message_for_test(
            subnet_id_as_canister_id,
            canister_test_id(0),
            CallbackId::from(1),
            "method".to_string(),
            payment,
        );

        state
            .subnet_queues_mut()
            .push_output_request(msg.clone())
            .unwrap();
        state
            .subnet_queues_mut()
            .pop_canister_output(&msg.receiver)
            .unwrap();

        let mut expected_state = state.clone();

        // Reject the message.
        let reject_message = "Reject response";
        stream_builder.reject_local_request(
            &mut state,
            msg.clone(),
            RejectCode::SysFatal,
            reject_message.to_string(),
        );

        // Which should result in a reject Response being enqueued onto the subnet
        // queue.
        expected_state
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: msg.sender,
                    respondent: msg.receiver,
                    originator_reply_callback: msg.sender_reply_callback,
                    refund: msg.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: RejectCode::SysFatal,
                        message: reject_message.to_string(),
                    }),
                }
                .into(),
                (u64::MAX / 2).into(),
                &mut (i64::MAX / 2),
            )
            .unwrap();

        assert_eq!(expected_state.subnet_queues(), state.subnet_queues());
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
fn build_streams_impl_at_limit_leaves_state_untouched() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

        // We put an empty stream for the destination subnet into the state because
        // the implementation of stream builder will always allow one message if
        // the stream does not exist yet.
        let mut streams = provided_state.take_streams();
        streams.get_mut_or_insert(REMOTE_SUBNET);
        provided_state.put_streams(streams);

        // Set up the provided_canister_states.
        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);
        let provided_canister_states = canister_states_with_outputs(msgs);
        provided_state.put_canister_states(provided_canister_states);

        let expected_state = provided_state.clone();

        // Act.
        let result_state = stream_builder.build_streams_impl(provided_state, 0);

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

#[test]
fn build_streams_impl_respects_limit() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);
        let msg_count = msgs.len();
        // All messages returned by `generate_messages_for_test` are of the same size
        let msg_size = msgs.get(0).unwrap().count_bytes() as u64;

        let routed_messages: u64 = 4;
        assert!(
            msg_count > routed_messages as usize,
            "Invalid test setup: msg_count ({}) must be greater than routed_messages ({})",
            msg_count,
            routed_messages
        );

        // Set up the provided_canister_states.
        let provided_canister_states = canister_states_with_outputs(msgs.clone());
        provided_state.put_canister_states(provided_canister_states);

        // Expected state starts off from the provided state.
        let mut expected_state = provided_state.clone();

        // With `routed_messages` consumed from output queues.
        expected_state
            .output_into_iter()
            .take(routed_messages as usize)
            .count();

        // And the same `routed_messages` in the stream to `REMOTE_SUBNET`.
        let expected_stream = Stream::new(
            requests_into_queue_round_robin(
                StreamIndex::from(0),
                msgs,
                Some(routed_messages * msg_size),
                provided_state.time(),
            ),
            Default::default(),
        );
        expected_state.modify_streams(|streams| {
            streams.insert(REMOTE_SUBNET, expected_stream);
        });

        // Act.
        let result_state = stream_builder
            .build_streams_impl(provided_state, (routed_messages * msg_size) as usize);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                routed_messages,
            )]),
            &metrics_registry,
        );
        assert_eq!(
            routed_messages,
            fetch_routed_payload_count(&metrics_registry)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                routed_messages
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
        assert_eq!(
            metric_vec(&[(
                &[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())],
                Stream::new(StreamIndexedQueue::default(), Default::default()).count_bytes() as u64
                    + routed_messages * msg_size
            )]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BYTES)
        );
        assert_eq!(
            metric_vec(&[(&[(LABEL_REMOTE, &REMOTE_SUBNET.to_string())], 0)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_BEGIN)
        );
    });
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
                msg,
                RejectCode::DestinationInvalid,
                format!("No route to canister {}", receiver),
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
        )];

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        // Ensure the routing table knows about the `REMOTE_SUBNET`.
        provided_state.metadata.network_topology.routing_table = Arc::new(RoutingTable::try_from(
            btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
            },
        ).unwrap());

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

// Tests that remote requests and all responses with oversized payloads are rejected.
#[test]
fn build_streams_with_oversized_payloads() {
    with_test_replica_logger(|log| {
        use std::iter::repeat;
        let local_canister = canister_test_id(0);
        let remote_canister = canister_test_id(1);
        let method_name: String = ['a'; 13].iter().collect();

        // Payloads/error message that result in `get_payload_size()` returning exactly
        // `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 + 1`.
        let oversized_request_payload: Vec<u8> = repeat(0u8)
            .take(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize - method_name.len() + 1)
            .collect();
        let oversized_response_payload: Vec<u8> = repeat(0u8)
            .take(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 1)
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
                    "Canister {} violated contract: payload too large",
                    local_canister
                ),
            )),
        };

        // Oversized response: will be replaced with a reject response.
        let data_response = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(3),
            response_payload: Payload::Data(oversized_response_payload),
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
                    "Canister {} violated contract: payload too large",
                    local_canister
                ),
            )),
        };

        // Oversized reject response: will be replaced with a reject response.
        let reject_response = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(4),
            refund: Cycles::new(4),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::SysTransient,
                oversized_error_message,
            )),
        };
        assert!(reject_response.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);
        let reject_response_reject = Response {
            originator: local_canister,
            respondent: local_canister,
            originator_reply_callback: CallbackId::from(4),
            refund: Cycles::new(4),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::SysTransient,
                "x".repeat(5 * 1024) + "..." + &"x".repeat(2 * 1024),
            )),
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
/// be used by a test.
fn new_fixture(log: &ReplicaLogger) -> (StreamBuilderImpl, ReplicatedState, MetricsRegistry) {
    let mut state =
        ReplicatedState::new_rooted_at(LOCAL_SUBNET, SubnetType::Application, "NOT_USED".into());
    state.metadata.batch_time = Time::from_nanos_since_unix_epoch(5);
    let metrics_registry = MetricsRegistry::new();
    let stream_handler = StreamBuilderImpl::new(
        LOCAL_SUBNET,
        &metrics_registry,
        Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
            &metrics_registry,
        ))),
        log.clone(),
    );

    (stream_handler, state, metrics_registry)
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
) -> StreamIndexedQueue<RequestOrResponse> {
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
    let rotation = rng.gen_range(0, request_ring.len().max(1));
    request_ring.rotate_left(rotation);

    let mut bytes_routed = 0;
    while let Some((src, mut requests)) = request_ring.pop_front() {
        if let Some((dst, mut req_queue)) = requests.pop_front() {
            if let Some(request) = req_queue.pop_front() {
                if let Some(limit) = byte_limit {
                    if bytes_routed >= limit {
                        break;
                    }
                }
                let req = RequestOrResponse::Request(request);
                bytes_routed += req.count_bytes() as u64;
                queue.push(req);
                requests.push_back((dst, req_queue));
            }
            request_ring.push_back((src, requests));
        }
    }

    queue
}

// Generates a collection of messages for test purposes based on the number of
// canisters that should send/receive messages.
fn generate_messages_for_test(senders: u64, receivers: u64) -> Vec<Request> {
    let mut messages = Vec::new();
    for snd in 3..(3 + senders) {
        let sender = canister_test_id(snd);
        let mut next_callback_id = 0;
        let payment = Cycles::from(100);
        for rcv in 700..(700 + receivers) {
            let receiver = canister_test_id(rcv);
            for i in snd..2 * snd {
                next_callback_id += 1;
                messages.push(generate_message_for_test(
                    sender,
                    receiver,
                    CallbackId::from(next_callback_id),
                    format!("req_{}_{}_{}", snd, rcv, i),
                    payment,
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
) -> Request {
    RequestBuilder::default()
        .sender(sender)
        .receiver(receiver)
        .sender_reply_callback(callback_id)
        .method_name(method_name)
        .payment(payment)
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
                // Create a matching callback, so that enqueuing any reject response will succeed.
                register_callback(
                    canister_state,
                    req.sender,
                    req.receiver,
                    req.sender_reply_callback,
                );

                canister_state.push_output_request(req).unwrap();
            }

            RequestOrResponse::Response(rep) => {
                // First push then pop a matching input request, to create a reservation.
                let req = generate_message_for_test(
                    rep.originator,
                    rep.respondent,
                    rep.originator_reply_callback,
                    "".to_string(),
                    Cycles::new(0),
                );
                push_input(canister_state, req.into());
                canister_state
                    .system_state
                    .queues_mut()
                    .pop_input()
                    .unwrap();

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
    canister_state
        .push_input(
            QUEUE_INDEX_NONE,
            msg,
            (1 << 30).into(),
            &mut subnet_available_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap()
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
        .unwrap_or_else(|| panic!("Histogram not found: {}", METRIC_ROUTED_PAYLOAD_SIZES))
        .count
}

fn assert_eq_critical_errors(
    payload_too_large: u64,
    response_destination_not_found: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        metric_vec(&[
            (&[("error", &CRITICAL_ERROR_INFINITE_LOOP)], 0),
            (
                &[("error", &CRITICAL_ERROR_PAYLOAD_TOO_LARGE)],
                payload_too_large
            ),
            (
                &[("error", &CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND)],
                response_destination_not_found
            )
        ]),
        fetch_int_counter_vec(metrics_registry, "critical_errors")
    );
}

/// Tests that requests sending cycles from Application to VerifiedApplication
/// subnets are rejected.
#[test]
fn build_streams_sending_cycles_from_app_to_verified_app_subnets() {
    with_test_replica_logger(|log| {
        let local_canister = canister_test_id(0);
        let remote_canister = canister_test_id(1);
        let method_name: String = ['a'; 13].iter().collect();

        // Request that sends cycles.
        let remote_request = Request {
            sender: local_canister,
            receiver: remote_canister,
            sender_reply_callback: CallbackId::from(1),
            payment: Cycles::new(1),
            method_name,
            method_payload: vec![],
        };

        // Reject for sending cycles from app to verified app subnets.
        let remote_request_reject = Response {
            originator: local_canister,
            respondent: remote_canister,
            originator_reply_callback: CallbackId::from(1),
            refund: Cycles::new(1),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!("Canister {} violated contract: Canisters on Application subnets cannot send cycles to canister {} on a Verified Application subnet", local_canister, remote_canister),
            )),
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

        // Make the LOCAL_SUBNET an Application subnet.
        provided_state.metadata.network_topology.subnets.insert(
            LOCAL_SUBNET,
            SubnetTopology {
                subnet_type: SubnetType::Application,
                ..SubnetTopology::default()
            },
        );
        // Make the REMOTE_SUBNET a VerifiedApplication subnet.
        provided_state.metadata.network_topology.subnets.insert(
            REMOTE_SUBNET,
            SubnetTopology {
                subnet_type: SubnetType::VerifiedApplication,
                ..SubnetTopology::default()
            },
        );

        // Provided_canister_states with message sending cycles as output.
        let provided_canister_states =
            canister_states_with_outputs::<RequestOrResponse>(vec![remote_request.into()]);
        provided_state.put_canister_states(provided_canister_states);

        // Expecting all canister outputs to have been consumed.
        let mut expected_state = consume_output_queues(&provided_state);

        // Expecting a reject response for the remote request.
        let local_canister = expected_state.canister_state_mut(&local_canister).unwrap();
        push_input(local_canister, remote_request_reject.into());

        // Act
        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(expected_state.canister_states, result_state.canister_states);
        assert_eq!(expected_state.metadata, result_state.metadata);
        assert_eq!(expected_state, result_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_INVALID_CYCLE_TRANSFER),
                ],
                1,
            )]),
            &metrics_registry,
        );
    });
}
