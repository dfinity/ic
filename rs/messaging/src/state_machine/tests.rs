use super::*;
use crate::message_routing::{CRITICAL_ERROR_NON_INCREASING_BATCH_TIME, LatencyMetrics};
use crate::routing::demux::MockDemux;
use crate::routing::stream_builder::{MockStreamBuilder, StreamBuilderImpl};
use crate::state_machine::StateMachineImpl;
use ic_config::message_routing::{MAX_STREAM_MESSAGES, TARGET_STREAM_SIZE_BYTES};
use ic_interfaces::execution_environment::Scheduler;
use ic_limits::SYSTEM_SUBNET_STREAM_MSG_LIMIT;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    InputQueueType, ReplicatedState, SubnetTopology,
    metadata_state::testing::NetworkTopologyTesting,
    testing::{OutputRequestBuilder, ReplicatedStateTesting},
};
use ic_test_utilities_execution_environment::test_registry_settings;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, metric_vec, nonzero_values};
use ic_test_utilities_state::new_canister_state;
use ic_test_utilities_types::batch::BatchBuilder;
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1, SUBNET_2};
use ic_test_utilities_types::messages::{RequestBuilder, SignedIngressBuilder};
use ic_types::batch::{BatchMessages, BlockmakerMetrics, ChainKeyData};
use ic_types::messages::{
    CallbackId, CanisterMessage, NO_DEADLINE, Payload, Response, SignedIngress, StreamMessage,
};
use ic_types::time::{CoarseTime, UNIX_EPOCH};
use ic_types::{
    CanisterId, Height, PrincipalId, Randomness, RegistryVersion, ReplicaVersion, Time,
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles, CyclesUseCase};
use maplit::btreemap;
use mockall::{Sequence, mock, predicate::*};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mock! {
    pub Scheduler {}

    impl Scheduler for Scheduler {
        type State = ReplicatedState;
        fn execute_round(
            &self,
            state: ReplicatedState,
            randomness: Randomness,
            chain_key_data: ChainKeyData,
            replica_version: &ReplicaVersion,
            current_round: ExecutionRound,
            round_summary: Option<ExecutionRoundSummary>,
            current_round_type: ExecutionRoundType,
            registry_settings: &RegistryExecutionSettings,
        ) -> ReplicatedState;

        fn checkpoint_round_with_no_execution(&self, state: &mut ReplicatedState);
    }
}

struct StateMachineTestFixture {
    scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
    demux: Box<dyn Demux>,
    stream_builder: Box<dyn StreamBuilder>,
    initial_state: ReplicatedState,
    network_topology: Arc<NetworkTopology>,
    metrics: MessageRoutingMetrics,
    metrics_registry: MetricsRegistry,
}

/// Returns a test fixture for state machine tests with Mocks for Demux,
/// Scheduler, and StreamBuilder. The Mocks will ensure that a panic
/// occurs if they are called in the wrong order.
fn test_fixture(provided_batch: &Batch) -> StateMachineTestFixture {
    // Initial state provided by the state manager.
    let initial_state = ReplicatedState::new(SUBNET_1, SubnetType::Application);
    let metrics_registry = MetricsRegistry::new();
    let metrics = MessageRoutingMetrics::new(&metrics_registry);

    let round = ExecutionRound::from(provided_batch.batch_number.get());
    let round_type = if provided_batch.requires_full_state_hash() {
        ExecutionRoundType::CheckpointRound
    } else {
        ExecutionRoundType::OrdinaryRound
    };

    let mut seq = Sequence::new();

    let (messages, chain_key_data) = match &provided_batch.content {
        BatchContent::Data {
            batch_messages,
            chain_key_data,
            ..
        } => (batch_messages.clone(), chain_key_data.clone()),
        BatchContent::Splitting { .. } => unimplemented!(),
    };

    let mut demux = Box::new(MockDemux::new());
    demux
        .expect_process_payload()
        .times(1)
        .in_sequence(&mut seq)
        .with(always(), eq(round), eq(messages))
        .returning(|state, _, _| state);

    let mut scheduler = Box::new(MockScheduler::new());
    scheduler
        .expect_execute_round()
        .times(1)
        .in_sequence(&mut seq)
        .with(
            always(),
            eq(provided_batch.randomness),
            eq(chain_key_data.clone()),
            eq(provided_batch.replica_version.clone()),
            eq(round),
            eq(None),
            eq(round_type),
            eq(test_registry_settings()),
        )
        .returning(|state, _, _, _, _, _, _, _| state);

    let mut stream_builder = Box::new(MockStreamBuilder::new());
    stream_builder
        .expect_build_streams()
        .times(1)
        .in_sequence(&mut seq)
        .with(always())
        .returning(|state| state);

    let mut subnets = BTreeMap::new();
    subnets.insert(
        SUBNET_0,
        SubnetTopology {
            public_key: vec![0, 1, 2, 3],
            nodes: BTreeSet::new(),
            subnet_type: SubnetType::Application,
            subnet_features: SubnetFeatures::default(),
            chain_keys_held: BTreeSet::new(),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
            subnet_admins: BTreeSet::new(),
        },
    );

    let mut network_topology = NetworkTopology::default();
    network_topology.nns_subnet_id = SUBNET_0;
    network_topology.set_subnets(subnets);

    StateMachineTestFixture {
        scheduler,
        demux,
        stream_builder,
        initial_state,
        network_topology: Arc::new(network_topology),
        metrics,
        metrics_registry,
    }
}

// Utility to build an Ingress message.
fn signed_ingress() -> SignedIngress {
    SignedIngressBuilder::new()
        .sign_for_randomly_generated_sender()
        .build()
}

#[test]
fn state_machine_populates_network_topology() {
    let provided_batch = BatchBuilder::new().batch_number(Height::new(1)).build();
    let fixture = test_fixture(&provided_batch);

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        ));

        assert_ne!(
            fixture.initial_state.metadata.network_topology,
            fixture.network_topology
        );

        let state = state_machine.execute_round(
            fixture.initial_state,
            provided_batch,
            fixture.network_topology.clone(),
            Default::default(),
            &test_registry_settings(),
        );

        assert_eq!(state.metadata.network_topology, fixture.network_topology);
    });
}

// Tests the processing of a batch. Ensures that the Demux, Scheduler, and
// StreamBuilder are invoked in order and that all of them are called.
fn test_delivered_batch(provided_batch: Batch) -> ReplicatedState {
    let fixture = test_fixture(&provided_batch);

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        ));

        state_machine.execute_round(
            fixture.initial_state,
            provided_batch,
            fixture.network_topology.clone(),
            Default::default(),
            &test_registry_settings(),
        )
    })
}

// Parameterized test engine for changing the number of ingress messages
// included in the provided batch.
fn param_batch_test(batch_num: Height, in_count: u64) {
    let mut ingress_messages = Vec::<SignedIngress>::new();
    for _ in 0..in_count {
        let in_msg = signed_ingress();
        ingress_messages.push(in_msg);
    }

    let batch_builder = BatchBuilder::new();
    let provided_batch = batch_builder
        .messages(BatchMessages {
            signed_ingress_msgs: ingress_messages,
            ..BatchMessages::default()
        })
        .batch_number(batch_num)
        .build();

    test_delivered_batch(provided_batch);
}

#[test]
fn test_delivered_batch_interface() {
    for i in 0..2 {
        param_batch_test(Height::from(27), i);
    }
}

#[test]
fn state_machine_handles_messages_to_deleted_subnet() {
    let provided_batch = BatchBuilder::new()
        .batch_number(Height::new(1))
        .time(Time::from_nanos_since_unix_epoch(1))
        .build();

    let mut demux = Box::new(MockDemux::new());
    demux
        .expect_process_payload()
        .times(1)
        .returning(|state, _, _| state);

    let mut scheduler = Box::new(MockScheduler::new());
    scheduler
        .expect_execute_round()
        .times(1)
        .returning(|state, _, _, _, _, _, _, _| state);

    // Build up a state with messages in output queues and
    // a stream to SUBNET_2, which is not in the network topology.
    let mut initial_state = ReplicatedState::new(SUBNET_1, SubnetType::Application);
    let mut subnet_available_memory = i64::MAX / 2;

    // Single canister covering all test scenarios.
    let local_canister_id = CANISTER_RANGE_A.start;
    let mut canister_state = new_canister_state(
        local_canister_id,
        PrincipalId::new_anonymous(),
        Cycles::new(1_000_000_000_000),
        3600.into(),
    );

    // Use a canister ID outside the routing table range so it has no route,
    // causing the stream builder to generate a reject for output requests.
    let remote_canister_id = CANISTER_RANGE_B.start;
    let remote_subnet_as_canister_id = CanisterId::from(SUBNET_2);
    let deadline = CoarseTime::from_secs_since_unix_epoch(u32::MAX);
    // The three amounts below are chosen a couple of orders of magnitude apart so no
    // small integer multiple of one can be mistaken for another in the assertions below.
    // Cycles attached to output-queue requests: refunded in reject responses.
    let req_payment = Cycles::new(1_000_000);
    // Cycles attached to output-queue responses: observed in DroppedMessages metric.
    let resp_refund = Cycles::new(100_000_000);
    // Cycles attached to stream messages: silently dropped, NOT observed in any metric.
    let stream_cycles = Cycles::new(10_000_000_000);

    // For stream requests, we have to first push the requests to the canister output queue
    // and then drain that queue, forwarding each drained request onto the stream — this leaves
    // callbacks + reservations intact while the request itself ends up on the stream.
    // The reservations must remain because generate_reject_responses_for_deleted_subnets()
    // calls push_input() to deliver each synthetic reject, which requires a matching slot.
    // For stream responses, no such preparation is required and
    // they can be pushed to the stream directly below.
    //
    // Regular requests: local_canister → remote_canister.
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(stream_cycles)
                .deadline(deadline)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(stream_cycles)
                .deadline(NO_DEADLINE)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    // Subnet requests: local_canister → remote_subnet_as_canister_id (SUBNET_2's mgmt canister).
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_subnet_as_canister_id)
                .payment(stream_cycles)
                .deadline(deadline)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_subnet_as_canister_id)
                .payment(stream_cycles)
                .deadline(NO_DEADLINE)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    // Drain the output queue, forwarding each request onto the stream to the deleted subnet.
    let mut requests_to_stream = Vec::new();
    canister_state
        .system_state
        .output_queues_for_each(|_, msg| {
            requests_to_stream.push(msg.clone());
            Ok(())
        });
    initial_state.modify_streams(|streams| {
        let stream = streams.entry(SUBNET_2).or_default();
        for msg in requests_to_stream {
            stream.push(msg.into());
        }
    });

    // The following two requests won't have a corresponding entry in the stream,
    // thus corresponding to requests that have already been delivered.
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(stream_cycles)
                .deadline(deadline)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(stream_cycles)
                .deadline(NO_DEADLINE)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    // Drain the output queue, discarding the "already delivered" requests.
    canister_state
        .system_state
        .output_queues_for_each(|_, _| Ok(()));

    // Push regular/subnet bounded-wait/unbounded-wait responses to the stream to the deleted
    // subnet — all are dropped silently when the stream is discarded.
    // Cycles in dropped stream messages are intentionally not observed as lost.
    initial_state.modify_streams(|streams| {
        let stream = streams.entry(SUBNET_2).or_default();
        // Regular responses: remote_canister → local_canister.
        stream.push(StreamMessage::Response(Arc::new(Response {
            originator: remote_canister_id,
            respondent: local_canister_id,
            originator_reply_callback: CallbackId::from(0),
            refund: stream_cycles,
            response_payload: Payload::Data(vec![]),
            deadline,
        })));
        stream.push(StreamMessage::Response(Arc::new(Response {
            originator: remote_canister_id,
            respondent: local_canister_id,
            originator_reply_callback: CallbackId::from(1),
            refund: stream_cycles,
            response_payload: Payload::Data(vec![]),
            deadline: NO_DEADLINE,
        })));
        // Subnet responses: remote_subnet_as_canister_id → local_canister.
        stream.push(StreamMessage::Response(Arc::new(Response {
            originator: remote_subnet_as_canister_id,
            respondent: local_canister_id,
            originator_reply_callback: CallbackId::from(0),
            refund: stream_cycles,
            response_payload: Payload::Data(vec![]),
            deadline,
        })));
        stream.push(StreamMessage::Response(Arc::new(Response {
            originator: remote_subnet_as_canister_id,
            respondent: local_canister_id,
            originator_reply_callback: CallbackId::from(1),
            refund: stream_cycles,
            response_payload: Payload::Data(vec![]),
            deadline: NO_DEADLINE,
        })));
    });
    assert_eq!(
        initial_state
            .get_stream(&SUBNET_2)
            .unwrap()
            .messages()
            .len(),
        8
    );

    // Requests that stay in the canister output queue for build_streams() to reject (payment is refunded, no critical error).
    // Regular requests: local_canister → remote_canister.
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(req_payment)
                .deadline(deadline)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_canister_id)
                .payment(req_payment)
                .deadline(NO_DEADLINE)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    // Subnet requests: local_canister → remote_subnet_as_canister_id (SUBNET_2's mgmt canister).
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_subnet_as_canister_id)
                .payment(req_payment)
                .deadline(deadline)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();
    canister_state
        .push_output_request(
            OutputRequestBuilder::default()
                .sender(local_canister_id)
                .receiver(remote_subnet_as_canister_id)
                .payment(req_payment)
                .deadline(NO_DEADLINE)
                .build(),
            UNIX_EPOCH,
        )
        .unwrap();

    // Responses in the canister output queue for build_streams() to discard (refund cycles
    // are observed in the DroppedMessages metric). The bounded-wait ones are discarded
    // silently; the unbounded-wait ones additionally raise a critical error, since a
    // guaranteed response with no route should never happen other than for a deleted subnet.
    // For every such response, we have to first push and then pop a matching input request
    // to create an output queue reservation.
    // Regular responses: remote_canister → local_canister.
    canister_state
        .push_input(
            RequestBuilder::new()
                .sender(remote_canister_id)
                .receiver(local_canister_id)
                .deadline(deadline)
                .build()
                .into(),
            &mut subnet_available_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    canister_state.pop_input().unwrap();
    canister_state.push_output_response(Arc::new(Response {
        originator: remote_canister_id,
        respondent: local_canister_id,
        originator_reply_callback: CallbackId::from(0),
        refund: resp_refund,
        response_payload: Payload::Data(vec![]),
        deadline,
    }));
    // Use CallbackId::from(1) to get a distinct reservation from the bounded-wait one above.
    canister_state
        .push_input(
            RequestBuilder::new()
                .sender(remote_canister_id)
                .receiver(local_canister_id)
                .sender_reply_callback(CallbackId::from(1))
                .deadline(NO_DEADLINE)
                .build()
                .into(),
            &mut subnet_available_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    canister_state.pop_input().unwrap();
    canister_state.push_output_response(Arc::new(Response {
        originator: remote_canister_id,
        respondent: local_canister_id,
        originator_reply_callback: CallbackId::from(1),
        refund: resp_refund,
        response_payload: Payload::Data(vec![]),
        deadline: NO_DEADLINE,
    }));
    // Subnet responses: remote_subnet_as_canister_id → local_canister.
    initial_state
        .push_input(
            RequestBuilder::new()
                .sender(remote_canister_id)
                .receiver(CanisterId::from(SUBNET_1))
                .deadline(deadline)
                .build()
                .into(),
            &mut subnet_available_memory,
        )
        .unwrap();
    initial_state.pop_subnet_input().unwrap();
    initial_state.push_subnet_output_response(Arc::new(Response {
        originator: remote_canister_id,
        respondent: CanisterId::from(SUBNET_1),
        originator_reply_callback: CallbackId::from(0),
        refund: resp_refund,
        response_payload: Payload::Data(vec![]),
        deadline,
    }));
    // Use CallbackId::from(1) to get a distinct reservation from the bounded-wait one above.
    initial_state
        .push_input(
            RequestBuilder::new()
                .sender(remote_canister_id)
                .receiver(CanisterId::from(SUBNET_1))
                .sender_reply_callback(CallbackId::from(1))
                .deadline(NO_DEADLINE)
                .build()
                .into(),
            &mut subnet_available_memory,
        )
        .unwrap();
    initial_state.pop_subnet_input().unwrap();
    initial_state.push_subnet_output_response(Arc::new(Response {
        originator: remote_canister_id,
        respondent: CanisterId::from(SUBNET_1),
        originator_reply_callback: CallbackId::from(1),
        refund: resp_refund,
        response_payload: Payload::Data(vec![]),
        deadline: NO_DEADLINE,
    }));

    initial_state.put_canister_state(canister_state);

    // Network topology with only SUBNET_0 (NNS) and SUBNET_1 (local); SUBNET_2 is absent.
    let mut subnets = BTreeMap::new();
    subnets.insert(
        SUBNET_0,
        SubnetTopology {
            public_key: vec![0, 1, 2, 3],
            nodes: BTreeSet::new(),
            subnet_type: SubnetType::System,
            subnet_features: SubnetFeatures::default(),
            chain_keys_held: BTreeSet::new(),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
            subnet_admins: BTreeSet::new(),
        },
    );
    subnets.insert(SUBNET_1, SubnetTopology::default());
    let mut network_topology = NetworkTopology::default();
    network_topology.nns_subnet_id = SUBNET_0;
    network_topology.set_subnets(subnets);
    network_topology.set_routing_table(
        RoutingTable::try_from(btreemap! {
            CANISTER_RANGE_NNS => SUBNET_0,
            CANISTER_RANGE_A => SUBNET_1,
        })
        .unwrap(),
    );

    with_test_replica_logger(|log| {
        let metrics_registry = MetricsRegistry::new();
        let message_routing_metrics = MessageRoutingMetrics::new(&metrics_registry);
        let stream_builder = Box::new(StreamBuilderImpl::new(
            SUBNET_1,
            MAX_STREAM_MESSAGES,
            TARGET_STREAM_SIZE_BYTES,
            SYSTEM_SUBNET_STREAM_MSG_LIMIT,
            &metrics_registry,
            &message_routing_metrics,
            Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
                &metrics_registry,
            ))),
            log.clone(),
        ));

        let state_machine = Box::new(StateMachineImpl::new(
            scheduler,
            demux,
            stream_builder,
            log,
            message_routing_metrics,
        ));

        let mut state = state_machine.execute_round(
            initial_state,
            provided_batch,
            Arc::new(network_topology),
            Default::default(),
            &test_registry_settings(),
        );

        // Stream to the deleted subnet (8 messages) is gone — all dropped silently.
        assert!(state.get_stream(&SUBNET_2).is_none());
        // Output queues are empty: requests rejected, responses dropped.
        assert!(
            !state
                .canister_state(&local_canister_id)
                .unwrap()
                .has_output()
        );
        assert!(!state.subnet_queues().has_output());

        // local_canister_id's input queue holds 10 reject responses:
        //   - 4 from build_streams() for output-queue requests (refund = req_payment each);
        //   - 4 synthetic rejects from generate_reject_responses_for_deleted_subnets()
        //       for callbacks with requests in the (dropped) stream (refund = zero);
        //   - 2 synthetic rejects from generate_reject_responses_for_deleted_subnets()
        //       for callbacks with requests already delivered to the deleted subnet (refund = zero).
        let canister = Arc::make_mut(state.canister_state_mut_arc(&local_canister_id).unwrap());
        let mut n_rejects = 0_u32;
        let mut n_destination_invalid = 0_u32;
        let mut n_canister_uninstalled = 0_u32;
        let mut total_refund = Cycles::zero();
        while let Some(msg) = canister.pop_input() {
            let CanisterMessage::Response { response, .. } = msg else {
                panic!("expected reject response, got {msg:?}");
            };
            assert_eq!(response.originator, local_canister_id);
            let Payload::Reject(ctx) = &response.response_payload else {
                panic!(
                    "expected reject payload, got {:?}",
                    response.response_payload
                );
            };
            if ctx.code() == ic_error_types::RejectCode::DestinationInvalid {
                assert!(ctx.message().contains("No route to canister"));
                n_destination_invalid += 1;
            } else {
                ctx.assert_contains(
                    ic_error_types::RejectCode::CanisterReject,
                    "Canister has been uninstalled",
                );
                n_canister_uninstalled += 1;
            }
            total_refund += response.refund;
            n_rejects += 1;
        }
        assert_eq!(n_rejects, 10);
        assert_eq!(n_destination_invalid, 4);
        assert_eq!(n_canister_uninstalled, 6);
        // 4 rejects for output-queue requests each refund req_payment;
        // synthetic rejects from generate_reject_responses_for_deleted_subnets() refund zero.
        assert_eq!(total_refund, req_payment * 4_u64);

        // Dropped output responses (4 total: 2 from canister + 2 from subnet) contribute to the
        // DroppedMessages metric. Stream message cycles are intentionally not tracked.
        let dropped_cycles = state
            .metadata
            .subnet_metrics
            .get_consumed_cycles_by_use_case()
            .get(&CyclesUseCase::DroppedMessages)
            .map(|n| n.get())
            .unwrap_or(0);
        assert_eq!(dropped_cycles, resp_refund.get() * 4);

        // Two critical errors: the unbounded-wait output-queue responses (1 from the canister,
        // 1 from the subnet) discarded by build_streams() due to having no route.
        assert_eq!(
            nonzero_values(metric_vec(&[(
                &[("error", "mr_stream_builder_response_destination_not_found")],
                2,
            )])),
            nonzero_values(fetch_int_counter_vec(&metrics_registry, "critical_errors"))
        );
    });
}

const NNS_SUBNET_ID: SubnetId = SUBNET_0;
const SUBNET_A: SubnetId = SUBNET_1;
const SUBNET_B: SubnetId = SUBNET_2;
const CANISTER_RANGE_NNS: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(0),
    end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
};
const CANISTER_RANGE_A: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET),
    end: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET - 1),
};
const CANISTER_RANGE_B: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET),
    end: CanisterId::from_u64(3 * CANISTER_IDS_PER_SUBNET - 1),
};

/// Returns a test fixture for subnet splitting tests with mocks for Demux,
/// Scheduler, and StreamBuilder. The mocks ensure that only expected calls are
/// made, and they are made in the expected order.
fn split_fixture() -> StateMachineTestFixture {
    // Initial state, with 2 canisters.
    let mut initial_state = ReplicatedState::new(SUBNET_A, SubnetType::Application);
    initial_state.put_canister_state(new_canister_state(
        CANISTER_RANGE_A.start,
        PrincipalId::new_anonymous(),
        Cycles::new(1_000_000_000_000),
        3600.into(),
    ));
    initial_state.put_canister_state(new_canister_state(
        CANISTER_RANGE_B.start,
        PrincipalId::new_anonymous(),
        Cycles::new(1_000_000_000_000),
        3600.into(),
    ));

    let mut scheduler = Box::new(MockScheduler::new());
    let demux = Box::new(MockDemux::new());
    let stream_builder = Box::new(MockStreamBuilder::new());
    let mut seq = Sequence::new();
    scheduler
        .expect_checkpoint_round_with_no_execution()
        .times(1)
        .in_sequence(&mut seq)
        .with(always())
        .return_const(());

    let subnets = btreemap! {
        SUBNET_A => SubnetTopology::default(),
        SUBNET_B => SubnetTopology::default(),
    };
    let mut network_topology = NetworkTopology::default();
    network_topology.nns_subnet_id = NNS_SUBNET_ID;
    network_topology.set_subnets(subnets);
    network_topology.set_routing_table(
        RoutingTable::try_from(btreemap! {
            CANISTER_RANGE_NNS => NNS_SUBNET_ID,
            CANISTER_RANGE_A => SUBNET_A,
            CANISTER_RANGE_B => SUBNET_B,
        })
        .unwrap(),
    );

    let metrics_registry = MetricsRegistry::new();
    let metrics = MessageRoutingMetrics::new(&metrics_registry);

    StateMachineTestFixture {
        scheduler,
        demux,
        stream_builder,
        initial_state,
        network_topology: Arc::new(network_topology),
        metrics,
        metrics_registry,
    }
}

fn test_online_split(new_subnet_id: SubnetId, other_subnet_id: SubnetId) -> ReplicatedState {
    let fixture = split_fixture();
    let split_batch = Batch {
        batch_number: Height::from(0),
        batch_summary: None,
        content: BatchContent::Splitting {
            new_subnet_id,
            other_subnet_id,
        },
        randomness: Randomness::from([0; 32]),
        registry_version: RegistryVersion::from(1),
        time: fixture
            .initial_state
            .metadata
            .batch_time
            .checked_add(Duration::from_secs(1))
            .unwrap(),
        blockmaker_metrics: BlockmakerMetrics::new_for_test(),
        replica_version: ReplicaVersion::default(),
    };

    let state_after_split = with_test_replica_logger(|log| {
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        ));

        state_machine.execute_round(
            fixture.initial_state,
            split_batch,
            fixture.network_topology.clone(),
            Default::default(),
            &test_registry_settings(),
        )
    });

    assert_eq!(
        BTreeMap::new(),
        nonzero_values(fetch_int_counter_vec(
            &fixture.metrics_registry,
            "critical_errors"
        ))
    );

    state_after_split
}

/// Tests a *subnet A* -> *subnet A'* online split.
#[test]
fn test_online_split_subnet_a() {
    let state_after_split = test_online_split(SUBNET_A, SUBNET_B);
    // Only hosting canister `CANISTER_RANGE_0.start`.
    assert_eq!(
        vec![&CANISTER_RANGE_A.start],
        state_after_split
            .canister_states()
            .all_keys()
            .collect::<Vec<_>>()
    );
}

/// Tests a *subnet A* -> *subnet B* online split.
#[test]
fn test_online_split_subnet_b() {
    let state_after_split = test_online_split(SUBNET_B, SUBNET_A);
    // Only hosting canister `CANISTER_RANGE_1.start`.
    assert_eq!(
        vec![&CANISTER_RANGE_B.start],
        state_after_split
            .canister_states()
            .all_keys()
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_batch_time_regression() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(1),
        Time::from_nanos_since_unix_epoch(2),
        1,
    );
}

#[test]
fn test_batch_time_same() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(2),
        1,
    );
}

#[test]
fn test_batch_time_advance() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(3),
        Time::from_nanos_since_unix_epoch(3),
        0,
    );
}

/// Executes a batch with the given `batch_time` on a state with the given
/// `state_batch_time`. Tests the resulting state's `batch_time` against
/// `expected_batch_time`, as well as the `mr_non_increasing_batch_time`
/// critical error counter.
fn test_batch_time_impl(
    state_batch_time: Time,
    batch_time: Time,
    expected_batch_time: Time,
    expected_regression_count: u64,
) {
    // Batch with the provided `batch_time`.
    let provided_batch = BatchBuilder::new()
        .batch_number(Height::new(1))
        .time(batch_time)
        .build();

    // Fixture wrapping a state with the given `state_time` as `batch_time`.
    let mut fixture = test_fixture(&provided_batch);
    fixture.initial_state.metadata.batch_time = state_batch_time;

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        );

        assert_eq!(
            Some(0),
            fetch_critical_error_non_increasing_batch_time_count(&fixture.metrics_registry)
        );
        assert_eq!(state_batch_time, fixture.initial_state.metadata.batch_time,);

        let state = state_machine.execute_round(
            fixture.initial_state,
            provided_batch,
            fixture.network_topology.clone(),
            Default::default(),
            &test_registry_settings(),
        );

        assert_eq!(
            Some(expected_regression_count),
            fetch_critical_error_non_increasing_batch_time_count(&fixture.metrics_registry)
        );
        assert_eq!(expected_batch_time, state.metadata.batch_time);
    });
}

fn fetch_critical_error_non_increasing_batch_time_count(
    metrics_registry: &MetricsRegistry,
) -> Option<u64> {
    fetch_int_counter_vec(metrics_registry, "critical_errors")
        .get(&btreemap! { "error".to_string() => CRITICAL_ERROR_NON_INCREASING_BATCH_TIME.to_string() })
        .cloned()
}
