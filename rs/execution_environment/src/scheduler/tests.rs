use super::test_utilities::{SchedulerTestBuilder, ingress, on_response, other_side};
use super::*;
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::execution_environment::STOP_CANISTER_TIMEOUT_DURATION;
use ic_config::subnet_config::SchedulerConfig;
use ic_management_canister_types_private::{
    self as ic00, BoundedHttpHeaders, CanisterHttpResponsePayload, CanisterIdRecord,
    CanisterStatusType, EcdsaKeyId, EmptyBlob, Method, Payload as _, SchnorrKeyId,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{CanisterStatus, metadata_state::testing::NetworkTopologyTesting};
use ic_state_machine_tests::{PayloadBuilder, StateMachineBuilder};
use ic_test_utilities_metrics::{fetch_counter, fetch_histogram_vec_buckets};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::CallbackId;
use ic_types::time::{UNIX_EPOCH, expiry_time_from_now};
use ic_types::{ComputeAllocation, Cycles};
use ic_types_test_utils::ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id};
use ic00::{CanisterHttpRequestArgs, HttpMethod};
use proptest::prelude::*;
use std::time::Duration;

mod charging;
mod dts;
mod ecdsa;
mod limits;
mod metrics;
mod rate_limiting;
mod routing;
mod scheduling;
mod subnet_messages;
mod timers;

#[test]
fn stopping_canisters_are_stopped_when_they_are_ready() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister();

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg,
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(
        test.canister_state(canister).status(),
        CanisterStatusType::Stopped
    );
}

#[test]
fn stopping_canisters_are_not_stopped_if_not_ready() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister();

    // Open a call context by calling a cross-net canister.

    test.send_ingress(
        canister,
        ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg,
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    assert_eq!(CanisterStatusType::Stopping, system_state.status());
}

#[test]
fn canister_is_stopped_if_timeout_occurs_and_ready_to_stop() {
    use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};

    let test = StateMachineBuilder::new().build();

    let canister_id = test
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Open a call context, so that the canister doesn't stop immediately.
    {
        let payload = Encode!(&CanisterHttpRequestArgs {
            url: "https://example.com".to_string(),
            headers: BoundedHttpHeaders::new(vec![]),
            method: HttpMethod::GET,
            body: None,
            transform: None,
            max_response_bytes: None,
            is_replicated: None,
            pricing_version: None,
        })
        .unwrap();

        test.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    "http_request",
                    call_args()
                        .other_side(payload)
                        .on_reject(wasm().reject_message().reject()),
                )
                .into(),
        );
        test.tick();
    }

    // Send request to stop the canister.
    let stop_msg = {
        let arg = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        let stop_msg = test.send_ingress(
            PrincipalId::new_anonymous(),
            ic00::IC_00,
            "stop_canister",
            arg,
        );
        test.tick();
        stop_msg
    };

    // The canister should now be stopping.
    {
        let status = test.canister_status(canister_id).unwrap().unwrap();
        assert_eq!(status.status(), CanisterStatusType::Stopping);
    }

    // Add the response to the output queue so that the context can be closed.
    {
        let response = CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: vec![],
        };

        let payload = PayloadBuilder::new().http_response(CallbackId::from(0), &response);
        test.execute_payload(payload);
    }

    // Advance the time such that the stop request has, in theory, timed out.
    test.advance_time(STOP_CANISTER_TIMEOUT_DURATION + Duration::from_secs(1));

    // Execute rounds, closing the call context and stopping the canister.
    // Even though the request should've timed out, it doesn't because the canister was ready to
    // stop when we were about to return a timeout, so instead we stop the canister and return
    // a success.
    assert!(test.await_ingress(stop_msg, 2).is_ok());

    // The canister has stopped.
    {
        let status = test.canister_status(canister_id).unwrap().unwrap();
        assert_eq!(status.status(), CanisterStatusType::Stopped);
    }
}

#[test]
fn can_timeout_stop_canister_requests() {
    let batch_time = Time::from_nanos_since_unix_epoch(u64::MAX / 2);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(batch_time)
        .build();

    let canister = test.create_canister();

    // Open a call context by calling a cross-net canister.

    test.send_ingress(
        canister,
        ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    test.set_time(batch_time + Duration::from_secs(60));
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    match system_state.get_status() {
        CanisterStatus::Stopping { stop_contexts, .. } => {
            // There are 3 associated stop_context due to the stop request that
            // was sent above.
            assert_eq!(stop_contexts.len(), 3);
        }
        CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
            unreachable!("Expected the canister to be in stopping mode");
        }
    }

    // Progress the time so that some stop_contexts will expire.
    test.set_time(batch_time + STOP_CANISTER_TIMEOUT_DURATION + Duration::from_secs(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    match system_state.get_status() {
        CanisterStatus::Stopping { stop_contexts, .. } => {
            // The first two stop_contexts should have expired, 1 is still active.
            assert_eq!(stop_contexts.len(), 1);
        }
        CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
            unreachable!("Expected the canister to be in stopping mode");
        }
    }
}

#[test]
fn expired_ingress_messages_are_removed_from_ingress_queues() {
    let batch_time = Time::from_nanos_since_unix_epoch(u64::MAX / 2);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(batch_time)
        .build();

    let canister_id = test.create_canister();

    // Add some ingress messages to a canister's queue.
    // Half of them are set with expiry time before the
    // time of the current round while the other half
    // are set to expire after the current round.
    let num_ingress_messages_to_canisters = 10;
    for i in 0..num_ingress_messages_to_canisters {
        if i % 2 == 0 {
            test.send_ingress_with_expiry(
                canister_id,
                ingress(1000),
                batch_time.saturating_sub(Duration::from_secs(1)),
            );
        } else {
            test.send_ingress_with_expiry(
                canister_id,
                ingress(1000),
                batch_time + Duration::from_secs(1),
            );
        }
    }

    // Add some ingress messages to the subnet's queue.
    // Half of them are set with expiry time before the
    // time of the current round while the other half
    // are set to expire after the current round.
    let num_ingress_messages_to_subnet: u64 = 20;
    for i in 0..num_ingress_messages_to_subnet {
        if i % 2 == 0 {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(
                Method::CanisterStatus,
                payload,
                batch_time + Duration::from_secs(1),
            );
        } else {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(
                Method::CanisterStatus,
                payload,
                batch_time.saturating_sub(Duration::from_secs(1)),
            );
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Ingress queues should be empty, messages either expired
    // or were executed in the round.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(test.subnet_ingress_queue_size(), 0);

    // Verify that half of the messages expired and the other half got executed.
    assert_eq!(
        fetch_counter(
            test.metrics_registry(),
            "scheduler_expired_ingress_messages_count",
        )
        .unwrap() as u64,
        (num_ingress_messages_to_canisters / 2) + (num_ingress_messages_to_subnet / 2)
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        (num_ingress_messages_to_canisters / 2) + (num_ingress_messages_to_subnet / 2)
    );
}

#[test]
fn test_is_next_method_added_to_task_queue() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        None,
        None,
    );
    let has_heartbeat = false;
    let has_active_timer = false;

    let mut heartbeat_and_timer_canisters = BTreeSet::new();
    assert!(
        !test
            .canister_state(canister)
            .system_state
            .queues()
            .has_input()
    );

    for _ in 0..3 {
        // The timer did not reach the deadline and the canister does not have
        // input, hence no method will be chosen.
        assert!(!is_next_method_chosen(
            test.canister_state_mut(canister),
            has_heartbeat,
            has_active_timer,
            &mut heartbeat_and_timer_canisters,
        ));
        assert_eq!(heartbeat_and_timer_canisters, BTreeSet::new());
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    // Make canister able to schedule both heartbeat and global timer.
    let has_heartbeat = true;
    let has_active_timer = true;

    // Set input.
    test.canister_state_mut(canister)
        .system_state
        .queues_mut()
        .push_ingress(Ingress {
            source: user_test_id(77),
            receiver: canister,
            effective_canister_id: None,
            method_name: String::from("test"),
            method_payload: vec![1_u8],
            message_id: message_test_id(555),
            expiry_time: expiry_time_from_now(),
        });

    assert!(
        test.canister_state(canister)
            .system_state
            .queues()
            .has_input()
    );

    while test.canister_state(canister).get_next_scheduled_method() != NextScheduledMethod::Message
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        has_heartbeat,
        has_active_timer,
        &mut heartbeat_and_timer_canisters,
    ));

    // Since NextScheduledMethod is Message it is not expected that Heartbeat
    // and GlobalTimer are added to the queue.
    assert!(
        test.canister_state(canister)
            .system_state
            .task_queue
            .is_empty()
    );

    assert_eq!(heartbeat_and_timer_canisters, BTreeSet::new());

    while test.canister_state(canister).get_next_scheduled_method()
        != NextScheduledMethod::Heartbeat
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    // Since NextScheduledMethod is Heartbeat it is expected that Heartbeat
    // and GlobalTimer are added at the front of the queue.
    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        has_heartbeat,
        has_active_timer,
        &mut heartbeat_and_timer_canisters,
    ));

    assert_eq!(heartbeat_and_timer_canisters, BTreeSet::from([canister]));
    assert_eq!(
        test.canister_state(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::Heartbeat)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(
        test.canister_state(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::GlobalTimer)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(heartbeat_and_timer_canisters, BTreeSet::from([canister]));

    heartbeat_and_timer_canisters = BTreeSet::new();

    while test.canister_state(canister).get_next_scheduled_method()
        != NextScheduledMethod::GlobalTimer
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }
    // Since NextScheduledMethod is GlobalTimer it is expected that GlobalTimer
    // and Heartbeat are added at the front of the queue.
    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        has_heartbeat,
        has_active_timer,
        &mut heartbeat_and_timer_canisters,
    ));

    assert_eq!(heartbeat_and_timer_canisters, BTreeSet::from([canister]));
    assert_eq!(
        test.canister_state(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::GlobalTimer)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(
        test.canister_state(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::Heartbeat)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(heartbeat_and_timer_canisters, BTreeSet::from([canister]));
}

#[test]
fn subnet_split_cleans_in_progress_raw_rand_requests() {
    let canister_id = canister_test_id(2);
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_query_message: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            max_instructions_per_install_code_slice: NumInstructions::from(1),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();
    test.advance_to_round(ExecutionRound::new(2));
    let last_round = test.last_round();

    // Inject fake request to be able to create a response.
    let canister = get_running_canister(canister_id);
    test.inject_call_to_ic00(
        Method::RawRand,
        EmptyBlob.encode(),
        Cycles::new(0),
        canister_id,
        InputQueueType::LocalSubnet,
    );
    let state = test.state_mut();
    state.put_canister_state(canister);
    state.pop_subnet_input();
    state
        .metadata
        .subnet_call_context_manager
        .push_raw_rand_request(
            RequestBuilder::new().sender(canister_id).build(),
            last_round,
            UNIX_EPOCH,
        );
    // `SubnetCallContextManager` contains one `RawRandContext`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    // Helper function for invoking `after_split()`.
    fn after_split(state: &mut ReplicatedState) {
        state.metadata.split_from = Some(state.metadata.own_subnet_id);
        state.after_split();
    }

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `RawRandContext` and does not produce a response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );
    assert!(!test.state().subnet_queues().has_output());

    // Simulate a subnet split that migrates the canister to another subnet.
    test.state_mut().take_canister_state(&canister_id);
    after_split(test.state_mut());

    // Should have removed the `RawRandContext` and produced a reject response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );
    assert!(test.state().subnet_queues().has_output());
}

#[test]
fn online_split_cleans_in_progress_raw_rand_requests() {
    let canister_id = canister_test_id(2);
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_query_message: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            max_instructions_per_install_code_slice: NumInstructions::from(1),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();
    test.advance_to_round(ExecutionRound::new(2));
    let last_round = test.last_round();

    // Inject fake request to be able to create a response.
    let canister = get_running_canister(canister_id);
    test.inject_call_to_ic00(
        Method::RawRand,
        EmptyBlob.encode(),
        Cycles::new(0),
        canister_id,
        InputQueueType::LocalSubnet,
    );
    let state = test.state_mut();
    state.put_canister_state(canister);
    state.pop_subnet_input();
    state
        .metadata
        .subnet_call_context_manager
        .push_raw_rand_request(
            RequestBuilder::new().sender(canister_id).build(),
            last_round,
            UNIX_EPOCH,
        );
    // `SubnetCallContextManager` contains one `RawRandContext`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    let own_subnet_id = test.state().metadata.own_subnet_id;
    let other_subnet_id = subnet_test_id(13);
    assert_ne!(own_subnet_id, other_subnet_id);

    // A no-op subnet split (no canisters migrated).
    test.state_mut()
        .metadata
        .network_topology
        .routing_table_mut()
        .assign_canister(canister_id, own_subnet_id);
    test.online_split_state(own_subnet_id, other_subnet_id);

    // Retains the `RawRandContext` and does not produce a response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );
    assert!(!test.state().subnet_queues().has_output());

    // Simulate a subnet split that migrates the canister to another subnet.
    test.state_mut()
        .metadata
        .network_topology
        .routing_table_mut()
        .assign_canister(canister_id, other_subnet_id);
    test.online_split_state(own_subnet_id, other_subnet_id);

    // Should have removed the `RawRandContext` and produced a reject response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );
    assert!(test.state().subnet_queues().has_output());
}

fn zero_instruction_messages(metrics_registry: &MetricsRegistry) -> u64 {
    let instructions_consumed_per_message = fetch_histogram_vec_buckets(
        metrics_registry,
        "scheduler_instructions_consumed_per_message",
    )
    .remove(&BTreeMap::new())
    .unwrap();

    *instructions_consumed_per_message.get("0").unwrap()
}

pub(crate) fn make_ecdsa_key_id(id: u64) -> EcdsaKeyId {
    EcdsaKeyId::from_str(&format!("Secp256k1:key_{id:?}")).unwrap()
}

pub(crate) fn make_schnorr_key_id(id: u64) -> SchnorrKeyId {
    SchnorrKeyId::from_str(&format!("Bip340Secp256k1:key_{id:?}")).unwrap()
}
