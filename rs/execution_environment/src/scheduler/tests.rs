use super::test_utilities::{SchedulerTestBuilder, ingress, on_response, other_side};
use super::*;
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::execution_environment::{
    LOG_MEMORY_STORE_FEATURE_ENABLED, STOP_CANISTER_TIMEOUT_DURATION,
};
use ic_config::subnet_config::SchedulerConfig;
use ic_error_types::RejectCode;
use ic_management_canister_types_private::{
    self as ic00, BoundedHttpHeaders, CanisterHttpResponsePayload, CanisterIdRecord,
    CanisterStatusType, EcdsaKeyId, EmptyBlob, Method, Payload as _, SchnorrKeyId,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterStatus, metadata_state::testing::NetworkTopologyTesting};
use ic_state_machine_tests::{PayloadBuilder, StateMachineBuilder};
use ic_test_utilities_metrics::{fetch_counter, fetch_histogram_vec_buckets};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::{CallbackId, Payload, RejectContext};
use ic_types::time::{UNIX_EPOCH, expiry_time_from_now};
use ic_types_cycles::Cycles;
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
fn state_sync_clears_paused_execution_registry() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Create a canister and hold on to a clean copy of it.
    let canister = test.create_canister();
    let clean_canister = test.canister_state(canister).clone();

    // Execute one DTS round to create a paused execution in both the canister's
    // task queue and the execution environment's paused execution registry.
    test.send_ingress(canister, ingress(1000));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(test.canister_state(canister).has_paused_execution());
    assert_eq!(
        test.scheduler().exec_env.paused_execution_registry_sizes(),
        (1, 0)
    );

    // Simulate a state sync replacing the replicated state: replace the canister
    // state with the clean copy. The registry still holds the orphaned paused
    // execution entry.
    test.state_mut().put_canister_state(clean_canister);
    let canister_priority = test.state_mut().canister_priority_mut(canister);
    canister_priority.long_execution_start_round = None;
    canister_priority.executed_rounds = 0;
    assert!(!test.canister_state(canister).has_long_execution());

    // Execute another round. The scheduler detects that no canister has a paused
    // execution and calls `abandon_paused_executions()` to clear the paused
    // execution registry.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.scheduler().exec_env.paused_execution_registry_sizes(),
        (0, 0)
    );

    // At this point, a new short message should complete immediately.
    let new_msg = test.send_ingress(canister, ingress(50));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.ingress_error(&new_msg).code(),
        ErrorCode::CanisterDidNotReply
    );
}

#[test]
fn expired_ingress_messages_are_removed_from_ingress_queues() {
    let batch_time = Time::from_nanos_since_unix_epoch(u64::MAX / 2);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(batch_time)
        .build();

    let canister_id = test.create_canister();

    // Send some ingress messages to a canister. Half of them have expiry times
    // before the current batch time, half have expiry times after.
    let canister_ingress_messages = 10;
    let expiry_time_before = batch_time.saturating_sub(Duration::from_secs(1));
    let expiry_time_after = batch_time + Duration::from_secs(1);
    for i in 0..canister_ingress_messages {
        if i % 2 == 0 {
            test.send_ingress_with_expiry(canister_id, ingress(1000), expiry_time_before);
        } else {
            test.send_ingress_with_expiry(canister_id, ingress(1000), expiry_time_after);
        }
    }

    // Send some ingress messages to the subnet. Half of them have expiry times
    // before the current batch time, half have expiry times after.
    let subnet_ingress_messages = 6;
    for i in 0..subnet_ingress_messages {
        if i % 2 == 0 {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(Method::CanisterStatus, payload, expiry_time_before);
        } else {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(Method::CanisterStatus, payload, expiry_time_after);
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Ingress queues should be empty, with all messages either expired or executed.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(test.subnet_ingress_queue_size(), 0);

    // Verify that half of the messages expired and the other half got executed.
    assert_eq!(
        fetch_counter(
            test.metrics_registry(),
            "scheduler_expired_ingress_messages_count",
        )
        .unwrap() as u64,
        (canister_ingress_messages / 2) + (subnet_ingress_messages / 2)
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        (canister_ingress_messages / 2) + (subnet_ingress_messages / 2)
    );
}

#[test]
fn consensus_queue_is_emptied() {
    use ic_management_canister_types_private::{
        DerivationPath, MasterPublicKeyId, SignWithECDSAArgs,
    };
    use ic_types::batch::ConsensusResponse;

    let ecdsa_key_id = make_ecdsa_key_id(0);
    let master_ecdsa_key_id = MasterPublicKeyId::Ecdsa(ecdsa_key_id.clone());
    let mut test = SchedulerTestBuilder::new()
        .with_replica_version(ReplicaVersion::default())
        .with_chain_keys(vec![master_ecdsa_key_id.clone()])
        .build();

    let canister_id = test.create_canister();

    let ecdsa_payload = Encode!(&SignWithECDSAArgs {
        message_hash: [1; 32],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: ecdsa_key_id,
    })
    .unwrap();

    // Execute two signing requests.
    for _ in 0..2 {
        test.inject_call_to_ic00(
            Method::SignWithECDSA,
            ecdsa_payload.clone(),
            test.ecdsa_signature_fee().real(),
            canister_id,
            InputQueueType::RemoteSubnet,
        );
    }
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Check that the SubnetCallContextManager now contains two signing contexts.
    let sign_with_ecdsa_contexts = test.state().signature_request_contexts().clone();
    assert_eq!(sign_with_ecdsa_contexts.len(), 2);

    // Produce reject responses for both contexts and execute a round.
    for (callback_id, _) in sign_with_ecdsa_contexts.iter() {
        let response = ConsensusResponse::new(
            *callback_id,
            Payload::Reject(RejectContext::new(RejectCode::SysFatal, "")),
        );
        test.state_mut().consensus_queue.push(response);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After the round, the signature request contexts should have completed.
    assert!(test.state().signature_request_contexts().is_empty());
}

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
fn test_maybe_add_heartbeat_or_global_timer_tasks() {
    use ExecutionTask as Task;
    use NextScheduledMethod::*;

    /// Calls `maybe_add_heartbeat_or_global_timer_tasks` in the given state and
    /// returns the tasks that were enqueued and the next scheduled method.
    fn call(
        has_input: bool,
        has_heartbeat: bool,
        has_active_timer: bool,
        next_scheduled_method: NextScheduledMethod,
    ) -> (Vec<ExecutionTask>, NextScheduledMethod) {
        let mut test = SchedulerTestBuilder::new().build();
        let canister_id = test.create_canister();
        let canister = test.canister_state_mut(canister_id);

        if has_input {
            canister.push_ingress(Ingress {
                source: user_test_id(77),
                receiver: canister_id,
                effective_canister_id: None,
                method_name: String::from("test"),
                method_payload: vec![1_u8],
                message_id: message_test_id(555),
                expiry_time: expiry_time_from_now(),
                sender_info: None,
            });
        }
        while canister.get_next_scheduled_method() != next_scheduled_method {
            canister.inc_next_scheduled_method();
        }

        let mut heartbeat_and_timer_canisters = BTreeSet::new();
        maybe_add_heartbeat_or_global_timer_tasks(
            canister,
            has_heartbeat,
            has_active_timer,
            &mut heartbeat_and_timer_canisters,
        );

        let mut tasks = Vec::new();
        while let Some(task) = canister.system_state.task_queue.pop_front() {
            tasks.push(task);
        }

        // Iff a task was enqueued, the canister was added to the set.
        assert!(
            tasks.is_empty() || heartbeat_and_timer_canisters.contains(&canister_id),
            "tasks: {tasks:?}, heartbeat_and_timer_canisters: {heartbeat_and_timer_canisters:?}"
        );

        (tasks, canister.get_next_scheduled_method())
    }

    fn inc(mut method: NextScheduledMethod) -> NextScheduledMethod {
        method.inc();
        method
    }

    // With no input, no heartbeat, no active timer, nothing changes.
    assert_eq!(call(false, false, false, Message), (vec![], Message));
    assert_eq!(call(false, false, false, Heartbeat), (vec![], Heartbeat));
    assert_eq!(
        call(false, false, false, GlobalTimer),
        (vec![], GlobalTimer)
    );

    // With an input but no heartbeat or timer, next method advances past Message.
    assert_eq!(call(true, false, false, Message), (vec![], inc(Message)));
    assert_eq!(call(true, false, false, Heartbeat), (vec![], inc(Message)));
    assert_eq!(
        call(true, false, false, GlobalTimer),
        (vec![], inc(Message))
    );

    // With an input and a heartbeat or timer, it depends on the next method.
    assert_eq!(call(true, true, false, Message), (vec![], inc(Message)));
    assert_eq!(
        call(true, true, false, Heartbeat),
        (vec![Task::Heartbeat], inc(Heartbeat))
    );
    assert_eq!(
        call(true, false, true, GlobalTimer),
        (vec![Task::GlobalTimer], inc(GlobalTimer))
    );

    // With all tree, the next method is always scheduled and advanced past.
    assert_eq!(call(true, true, true, Message), (vec![], inc(Message)));
    assert_eq!(
        call(true, true, true, Heartbeat),
        (vec![Task::Heartbeat, Task::GlobalTimer], inc(Heartbeat))
    );
    assert_eq!(
        call(true, true, true, GlobalTimer),
        (vec![Task::GlobalTimer, Task::Heartbeat], inc(GlobalTimer))
    );
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
            max_instructions_per_slice: NumInstructions::from(1),
            max_instructions_per_install_code_slice: NumInstructions::from(1),
            ..zero_instruction_overhead_config()
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
            max_instructions_per_slice: NumInstructions::from(1),
            max_instructions_per_install_code_slice: NumInstructions::from(1),
            ..zero_instruction_overhead_config()
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

#[test]
fn finalization_clears_scheduled_canister_log_delta_sizes() {
    let mut test = SchedulerTestBuilder::new().build();
    let mut next_idx = 0;
    let canister_a = test.create_canister();
    let canister_b = test.create_canister();

    // Populate delta_log_sizes on canister_a's canister_log by appending two
    // non-empty delta logs.
    fn append_delta_log(next_idx: u64, canister: &mut CanisterState, content: &str) -> usize {
        let mut delta = ic_types::CanisterLog::new_delta_with_next_index(next_idx, 4096);
        delta.add_record(next_idx, content.as_bytes().to_vec());
        let size = delta.bytes_used();
        if LOG_MEMORY_STORE_FEATURE_ENABLED {
            canister
                .system_state
                .log_memory_store
                .append_delta_log(&mut delta);
        } else {
            canister
                .system_state
                .canister_log
                .append_delta_log(&mut delta);
        };
        size
    }
    let size1 = append_delta_log(next_idx, test.canister_state_mut(canister_a), "hello");
    next_idx += 1;
    let size2 = append_delta_log(next_idx, test.canister_state_mut(canister_a), "world!");
    next_idx += 1;

    // Also append a delta log to canister_b's canister_log.
    let size3 = append_delta_log(next_idx, test.canister_state_mut(canister_b), "oops");

    // Both canisters have delta log sizes.
    fn has_delta_log_sizes(canister: &CanisterState) -> bool {
        if LOG_MEMORY_STORE_FEATURE_ENABLED {
            canister.system_state.log_memory_store.has_delta_log_sizes()
        } else {
            canister.system_state.canister_log.has_delta_log_sizes()
        }
    }
    assert!(has_delta_log_sizes(test.canister_state(canister_a)));
    assert!(has_delta_log_sizes(test.canister_state(canister_b)));

    // Only schedule canister_a. This is not realistic behavior (canister_b would
    // not have produced logs if it had not been scheduled), but it's useful for
    // testing.
    test.send_ingress(canister_a, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After the round, delta_log_sizes have been cleared for both canisters.
    assert!(!has_delta_log_sizes(test.canister_state(canister_a)));
    assert!(!has_delta_log_sizes(test.canister_state(canister_b)));

    // The metric must have recorded all delta sizes we appended.
    let canister_log_delta_memory_usage = &test.scheduler().metrics.canister_log_delta_memory_usage;
    assert_eq!(canister_log_delta_memory_usage.get_sample_count(), 3);
    assert_eq!(
        canister_log_delta_memory_usage.get_sample_sum() as usize,
        size1 + size2 + size3
    );
}

#[test]
#[should_panic(expected = "scheduler_canister_invariant_broken")]
fn check_canister_invariants_detects_wasm_memory_exceeding_limit() {
    use ic_replicated_state::NumWasmPages;

    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister();

    // Inflate the canister's wasm memory size beyond `max_wasm_memory_size`
    // (default 4 GiB = 65536 wasm pages of 64 KiB each).
    test.canister_state_mut(canister)
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_memory
        .size = NumWasmPages::from(65536 + 1);

    // Send a message so the canister is scheduled, then execute a round.
    // The invariant check during finalization detects the violation and
    // panics via debug_assert.
    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
}

#[test]
fn finalization_prunes_expired_ingress_history_entries() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(initial_time)
        .build();

    let canister = test.create_canister();

    // Execute two ingress messages so they reach a terminal state
    // (Failed / CanisterDidNotReply) and are recorded in the ingress history.
    let msg_a = test.send_ingress(canister, ingress(1));
    let msg_b = test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Both messages should be in a terminal (Failed) state.
    assert!(matches!(
        test.ingress_state(&msg_a),
        IngressState::Failed(_)
    ));
    assert!(matches!(
        test.ingress_state(&msg_b),
        IngressState::Failed(_)
    ));
    // The ingress history should have two entries.
    assert_eq!(test.state().metadata.ingress_history.len(), 2);

    // Advance time just short of MAX_INGRESS_TTL and execute a round.
    // The entries must still be present.
    let before_deadline = initial_time + (ic_limits::MAX_INGRESS_TTL - Duration::from_secs(1));
    test.set_time(before_deadline);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert!(matches!(
        test.ingress_state(&msg_a),
        IngressState::Failed(_)
    ));
    assert!(matches!(
        test.ingress_state(&msg_b),
        IngressState::Failed(_)
    ));

    // Advance time past MAX_INGRESS_TTL so the pruning time is exceeded.
    let after_deadline = initial_time + ic_limits::MAX_INGRESS_TTL + Duration::from_secs(1);
    test.set_time(after_deadline);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After pruning, the statuses must be gone (Unknown).
    assert_eq!(test.ingress_status(&msg_a), IngressStatus::Unknown);
    assert_eq!(test.ingress_status(&msg_b), IngressStatus::Unknown);
    // The ingress history should be empty.
    assert_eq!(test.state().metadata.ingress_history.len(), 0);
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

fn zero_instruction_overhead_config() -> SchedulerConfig {
    SchedulerConfig {
        instruction_overhead_per_execution: NumInstructions::from(0),
        instruction_overhead_per_canister: NumInstructions::from(0),
        instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
        dirty_page_overhead: NumInstructions::from(0),
        ..SchedulerConfig::application_subnet()
    }
}

pub(crate) fn make_ecdsa_key_id(id: u64) -> EcdsaKeyId {
    EcdsaKeyId::from_str(&format!("Secp256k1:key_{id:?}")).unwrap()
}

pub(crate) fn make_schnorr_key_id(id: u64) -> SchnorrKeyId {
    SchnorrKeyId::from_str(&format!("Bip340Secp256k1:key_{id:?}")).unwrap()
}
