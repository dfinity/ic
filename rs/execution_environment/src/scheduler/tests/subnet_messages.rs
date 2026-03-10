//! Tests for subnet message execution.

use super::super::test_utilities::{SchedulerTest, SchedulerTestBuilder, ingress};
use super::super::*;
use candid::Encode;
use ic_config::subnet_config::SchedulerConfig;
use ic_management_canister_types_private::{CanisterIdRecord, EmptyBlob, Method, Payload as _};
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities_metrics::{HistogramStats, fetch_histogram_vec_stats, labels};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::time::UNIX_EPOCH;
use ic_types_test_utils::ids::canister_test_id;

#[test]
fn test_drain_subnet_messages_with_some_long_running_canisters() {
    let instructions_per_slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(instructions_per_slice),
            max_instructions_per_message: NumInstructions::from(instructions_per_slice * 100),
            max_instructions_per_query_message: NumInstructions::new(instructions_per_slice),
            max_instructions_per_slice: NumInstructions::from(instructions_per_slice),
            max_instructions_per_install_code_slice: NumInstructions::from(instructions_per_slice),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let mut local_canisters = vec![];
    let mut remote_canisters = vec![];
    let add_messages = |test: &mut SchedulerTest, canisters: &mut Vec<CanisterId>| {
        for _ in 0..2 {
            let canister = test.create_canister();
            canisters.push(canister);
        }
    };
    add_messages(&mut test, &mut local_canisters);
    add_messages(&mut test, &mut remote_canisters);

    // Start a long execution on `local_canisters[1]` and `remote_canisters[0]`.
    for canister_id in [&local_canisters[1], &remote_canisters[0]] {
        test.send_ingress(*canister_id, ingress(instructions_per_slice * 100));
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    // Add 3 local subnet input messages.
    // Canister `local_canisters[1]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(local_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StartCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );

    let arg2 = Encode!(&CanisterIdRecord::from(local_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(11),
        InputQueueType::LocalSubnet,
    );

    // Add 2 remote subnet input messages.
    // Canister `remote_canisters[0]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(remote_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(12),
        InputQueueType::RemoteSubnet,
    );
    let arg2 = Encode!(&CanisterIdRecord::from(remote_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(13),
        InputQueueType::RemoteSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 6);

    let new_state = test.drain_subnet_messages();
    // Left messages that were not able to be executed due to other long running messages
    // belong to `local_canisters[1]` and `remote_canisters[0]` canisters.
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 2);
}

#[test]
fn test_drain_subnet_messages_no_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_query_message: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            max_instructions_per_install_code_slice: NumInstructions::from(1),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();

    let add_messages = |test: &mut SchedulerTest, input_type: InputQueueType| {
        for id in 0..2 {
            let local_canister = test.create_canister_with(
                Cycles::new(1_000_000_000_000),
                ComputeAllocation::zero(),
                MemoryAllocation::default(),
                None,
                None,
                None,
            );
            let arg = Encode!(&CanisterIdRecord::from(local_canister)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(id),
                input_type,
            );
        }
    };
    add_messages(&mut test, InputQueueType::LocalSubnet);
    add_messages(&mut test, InputQueueType::RemoteSubnet);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let new_state = test.drain_subnet_messages();
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
}

#[test]
fn test_drain_subnet_messages_all_long_running_canisters() {
    let instructions_per_slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(instructions_per_slice),
            max_instructions_per_message: NumInstructions::from(instructions_per_slice * 100),
            max_instructions_per_query_message: NumInstructions::new(instructions_per_slice),
            max_instructions_per_slice: NumInstructions::from(instructions_per_slice),
            max_instructions_per_install_code_slice: NumInstructions::from(instructions_per_slice),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let add_messages = |test: &mut SchedulerTest, input_type: InputQueueType| {
        for i in 0..2 {
            let canister_id = test.create_canister();
            // Start a long execution.
            test.send_ingress(canister_id, ingress(instructions_per_slice * 100));
            test.execute_round(ExecutionRoundType::OrdinaryRound);

            let arg = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(i),
                input_type,
            );
        }
    };
    add_messages(&mut test, InputQueueType::LocalSubnet);
    add_messages(&mut test, InputQueueType::RemoteSubnet);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let new_state = test.drain_subnet_messages();
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 4);
}

#[test]
fn scheduler_executes_postponed_raw_rand_requests() {
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
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    // Execute the postponed `raw_rand` messages.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );

    assert_eq!(
        fetch_histogram_vec_stats(test.metrics_registry(), "execution_round_phase_messages")
            .get(&labels(&[("phase", "raw_rand")])),
        Some(&HistogramStats { sum: 1.0, count: 1 })
    );

    assert_eq!(
        fetch_histogram_vec_stats(
            test.metrics_registry(),
            "execution_round_phase_instructions",
        )
        .get(&labels(&[("phase", "raw_rand")])),
        Some(&HistogramStats { count: 1, sum: 0.0 })
    );
}
