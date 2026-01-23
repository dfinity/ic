use ic_base_types::{CanisterId, NumBytes, NumSeconds, SubnetId};
use ic_config::execution_environment::SUBNET_CALLBACK_SOFT_LIMIT;
use ic_config::subnet_config::SchedulerConfig;
use ic_embedders::wasmtime_embedder::system_api::SystemApiImpl;
use ic_embedders::wasmtime_embedder::system_api::sandbox_safe_system_state::SandboxSafeSystemState;
use ic_interfaces::execution_environment::{
    HypervisorResult, MessageMemoryUsage, SubnetAvailableMemory, SystemApi,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterSettingsArgs, IC_00, Payload, UpdateSettingsArgs,
};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{NetworkTopology, SystemState};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::{
    ids::{canister_test_id, subnet_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::nominal_cycles::NominalCycles;
use ic_types::{
    ComputeAllocation, Cycles, NumInstructions,
    messages::{CanisterMessage, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES},
    time::UNIX_EPOCH,
};
use prometheus::IntCounter;
use std::collections::BTreeSet;
use std::convert::From;
use std::sync::Arc;

mod common;
use common::*;

use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1 << 30);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);
const WASM_EXECUTION_MODE: WasmExecutionMode = WasmExecutionMode::Wasm32;

#[test]
fn push_output_request_fails_not_enough_cycles_for_request() {
    let request = RequestBuilder::default()
        .sender(canister_test_id(0))
        .build();

    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(MAX_NUM_INSTRUCTIONS)
        .build();

    let request_payload_cost = cycles_account_manager.xnet_call_bytes_transmitted_fee(
        request.payload_size_bytes(),
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
    );

    // Set cycles balance low enough that not even the cost for transferring
    // the request is covered.
    let system_state = SystemState::new_running_for_testing(
        canister_test_id(0),
        user_test_id(1).get(),
        request_payload_cost - Cycles::new(10),
        NumSeconds::from(100_000),
    );

    let mut sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        Some(request.sender().into()),
        None,
        CanisterCyclesCostSchedule::Normal,
    );

    assert_eq!(
        sandbox_safe_system_state.push_output_request(
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            request.clone(),
            Cycles::zero(),
            Cycles::zero(),
        ),
        Err(request)
    );
}

#[test]
fn push_output_request_fails_not_enough_cycles_for_response() {
    let request = RequestBuilder::default()
        .sender(canister_test_id(0))
        .build();

    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(MAX_NUM_INSTRUCTIONS)
        .build();

    let xnet_cost = cycles_account_manager.xnet_call_performed_fee(
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
    );
    let request_payload_cost = cycles_account_manager.xnet_call_bytes_transmitted_fee(
        request.payload_size_bytes(),
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
    );
    let prepayment_for_response_execution = cycles_account_manager
        .prepayment_for_response_execution(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            WASM_EXECUTION_MODE,
        );
    let prepayment_for_response_transmission = cycles_account_manager
        .prepayment_for_response_transmission(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
        );
    let total_cost = xnet_cost
        + request_payload_cost
        + prepayment_for_response_execution
        + prepayment_for_response_transmission;

    // Set cycles balance to a number that is enough to cover for the request
    // transfer but not to cover the cost of processing the expected response.
    let system_state = SystemState::new_running_for_testing(
        canister_test_id(0),
        user_test_id(1).get(),
        total_cost - Cycles::new(10),
        NumSeconds::from(100_000),
    );

    let mut sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        Some(request.sender().into()),
        None,
        CanisterCyclesCostSchedule::Normal,
    );

    assert_eq!(
        sandbox_safe_system_state.push_output_request(
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            request.clone(),
            prepayment_for_response_execution,
            prepayment_for_response_transmission
        ),
        Err(request)
    );
}

#[test]
fn push_output_request_succeeds_with_enough_cycles() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(MAX_NUM_INSTRUCTIONS)
        .build();

    let system_state = SystemState::new_running_for_testing(
        canister_test_id(0),
        user_test_id(1).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );

    let caller = None;
    let mut sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        caller,
        None,
        cost_schedule,
    );

    let prepayment_for_response_execution = cycles_account_manager
        .prepayment_for_response_execution(
            SMALL_APP_SUBNET_MAX_SIZE,
            cost_schedule,
            WASM_EXECUTION_MODE,
        );
    let prepayment_for_response_transmission = cycles_account_manager
        .prepayment_for_response_transmission(SMALL_APP_SUBNET_MAX_SIZE, cost_schedule);

    assert_eq!(
        sandbox_safe_system_state.push_output_request(
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            RequestBuilder::default()
                .sender(canister_test_id(0))
                .build(),
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
        ),
        Ok(())
    );
}

#[test]
fn correct_charging_source_canister_for_a_request() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(MAX_NUM_INSTRUCTIONS)
        .with_subnet_type(subnet_type)
        .build();
    let mut system_state = SystemState::new_running_for_testing(
        canister_test_id(0),
        user_test_id(1).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );

    let initial_cycles_balance = system_state.balance();

    let request = RequestBuilder::default()
        .sender(canister_test_id(0))
        .receiver(canister_test_id(1))
        .build();

    let mut sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        Some(request.sender().into()),
        None,
        CanisterCyclesCostSchedule::Normal,
    );

    let xnet_cost =
        cycles_account_manager.xnet_call_performed_fee(SMALL_APP_SUBNET_MAX_SIZE, cost_schedule);
    let request_payload_cost = cycles_account_manager.xnet_call_bytes_transmitted_fee(
        request.payload_size_bytes(),
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
    );
    let prepayment_for_response_execution = cycles_account_manager
        .prepayment_for_response_execution(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            WASM_EXECUTION_MODE,
        );
    let prepayment_for_response_transmission = cycles_account_manager
        .prepayment_for_response_transmission(SMALL_APP_SUBNET_MAX_SIZE, cost_schedule);
    let total_cost = xnet_cost
        + request_payload_cost
        + prepayment_for_response_execution
        + prepayment_for_response_transmission;

    // Enqueue the Request.
    sandbox_safe_system_state
        .push_output_request(
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            request,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
        )
        .unwrap();

    // Assume the destination canister got the message and prepared a response
    let response = ResponseBuilder::default()
        .respondent(canister_test_id(1))
        .originator(canister_test_id(0))
        .build();

    // The response will find its way into the
    // ExecutionEnvironmentImpl::execute_canister_response()
    // => Mock the response_cycles_refund() invocation from the
    // execute_canister_response()
    let mut subnet_available_memory =
        SubnetAvailableMemory::new_for_testing(i64::MAX / 2, i64::MAX / 2, i64::MAX / 2);
    sandbox_safe_system_state
        .system_state_modifications
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &mut subnet_available_memory,
            &default_network_topology(),
            subnet_test_id(1),
            false,
            &no_op_logger(),
        )
        .unwrap();
    let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
    let refund_cycles = cycles_account_manager.refund_for_response_transmission(
        &no_op_logger(),
        &no_op_counter,
        &response.response_payload,
        prepayment_for_response_transmission,
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
    );

    system_state.add_cycles(refund_cycles, CyclesUseCase::RequestAndResponseTransmission);

    // MAX_NUM_INSTRUCTIONS also gets partially refunded in the real
    // ExecutionEnvironmentImpl::execute_canister_response()
    assert_eq!(
        initial_cycles_balance - total_cost
            + cycles_account_manager.xnet_call_bytes_transmitted_fee(
                MAX_INTER_CANISTER_PAYLOAD_IN_BYTES - response.payload_size_bytes(),
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
            ),
        system_state.balance()
    );
}

// Helper to deal with cycles being written to the heap.
#[allow(clippy::type_complexity)]
fn handle_heap_cycles<T>(
    slf: T,
    f: &dyn Fn(T, usize, &mut [u8]) -> HypervisorResult<()>,
) -> HypervisorResult<Cycles> {
    let mut res = [0u8; 16];
    f(slf, 0, &mut res)?;
    Ok(Cycles::new(u128::from_le_bytes(res)))
}

// Helper to deal with cycles being written to the heap.
// For methods with 1 additional argument.
#[allow(clippy::type_complexity)]
fn handle_heap_cycles_1<T, A>(
    slf: T,
    a: A,
    f: &dyn Fn(T, A, usize, &mut [u8]) -> HypervisorResult<()>,
) -> HypervisorResult<Cycles> {
    let mut res = [0u8; 16];
    f(slf, a, 0, &mut res)?;
    Ok(Cycles::new(u128::from_le_bytes(res)))
}

/// Convenience wrapper for ic0_canister_cycle_balance128
pub fn canister_cycle_balance128(slf: &mut SystemApiImpl) -> HypervisorResult<Cycles> {
    handle_heap_cycles(slf, &SystemApiImpl::ic0_canister_cycle_balance128)
}

/// Convenience wrapper for ic0_mint_cycles128
pub fn mint_cycles128(slf: &mut SystemApiImpl, amount: Cycles) -> HypervisorResult<Cycles> {
    handle_heap_cycles_1(slf, amount, &SystemApiImpl::ic0_mint_cycles128)
}

#[test]
fn mint_all_cycles() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let api_type = ApiTypeBuilder::build_update_api();
    let mut api = get_system_api(api_type, &get_cmc_system_state(), cycles_account_manager);
    let balance_before = canister_cycle_balance128(&mut api).unwrap();

    let amount = Cycles::new(50);
    assert_eq!(amount, mint_cycles128(&mut api, amount).unwrap());
    assert_eq!(
        canister_cycle_balance128(&mut api).unwrap() - balance_before,
        amount
    );
}

#[test]
fn mint_cycles_large_value() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .canister_id(CYCLES_MINTING_CANISTER_ID)
        .build();

    system_state.add_cycles(
        Cycles::from(1_000_000_000_000_000_u128),
        CyclesUseCase::NonConsumed,
    );

    let api_type = ApiTypeBuilder::build_update_api();
    let mut api = get_system_api(api_type, &system_state, cycles_account_manager);
    let balance_before = canister_cycle_balance128(&mut api).unwrap();

    let amount = Cycles::new(50);
    // Canisters on the System subnet can hold any amount of cycles
    assert_eq!(mint_cycles128(&mut api, amount).unwrap(), amount);
    assert_eq!(
        canister_cycle_balance128(&mut api).unwrap() - balance_before,
        amount
    );
}

#[test]
fn mint_cycles_fails_caller_not_on_nns() {
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    let balance_before = canister_cycle_balance128(&mut api).unwrap();

    assert!(mint_cycles128(&mut api, Cycles::new(50)).is_err());
    assert_eq!(
        canister_cycle_balance128(&mut api).unwrap() - balance_before,
        Cycles::new(0)
    );
}

fn common_mint_cycles_128(
    initial_cycles: Cycles,
    cycles_to_mint: Cycles,
    expected_actually_minted: Cycles,
) {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let system_state = SystemStateBuilder::new()
        .initial_cycles(initial_cycles)
        .canister_id(CYCLES_MINTING_CANISTER_ID)
        .build();

    let api_type = ApiTypeBuilder::build_update_api();
    let mut api = get_system_api(api_type, &system_state, cycles_account_manager);
    let balance_before = canister_cycle_balance128(&mut api).unwrap();
    assert_eq!(balance_before, initial_cycles);
    let cycles_minted = mint_cycles128(&mut api, cycles_to_mint).unwrap();
    assert_eq!(cycles_minted, expected_actually_minted);
    let balance_after = canister_cycle_balance128(&mut api).unwrap();
    assert_eq!(balance_after - balance_before, expected_actually_minted);
}

#[test]
fn mint_cycles_very_large_value() {
    let to_mint = Cycles::from_parts(u64::MAX, 50);
    common_mint_cycles_128(INITIAL_CYCLES, to_mint, to_mint);
}

#[test]
fn mint_cycles_max() {
    let to_mint = Cycles::from_parts(u64::MAX, u64::MAX);
    common_mint_cycles_128(Cycles::zero(), to_mint, to_mint);
}

#[test]
fn mint_cycles_saturate() {
    let to_mint = Cycles::from_parts(u64::MAX, u64::MAX);
    common_mint_cycles_128(INITIAL_CYCLES, to_mint, to_mint - INITIAL_CYCLES);
}

#[test]
fn is_controller_test() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.controllers = BTreeSet::from([user_test_id(1).get(), user_test_id(2).get()]);

    let caller = None;
    let sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        caller,
        None,
        CanisterCyclesCostSchedule::Normal,
    );

    // Users IDs 1 and 2 are controllers, hence is_controller should return true,
    // otherwise, it should return false.
    for i in 1..5 {
        assert_eq!(
            sandbox_safe_system_state.is_controller(&user_test_id(i).get()),
            i <= 2
        );
    }
}

#[test]
fn call_increases_cycles_consumed_metric() {
    let mut system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]).unwrap();
    api.ic0_call_perform().unwrap();

    let system_state_modifications = api.take_system_state_modifications();
    let mut subnet_available_memory =
        SubnetAvailableMemory::new_for_testing(i64::MAX / 2, i64::MAX / 2, i64::MAX / 2);
    system_state_modifications
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &mut subnet_available_memory,
            &default_network_topology(),
            subnet_test_id(1),
            false,
            &no_op_logger(),
        )
        .unwrap();
    assert!(system_state.canister_metrics.consumed_cycles.get() > 0);
    assert_ne!(
        *system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .get(&CyclesUseCase::RequestAndResponseTransmission)
            .unwrap(),
        NominalCycles::from(0)
    );
}

/// Returns the system state after performing an inter-canister call
/// from sender to recv with given method name and argument.
/// The sender is assumed to be on subnet with given subnet ID
/// as in the provided network topology.
/// The sender's subnet is assumed to be an application subnet.
fn test_inter_canister_call(
    topo: &NetworkTopology,
    subnet_id: SubnetId,
    sender: CanisterId,
    recv: CanisterId,
    method_name: &str,
    arg: Vec<u8>,
) -> SystemState {
    let subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(MAX_NUM_INSTRUCTIONS)
        .with_subnet_type(subnet_type)
        .build();
    let sender_controller = user_test_id(1).get();
    let mut system_state = SystemState::new_running_for_testing(
        sender,
        sender_controller,
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );

    let mut sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        topo,
        SchedulerConfig::application_subnet().dirty_page_overhead,
        ComputeAllocation::default(),
        SUBNET_CALLBACK_SOFT_LIMIT as u64,
        Default::default(),
        Some(sender.into()),
        None,
        CanisterCyclesCostSchedule::Normal,
    );

    let request = RequestBuilder::default()
        .sender(sender)
        .receiver(recv)
        .method_name(method_name)
        .method_payload(arg)
        .build();

    let prepayment_for_response_execution = cycles_account_manager
        .prepayment_for_response_execution(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            WASM_EXECUTION_MODE,
        );
    let prepayment_for_response_transmission = cycles_account_manager
        .prepayment_for_response_transmission(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
        );

    // Enqueue the Request.
    sandbox_safe_system_state
        .push_output_request(
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            request,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
        )
        .unwrap();

    let mut subnet_available_memory =
        SubnetAvailableMemory::new_for_testing(i64::MAX / 2, i64::MAX / 2, i64::MAX / 2);
    sandbox_safe_system_state
        .system_state_modifications
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &mut subnet_available_memory,
            topo,
            subnet_id,
            false,
            &no_op_logger(),
        )
        .unwrap();

    system_state
}

/// Creates a network topology with NNS subnet and one test subnet,
/// both subnets having a single canister ID in their routing table ranges.
fn two_subnet_topology(
    nns_subnet_id: SubnetId,
    nns_canister_id: CanisterId,
    test_subnet_id: SubnetId,
    test_canister_id: CanisterId,
) -> NetworkTopology {
    let mut topo = NetworkTopology {
        nns_subnet_id,
        ..Default::default()
    };
    topo.subnets.insert(nns_subnet_id, Default::default());
    topo.subnets.insert(test_subnet_id, Default::default());
    let nns_canister_range = CanisterIdRange {
        start: nns_canister_id,
        end: nns_canister_id,
    };
    Arc::make_mut(&mut topo.routing_table)
        .insert(nns_canister_range, nns_subnet_id)
        .unwrap();
    let test_canister_range = CanisterIdRange {
        start: test_canister_id,
        end: test_canister_id,
    };
    Arc::make_mut(&mut topo.routing_table)
        .insert(test_canister_range, test_subnet_id)
        .unwrap();
    topo
}

/// Test successful IC00 call from test subnet to NNS subnet with given method name and argument.
fn correct_mgmt_canister_call_ic00(method_name: &str, arg: Vec<u8>) {
    let nns_subnet_id = subnet_test_id(1);
    let nns_canister_id = canister_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let test_canister_id = canister_test_id(2);
    let topo = two_subnet_topology(
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id,
        test_canister_id,
    );
    let mut system_state = test_inter_canister_call(
        &topo,
        test_subnet_id,
        test_canister_id,
        IC_00,
        method_name,
        arg,
    );
    assert!(system_state.queues_mut().has_output());
}

/// Test successful management canister call with an explicit subnet ID
/// as the target of the request from NNS subnet (otherwise such a call is not allowed)
/// to test subnet with given method name and argument.
fn correct_mgmt_canister_call_subnet_message(method_name: &str, arg: Vec<u8>) {
    let nns_subnet_id = subnet_test_id(1);
    let nns_canister_id = canister_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let test_canister_id = canister_test_id(2);
    let topo = two_subnet_topology(
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id,
        test_canister_id,
    );
    let mut system_state = test_inter_canister_call(
        &topo,
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id.into(),
        method_name,
        arg,
    );
    assert!(system_state.queues_mut().has_output());
}

/// Test that the system state has a reject input response
/// for a call from originator to respondent with an expected reject message
/// and pops that input response from the system state.
fn assert_failed_call(
    system_state: &mut SystemState,
    originator: CanisterId,
    respondent: CanisterId,
    expected_message: String,
) {
    match system_state.pop_input().unwrap() {
        CanisterMessage::Response(resp) => {
            assert_eq!(resp.originator, originator);
            assert_eq!(resp.respondent, respondent);
            match &resp.response_payload {
                ic_types::messages::Payload::Reject(ctxt) => {
                    assert_eq!(ctxt.message(), &expected_message)
                }
                _ => panic!("input response should be a reject"),
            }
        }
        _ => panic!("input message should be a response"),
    };
}

/// Test failing IC00 call from test subnet to NNS subnet with given method name and argument.
fn failing_mgmt_canister_call_ic00(method_name: &str, arg: Vec<u8>, expected_message: String) {
    let nns_subnet_id = subnet_test_id(1);
    let nns_canister_id = canister_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let test_canister_id = canister_test_id(2);
    let topo = two_subnet_topology(
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id,
        test_canister_id,
    );
    let mut system_state = test_inter_canister_call(
        &topo,
        test_subnet_id,
        test_canister_id,
        IC_00,
        method_name,
        arg,
    );
    assert_failed_call(&mut system_state, test_canister_id, IC_00, expected_message);
}

/// Test failing management canister call with an explicit subnet ID
/// as the target of the request from NNS subnet (otherwise such a call is not allowed)
/// to test subnet with given method name and argument.
fn failing_mgmt_canister_call_subnet_message(
    method_name: &str,
    arg: Vec<u8>,
    expected_message: String,
) {
    let nns_subnet_id = subnet_test_id(1);
    let nns_canister_id = canister_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let test_canister_id = canister_test_id(2);
    let topo = two_subnet_topology(
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id,
        test_canister_id,
    );
    let mut system_state = test_inter_canister_call(
        &topo,
        nns_subnet_id,
        nns_canister_id,
        test_subnet_id.into(),
        method_name,
        arg,
    );
    assert_failed_call(
        &mut system_state,
        nns_canister_id,
        test_subnet_id.into(),
        expected_message,
    );
}

#[test]
fn no_sender_canister_version_update_settings_ic00() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(1).into(),
        settings,
        sender_canister_version: None,
    };
    correct_mgmt_canister_call_ic00("update_settings", arg.encode());
}

#[test]
fn no_sender_canister_version_update_settings_subnet_message() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(2).into(),
        settings,
        sender_canister_version: None,
    };
    correct_mgmt_canister_call_subnet_message("update_settings", arg.encode());
}

#[test]
fn correct_sender_canister_version_update_settings_ic00() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(1).into(),
        settings,
        sender_canister_version: Some(0),
    };
    correct_mgmt_canister_call_ic00("update_settings", arg.encode());
}

#[test]
fn correct_sender_canister_version_update_settings_subnet_message() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(2).into(),
        settings,
        sender_canister_version: Some(0),
    };
    correct_mgmt_canister_call_subnet_message("update_settings", arg.encode());
}

#[test]
fn wrong_sender_canister_version_update_settings_ic00() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(1).into(),
        settings,
        sender_canister_version: Some(666),
    };
    failing_mgmt_canister_call_ic00(
        "update_settings",
        arg.encode(),
        format!(
            "IC0504: Management canister call payload includes sender canister version {:?} that does not match the actual sender canister version {}.",
            666, 0
        ),
    );
}

#[test]
fn wrong_sender_canister_version_update_settings_subnet_message() {
    let settings = CanisterSettingsArgs::default();
    let arg = UpdateSettingsArgs {
        canister_id: canister_test_id(2).into(),
        settings,
        sender_canister_version: Some(666),
    };
    failing_mgmt_canister_call_subnet_message(
        "update_settings",
        arg.encode(),
        format!(
            "IC0504: Management canister call payload includes sender canister version {:?} that does not match the actual sender canister version {}.",
            666, 0
        ),
    );
}

#[test]
fn correct_start_canister_ic00() {
    let arg: CanisterIdRecord = canister_test_id(1).into();
    correct_mgmt_canister_call_ic00("start_canister", arg.encode());
}

#[test]
fn correct_start_canister_subnet_message() {
    let arg: CanisterIdRecord = canister_test_id(2).into();
    correct_mgmt_canister_call_subnet_message("start_canister", arg.encode());
}

#[test]
fn wrong_method_name_ic00() {
    let arg: CanisterIdRecord = canister_test_id(1).into();
    failing_mgmt_canister_call_ic00(
        "start",
        arg.encode(),
        "IC0536: Management canister has no method 'start'".to_string(),
    );
}

#[test]
fn wrong_method_name_subnet_message() {
    let arg: CanisterIdRecord = canister_test_id(2).into();
    failing_mgmt_canister_call_subnet_message(
        "start",
        arg.encode(),
        "IC0536: Management canister has no method 'start'".to_string(),
    );
}
