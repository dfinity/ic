use ic_base_types::NumSeconds;
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, ExecutionParameters, HypervisorError, HypervisorResult,
    SubnetAvailableMemory, SystemApi, TrapCode,
};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::ENFORCE_MESSAGE_MEMORY_USAGE, testing::CanisterQueuesTesting, CallOrigin,
    Memory, NumWasmPages64, PageMap, SystemState,
};
use ic_system_api::{
    ApiType, NonReplicatedQueryKind, SystemApiImpl, SystemStateAccessor, SystemStateAccessorDirect,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::SystemStateBuilder,
    types::{
        ids::{call_context_test_id, canister_test_id, user_test_id},
        messages::RequestBuilder,
    },
};
use ic_types::{
    messages::{CallContextId, CallbackId, RejectContext, MAX_RESPONSE_COUNT_BYTES},
    user_error::RejectCode,
    ComputeAllocation, CountBytes, Cycles, NumBytes, NumInstructions,
};
use std::convert::TryInto;
use std::{convert::From, sync::Arc};

mod common;
use common::*;

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 40);

fn get_system_state_for_reject() -> SystemState {
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    system_state
}

fn get_test_api_for_reject(
    reject_context: RejectContext,
    system_state_accessor: SystemStateAccessorDirect,
) -> SystemApiImpl<SystemStateAccessorDirect> {
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    SystemApiImpl::new(
        system_state_accessor.canister_id(),
        ApiType::reject_callback(
            mock_time(),
            reject_context,
            Cycles::from(0),
            call_context_test_id(1),
            false,
            subnet_id,
            subnet_type,
            routing_table,
            subnet_records,
        ),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        execution_parameters(),
        no_op_logger(),
    )
}

fn assert_api_supported<T>(res: HypervisorResult<T>) {
    if let Err(HypervisorError::ContractViolation(err)) = res {
        assert!(!err.contains("cannot be executed"), "{}", err)
    }
}

fn assert_api_not_supported<T>(res: HypervisorResult<T>) {
    match res {
        Err(HypervisorError::ContractViolation(err)) => {
            assert!(err.contains("cannot be executed"), "{}", err)
        }
        _ => unreachable!("Expected api to be unsupported."),
    }
}

fn get_new_running_system_state(
    cycles_amount: Cycles,
    _own_subnet_type: SubnetType,
) -> SystemState {
    SystemState::new_running(
        canister_test_id(42),
        user_test_id(24).get(),
        cycles_amount,
        NumSeconds::from(100_000),
    )
}

fn get_reply_api_type(incoming_cycles: Cycles) -> ApiType {
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    ApiType::reply_callback(
        mock_time(),
        vec![],
        incoming_cycles,
        CallContextId::new(1),
        false,
        subnet_id,
        subnet_type,
        routing_table,
        subnet_records,
    )
}

fn get_heartbeat_api_type() -> ApiType {
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    ApiType::heartbeat(
        mock_time(),
        CallContextId::from(1),
        subnet_id,
        subnet_type,
        routing_table,
        subnet_records,
    )
}

#[test]
fn test_canister_init_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::init(mock_time(), vec![], user_test_id(1).get()),
        system_state,
        cycles_account_manager,
    );

    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_update_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_supported(api.ic0_msg_cycles_available());
    assert_api_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_supported(api.ic0_msg_cycles_accept(0));
    assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_replicated_query_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::replicated_query(mock_time(), vec![], user_test_id(1).get(), None),
        system_state,
        cycles_account_manager,
    );

    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_pure_query_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::replicated_query(mock_time(), vec![], user_test_id(1).get(), None),
        system_state,
        cycles_account_manager,
    );

    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_stateful_query_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let (subnet_id, _, routing_table, _) = setup();
    let mut api = get_system_api(
        ApiType::non_replicated_query(
            mock_time(),
            vec![],
            user_test_id(1).get(),
            CallContextId::from(1),
            subnet_id,
            routing_table,
            Some(vec![1]),
            NonReplicatedQueryKind::Stateful,
        ),
        system_state,
        cycles_account_manager,
    );

    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_supported(api.ic0_data_certificate_size());
    assert_api_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

fn get_test_api_for_reply(own_subnet_type: SubnetType) -> SystemApiImpl<SystemStateAccessorDirect> {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(own_subnet_type)
        .build();
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );
    get_system_api(
        get_reply_api_type(Cycles::from(0)),
        system_state,
        cycles_account_manager,
    )
}

#[test]
fn test_reply_api_support_on_nns() {
    let mut api = get_test_api_for_reply(SubnetType::System);

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_supported(api.ic0_msg_cycles_available());
    assert_api_supported(api.ic0_msg_cycles_available128());
    assert_api_supported(api.ic0_msg_cycles_refunded());
    assert_api_supported(api.ic0_msg_cycles_refunded128());
    assert_api_supported(api.ic0_msg_cycles_accept(0));
    assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_reply_api_support_non_nns() {
    let mut api = get_test_api_for_reply(SubnetType::Application);

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_supported(api.ic0_msg_cycles_available());
    assert_api_supported(api.ic0_msg_cycles_available128());
    assert_api_supported(api.ic0_msg_cycles_refunded());
    assert_api_supported(api.ic0_msg_cycles_refunded128());
    assert_api_supported(api.ic0_msg_cycles_accept(0));
    assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_reject_api_support_on_nns() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let system_state = get_system_state_for_reject();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = get_test_api_for_reject(
        RejectContext {
            code: RejectCode::CanisterReject,
            message: "error".to_string(),
        },
        system_state_accessor,
    );

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject_code());
    assert_api_supported(api.ic0_msg_reject_msg_size());
    assert_api_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_supported(api.ic0_msg_cycles_available());
    assert_api_supported(api.ic0_msg_cycles_available128());
    assert_api_supported(api.ic0_msg_cycles_refunded());
    assert_api_supported(api.ic0_msg_cycles_refunded128());
    assert_api_supported(api.ic0_msg_cycles_accept(0));
    assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_reject_api_support_non_nns() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = get_system_state_for_reject();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = get_test_api_for_reject(
        RejectContext {
            code: RejectCode::CanisterReject,
            message: "error".to_string(),
        },
        system_state_accessor,
    );

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_supported(api.ic0_msg_reply());
    assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_supported(api.ic0_msg_reject_code());
    assert_api_supported(api.ic0_msg_reject_msg_size());
    assert_api_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_supported(api.ic0_msg_cycles_available());
    assert_api_supported(api.ic0_msg_cycles_available128());
    assert_api_supported(api.ic0_msg_cycles_refunded());
    assert_api_supported(api.ic0_msg_cycles_refunded128());
    assert_api_supported(api.ic0_msg_cycles_accept(0));
    assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_pre_upgrade_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::pre_upgrade(mock_time(), user_test_id(1).get()),
        system_state,
        cycles_account_manager,
    );

    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_start_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemState::new_for_start(canister_test_id(91));
    let mut api = get_system_api(ApiType::start(), system_state, cycles_account_manager);

    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_canister_self_size());
    assert_api_not_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_controller_size());
    assert_api_not_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_not_supported(api.ic0_stable_size());
    assert_api_not_supported(api.ic0_stable_grow(1));
    assert_api_not_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_stable64_size());
    assert_api_not_supported(api.ic0_stable64_grow(1));
    assert_api_not_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_time());
    assert_api_not_supported(api.ic0_canister_cycle_balance());
    assert_api_not_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_not_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_cleanup_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::Cleanup { time: mock_time() },
        system_state,
        cycles_account_manager,
    );

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_inspect_message_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::inspect_message(
            user_test_id(1).get(),
            "hello".to_string(),
            vec![],
            mock_time(),
        ),
        system_state,
        cycles_account_manager,
    );

    assert_api_supported(api.ic0_msg_caller_size());
    assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_arg_data_size());
    assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_msg_method_name_size());
    assert_api_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_not_supported(api.ic0_call_cycles_add(0));
    assert_api_not_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_heartbeat_support() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    let mut api = get_system_api(
        get_heartbeat_api_type(),
        system_state,
        cycles_account_manager,
    );

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    assert_api_not_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_canister_heartbeat_support_nns() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut system_state = SystemStateBuilder::new().build();

    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    let mut api = get_system_api(
        get_heartbeat_api_type(),
        system_state,
        cycles_account_manager,
    );

    assert_api_not_supported(api.ic0_msg_caller_size());
    assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_arg_data_size());
    assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_msg_method_name_size());
    assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
    assert_api_not_supported(api.ic0_accept_message());
    assert_api_not_supported(api.ic0_msg_reply());
    assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
    assert_api_not_supported(api.ic0_msg_reject_code());
    assert_api_not_supported(api.ic0_msg_reject_msg_size());
    assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_canister_self_size());
    assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_controller_size());
    assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
    assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
    assert_api_supported(api.ic0_call_on_cleanup(0, 0));
    assert_api_supported(api.ic0_call_cycles_add(0));
    assert_api_supported(api.ic0_call_perform());
    assert_api_supported(api.ic0_stable_size());
    assert_api_supported(api.ic0_stable_grow(1));
    assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_stable64_size());
    assert_api_supported(api.ic0_stable64_grow(1));
    assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
    assert_api_supported(api.ic0_time());
    assert_api_supported(api.ic0_canister_cycle_balance());
    assert_api_supported(api.ic0_canister_cycles_balance128());
    assert_api_not_supported(api.ic0_msg_cycles_available());
    assert_api_not_supported(api.ic0_msg_cycles_available128());
    assert_api_not_supported(api.ic0_msg_cycles_refunded());
    assert_api_not_supported(api.ic0_msg_cycles_refunded128());
    assert_api_not_supported(api.ic0_msg_cycles_accept(0));
    assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
    assert_api_supported(api.ic0_data_certificate_present());
    assert_api_not_supported(api.ic0_data_certificate_size());
    assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
    assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
    assert_api_supported(api.ic0_canister_status());
    // Only supported on NNS.
    assert_api_supported(api.ic0_mint_cycles(0));
}

#[test]
fn test_discard_cycles_charge_by_new_call() {
    let cycles_amount = Cycles::from(1_000_000_000_000u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );

    // Add cycles to call.
    let amount = Cycles::from(49);
    assert_eq!(api.ic0_call_cycles_add128(amount), Ok(()));
    // Check cycles balance after call_add_cycles.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount - amount
    );

    // Discard the previous call
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance -> should be the same as the original as the call was
    // discarded.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );
}

#[test]
fn test_fail_add_cycles_when_not_enough_balance() {
    let cycles_amount = Cycles::from(1_000_000_000_000u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
    let canister_id = system_state.canister_id();
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );

    // Add cycles to call.
    let amount = cycles_amount + Cycles::from(1);
    assert_eq!(
        api.ic0_call_cycles_add128(amount).unwrap_err(),
        HypervisorError::InsufficientCyclesBalance(CanisterOutOfCyclesError {
            canister_id,
            available: cycles_amount,
            threshold: Cycles::from(0),
            requested: amount,
        })
    );
    //Check cycles balance after call_add_cycles.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );
}

#[test]
fn test_fail_adding_more_cycles_when_not_enough_balance() {
    let cycles_amount = 1_000_000_000_000;
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let system_state =
        get_new_running_system_state(Cycles::from(cycles_amount), SubnetType::Application);
    let canister_id = system_state.canister_id();
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount
    );

    // Add cycles to call.
    let amount = cycles_amount / 2 + 1;
    assert_eq!(
        api.ic0_call_cycles_add128(amount.try_into().unwrap()),
        Ok(())
    );
    // Check cycles balance after call_add_cycles.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount - amount
    );

    // Adding more cycles fails because not enough balance left.
    assert_eq!(
        api.ic0_call_cycles_add128(amount.try_into().unwrap())
            .unwrap_err(),
        HypervisorError::InsufficientCyclesBalance(CanisterOutOfCyclesError {
            canister_id,
            available: Cycles::from(cycles_amount - amount),
            threshold: Cycles::from(0),
            requested: Cycles::from(amount),
        })
    );
    // Balance unchanged after the second call_add_cycles.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount - amount
    );
}

#[test]
fn test_canister_balance() {
    let cycles_amount = 100;
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let mut system_state =
        get_new_running_system_state(Cycles::from(cycles_amount), SubnetType::Application);

    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    // Check cycles balance.
    assert_eq!(api.ic0_canister_cycle_balance().unwrap(), cycles_amount);
}

#[test]
fn test_canister_cycle_balance() {
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let mut system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);

    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
        );

    let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    // Check ic0_canister_cycle_balance.
    assert_eq!(
        api.ic0_canister_cycle_balance(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );
    let (high, low) = api.ic0_canister_cycles_balance128().unwrap();
    assert_eq!(Cycles::from_parts(high, low), cycles_amount);
}

#[test]
fn test_msg_cycles_available_traps() {
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let available_cycles = Cycles::from(789012345678901234567890u128);
    let mut system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            available_cycles,
        );

    let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(
        api.ic0_msg_cycles_available(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );
    let (high, low) = api.ic0_msg_cycles_available128().unwrap();
    assert_eq!(Cycles::from_parts(high, low), available_cycles);
}

#[test]
fn test_msg_cycles_refunded_traps() {
    let incoming_cycles = Cycles::from(789012345678901234567890u128);
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let api = get_system_api(
        get_reply_api_type(incoming_cycles),
        system_state,
        cycles_account_manager,
    );

    assert_eq!(
        api.ic0_msg_cycles_refunded(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );
    let (high, low) = api.ic0_msg_cycles_refunded128().unwrap();
    assert_eq!(Cycles::from_parts(high, low), incoming_cycles);
}

#[test]
fn certified_data_set() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
    let heap = vec![10; 33];

    // Setting more than 32 bytes fails.
    assert!(api.ic0_certified_data_set(0, 33, &heap).is_err());

    // Setting out of bounds size fails.
    assert!(api.ic0_certified_data_set(30, 10, &heap).is_err());

    // Copy the certified data into the system state.
    api.ic0_certified_data_set(0, 32, &heap).unwrap();

    let system_state_accessor = api.release_system_state_accessor();
    assert_eq!(
        system_state_accessor
            .release_system_state()
            .0
            .certified_data,
        vec![10; 32]
    )
}

#[test]
fn data_certificate_copy() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let api = get_system_api(
        ApiType::replicated_query(
            mock_time(),
            vec![],
            user_test_id(1).get(),
            Some(vec![1, 2, 3, 4, 5, 6]),
        ),
        system_state,
        cycles_account_manager,
    );
    let mut heap = vec![0; 10];

    // Copying with out of bounds offset + size fails.
    assert!(api.ic0_data_certificate_copy(0, 0, 10, &mut heap).is_err());
    assert!(api.ic0_data_certificate_copy(0, 10, 1, &mut heap).is_err());

    // Copying with out of bounds dst + size fails.
    assert!(api.ic0_data_certificate_copy(10, 1, 1, &mut heap).is_err());
    assert!(api.ic0_data_certificate_copy(0, 1, 11, &mut heap).is_err());

    // Copying all the data certificate.
    api.ic0_data_certificate_copy(0, 0, 6, &mut heap).unwrap();
    assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);

    // Copying part of the data certificate.
    api.ic0_data_certificate_copy(6, 2, 4, &mut heap).unwrap();
    assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 3, 4, 5, 6]);
}

#[test]
fn canister_status() {
    let own_subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    let running_system_state = get_new_running_system_state(INITIAL_CYCLES, own_subnet_type);

    let api = get_system_api(
        get_update_api_type(),
        running_system_state,
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(1));

    let stopping_system_state = SystemState::new_stopping(
        canister_test_id(42),
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let api = get_system_api(
        get_update_api_type(),
        stopping_system_state,
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(2));

    let stopped_system_state = SystemState::new_stopped(
        canister_test_id(42),
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let api = get_system_api(
        get_update_api_type(),
        stopped_system_state,
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(3));
}

/// msg_cycles_accept() can accept all cycles in call context
#[test]
fn msg_cycles_accept_all_cycles_in_call_context() {
    let amount = 50;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(amount),
        );
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(api.ic0_msg_cycles_accept(amount), Ok(amount));
}

/// msg_cycles_accept() can accept all cycles in call context when more
/// asked for
#[test]
fn msg_cycles_accept_all_cycles_in_call_context_when_more_asked() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(40),
        );
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(api.ic0_msg_cycles_accept(50), Ok(40));
}

/// msg_cycles_accept() can accept till max it can store
#[test]
fn msg_cycles_accept_accept_till_max_on_application_subnet() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_cycles_limit_per_canister(Some(CYCLES_LIMIT_PER_CANISTER))
        .build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(40),
        );

    // Set cycles balance to max - 10.
    cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::from(10),
        )
        .unwrap();

    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(api.ic0_msg_cycles_accept(50), Ok(10));
}

#[test]
fn msg_cycles_accept_max_cycles_per_canister_none_on_application_subnet() {
    let cycles = 10_000_000_000;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_cycles_limit_per_canister(None)
        .build();
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(cycles),
        );

    cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);

    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(api.ic0_msg_cycles_accept(cycles), Ok(cycles));
    let balance = api.ic0_canister_cycle_balance().unwrap();
    assert!(Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER);
}

/// msg_cycles_accept() can accept above max
#[test]
fn msg_cycles_accept_above_max_on_nns() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(40),
        );

    // Set cycles balance to max - 10.
    cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::from(10),
        )
        .unwrap();

    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

    assert_eq!(api.ic0_msg_cycles_accept(50), Ok(40));
    let balance = api.ic0_canister_cycle_balance().unwrap();
    assert!(Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER);
}

/// If call call_perform() fails because canister does not have enough
/// cycles to send the message, then the state is reset.
#[test]
fn call_perform_not_enough_cycles_resets_state() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    // Set initial cycles small enough so that it does not have enough
    // cycles to send xnet messages.
    let initial_cycles = cycles_account_manager.xnet_call_performed_fee() - Cycles::from(10);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(initial_cycles)
        .build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(40),
        );
    let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
    api.ic0_call_new(0, 10, 0, 10, 0, 0, 0, 0, &[0; 1024])
        .unwrap();
    api.ic0_call_cycles_add128(Cycles::from(100)).unwrap();
    assert_eq!(api.ic0_call_perform().unwrap(), 2);
    let system_state = api.release_system_state_accessor().release_system_state().0;
    let call_context_manager = system_state.call_context_manager().unwrap();
    assert_eq!(call_context_manager.call_contexts().len(), 1);
    assert_eq!(call_context_manager.callbacks().len(), 0);
    assert_eq!(system_state.cycles_balance, initial_cycles);
}

#[test]
fn stable_grow_updates_subnet_available_memory() {
    let wasm_page_size = 64 << 10;
    let subnet_available_memory_bytes = 2 * wasm_page_size;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = SystemApiImpl::new(
        system_state_accessor.canister_id(),
        get_update_api_type(),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        ExecutionParameters {
            subnet_available_memory: subnet_available_memory.clone(),
            ..execution_parameters()
        },
        no_op_logger(),
    );

    assert_eq!(api.ic0_stable_grow(1).unwrap(), 0);
    assert_eq!(subnet_available_memory.get(), wasm_page_size);

    assert_eq!(api.ic0_stable_grow(10).unwrap(), -1);
    assert_eq!(subnet_available_memory.get(), wasm_page_size);
}

#[test]
fn stable_grow_returns_allocated_memory_on_error() {
    // Subnet with stable memory size above what can be represented on 32 bits.
    let wasm_page_size = 64 << 10;
    let subnet_available_memory_bytes = 2 * wasm_page_size;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::new(PageMap::default(), NumWasmPages64::new(1 << 32)),
    );
    let mut api = SystemApiImpl::new(
        system_state_accessor.canister_id(),
        get_update_api_type(),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        ExecutionParameters {
            subnet_available_memory: subnet_available_memory.clone(),
            ..execution_parameters()
        },
        no_op_logger(),
    );

    // Ensure that ic0_stable_grow() returns an error.
    assert_eq!(
        api.ic0_stable_grow(1),
        Err(HypervisorError::Trapped(
            TrapCode::StableMemoryTooBigFor32Bit
        ))
    );
    // Subnet available memory should be unchanged.
    assert_eq!(subnet_available_memory.get(), subnet_available_memory_bytes);
    // As should the canister's current memory usage.
    assert_eq!(
        api.get_current_memory_usage(),
        CANISTER_CURRENT_MEMORY_USAGE
    );
}

#[test]
fn update_available_memory_updates_subnet_available_memory() {
    let wasm_page_size = 64 << 10;
    let subnet_available_memory_bytes = 2 * wasm_page_size;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = SystemApiImpl::new(
        system_state_accessor.canister_id(),
        get_update_api_type(),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        ExecutionParameters {
            subnet_available_memory: subnet_available_memory.clone(),
            ..execution_parameters()
        },
        no_op_logger(),
    );

    api.update_available_memory(0, 1).unwrap();
    assert_eq!(subnet_available_memory.get(), wasm_page_size);

    api.update_available_memory(0, 10).unwrap_err();
    assert_eq!(subnet_available_memory.get(), wasm_page_size);
}

#[test]
fn push_output_request_respects_memory_limits() {
    let subnet_available_memory_bytes = MAX_RESPONSE_COUNT_BYTES as i64 + 13;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
    let system_state = SystemStateBuilder::default().build();
    let own_canister_id = system_state.canister_id;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = SystemApiImpl::new(
        system_state_accessor.canister_id(),
        get_update_api_type(),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        ExecutionParameters {
            subnet_available_memory: subnet_available_memory.clone(),
            ..execution_parameters()
        },
        no_op_logger(),
    );

    let req = RequestBuilder::default().sender(own_canister_id).build();

    // First push succeeds with of without message memory usage accounting, as the
    // initial subnet available memory is `MAX_RESPONSE_COUNT_BYTES + 13`.
    assert_eq!(0, api.push_output_request(req.clone()).unwrap());
    if ENFORCE_MESSAGE_MEMORY_USAGE {
        // With message memory usage enabled, `MAX_RESPONSE_COUNT_BYTES` are consumed.
        assert_eq!(13, subnet_available_memory.get());
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE + NumBytes::from(MAX_RESPONSE_COUNT_BYTES as u64),
            api.get_current_memory_usage()
        );

        // And the second push fails.
        assert_eq!(
            RejectCode::SysTransient as i32,
            api.push_output_request(req).unwrap()
        );
        // Without altering memory usage.
        assert_eq!(13, subnet_available_memory.get());
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE + NumBytes::from(MAX_RESPONSE_COUNT_BYTES as u64),
            api.get_current_memory_usage()
        );
    } else {
        // With message memory usage disabled, any number of pushes will succeed, as the
        // memory usage is not affected.
        assert_eq!(subnet_available_memory_bytes, subnet_available_memory.get());
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE,
            api.get_current_memory_usage()
        );
    }

    // Ensure that exactly one output request was pushed.
    let system_state = api.release_system_state_accessor().release_system_state().0;
    assert_eq!(1, system_state.queues().output_queues_len());
}

#[test]
fn push_output_request_oversized_request_memory_limits() {
    let subnet_available_memory_bytes = 3 * MAX_RESPONSE_COUNT_BYTES as i64;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
    let system_state = SystemStateBuilder::default().build();
    let own_canister_id = system_state.canister_id;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    let mut api = SystemApiImpl::new(
        system_state_accessor.canister_id(),
        get_update_api_type(),
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        ExecutionParameters {
            subnet_available_memory: subnet_available_memory.clone(),
            ..execution_parameters()
        },
        no_op_logger(),
    );

    // Oversized payload larger than available memory.
    let req = RequestBuilder::default()
        .sender(own_canister_id)
        .method_payload(vec![13; 4 * MAX_RESPONSE_COUNT_BYTES])
        .build();

    if ENFORCE_MESSAGE_MEMORY_USAGE {
        // With message memory usage enabled, not enough memory to push the request.
        assert_eq!(
            RejectCode::SysTransient as i32,
            api.push_output_request(req).unwrap()
        );
        // Memory usage unchanged.
        assert_eq!(
            3 * MAX_RESPONSE_COUNT_BYTES as i64,
            subnet_available_memory.get()
        );
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE,
            api.get_current_memory_usage()
        );

        // Slightly smaller, still oversized request.
        let req = RequestBuilder::default()
            .sender(own_canister_id)
            .method_payload(vec![13; 2 * MAX_RESPONSE_COUNT_BYTES])
            .build();
        let req_size_bytes = req.count_bytes();
        assert!(req_size_bytes > MAX_RESPONSE_COUNT_BYTES);

        // Pushing succeeds.
        assert_eq!(0, api.push_output_request(req).unwrap());
        // `req_size_bytes` are consumed.
        assert_eq!(
            (3 * MAX_RESPONSE_COUNT_BYTES - req_size_bytes) as i64,
            subnet_available_memory.get()
        );
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE + NumBytes::from(req_size_bytes as u64),
            api.get_current_memory_usage()
        );
    } else {
        // With message memory usage disabled, push always succeeds.
        assert_eq!(0, api.push_output_request(req).unwrap());
        // And memory usage is not affected.
        assert_eq!(subnet_available_memory_bytes, subnet_available_memory.get());
        assert_eq!(
            CANISTER_CURRENT_MEMORY_USAGE,
            api.get_current_memory_usage()
        );
    }

    // Ensure that exactly one output request was pushed.
    let system_state = api.release_system_state_accessor().release_system_state().0;
    assert_eq!(1, system_state.queues().output_queues_len());
}
