use crate::config;
use ic_execution_environment::{Hypervisor, QueryExecutionType};
use ic_interfaces::execution_environment::ExecutionMode;
use ic_interfaces::execution_environment::{
    ExecutionParameters, HypervisorError, HypervisorError::ContractViolation, HypervisorResult,
    SubnetAvailableMemory, TrapCode,
};
use ic_interfaces::messages::RequestOrIngress;
use ic_metrics::MetricsRegistry;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::MemoryRegion;
use ic_replicated_state::{
    testing::CanisterQueuesTesting, CallContextAction, CallOrigin, CanisterState, Global,
    NumWasmPages, SystemState,
};
use ic_replicated_state::{ExportedFunctions, PageIndex};
use ic_sys::PAGE_SIZE;
use ic_system_api::ApiType;
use ic_test_utilities::types::messages::{IngressBuilder, RequestBuilder};
use ic_test_utilities::{
    assert_utils::assert_balance_equals,
    cycles_account_manager::CyclesAccountManagerBuilder,
    metrics::{fetch_histogram_stats, HistogramStats},
    mock_time,
    state::{
        canister_from_exec_state, get_stopped_canister, get_stopping_canister, SystemStateBuilder,
    },
    types::ids::{call_context_test_id, canister_test_id, subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{
    ingress::WasmResult,
    messages::{CallbackId, Payload, RejectContext, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES},
    methods::{Callback, FuncRef, SystemMethod, WasmClosure, WasmMethod},
    user_error::RejectCode,
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, SubnetId, Time, UserId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::{collections::BTreeMap, convert::TryFrom, sync::Arc, time::Duration};

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const EMPTY_PAYLOAD: Vec<u8> = Vec::new();
const MEMORY_ALLOCATION: NumBytes = NumBytes::new(10_000_000);
const BALANCE_EPSILON: Cycles = Cycles::new(10_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX / 2);
}

fn execution_parameters_with_unique_subnet_available_memory(
    canister: &CanisterState,
    instruction_limit: NumInstructions,
    subnet_available_memory: SubnetAvailableMemory,
) -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit,
        canister_memory_limit: canister.memory_limit(NumBytes::new(u64::MAX / 2)),
        subnet_available_memory,
        compute_allocation: canister.scheduler_state.compute_allocation,
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    }
}

fn execution_parameters(
    canister: &CanisterState,
    instruction_limit: NumInstructions,
) -> ExecutionParameters {
    execution_parameters_with_unique_subnet_available_memory(
        canister,
        instruction_limit,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    )
}

fn test_func_ref() -> FuncRef {
    FuncRef::Method(WasmMethod::Update(String::from("test")))
}

fn test_caller() -> PrincipalId {
    user_test_id(1).get()
}

fn setup() -> (
    SubnetId,
    SubnetType,
    Arc<RoutingTable>,
    Arc<BTreeMap<SubnetId, SubnetType>>,
) {
    let subnet_id = subnet_test_id(1);
    let subnet_id_2 = subnet_test_id(2);
    let subnet_type = SubnetType::Application;
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfe) } => subnet_id,
            CanisterIdRange{ start: CanisterId::from(0xff), end: CanisterId::from(0xff) } => subnet_id_2,
        })
        .unwrap(),
    );
    let subnet_records = Arc::new(btreemap! {
        subnet_id => subnet_type,
        subnet_id_2 => SubnetType::VerifiedApplication,
    });
    (subnet_id, subnet_type, routing_table, subnet_records)
}

fn test_api_type_for_update(caller: Option<PrincipalId>, payload: Vec<u8>) -> ApiType {
    let caller = caller.unwrap_or_else(|| user_test_id(24).get());
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    ApiType::update(
        mock_time(),
        payload,
        Cycles::from(0),
        caller,
        call_context_test_id(13),
        subnet_id,
        subnet_type,
        routing_table,
        subnet_records,
    )
}

fn test_api_type_for_reject(reject_context: RejectContext) -> ApiType {
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    ApiType::reject_callback(
        mock_time(),
        reject_context,
        Cycles::from(0),
        call_context_test_id(13),
        false,
        subnet_id,
        subnet_type,
        routing_table,
        subnet_records,
    )
}

pub fn with_hypervisor<F>(f: F)
where
    F: FnOnce(Hypervisor, std::path::PathBuf),
{
    with_test_replica_logger(|log| {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            config(),
            &metrics_registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        f(hypervisor, tmpdir.path().into());
    });
}

fn execute_update(
    hypervisor: &Hypervisor,
    wast: &str,
    method: &str,
    payload: Vec<u8>,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    execute_update_on(hypervisor, wast, method, payload, None, None, canister_root)
}

fn execute_update_on(
    hypervisor: &Hypervisor,
    wast: &str,
    method: &str,
    payload: Vec<u8>,
    source: Option<UserId>,
    receiver: Option<CanisterId>,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    execute_update_with_cycles_memory_time(
        hypervisor,
        wast,
        method,
        payload,
        source,
        receiver,
        MAX_NUM_INSTRUCTIONS,
        NumBytes::from(0),
        mock_time(),
        canister_root,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_update_with_cycles_memory_time_subnet_memory(
    hypervisor: &Hypervisor,
    wast: &str,
    method: &str,
    payload: Vec<u8>,
    instructions_limit: NumInstructions,
    bytes: NumBytes,
    time: Time,
    canister_root: std::path::PathBuf,
    subnet_available_memory: SubnetAvailableMemory,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    let source = user_test_id(24);
    let receiver = canister_test_id(42);

    let wasm_binary = wabt::wat2wasm(wast).unwrap();
    let execution_state = hypervisor
        .create_execution_state(wasm_binary, canister_root, receiver)
        .unwrap();
    let mut canister = canister_from_exec_state(execution_state, receiver);
    canister.system_state.memory_allocation = MemoryAllocation::try_from(bytes).unwrap();

    let req = IngressBuilder::new()
        .method_name(method.to_string())
        .method_payload(payload)
        .source(source)
        .build();

    let (_, _, routing_table, subnet_records) = setup();
    let execution_parameters = execution_parameters_with_unique_subnet_available_memory(
        &canister,
        instructions_limit,
        subnet_available_memory,
    );
    let (canister, num_instructions_left, action, heap_delta) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Ingress(req),
        time,
        routing_table,
        subnet_records,
        execution_parameters,
    );

    (canister, num_instructions_left, action, heap_delta)
}

#[allow(clippy::too_many_arguments)]
fn execute_update_with_cycles_memory_time(
    hypervisor: &Hypervisor,
    wast: &str,
    method: &str,
    payload: Vec<u8>,
    source: Option<UserId>,
    receiver: Option<CanisterId>,
    instructions_limit: NumInstructions,
    bytes: NumBytes,
    time: Time,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    let source = source.unwrap_or_else(|| user_test_id(24));
    let receiver = receiver.unwrap_or_else(|| canister_test_id(42));

    let wasm_binary = wabt::wat2wasm(wast).unwrap();
    let execution_state = hypervisor
        .create_execution_state(wasm_binary, canister_root, receiver)
        .unwrap();
    let mut canister = canister_from_exec_state(execution_state, receiver);
    canister.system_state.memory_allocation = MemoryAllocation::try_from(bytes).unwrap();
    canister.system_state.canister_id = receiver;

    let req = IngressBuilder::new()
        .method_name(method.to_string())
        .method_payload(payload)
        .source(source)
        .receiver(receiver)
        .build();

    let (_, _, routing_table, subnet_records) = setup();
    let execution_parameters = execution_parameters(&canister, instructions_limit);
    let (canister, num_instructions_left, action, heap_delta) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Ingress(req),
        time,
        routing_table,
        subnet_records,
        execution_parameters,
    );

    (canister, num_instructions_left, action, heap_delta)
}

#[allow(clippy::too_many_arguments)]
fn execute_update_for_request(
    hypervisor: &Hypervisor,
    wast: &str,
    method: &str,
    payload: Vec<u8>,
    payment: Cycles,
    caller: Option<PrincipalId>,
    instructions_limit: NumInstructions,
    time: Time,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction) {
    let caller = CanisterId::new(caller.unwrap_or_else(|| canister_test_id(24).get())).unwrap();

    let wasm_binary = wabt::wat2wasm(wast).unwrap();
    let canister_id = canister_test_id(42);
    let execution_state = hypervisor
        .create_execution_state(wasm_binary, canister_root, canister_id)
        .unwrap();

    let canister = canister_from_exec_state(execution_state, canister_id);

    let req = RequestBuilder::new()
        .method_name(method.to_string())
        .method_payload(payload)
        .sender(caller)
        .receiver(canister.canister_id())
        .payment(payment)
        .build();

    let (_, _, routing_table, subnet_records) = setup();
    let execution_parameters = execution_parameters(&canister, instructions_limit);
    let (canister, num_instructions_left, action, _) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Request(req),
        time,
        routing_table,
        subnet_records,
        execution_parameters,
    );

    (canister, num_instructions_left, action)
}

fn execute(
    api_type: ApiType,
    system_state: SystemState,
    wast: &str,
    func_ref: FuncRef,
) -> Result<Option<WasmResult>, HypervisorError> {
    let mut result = Ok(None);
    let result_ref = &mut result;
    with_hypervisor(move |hypervisor, tmp_path| {
        let wasm_binary = wabt::wat2wasm(wast).unwrap();
        let execution_state = hypervisor
            .create_execution_state(wasm_binary, tmp_path, system_state.canister_id)
            .unwrap();
        let execution_parameters = ExecutionParameters {
            instruction_limit: MAX_NUM_INSTRUCTIONS,
            canister_memory_limit: NumBytes::from(4 << 30),
            subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
        };
        *result_ref = hypervisor
            .execute(
                api_type,
                system_state,
                NumBytes::from(0),
                execution_parameters,
                func_ref,
                execution_state,
            )
            .0
            .wasm_result;
    });
    result
}

#[test]
// Runs unexported name
fn test_method_not_found_error() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(&hypervisor, "(module)", "test", EMPTY_PAYLOAD, tmp_path,).2,
            CallContextAction::Fail {
                error: HypervisorError::MethodNotFound(WasmMethod::Update("test".to_string())),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
// Runs unavailable table function
fn test_function_not_found_error() {
    let func_idx = 111;
    let wast = r#"(module
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (func $test (param i64 i32)
                    (call $ic_trap (i32.const 0) (i32.const 6)))
                  (table funcref (elem $test))
                  (memory (export "memory") 1)
                  (data (i32.const 0) "table!")
            )"#;

    let api_type = test_api_type_for_update(None, vec![]);
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        wast,
        FuncRef::UpdateClosure(WasmClosure::new(func_idx, 1)),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::FunctionNotFound(0, func_idx))
    );
}

#[test]
// Runs table function with a wrong signature
fn test_table_function_unexpected_signature() {
    let api_type = test_api_type_for_update(None, vec![]);
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"(module
                  (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                  (func $test
                    (call $ic_trap (i32.const 0) (i32.const 6)))
                  (table funcref (elem $test))
                  (memory (export "memory") 1)
                  (data (i32.const 0) "table!")
                )"#,
        FuncRef::UpdateClosure(WasmClosure::new(0, 1)),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::ContractViolation(
            "function invocation does not match its signature".to_string()
        ))
    );
}

#[test]
// noop start
fn start_noop() {
    with_hypervisor(|hypervisor, tmp_path| {
        let binary = wabt::wat2wasm(
            r#"(module
                          (func (;0;))
                          (start 0))"#,
        )
        .unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        hypervisor
            .execute_canister_start(canister, execution_parameters)
            .2
            .expect("(start) succeeds");
    });
}

#[test]
// tests calling a func_ref by table index
fn test_func_ref_call_by_index() {
    let api_type = test_api_type_for_update(None, vec![0, 1, 2, 3]);
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"(module
                  (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                  (func $test (param $env i32)
                    (call $ic_trap (i32.const 0) (i32.const 6)))
                  (table funcref (elem $test))
                  (memory (export "memory") 1)
                  (data (i32.const 0) "table!")
            )"#,
        FuncRef::UpdateClosure(WasmClosure::new(0, 0)),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::CalledTrap("table!".to_string()))
    );
}

#[test]
// tests that canister_status returns 1 for running canister
fn sys_api_call_canister_status() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
             (module
              (import "ic0" "canister_status" (func $canister_status (result i32)))
              (func $hi
               (if (i32.ne (call $canister_status) (i32.const 1))
                (then unreachable)
               )
              )
              (memory $memory 1)
              (export "canister_update hi" (func $hi))
             )"#,
                "hi",
                vec![],
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse {
                refund: Cycles::from(0),
            },
        )
    })
}

#[test]
// tests the correct payload length of 4
fn sys_api_call_arg_data_size() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                  (import "ic0" "msg_arg_data_size" (func (;0;) (result i32)))
                  (func (;1;)
                    block
                        call 0
                        i32.const 4
                        i32.eq
                        br_if 0
                        unreachable
                    end)
                  (export "canister_update test" (func 1)))"#,
                "test",
                vec![0, 1, 2, 3],
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse {
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn sys_api_call_stable_grow() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_size" (func $stable_size (result i32)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow the memory by 1 page and verify that the return value
                        ;; is the previous number of pages, which should be 0.
                        (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                            (then (unreachable))
                        )

                        ;; Grow the memory by 5 more pages and verify that the return value
                        ;; is the previous number of pages, which should be 1.
                        (if (i32.ne (call $stable_grow (i32.const 5)) (i32.const 1))
                            (then (unreachable))
                        )

                        ;; Stable memory size now should be 6
                        (if (i32.ne (call $stable_size) (i32.const 6))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn exercise_stable_memory_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm_module = r#"
                (module
                    (import "ic0" "stable_size" (func $stable_size (result i32)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $grow
                        (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                            (then (unreachable))
                        )
                        (if (i32.ne (call $stable_size) (i32.const 1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (func $write
                        (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                            (then (unreachable))
                        )
                        (if (i32.ne (call $stable_size) (i32.const 1))
                            (then (unreachable))
                        )
                        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 6144))
                        (call $msg_reply)
                    )

                    (memory $memory 1)
                    (export "memory" (memory $memory))
                    (export "canister_update write" (func $write))
                    (export "canister_update grow" (func $grow)))"#;

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "grow",
            EMPTY_PAYLOAD,
            tmp_path.clone(),
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(delta, NumBytes::from(0));

        let (_, _, action, delta) =
            execute_update(&hypervisor, wasm_module, "write", EMPTY_PAYLOAD, tmp_path);
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        // We wrote more than 1 page but less than 2 pages so we should expect a
        // 2 page delta.
        assert_eq!(delta, NumBytes::from(8192));
    });
}

#[test]
fn exercise_stable_memory_delta_2() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm_module = r#"
                (module
                    (import "ic0" "stable_size" (func $stable_size (result i32)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $grow
                        (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                            (then (unreachable))
                        )
                        (if (i32.ne (call $stable_size) (i32.const 1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (func $write
                        (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                            (then (unreachable))
                        )
                        (if (i32.ne (call $stable_size) (i32.const 1))
                            (then (unreachable))
                        )
                        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 8192))
                        (call $msg_reply)
                    )

                    (memory $memory 1)
                    (export "memory" (memory $memory))
                    (export "canister_update write" (func $write))
                    (export "canister_update grow" (func $grow)))"#;

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "grow",
            EMPTY_PAYLOAD,
            tmp_path.clone(),
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(delta, NumBytes::from(0));

        let (_, _, action, delta) =
            execute_update(&hypervisor, wasm_module, "write", EMPTY_PAYLOAD, tmp_path);
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        // We wrote exactly two pages, so we should get a 2 page delta.
        assert_eq!(delta, NumBytes::from(8192));
    });
}

#[test]
fn exercise_stable_memory_delta64() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm_module = r#"
                (module
                    (import "ic0" "stable64_size" (func $stable64_size (result i64)))
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $grow
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                            (then (unreachable))
                        )
                        (if (i64.ne (call $stable64_size) (i64.const 1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (func $write
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                            (then (unreachable))
                        )
                        (if (i64.ne (call $stable64_size) (i64.const 1))
                            (then (unreachable))
                        )
                        (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 6144))
                        (call $msg_reply)
                    )

                    (memory $memory 1)
                    (export "memory" (memory $memory))
                    (export "canister_update write" (func $write))
                    (export "canister_update grow" (func $grow)))"#;

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "grow",
            EMPTY_PAYLOAD,
            tmp_path.clone(),
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(delta, NumBytes::from(0));

        let (_, _, action, delta) =
            execute_update(&hypervisor, wasm_module, "write", EMPTY_PAYLOAD, tmp_path);
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        // We wrote more than 1 page but less than 2 pages so we should expect a
        // 2 page delta.
        assert_eq!(delta, NumBytes::from(8192));
    });
}

#[test]
fn exercise_stable_memory_delta64_exact_page() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm_module = r#"
                (module
                    (import "ic0" "stable64_size" (func $stable64_size (result i64)))
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $grow
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                            (then (unreachable))
                        )
                        (if (i64.ne (call $stable64_size) (i64.const 1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (func $write
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                            (then (unreachable))
                        )
                        (if (i64.ne (call $stable64_size) (i64.const 1))
                            (then (unreachable))
                        )
                        (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 8192))
                        (call $msg_reply)
                    )

                    (memory $memory 1)
                    (export "memory" (memory $memory))
                    (export "canister_update write" (func $write))
                    (export "canister_update grow" (func $grow)))"#;

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "grow",
            EMPTY_PAYLOAD,
            tmp_path.clone(),
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(delta, NumBytes::from(0));

        let (_, _, action, delta) =
            execute_update(&hypervisor, wasm_module, "write", EMPTY_PAYLOAD, tmp_path);
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        // We wrote exactly 2 pages, so we should a 2 page delta.
        assert_eq!(delta, NumBytes::from(8192));
    });
}

#[test]
fn sys_api_call_stable_grow_too_many_pages() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_size" (func $stable_size (result i32)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow the memory by 10 pages.
                        (drop (call $stable_grow (i32.const 10)))
                        ;; Grow the memory by 2^32-1 pages.
                        ;; This should fail since it's bigger than the maximum number of memory
                        ;; pages that can be allocated and return -1.
                        (if (i32.ne (call $stable_grow (i32.const 4294967295)) (i32.const -1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn sys_api_call_stable64_grow() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_size" (func $stable64_size (result i64)))
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow the memory by 1 page and verify that the return value
                        ;; is the previous number of pages, which should be 0.
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                            (then (unreachable))
                        )

                        ;; Grow the memory by 5 more pages and verify that the return value
                        ;; is the previous number of pages, which should be 1.
                        (if (i64.ne (call $stable64_grow (i64.const 5)) (i64.const 1))
                            (then (unreachable))
                        )

                        ;; Grow the memory by 2^64-1 more pages. This should fail.
                        (if (i64.ne (call $stable64_grow (i64.const 18446744073709551615)) (i64.const -1))
                            (then (unreachable))
                        )

                        ;; Stable memory size now should be 6.
                        (if (i64.ne (call $stable64_size) (i64.const 6))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                NumBytes::from(8 * 1024 * 1024 * 1024),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn sys_api_call_stable_grow_by_0_traps_if_memory_exceeds_4gb() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow the memory to 4GiB.
                        (if (i64.ne (call $stable64_grow (i64.const 65536)) (i64.const 0))
                            (then (unreachable))
                        )
                        ;; Grow the memory by 0 pages using 32-bit API. This should succeed.
                        (if (i32.ne (call $stable_grow (i32.const 0)) (i32.const 65536))
                            (then (unreachable))
                        )
                        ;; Grow the memory by 1 page. This should succeed.
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 65536))
                            (then (unreachable))
                        )

                        ;; Grow the memory by 0 pages using 32-bit API. This should trap.
                        (drop (call $stable_grow (i32.const 0)))

                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                NumBytes::from(8 * 1024 * 1024 * 1024),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryTooBigFor32Bit),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_grow_by_traps_if_memory_exceeds_4gb() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow the memory to 4GiB.
                        (if (i64.ne (call $stable64_grow (i64.const 65536)) (i64.const 0))
                            (then (unreachable))
                        )
                        ;; Grow the memory by 0 pages using 32-bit API. This should succeed.
                        (if (i32.ne (call $stable_grow (i32.const 0)) (i32.const 65536))
                            (then (unreachable))
                        )
                        ;; Grow the memory by 1 page. This should succeed.
                        (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 65536))
                            (then (unreachable))
                        )

                        ;; Grow the memory by 100 pages using 32-bit API. This should trap.
                        (drop (call $stable_grow (i32.const 100)))

                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                NumBytes::from(8 * 1024 * 1024 * 1024),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryTooBigFor32Bit),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_write() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))
                    (import "ic0" "msg_reply_data_append"
                        (func $msg_reply_data_append (param i32 i32)))

                    (func $test
                        ;; Swap the first 8 bytes from "abcdefgh" to "efghabcd" using stable memory

                        ;; Grow stable memory by 1 page.
                        (drop (call $stable_grow (i32.const 1)))

                        ;; stable_memory[0..4] = heap[0..4]
                        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))

                        ;; stable_memory[60000..60004] = heap[4..8]
                        (call $stable_write (i32.const 60000) (i32.const 4) (i32.const 4))

                        ;; heap[0..4] = stable_memory[60000..60004]
                        (call $stable_read (i32.const 0) (i32.const 60000) (i32.const 4))

                        ;; heap[4..8] = stable_memory[0..4]
                        (call $stable_read (i32.const 4) (i32.const 0) (i32.const 4))

                        ;; Return the first 8 bytes of the heap.
                        (call $msg_reply_data_append
                            (i32.const 0)     ;; heap offset = 0
                            (i32.const 8))    ;; length = 8
                        (call $msg_reply)     ;; call reply
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: b"efghabcd".to_vec(),
                refund: Cycles::from(0),
            },
        );
    });
}

// -------------------- Edge cases for stable_read/write --------------------

#[test]
fn sys_api_call_stable_read_traps_when_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

                    (func $test
                        ;; Reading from stable memory should fail, since the memory size is
                        ;; initially zero.
                        (call $stable_read (i32.const 0) (i32.const 0) (i32.const 4))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_can_handle_overflows() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

                    (func $test
                        ;; Reading from stable memory with the maximum possible size.
                        ;; Ensure the function errors gracefully and doesn't panic due to overflow.
                        (call $stable_read (i32.const 0) (i32.const 1) (i32.const 4294967295))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS * 10,
                NumBytes::from(0),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_write_traps_when_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

                    (func $test
                        ;; Writing to stable memory should fail, since the memory size is zero.
                        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_write_can_handle_overflows() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

                    (func $test
                        ;; Writing to stable memory with the maximum possible size.
                        ;; Ensure the function errors gracefully and doesn't panic due to overflow.
                        (call $stable_write (i32.const 1) (i32.const 0) (i32.const 4294967295))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS * 10,
                NumBytes::from(0),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_traps_when_heap_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

                    (func $test
                        ;; Grow stable memory by 2 page.
                        (drop (call $stable_grow (i32.const 2)))

                        ;; Attempting to read 2 pages into memory of size 1. This should fail.
                        (call $stable_read
                            (i32.const 0)
                            (i32.const 0)
                            (i32.mul (i32.const 2) (i32.const 65536))
                        )
                    )

                    (memory 1)
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::HeapOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_write_traps_when_heap_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

                    (func $test
                        (drop (call $stable_grow (i32.const 2)))

                        ;; Attempting to copy 2 pages from memory of size 1. This should fail.
                        (call $stable_write
                            (i32.const 0)
                            (i32.const 0)
                            (i32.mul (i32.const 2) (i32.const 65536)))
                    )

                    (memory 1)
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::HeapOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_write_at_max_size_handled_gracefully() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow"
                        (func $stable_grow (param $additional_pages i32) (result i32)))
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow stable memory to maximum size.
                        (drop (call $stable_grow (i32.const 65536)))
                        ;; Write to stable memory from position 10 till the end (including).
                        (call $stable_write (i32.const 4294967286) (i32.const 0) (i32.const 10))
                        (call $msg_reply)
                    )

                    (memory 65536)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_does_not_trap_at_end_of_page() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow stable memory by 1 page (64kb)
                        (drop (call $stable_grow (i32.const 1)))

                        ;; Reading from stable memory at end of page should not fail.
                        (call $stable_read (i32.const 0) (i32.const 0) (i32.const 65536))
                        (call $msg_reply)
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_traps_beyond_end_of_page() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

                    (func $test
                        ;; Grow stable memory by 1 page (64kb)
                        (drop (call $stable_grow (i32.const 1)))

                        ;; Reading from stable memory just after the page should trap.
                        (call $stable_read (i32.const 0) (i32.const 65536) (i32.const 1))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable_read_at_max_size_handled_gracefully() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_grow"
                        (func $stable_grow (param $additional_pages i32) (result i32)))
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow stable memory to maximum size.
                        (drop (call $stable_grow (i32.const 65536)))
                        ;; Read from position at index 10 till the end of stable memory (including).
                        (call $stable_read (i32.const 0) (i32.const 4294967286) (i32.const 10))
                        (call $msg_reply)
                    )

                    (memory 65536)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

// --------------------------------------------------------------------------

// ----------------- Edge cases for stable64_read/write64 -------------------

#[test]
fn sys_api_call_stable64_read_traps_when_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))

                    (func $test
                        ;; Reading from stable memory should fail, since the memory size is
                        ;; initially zero.
                        (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 4))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_read_can_handle_overflows() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow"
                        (func $stable64_grow (param $additional_pages i64) (result i64)))
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))

                    (func $test
                        ;; Grow the memory by 1 page.
                        (drop (call $stable64_grow (i64.const 1)))
                        ;; Ensure reading from stable memory with overflow doesn't panic.
                        (call $stable64_read (i64.const 0) (i64.const 18446744073709551615) (i64.const 10))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_write_traps_when_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                    (func $test
                        ;; Writing to stable memory should fail, since the memory size is zero.
                        (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 4))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_write_can_handle_overflows() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow"
                        (func $stable64_grow (param $additional_pages i64) (result i64)))
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                    (func $test
                        ;; Grow the memory by 1 page.
                        (drop (call $stable64_grow (i64.const 1)))
                        ;; Writing to stable memory with the maximum possible size.
                        ;; Ensure the function errors gracefully and doesn't panic due to overflow.
                        (call $stable64_write (i64.const 18446744073709551615) (i64.const 0) (i64.const 10))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_read_traps_when_heap_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))

                    (func $test
                        ;; Grow stable memory by 2 page.
                        (drop (call $stable64_grow (i64.const 2)))

                        ;; Attempting to read 2 pages into memory of size 1. This should fail.
                        (call $stable64_read
                            (i64.const 0)
                            (i64.const 0)
                            (i64.mul (i64.const 2) (i64.const 65536))
                        )
                    )

                    (memory 1)
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::HeapOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_write_traps_when_heap_out_of_bounds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                    (func $test
                        (drop (call $stable64_grow (i64.const 2)))

                        ;; Attempting to copy 2 pages from memory of size 1. This should fail.
                        (call $stable64_write
                            (i64.const 0)
                            (i64.const 0)
                            (i64.mul (i64.const 2) (i64.const 65536)))
                    )

                    (memory 1)
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::HeapOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_read_does_not_trap_at_end_of_page() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Grow stable memory by 1 page (64kb)
                        (drop (call $stable64_grow (i64.const 1)))

                        ;; Reading from stable memory at end of page should not fail.
                        (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 65536))
                        (call $msg_reply)
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_stable64_read_traps_beyond_end_of_page() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))

                    (func $test
                        ;; Grow stable memory by 1 page (64kb)
                        (drop (call $stable64_grow (i64.const 1)))

                        ;; Reading from stable memory just after the page should trap.
                        (call $stable64_read (i64.const 0) (i64.const 65536) (i64.const 1))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

// ---------------------------------------------------------------------------

#[test]
fn sys_api_call_time_with_5_nanoseconds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "time" (func $time (result i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Make sure that time is callable.
                        (if (i64.ne (call $time) (i64.const 5))
                            (then (unreachable))
                        )

                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                MEMORY_ALLOCATION,
                // Five nanoseconds
                mock_time() + Duration::new(0, 5),
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_time_with_5_seconds() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "time" (func $time (result i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $test
                        ;; Make sure that time is callable.
                        (if (i64.ne (call $time) (i64.const 5000000000))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                MEMORY_ALLOCATION,
                // Five seconds
                mock_time() + Duration::new(5, 0),
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
// tests that ic0_msg_arg_data_size cannot be accessed in a reject callback
fn sys_api_call_arg_data_size_fail() {
    let api_type = test_api_type_for_reject(RejectContext {
        code: RejectCode::CanisterError,
        message: "error".to_string(),
    });
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (import "ic0" "msg_arg_data_size" (func (;0;) (result i32)))
                  (func (;1;) (call 0) drop)
                  (export "canister_update test" (func 1)))"#,
        test_func_ref(),
    );
    let err = wasm_result.unwrap_err();
    assert_eq!(
        err,
        HypervisorError::ContractViolation(
            "\"ic0_msg_arg_data_size\" cannot be executed in reject callback mode".to_string()
        )
    );
}

#[test]
// reads data from the heap
fn sys_api_call_reply() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"(module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32) (param i32)))
                  (func $test
                        (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                        (call $msg_reply_data_append (i32.const 4) (i32.const 4))
                        (call $msg_reply))
                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (data (i32.const 0) "xxxxabcd")
                  (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: b"xxxxabcd".to_vec(),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
// reads data from the heap
fn sys_api_call_reply_without_finishing() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"(module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32) (param i32)))
                  (func $test
                        (call $msg_reply_data_append (i32.const 0) (i32.const 8)))
                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (data (i32.const 0) "xxxxabcd")
                  (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse {
                refund: Cycles::from(0),
            },
        );
    });
}

const MSG_CALLER_WAT: &str = r#"
        (module
          (import "ic0" "msg_caller_size"
            (func $ic0_msg_caller_size (result i32)))
          (import "ic0" "msg_caller_copy"
            (func $ic0_msg_caller_copy (param i32 i32 i32)))
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32) (param i32)))

          (func $test
            (local $half_len i32)
            ;; divide caller size by 2 and store it
            (local.set $half_len (i32.div_u (call $ic0_msg_caller_size) (i32.const 2)))

            ;; heap[0..$half_len] = canister_id_bytes[0..$half_len]
            (call $ic0_msg_caller_copy (i32.const 0) (i32.const 0) (local.get $half_len))

            ;; heap[$half_len..2*$half_len] = canister_id_bytes[$half_len..2*$half_len]
            (call $ic0_msg_caller_copy
                (local.get $half_len)
                (local.get $half_len)
                (i32.sub (call $ic0_msg_caller_size) (local.get $half_len)))

            ;; return heap[0..2*$half_len]
            (call $msg_reply_data_append (i32.const 0) (call $ic0_msg_caller_size))
            (call $msg_reply))

          (memory $memory 1)
          (export "memory" (memory $memory))
          (export "canister_query query_test" (func $test))
          (export "canister_update update_test" (func $test)))"#;

#[test]
// Tests msg_caller functions in update calls.
fn test_execute_update_msg_caller() {
    with_hypervisor(|hypervisor, tmp_path| {
        let id = user_test_id(12);
        assert_eq!(
            execute_update_on(
                &hypervisor,
                MSG_CALLER_WAT,
                "update_test",
                EMPTY_PAYLOAD,
                Some(id),
                None,
                tmp_path.clone(),
            )
            .2,
            CallContextAction::Reply {
                payload: id.get().into_vec(),
                refund: Cycles::from(0),
            },
        );

        let id = user_test_id(32);
        assert_eq!(
            execute_update_on(
                &hypervisor,
                MSG_CALLER_WAT,
                "update_test",
                EMPTY_PAYLOAD,
                Some(id),
                None,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: id.get().into_vec(),
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
// Tests msg_caller functions in query calls.
fn test_execute_query_msg_caller() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm_binary = wabt::wat2wasm(MSG_CALLER_WAT).unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm_binary, tmp_path, canister_id)
            .unwrap();
        let _system_state = SystemStateBuilder::default().build();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let id = user_test_id(12);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (canister, _, result) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_test",
            &[],
            id.get(),
            canister,
            None,
            mock_time(),
            execution_parameters.clone(),
        );
        assert_eq!(result, Ok(Some(WasmResult::Reply(id.get().into_vec()))));

        let id = canister_test_id(37);
        let (_, _, result) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_test",
            &[],
            id.get(),
            canister,
            None,
            mock_time(),
            execution_parameters,
        );
        assert_eq!(result, Ok(Some(WasmResult::Reply(id.get().into_vec()))));
    });
}

#[test]
// Tests that ic0_msg_arg_data_copy cannot be accessed in a reject callback
fn sys_api_call_arg_data_copy_fail() {
    let api_type = test_api_type_for_reject(RejectContext {
        code: RejectCode::CanisterError,
        message: "error".to_string(),
    });
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (import "ic0" "msg_arg_data_copy"
                    (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
                  (func $test
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 0)))
                  (memory 1)
                  (export "canister_update test" (func $test)))"#,
        test_func_ref(),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::ContractViolation(
            "\"ic0_msg_arg_data_copy\" cannot be executed in reject callback mode".to_string()
        ))
    );
}

#[test]
// copies data from payload to the heap and returns it
fn sys_api_call_arg_data_copy() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32 i32)))
                  (import "ic0" "msg_arg_data_copy"
                    (func $msg_arg_data_copy (param i32 i32 i32)))
                  (func $test
                    (call $msg_arg_data_copy
                        (i32.const 4)     ;; heap dst = 4
                        (i32.const 0)     ;; payload offset = 0
                        (i32.const 4))     ;; length = 4
                    (call $msg_reply_data_append
                        (i32.const 0)     ;; heap offset = 0
                        (i32.const 8))     ;; length = 8
                    (call $msg_reply)) ;; call reply
                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (data (i32.const 0) "xxxxabcd")
                  (export "canister_update test" (func $test)))"#,
                "test",
                vec![121, 121, 121, 121],
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: b"xxxxyyyy".to_vec(),
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
// calls reject
fn sys_api_call_reject() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                  (type (;0;) (func))
                  (type (;1;) (func (param i32) (param i32)))
                  (import "ic0" "msg_reject" (func (;0;) (type 1)))
                  (func (;1;) (type 0)
                    i32.const 0
                    i32.const 6
                    call 0)
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "panic!")
                  (export "canister_update test" (func 1)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reject {
                payload: "panic!".to_string(),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn test_msg_caller_size_in_reject() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterError,
        "canister_reject".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (import "ic0" "msg_caller_size"
                    (func $msg_caller_size (result i32)))
                  (func $test (drop (call $msg_caller_size)))
                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func $test)))"#,
        test_func_ref(),
    );
    assert_eq!(
        wasm_result,
        Err(ContractViolation(
            "\"ic0_msg_caller_size\" cannot be executed in reject callback mode".to_string()
        ))
    );
}

#[test]
fn test_msg_caller_copy_in_reject() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterError,
        "canister_reject".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (import "ic0" "msg_caller_copy"
                    (func $msg_caller_copy (param i32 i32 i32)))
                  (func $test
                    (call $msg_caller_copy (i32.const 0) (i32.const 0) (i32.const 0)))

                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func $test)))"#,
        test_func_ref(),
    );
    assert_eq!(
        wasm_result,
        Err(ContractViolation(
            "\"ic0_msg_caller_copy\" cannot be executed in reject callback mode".to_string()
        ))
    );
}

#[test]
// calls reject twice
fn sys_api_call_reject_2() {
    let api_type = test_api_type_for_update(None, vec![]);
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (type (;0;) (func))
                  (type (;1;) (func (param i32) (param i32)))
                  (import "ic0" "msg_reject" (func (;0;) (type 1)))
                  (func (;1;) (type 0)
                    i32.const 0
                    i32.const 6
                    call 0
                    i32.const 0
                    i32.const 6
                    call 0)
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "panic!")
                  (export "canister_update test" (func 1)))"#,
        test_func_ref(),
    );
    assert_eq!(
        wasm_result,
        Err(ContractViolation(
            "ic0.msg_reject: the call is already replied".to_string(),
        ))
    );
}

#[test]
// tests the correct reject code is returned
fn sys_api_call_reject_code() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterReject,
        "rejected".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (type (;0;) (func (result i32)))
                  (type (;1;) (func))
                  (import "ic0" "msg_reject_code" (func (;0;) (type 0)))
                  (func (;1;) (type 1)
                    block
                        call 0
                        i32.const 4
                        i32.eq
                        br_if 0
                        unreachable
                    end)
                  (export "canister_update test" (func 1)))"#,
        test_func_ref(),
    );
    wasm_result.unwrap();
}

#[test]
// tests the correct reject code is returned
fn sys_api_call_reject_code_outside_reject_callback() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterError,
        "canister_reject".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
                (module
                  (type (;0;) (func (result i32)))
                  (type (;1;) (func))
                  (import "ic0" "msg_reject_code" (func (;0;) (type 0)))
                  (func (;1;) (type 1)
                    block
                        call 0
                        i32.const 5
                        i32.eq
                        br_if 0
                        unreachable
                    end)
                  (export "canister_update test" (func 1)))"#,
        test_func_ref(),
    );
    wasm_result.unwrap();
}

#[test]
// calls ic0_msg_reject_msg_size
fn sys_api_call_reject_msg_size() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterReject,
        "rejected".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        r#"
            (module
              (type (;0;) (func (result i32)))
              (type (;1;) (func))
              (import "ic0" "msg_reject_msg_size" (func (;0;) (type 0)))
              (func (;1;) (type 1)
                block
                    call 0
                    i32.const 8
                    i32.eq
                    br_if 0
                    unreachable
                end)
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_update test" (func 1)))"#,
        test_func_ref(),
    );
    wasm_result.unwrap();
}

#[test]
// calls reject_msg_size outside a reject callback
fn sys_api_call_reject_msg_size_outside_reject_callback() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
            (module
              (type (;0;) (func (result i32)))
              (type (;1;) (func))
              (import "ic0" "msg_reject_msg_size" (func (;0;) (type 0)))
              (func (;1;) (type 1)
                block
                    call 0
                    i32.const 8
                    i32.eq
                    br_if 0
                    unreachable
                end)
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_update test" (func 1)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::ContractViolation(
                    "\"ic0_msg_reject_msg_size\" cannot be executed in update mode".to_string()
                ),
                refund: Cycles::from(0),
            }
        );
    });
}

const REJECT_MSG_COPY_WAT: &str = r#"
                (module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32 i32)))
                  (import "ic0" "msg_reject_msg_copy" (func $msg_reject_msg_copy (param i32 i32 i32)))
                  (func $test
                    (call $msg_reject_msg_copy
                        (i32.const 4)     ;; heap dst = 4
                        (i32.const 0)     ;; offset = 0
                        (i32.const 8))    ;; length = 8
                    (call $msg_reply_data_append
                        (i32.const 0)      ;; heap offset = 0
                        (i32.const 12))    ;; length = 12 (len("xxxx") + len("rejected"))
                    (call $msg_reply))
                  (memory (;0;) 1)
                  (export "memory" (memory 0))
                  (data (i32.const 0) "xxxx")
                  (export "canister_update test" (func $test)))"#;

#[test]
// copies data from reject message to the heap and returns it
fn sys_api_call_reject_msg_copy() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterReject,
        "rejected".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        REJECT_MSG_COPY_WAT,
        test_func_ref(),
    );
    match wasm_result {
        Ok(Some(WasmResult::Reply(v))) => assert_eq!(&b"xxxxrejected"[..], &v[..]),
        val => panic!("unexpected response: {:?}", val),
    }
}

#[test]
fn sys_api_call_reject_msg_copy_called_outside_reject_callback() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                REJECT_MSG_COPY_WAT,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::ContractViolation(
                    "\"ic0_msg_reject_msg_copy\" cannot be executed in update mode".to_string()
                ),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn sys_api_call_reject_msg_copy_called_with_length_that_exceeds_message_length() {
    let api_type = test_api_type_for_reject(RejectContext::new(
        RejectCode::CanisterReject,
        "error".to_string(),
    ));
    let wasm_result = execute(
        api_type,
        SystemStateBuilder::default().build(),
        REJECT_MSG_COPY_WAT,
        test_func_ref(),
    );
    let err = wasm_result.unwrap_err();
    assert_eq!(
        err,
        HypervisorError::ContractViolation(
            "ic0.msg_reject_msg_copy msg: src=0 + length=8 exceeds the slice size=5".to_string()
        )
    );
}

#[test]
fn sys_api_call_canister_self_size() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"(module
                  (import "ic0" "canister_self_size" (func $canister_self_size (result i32)))
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32 i32)))
                  (func $test
                    ;; heap[0] = $canister_self_size()
                    (i32.store (i32.const 0) (call $canister_self_size))
                    ;; return heap[0]
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: vec![10],
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn sys_api_call_canister_self_copy() {
    with_hypervisor(|hypervisor, tmp_path| {
        let canister_id = canister_test_id(42);
        assert_eq!(
            execute_update_on(
                &hypervisor,
                r#"(module
                  (import "ic0" "canister_self_copy"
                    (func $canister_self_copy (param i32 i32 i32)))
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32 i32)))
                  (func $test
                    ;; heap[0..4] = canister_id_bytes[0..4]
                    (call $canister_self_copy (i32.const 0) (i32.const 0) (i32.const 4))
                    ;; heap[4..10] = canister_id_bytes[4..8]
                    (call $canister_self_copy (i32.const 4) (i32.const 4) (i32.const 6))
                    ;; return heap[0..10]
                    (call $msg_reply_data_append (i32.const 0) (i32.const 10))
                    (call $msg_reply))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                Some(canister_id),
                tmp_path,
            )
            .2,
            CallContextAction::Reply {
                payload: canister_id.get().into_vec(),
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn test_call_simple_does_not_enqueue_request_if_err() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_simple"
                    (func $ic0_call_simple
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                        (param $data_src i32)           (param $data_len i32)
                        (result i32)))
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (func $test
                    (call $ic0_call_simple
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                        (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                        )
                    drop

                    ;; call_simple and then fail.
                    (call $ic_trap (i32.const 0) (i32.const 18)))

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("some_remote_method".to_string()),
                refund: Cycles::from(0),
            }
        );
        assert_eq!(canister.system_state.queues().output_queues_len(), 0);
    });
}

#[test]
fn test_call_with_builder_does_not_enqueue_request_if_err() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                    ))
                  (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    )
                    (call $ic0_call_data_append
                        (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                    )
                    (call $ic0_call_perform)
                    drop

                    ;; call_simple and then fail.
                    (call $ic_trap (i32.const 0) (i32.const 18)))

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("some_remote_method".to_string()),
                refund: Cycles::from(0),
            }
        );
        assert_eq!(canister.system_state.queues().output_queues_len(), 0);
    });
}

#[test]
fn send_cycles_from_application_to_verified_subnet_fails() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _instructions_left, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                    ))
                  (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    )
                    (call $ic0_call_cycles_add
                        (i64.const 10000000000)         ;; amount of cycles used to be transferred
                    )
                    (call $ic0_call_perform)
                    drop)

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\00\00\00\00\00\00\00\ff\01\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(action, CallContextAction::Fail {
            error: ContractViolation(
                "Canisters on Application subnets cannot send cycles to canisters on VerifiedApplication subnets".to_string()
            ),
            refund: Cycles::from(0)
        });
        assert_eq!(canister.system_state.queues().output_queues_len(), 0);

        assert_balance_equals(
            INITIAL_CYCLES,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_call_add_cycles_deducts_cycles() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _instructions_left, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                    ))
                  (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    )
                    (call $ic0_call_cycles_add
                        (i64.const 10000000000)         ;; amount of cycles used to be transferred
                    )
                    (call $ic0_call_perform)
                    drop)

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(action, CallContextAction::NotYetResponded);
        assert_eq!(canister.system_state.queues().output_queues_len(), 1);

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let messaging_fee = cycles_account_manager.xnet_call_performed_fee()
            + cycles_account_manager
                .xnet_call_bytes_transmitted_fee(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES)
            + cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS);

        // Amount of cycles used to be transferred.
        let amount_cycles = Cycles::new(10_000_000_000);
        assert_balance_equals(
            INITIAL_CYCLES - amount_cycles - messaging_fee,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_call_add_cycles_no_effect_when_perform_not_called() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, _, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                    ))
                  (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    )
                    (call $ic0_call_cycles_add
                        (i64.const 10000000000)         ;; amount of cycles used to be transferred
                    ))

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(canister.system_state.queues().output_queues_len(), 0);

        //Cycles deducted by `ic0.call_cycles_add` are refunded.
        //Call `ic0.call_perform` never called.
        assert_balance_equals(
            INITIAL_CYCLES,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

const MINT_CYCLES: &str = r#"(module
                  (import "ic0" "msg_reply_data_append"
                            (func $msg_reply_data_append (param i32) (param i32)))
                  (import "ic0" "mint_cycles" (func $ic0_mint_cycles (param i64) (result i64)))
                  (import "ic0" "msg_reply" (func $ic0_msg_reply))


                  (func $test
                        (i64.store
                            ;; store at the beginning of the heap
                            (i32.const 0) ;; store at the beginning of the heap
                            (call $ic0_mint_cycles (i64.const 10000000000))
                        )
                        (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                        (call $ic0_msg_reply)
                  )


                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                )"#;

#[test]
fn test_mint_cycles_non_nns_canister() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) =
            execute_update(&hypervisor, MINT_CYCLES, "test", EMPTY_PAYLOAD, tmp_path);

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: ContractViolation(format!(
                    "ic0.mint_cycles cannot be executed on non Cycles Minting Canister: {} != {}",
                    canister.canister_id(),
                    CYCLES_MINTING_CANISTER_ID,
                )),
                refund: Cycles::from(0)
            }
        );

        assert_eq!(canister.system_state.queues().output_queues_len(), 0);

        //Not on NNS subnet -> balance remains unchanged
        assert_balance_equals(
            INITIAL_CYCLES,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_mint_cycles_cmc_canister() {
    with_test_replica_logger(|log| {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(SubnetType::System)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            config(),
            &metrics_registry,
            cycles_account_manager.get_subnet_id(),
            SubnetType::System,
            log,
            cycles_account_manager,
        );
        let (canister, _, _, _) = execute_update_on(
            &hypervisor,
            MINT_CYCLES,
            "test",
            EMPTY_PAYLOAD,
            None,
            Some(CYCLES_MINTING_CANISTER_ID),
            tmpdir.path().into(),
        );

        assert_eq!(canister.system_state.queues().output_queues_len(), 0);
        assert_balance_equals(
            INITIAL_CYCLES + Cycles::new(10_000_000_000),
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_mint_cycles_fail_on_system_canister() {
    with_test_replica_logger(|log| {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(SubnetType::System)
                .with_subnet_id(subnet_test_id(1))
                .build(),
        );
        let hypervisor = Hypervisor::new(
            config(),
            &metrics_registry,
            cycles_account_manager.get_subnet_id(),
            SubnetType::System,
            log,
            cycles_account_manager,
        );
        let (canister, _, _, _) = execute_update(
            &hypervisor,
            MINT_CYCLES,
            "test",
            EMPTY_PAYLOAD,
            tmpdir.path().into(),
        );

        assert_eq!(canister.system_state.queues().output_queues_len(), 0);

        //Not on NNS subnet -> balance remains unchanged
        assert_balance_equals(
            INITIAL_CYCLES,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_call_simple_enqueues_request() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_simple"
                    (func $ic0_call_simple
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                        (param $data_src i32)           (param $data_len i32)
                        (result i32)))
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (func $test
                    (call $ic0_call_simple
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                        (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                        )
                    drop
                    (call $msg_reply)
                    )

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(canister.system_state.queues().output_queues_len(), 1);
    });
}

#[test]
fn test_call_with_builder_enqueues_request() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                      (param i32 i32)
                      (param $method_name_src i32)    (param $method_name_len i32)
                      (param $reply_fun i32)          (param $reply_env i32)
                      (param $reject_fun i32)         (param $reject_env i32)
                  ))
                  (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    )
                    (call $ic0_call_data_append
                        (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                    )
                    (call $ic0_call_perform)
                    drop
                    (call $msg_reply)
                    )

                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
                )"#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(canister.system_state.queues().output_queues_len(), 1);
    });
}

#[test]
// calls ic.trap
fn sys_api_call_ic_trap() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"(module
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  (func $test
                    (call $ic_trap (i32.const 0) (i32.const 3)))

                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (export "canister_update test" (func $test))
                  (data (i32.const 0) "Hi!")
            )"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("Hi!".to_string()),
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
fn globals_are_updated_in_execution_state_after_message_execution() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"
                (module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (func $write
                    (i32.add
                      (global.get 0)
                      (i32.const 1)
                    )
                    global.set 0
                    (call $msg_reply)
                  )
                  (export "canister_update write" (func $write))
                  ;; globals must be exported to be accessible to hypervisor or persisted
                  (global (export "g") (mut i32) (i32.const 0))
                )
            "#,
            "write",
            EMPTY_PAYLOAD,
            tmp_path,
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(
            canister.execution_state.unwrap().exported_globals[0],
            Global::I32(1)
        );
    });
}

#[test]
fn comparison_of_non_canonical_nans() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            r#"
                (module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (func $test
                    (global.set 0 (f32.eq (f32.const nan:0x1234) (f32.const nan:0x1234)))
                    (call $msg_reply)
                  )
                  (export "canister_update test" (func $test))
                  ;; globals must be exported to be accessible to hypervisor or persisted
                  (global (export "g") (mut i32) (i32.const 137))
                )
            "#,
            "test",
            EMPTY_PAYLOAD,
            tmp_path,
        );
        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(
            canister.execution_state.unwrap().exported_globals[0],
            Global::I32(0)
        );
    });
}

#[test]
// sets cycles to a too small number, provokes an out of cycles error
fn sys_api_call_out_of_cycles() {
    with_hypervisor(|hypervisor, tmp_path| {
        // this is not enough for 4 instructions
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                  (func (;0;)
                    (i32.const 0)
                    (i32.const 0)
                    (drop)
                    (drop))
                  (export "canister_update test" (func 0)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                // this is not enough for 4 instructions
                NumInstructions::from(3),
                MEMORY_ALLOCATION,
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::InstructionLimitExceeded,
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
// Sets the available memory to quite a low number to force a
// `HypervisorError::OutOfMemory`.
fn sys_api_call_update_available_memory_1() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update_with_cycles_memory_time(
                &hypervisor,
                r#"
                (module
                  (func (;0;)
                    i32.const 10
                    memory.grow ;; Try to grow by 10 wasm pages
                    drop
                  )
                  (memory (;0;) 1 20)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func 0)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
                None,
                MAX_NUM_INSTRUCTIONS,
                // Only 9 pages available
                ic_replicated_state::num_bytes_try_from(NumWasmPages::from(9)).unwrap(),
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::OutOfMemory,
                refund: Cycles::from(0),
            }
        );
    });
}

#[test]
// Growing memory succeeds if given enough available memory.
fn sys_api_call_update_available_memory_2() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                  (func (;0;)
                    i32.const 10
                    memory.grow
                    drop
                  )
                  (memory (;0;) 1 20)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func 0)))"#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse {
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
// Verifies that subnet available memory decreases when execution succeeds.
fn available_memory_is_updated() {
    let available_memory = ic_replicated_state::num_bytes_try_from(NumWasmPages::from(9)).unwrap();
    with_hypervisor(|hypervisor, tmp_path| {
        let subnet_available_memory = SubnetAvailableMemory::new(1_000_000_000);
        let initial_subnet_available_memory = subnet_available_memory.get();
        let _ = execute_update_with_cycles_memory_time_subnet_memory(
            &hypervisor,
            r#"
                (module
                  (func (;0;)
                    i32.const 1
                    memory.grow ;; Try to grow by 1 wasm page
                    drop
                  )
                  (memory (;0;) 1 20)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func 0)))"#,
            "test",
            EMPTY_PAYLOAD,
            MAX_NUM_INSTRUCTIONS,
            available_memory,
            mock_time(),
            tmp_path,
            subnet_available_memory.clone(),
        );
        assert_eq!(
            initial_subnet_available_memory - WASM_PAGE_SIZE as i64,
            subnet_available_memory.get()
        );
    });
}

#[test]
// Verifies that subnet available memory doesn't decrease when execution fails.
fn available_memory_isnt_updated_from_failed_message() {
    let available_memory = ic_replicated_state::num_bytes_try_from(NumWasmPages::from(9)).unwrap();
    with_hypervisor(|hypervisor, tmp_path| {
        let subnet_available_memory = SubnetAvailableMemory::new(1_000_000_000);
        let initial_subnet_available_memory = subnet_available_memory.get();
        let _ = execute_update_with_cycles_memory_time_subnet_memory(
            &hypervisor,
            r#"
                (module
                  (func (;0;)
                    i32.const 1
                    memory.grow ;; Try to grow by 1 wasm page
                    drop
                    unreachable
                  )
                  (memory (;0;) 1 20)
                  (export "memory" (memory 0))
                  (export "canister_update test" (func 0)))"#,
            "test",
            EMPTY_PAYLOAD,
            MAX_NUM_INSTRUCTIONS,
            available_memory,
            mock_time(),
            tmp_path,
            subnet_available_memory.clone(),
        );
        assert_eq!(
            initial_subnet_available_memory,
            subnet_available_memory.get()
        );
    });
}

#[test]
fn sys_api_call_msg_cycles_available_for_ingress() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
                (module
                  (import "ic0" "msg_cycles_available" (func (;0;) (result i64)))
                  (func (;1;)
                    block
                        call 0
                        i64.eqz
                        br_if 0
                        unreachable
                    end)
                  (memory (;0;) 1 20)
                  (export "canister_update test" (func 1)))"#,
                "test",
                vec![0, 1, 2, 3],
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse {
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn sys_api_call_msg_cycles_available_for_inter_canister_message() {
    with_hypervisor(|hypervisor, tmp_path| {
        let payment = Cycles::from(50);
        assert_eq!(
            execute_update_for_request(
                &hypervisor,
                r#"
                (module
                  (import "ic0" "msg_cycles_available" (func (;0;) (result i64)))
                  (func (;1;)
                    block
                        call 0
                        i64.const 50
                        i64.eq
                        br_if 0
                        unreachable
                    end)
                  (memory (;0;) 1 20)
                  (export "canister_update test" (func 1)))"#,
                "test",
                EMPTY_PAYLOAD,
                payment,
                None,
                MAX_NUM_INSTRUCTIONS,
                // Five nanoseconds
                mock_time() + Duration::new(0, 5),
                tmp_path,
            )
            .2,
            CallContextAction::NoResponse { refund: payment },
        );
    });
}

#[test]
fn canister_metrics_are_recorded() {
    with_test_replica_logger(|log| {
        let registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            config(),
            &registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        let wast = r#"
                (module
                  (func $write
                    (i32.store
                      (i32.const 0)
                      (i32.add
                        (i32.load (i32.const 70000))
                        (i32.const 1)
                      )
                    )
                    (unreachable)
                  )
                  (export "canister_update write" (func $write))
                  (memory (;0;) 2)
                  (export "memory" (memory 0))
                )
            "#;
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        assert_eq!(
            execute_update(
                &hypervisor,
                wast,
                "write",
                EMPTY_PAYLOAD,
                tmpdir.path().into(),
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::Unreachable),
                refund: Cycles::from(0),
            }
        );

        assert_eq!(
            fetch_histogram_stats(&registry, "hypervisor_dirty_pages"),
            Some(HistogramStats { sum: 1.0, count: 1 })
        );

        match fetch_histogram_stats(&registry, "hypervisor_accessed_pages") {
            Some(HistogramStats { sum, count }) => {
                assert_eq!(count, 1);
                assert!(sum >= 2.0);
            }
            None => unreachable!(),
        }
    });
}

#[test]
fn executing_non_existing_method_does_not_consume_cycles() {
    with_test_replica_logger(|log| {
        let registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            config(),
            &registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        let wast = r#"
                (module
                  (func $write
                    (i32.store
                      (i32.const 0)
                      (i32.add
                        (i32.load (i32.const 70000))
                        (i32.const 1)
                      )
                    )
                  )
                  (func $read
                  )
                  (export "canister_update write" (func $write))
                  (export "canister_query read" (func $write))
                  (memory (;0;) 2)
                  (export "memory" (memory 0))
                )
            "#;

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        // Check an update method.
        let (canister, num_instructions_left, action, _) = execute_update(
            &hypervisor,
            wast,
            "foo",
            EMPTY_PAYLOAD,
            tmpdir.path().into(),
        );
        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::MethodNotFound(WasmMethod::Update("foo".to_string())),
                refund: Cycles::from(0),
            }
        );
        assert_eq!(num_instructions_left, MAX_NUM_INSTRUCTIONS);

        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        // Check a query method.
        let (_, num_instructions_left, res) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "foo",
            EMPTY_PAYLOAD.as_slice(),
            test_caller(),
            canister,
            None,
            mock_time(),
            execution_parameters,
        );
        assert_eq!(
            res,
            Err(HypervisorError::MethodNotFound(WasmMethod::Query(
                "foo".to_string()
            )))
        );
        assert_eq!(num_instructions_left, MAX_NUM_INSTRUCTIONS);
    });
}

#[test]
fn grow_memory() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func (export "canister_init")
                            (drop (memory.grow (i32.const 1))))
                          (memory 1 2))
                        "#,
        )
        .unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        hypervisor
            .execute_canister_init(
                canister,
                user_test_id(0).get(),
                &[],
                mock_time(),
                execution_parameters,
            )
            .2
            .unwrap();
    });
}

#[test]
fn memory_access_between_min_and_max_canister_start() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func $start
                            ;; attempt to load page(1)[0;4] which should fail
                            (drop (i32.load (i32.const 65536))))
                          (start $start)
                          (memory 1 2)
                          )
                        "#,
        )
        .unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();

        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        assert_eq!(
            hypervisor
                .execute_canister_start(canister, execution_parameters,)
                .2,
            Err(HypervisorError::Trapped(TrapCode::HeapOutOfBounds))
        );
    });
}

#[test]
fn memory_access_between_min_and_max_ingress() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                r#"
            (module
              (func (export "canister_update test")
                ;; attempt to load page(1)[0;4] which should fail
                (drop (i32.load (i32.const 65536))))
              (memory 1 2))
            "#,
                "test",
                EMPTY_PAYLOAD,
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::Trapped(TrapCode::HeapOutOfBounds),
                refund: Cycles::from(0),
            }
        );
    });
}

fn test_system_method_is_callable(system_method: SystemMethod) {
    with_hypervisor(|hypervisor, tmp_path| {
        let wat = r#"
                (module
                    (import "ic0" "msg_reply" (func $msg_reply))
                    (import "ic0" "msg_reply_data_append"
                        (func $msg_reply_data_append (param i32 i32)))
                    (func $inc
                        ;; Increment a counter.
                        (i32.store
                            (i32.const 0)
                            (i32.add (i32.load (i32.const 0)) (i32.const 1))))
                    (func $read
                        (call $msg_reply_data_append
                            (i32.const 0) ;; the counter from heap[0]
                            (i32.const 4)) ;; length
                        (call $msg_reply))
                    (memory $memory 1)
                    (start $inc)
                    (export "canister_init" (func $inc))
                    (export "canister_pre_upgrade" (func $inc))
                    (export "canister_post_upgrade" (func $inc))
                    (export "canister_heartbeat" (func $inc))
                    (export "canister_query read" (func $read))
                )"#;

        let binary = wabt::wat2wasm(wat).unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();

        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        // Run the system method to increment the counter.
        let (canister, instructions, res) = match system_method {
            SystemMethod::CanisterPostUpgrade => hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters.clone(),
            ),
            SystemMethod::CanisterPreUpgrade => hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                mock_time(),
                execution_parameters.clone(),
            ),
            SystemMethod::CanisterInit => hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters.clone(),
            ),
            SystemMethod::CanisterStart => {
                hypervisor.execute_canister_start(canister, execution_parameters.clone())
            }
            SystemMethod::CanisterInspectMessage => unimplemented!(),
            SystemMethod::Empty => unimplemented!(),
            SystemMethod::CanisterHeartbeat => unimplemented!("We don't need this test."),
        };

        assert!(
            res.is_ok(),
            "{} should execute successfully and not return a value.",
            system_method
        );
        assert!(
            instructions < MAX_NUM_INSTRUCTIONS,
            "Calling {} should cost cycles.",
            system_method
        );

        // The counter should now be incremented to 1.
        let (_, _, result) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "read",
            EMPTY_PAYLOAD.as_slice(),
            test_caller(),
            canister,
            None,
            mock_time(),
            execution_parameters,
        );
        assert_eq!(result, Ok(Some(WasmResult::Reply(vec![1, 0, 0, 0]))));
    });
}

#[test]
fn test_canister_post_upgrade_is_callable() {
    test_system_method_is_callable(SystemMethod::CanisterPostUpgrade);
}

#[test]
fn test_canister_pre_upgrade_is_callable() {
    test_system_method_is_callable(SystemMethod::CanisterPreUpgrade);
}

#[test]
fn test_canister_init_is_callable() {
    test_system_method_is_callable(SystemMethod::CanisterInit);
}

#[test]
fn test_canister_start_is_callable() {
    test_system_method_is_callable(SystemMethod::CanisterStart);
}

fn test_non_existing_system_method(system_method: SystemMethod) {
    with_hypervisor(|hypervisor, tmp_path| {
        let wat = "(module)";
        let binary = wabt::wat2wasm(wat).unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();

        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, routing_table, subnet_records) = setup();
        // Run the non-existing system method.
        let (_, cycles, res) = match system_method {
            SystemMethod::CanisterPostUpgrade => hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters,
            ),
            SystemMethod::CanisterPreUpgrade => hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                mock_time(),
                execution_parameters,
            ),
            SystemMethod::CanisterInit => hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters,
            ),
            SystemMethod::CanisterStart => {
                hypervisor.execute_canister_start(canister, execution_parameters)
            }
            SystemMethod::CanisterInspectMessage => unimplemented!(),
            SystemMethod::Empty => unimplemented!(),
            SystemMethod::CanisterHeartbeat => hypervisor.execute_canister_heartbeat(
                canister,
                routing_table,
                subnet_records,
                mock_time(),
                execution_parameters,
            ),
        };

        assert!(
            res.is_ok(),
            "{} should return gracefully if it isn't exported.",
            system_method
        );
        assert_eq!(
            cycles, MAX_NUM_INSTRUCTIONS,
            "Calling {} should not cost cycles if it doesn't exist.",
            system_method
        );
    });
}

#[test]
fn test_non_existing_canister_post_upgrade() {
    test_non_existing_system_method(SystemMethod::CanisterPostUpgrade);
}

#[test]
fn test_non_existing_canister_pre_upgrade() {
    test_non_existing_system_method(SystemMethod::CanisterPreUpgrade);
}

#[test]
fn test_non_existing_canister_init() {
    test_non_existing_system_method(SystemMethod::CanisterInit);
}

#[test]
fn test_non_existing_canister_start() {
    test_non_existing_system_method(SystemMethod::CanisterStart);
}

#[test]
fn test_non_existing_canister_heartbeat() {
    test_non_existing_system_method(SystemMethod::CanisterHeartbeat);
}

#[test]
fn canister_init_can_set_mutable_globals() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                    (module
                        (func $read)
                        (func $canister_init
                          (global.set 0 (i32.const 42)))
                        (export "canister_init" (func $canister_init))
                        (export "canister_query read" (func $read))
                        (global (export "globals_must_be_exported") (mut i32) (i32.const 0))
                    )
                "#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (canister, _, _) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            mock_time(),
            execution_parameters,
        );

        assert_eq!(
            canister.execution_state.unwrap().exported_globals[0],
            Global::I32(42)
        );
    });
}

#[test]
fn grow_memory_beyond_max_size_1() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func (export "canister_init")
                            ;; growing memory past limit does not trigger trap or error
                            (drop (memory.grow (i32.const 1)))
                            ;; but accessing the memory triggers HeapOutOfBounds (Lucet)
                            ;; page(2)[0;4] = 1
                            (i32.store
                              (i32.add (i32.const 65536) (i32.const 1))
                              (i32.const 1)))
                          (memory 1 1)
                          )
                        "#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            mock_time(),
            execution_parameters,
        );

        assert_eq!(
            res.unwrap_err(),
            HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        );
    });
}

#[test]
fn memory_access_between_min_and_max_canister_init() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func (export "canister_init")
                            ;; attempt to load page(1)[0;4] which should fail
                            (drop (i32.load (i32.const 65536))))
                          (memory 1 2))
                        "#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            mock_time(),
            execution_parameters,
        );

        assert_eq!(
            res.unwrap_err(),
            HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        );
    });
}

#[test]
fn grow_memory_beyond_max_size_2() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func (export "canister_init")
                            ;; growing memory past limit does not trigger trap or error
                            (drop (memory.grow (i32.const 100)))
                            ;; but accessing the memory triggers HeapOutOfBounds (Lucet)
                            ;; page(3)[0;4] = 1
                            (i32.store
                              (i32.add (i32.mul (i32.const 65536) (i32.const 2)) (i32.const 1))
                              (i32.const 1)))
                          (memory 1 2))
                        "#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            mock_time(),
            execution_parameters,
        );

        assert_eq!(
            res.unwrap_err(),
            HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        );
    });
}

#[test]
fn grow_memory_beyond_32_bit_limit_fails() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
                        (module
                          (func (export "canister_init")
                            ;; 65536 is the maximum number of 32-bit wasm memory pages 
                            (drop (memory.grow (i32.const 65537)))
                            ;; grow failed so accessing the memory triggers HeapOutOfBounds
                            (i32.store
                              (i32.const 1)
                              (i32.const 1)))
                          (memory 0))
                        "#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            mock_time(),
            execution_parameters,
        );

        assert_eq!(
            res.unwrap_err(),
            HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        );
    });
}

fn test_stable_memory_is_rolled_back_on_failure<F>(execute_method: F)
where
    F: FnOnce(
        &Hypervisor,
        CanisterState,
    ) -> (CanisterState, NumInstructions, HypervisorResult<NumBytes>),
{
    with_hypervisor(|hypervisor, tmp_path| {
        let wat = r#"
            (module
                (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                (import "ic0" "stable_read"
                    (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                (import "ic0" "stable_write"
                    (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

                (func $test
                    ;; Grow stable memory by 1 page.
                    (drop (call $stable_grow (i32.const 1)))

                    ;; stable_memory[0..4] = heap[0..4] ("abcd")
                    (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))

                    ;; Reference an invalid part of the heap. Should trap.
                    (call $stable_write (i32.const 0) (i32.const -1) (i32.const -4))
                )

                (memory 1)
                (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
                (export "canister_init" (func $test))
                (export "canister_pre_upgrade" (func $test))
                (export "canister_post_upgrade" (func $test)))"#;

        let wasm = wabt::wat2wasm(wat).unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);

        let (canister, _, res) = execute_method(&hypervisor, canister);

        // We expect an out of bounds memory error. The order and
        // applicability we do the checks depends on runtime mode
        // however. Specifically, in sandboxing the stable memory
        // check is done in the replica and heap check is done by the
        // sandboxed process.
        let should_error = res.unwrap_err();
        if should_error != HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds)
            && should_error != HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
        {
            panic!("Expected a heap or stable memory out of bounds error.");
        }

        // Stable memory should remain empty since the call failed.
        assert_eq!(
            canister.execution_state.unwrap().stable_memory.size,
            NumWasmPages::new(0)
        );
    });
}

#[test]
fn changes_to_stable_memory_in_canister_init_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS * 10);
            hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters,
            )
        },
    );
}

#[test]
fn changes_to_stable_memory_in_canister_pre_upgrade_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS * 10);
            hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                mock_time(),
                execution_parameters,
            )
        },
    )
}

#[test]
fn changes_to_stable_memory_in_canister_post_upgrade_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS * 10);
            hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                mock_time(),
                execution_parameters,
            )
        },
    )
}

#[test]
fn cannot_execute_update_on_stopping_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopping_canister(canister_test_id(0));
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_update(
                    canister,
                    RequestOrIngress::Ingress(IngressBuilder::new().build()),
                    mock_time(),
                    routing_table,
                    subnet_records,
                    execution_parameters,
                )
                .2,
            CallContextAction::Fail {
                error: HypervisorError::CanisterStopped,
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn cannot_execute_update_on_stopped_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopped_canister(canister_test_id(0));
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_update(
                    canister,
                    RequestOrIngress::Ingress(IngressBuilder::new().build()),
                    mock_time(),
                    routing_table,
                    subnet_records,
                    execution_parameters,
                )
                .2,
            CallContextAction::Fail {
                error: HypervisorError::CanisterStopped,
                refund: Cycles::from(0),
            },
        );
    });
}

#[test]
fn cannot_execute_query_on_stopping_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopping_canister(canister_test_id(0));
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    "query_test",
                    &[],
                    user_test_id(0).get(),
                    canister,
                    None,
                    mock_time(),
                    execution_parameters,
                )
                .2,
            Err(HypervisorError::CanisterStopped)
        );
    });
}

#[test]
fn cannot_execute_query_on_stopped_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopped_canister(canister_test_id(0));
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    "query_test",
                    &[],
                    user_test_id(0).get(),
                    canister,
                    None,
                    mock_time(),
                    execution_parameters,
                )
                .2,
            Err(HypervisorError::CanisterStopped)
        );
    });
}

#[test]
fn cannot_execute_callback_on_stopped_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopped_canister(canister_test_id(0));
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_callback(
                    canister,
                    &CallOrigin::CanisterUpdate(canister_test_id(0), CallbackId::from(0)),
                    Callback::new(
                        call_context_test_id(0),
                        None,
                        None,
                        Cycles::from(0),
                        WasmClosure::new(0, 0),
                        WasmClosure::new(0, 0),
                        None
                    ),
                    Payload::Data(EMPTY_PAYLOAD),
                    Cycles::from(0),
                    mock_time(),
                    routing_table,
                    subnet_records,
                    execution_parameters,
                )
                .3,
            Err(HypervisorError::CanisterStopped)
        );
    });
}

#[test]
fn sys_api_call_ic_trap_preserves_some_cycles() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wat = r#"(module
                  (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                  ;; globals must be exported to be accessible to hypervisor or persisted
                  (global (export "g1") (mut i32) (i32.const -1))
                  (global (export "g2") (mut i64) (i64.const -1))
                  (func $func_that_traps
                    (call $ic_trap (i32.const 0) (i32.const 12)))

                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (export "canister_update update_trap" (func $func_that_traps))
                  (export "canister_query query_trap" (func $func_that_traps))
                  (data (i32.const 0) "Trap called!")
            )"#;

        // Check an update method.
        let (canister, num_instructions_left, action, _) =
            execute_update(&hypervisor, wat, "update_trap", EMPTY_PAYLOAD, tmp_path);
        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("Trap called!".to_string()),
                refund: Cycles::from(0),
            }
        );
        // Check that ic0.trap call wasn't expensive
        assert_eq!(
            num_instructions_left,
            MAX_NUM_INSTRUCTIONS - NumInstructions::new(15)
        );

        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        // Check a query method.
        let (_, num_instructions_left, res) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_trap",
            EMPTY_PAYLOAD.as_slice(),
            test_caller(),
            canister,
            None,
            mock_time(),
            execution_parameters,
        );
        assert_eq!(
            res,
            Err(HypervisorError::CalledTrap("Trap called!".to_string()))
        );
        // Check that ic0.trap call wasn't expensive
        assert_eq!(
            num_instructions_left,
            MAX_NUM_INSTRUCTIONS - NumInstructions::new(15)
        );
    });
}

// Tests that canister heartbeat is executed.
#[test]
fn canister_heartbeat() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_heartbeat")
                    unreachable)
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        assert_eq!(
            hypervisor
                .execute_canister_heartbeat(
                    canister,
                    routing_table,
                    subnet_records,
                    mock_time(),
                    execution_parameters,
                )
                .2,
            Err(HypervisorError::Trapped(TrapCode::Unreachable))
        );
    });
}

// Tests that execute_canister_heartbeat produces a heap delta.
#[test]
fn execute_canister_heartbeat_produces_heap_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_heartbeat")
                (i32.store (i32.const 10) (i32.const 10))
              )
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let (_, _, result) = hypervisor.execute_canister_heartbeat(
            canister,
            routing_table,
            subnet_records,
            mock_time(),
            execution_parameters,
        );
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (PAGE_SIZE) as u64);
    });
}

// Tests that execute_update produces a heap delta.
#[test]
fn execute_update_produces_heap_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_update hello")
                (i32.store (i32.const 10) (i32.const 10))
              )
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let (_, _, routing_table, subnet_records) = setup();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let message = RequestOrIngress::Ingress(
            IngressBuilder::new()
                .method_name("hello".to_string())
                .build(),
        );

        let (_, _, _, heap_delta) = hypervisor.execute_update(
            canister,
            message,
            mock_time(),
            routing_table,
            subnet_records,
            execution_parameters,
        );
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (PAGE_SIZE) as u64);
    });
}

// Tests that execute_canister_start produces a heap delta.
#[test]
fn execute_canister_start_produces_heap_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (;0;)
                (i32.store (i32.const 10) (i32.const 10))
              )
              (memory (export "memory") 1)
              (start 0))"#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let (_, _, result) = hypervisor.execute_canister_start(canister, execution_parameters);
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (PAGE_SIZE) as u64);
    });
}

// Tests that execute_system produces a heap delta.
#[test]
fn execute_system_produces_heap_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_init")
                (i32.store (i32.const 10) (i32.const 10))
              )
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let (_, _, result) = hypervisor.execute_canister_init(
            canister,
            user_test_id(0).get(),
            &[],
            mock_time(),
            execution_parameters,
        );
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (PAGE_SIZE) as u64);
    });
}

fn memory_module_wat(wasm_pages: i32) -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply"
                (func $ic0_msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $ic0_msg_reply_data_append (param i32) (param i32)))
            (import "ic0" "msg_arg_data_copy"
                (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
            (import "ic0" "msg_arg_data_size"
                (func $ic0_msg_arg_data_size (result i32)))

            ;; $read(addr: i32, len: i32) -> &[u8]
            ;; Read the slice at the given location in memory.
            (func $read
                ;; copy the i32 `addr` to heap[0;4]
                (call $ic0_msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; off
                  (i32.const 4) ;; len
                )
                ;; copy the i32 `len` to heap[4;8]
                (call $ic0_msg_arg_data_copy
                  (i32.const 4) ;; dst
                  (i32.const 4) ;; off
                  (i32.const 4) ;; len
                )
                (call $ic0_msg_reply_data_append
                  ;; addr
                  (i32.load (i32.const 0))
                  ;; size
                  (i32.load (i32.const 4))
                )
                (call $ic0_msg_reply)
            )

            ;; $write(addr: i32, bytes: &[u8])
            ;; Copies the slice into the memory starting at the given address.
            (func $write
                ;; copy the i32 `addr` to heap[0;4]
                (call $ic0_msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; off
                  (i32.const 4) ;; len
                )
                ;; copy the remainder of the payload to the heap[addr;size]
                (call $ic0_msg_arg_data_copy
                  ;; addr
                  (i32.load (i32.const 0))
                  ;; offset
                  (i32.const 4)
                  ;; size
                  (i32.sub
                    (call $ic0_msg_arg_data_size)
                    (i32.const 4)
                  )
                )
            )

            ;; $grow_and_read() -> &[u8]
            ;; Grows the memory by 1 Wasm page (64KiB) and return its contents.
            (func $grow_and_read
                (call $ic0_msg_reply_data_append
                  ;; addr
                  (i32.mul (memory.grow (i32.const 1)) (i32.const 65536))
                  ;; size
                  (i32.const 65536)
                )
                (call $ic0_msg_reply)
            )

            ;; $grow_and_write(value: u8)
            ;; Grows the memory by 1 Wasm page (64KiB) and fills it with
            ;; the given value.
            (func $grow_and_write
                (call $ic0_msg_arg_data_copy
                  ;; addr
                  (i32.mul (memory.grow (i32.const 1)) (i32.const 65536))
                  ;; offset
                  (i32.const 0)
                  ;; size
                  (call $ic0_msg_arg_data_size)
                )
            )

            (memory {wasm_pages})

            (export "canister_update read" (func $read))
            (export "canister_update write" (func $write))
            (export "canister_update grow_and_read" (func $grow_and_read))
            (export "canister_update grow_and_write" (func $grow_and_write))
        )"#,
        wasm_pages = wasm_pages,
    )
}

const WASM_PAGE_SIZE: i32 = 65536;

// A helper for executing read/write/grow operations.
struct MemoryAccessor {
    hypervisor: Hypervisor,
    canister: CanisterState,
    routing_table: Arc<RoutingTable>,
    subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    execution_parameters: ExecutionParameters,
}

impl MemoryAccessor {
    fn new(wasm_pages: i32, hypervisor: Hypervisor, tmp_path: PathBuf) -> Self {
        let wat = memory_module_wat(wasm_pages);
        let wasm = wabt::wat2wasm(wat).unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();

        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let (_, _, routing_table, subnet_records) = setup();
        Self {
            hypervisor,
            canister,
            routing_table,
            subnet_records,
            execution_parameters,
        }
    }

    fn write(&mut self, addr: i32, bytes: &[u8]) -> CallContextAction {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(bytes.iter());
        let method = "write";
        let caller = user_test_id(24).get();
        let req = IngressBuilder::new()
            .method_name(method.to_string())
            .method_payload(payload)
            .source(UserId::from(caller))
            .build();

        let result = self.hypervisor.execute_update(
            self.canister.clone(),
            RequestOrIngress::Ingress(req),
            mock_time(),
            Arc::clone(&self.routing_table),
            Arc::clone(&self.subnet_records),
            self.execution_parameters.clone(),
        );
        self.canister = result.0;
        result.2
    }

    fn read(&mut self, addr: i32, size: i32) -> CallContextAction {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(size.to_le_bytes().to_vec());
        let method = "read";
        let caller = user_test_id(24).get();
        let req = IngressBuilder::new()
            .method_name(method.to_string())
            .method_payload(payload)
            .source(UserId::from(caller))
            .build();

        let result = self.hypervisor.execute_update(
            self.canister.clone(),
            RequestOrIngress::Ingress(req),
            mock_time(),
            Arc::clone(&self.routing_table),
            Arc::clone(&self.subnet_records),
            self.execution_parameters.clone(),
        );
        self.canister = result.0;
        result.2
    }

    fn grow_and_read(&mut self) -> CallContextAction {
        let method = "grow_and_read";
        let caller = user_test_id(24).get();
        let req = IngressBuilder::new()
            .method_name(method.to_string())
            .method_payload(EMPTY_PAYLOAD)
            .source(UserId::from(caller))
            .build();

        let result = self.hypervisor.execute_update(
            self.canister.clone(),
            RequestOrIngress::Ingress(req),
            mock_time(),
            Arc::clone(&self.routing_table),
            Arc::clone(&self.subnet_records),
            self.execution_parameters.clone(),
        );
        self.canister = result.0;
        result.2
    }

    fn grow_and_write(&mut self, bytes: &[u8]) -> CallContextAction {
        let payload = bytes.to_vec();
        let method = "grow_and_write";
        let caller = user_test_id(24).get();
        let req = IngressBuilder::new()
            .method_name(method.to_string())
            .method_payload(payload)
            .source(UserId::from(caller))
            .build();

        let result = self.hypervisor.execute_update(
            self.canister.clone(),
            RequestOrIngress::Ingress(req),
            mock_time(),
            Arc::clone(&self.routing_table),
            Arc::clone(&self.subnet_records),
            self.execution_parameters.clone(),
        );
        self.canister = result.0;
        result.2
    }

    fn verify_dirty_pages(&self, is_dirty_page: &[bool]) {
        for (page_index, is_dirty_page) in is_dirty_page.iter().enumerate() {
            match self
                .canister
                .execution_state
                .as_ref()
                .unwrap()
                .wasm_memory
                .page_map
                .get_memory_region(PageIndex::new(page_index as u64))
            {
                MemoryRegion::Zeros(_) | MemoryRegion::BackedByFile(_, _) => {
                    assert!(!is_dirty_page,);
                }
                MemoryRegion::BackedByPage(_) => {
                    assert!(is_dirty_page);
                }
            }
        }
    }
}

fn with_memory_accessor<F>(wasm_pages: i32, test: F)
where
    F: FnOnce(MemoryAccessor),
{
    with_hypervisor(|hypervisor, tmp_path| {
        let memory_accessor = MemoryAccessor::new(wasm_pages, hypervisor, tmp_path);
        test(memory_accessor);
    });
}

#[test]
fn write_last_page() {
    let wasm_pages = 1;
    with_memory_accessor(wasm_pages, |mut memory_accessor| {
        let memory_size = WASM_PAGE_SIZE * wasm_pages;
        memory_accessor.write(memory_size - 8, &[42; 8]);
    });
}

#[test]
fn read_last_page() {
    let wasm_pages = 1;
    with_memory_accessor(wasm_pages, |mut memory_accessor| {
        let memory_size = WASM_PAGE_SIZE * wasm_pages;
        assert_eq!(
            CallContextAction::Reply {
                payload: vec![0; 8],
                refund: Cycles::new(0)
            },
            memory_accessor.read(memory_size - 8, 8),
        );
    });
}

#[test]
fn write_and_read_last_page() {
    let wasm_pages = 1;
    with_memory_accessor(wasm_pages, |mut memory_accessor| {
        let memory_size = WASM_PAGE_SIZE * wasm_pages;
        memory_accessor.write(memory_size - 8, &[42; 8]);
        assert_eq!(
            CallContextAction::Reply {
                payload: vec![42; 8],
                refund: Cycles::new(0)
            },
            memory_accessor.read(memory_size - 8, 8),
        );
    });
}

#[test]
fn read_after_grow() {
    let wasm_pages = 1;
    with_memory_accessor(wasm_pages, |mut memory_accessor| {
        // Skip the beginning of the memory because it is used as a scratchpad.
        memory_accessor.write(100, &[42; WASM_PAGE_SIZE as usize - 100]);
        // The new page should have only zeros.
        assert_eq!(
            CallContextAction::Reply {
                payload: vec![0; 65536],
                refund: Cycles::new(0)
            },
            memory_accessor.grow_and_read(),
        );
    });
}

#[test]
fn write_after_grow() {
    let wasm_pages = 1;
    with_memory_accessor(wasm_pages, |mut memory_accessor| {
        memory_accessor.grow_and_write(&[42; WASM_PAGE_SIZE as usize]);
        assert_eq!(
            CallContextAction::Reply {
                payload: vec![42; WASM_PAGE_SIZE as usize],
                refund: Cycles::new(0)
            },
            memory_accessor.read(wasm_pages * WASM_PAGE_SIZE, 65536),
        );
    });
}

#[derive(Debug, Clone)]
enum Operation {
    Read(i32),
    Write(i32, u8),
    GrowAndRead,
    GrowAndWrite(u8),
}

fn random_operations(
    num_pages: i32,
    num_operations: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    // Make sure that the value to be written is non-zero because
    // pages are zero-initialized and overwriting them with zeros
    // does not necessarily dirty the pages.
    let operation = (0..100).prop_flat_map(move |p| match p {
        0 => Just(Operation::GrowAndRead).boxed(),
        1 => (1..100_u8).prop_map(Operation::GrowAndWrite).boxed(),
        _ => prop_oneof![
            (1..num_pages).prop_map(Operation::Read),
            (1..num_pages, 1..100_u8).prop_map(|(page, value)| Operation::Write(page, value))
        ]
        .boxed(),
    });
    prop::collection::vec(operation, 1..num_operations)
}

proptest! {
    // Limit the number of cases to keep the running time low.
    #![proptest_config(ProptestConfig { cases: 20, .. ProptestConfig::default() })]
    #[test]
    fn random_memory_accesses(operations in random_operations(10, 100)) {
        const PAGES_PER_WASM_PAGE: i32 = WASM_PAGE_SIZE / 4096;
        let mut pages = vec![0_u8; 10 * PAGES_PER_WASM_PAGE as usize];
        let mut dirty = vec![false; 10 * PAGES_PER_WASM_PAGE as usize];
        with_memory_accessor(10, |mut memory_accessor| {
            for op in operations {
                match op {
                    Operation::Read (page) => {
                        assert_eq!(
                            CallContextAction::Reply {
                                payload: vec![pages[page as usize]; 4096],
                                refund: Cycles::new(0)
                            },
                            memory_accessor.read(page * 4096, 4096),
                        );
                        // Read uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::Write (page, value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        assert!(value > 0);
                        assert_eq!(
                            CallContextAction::NoResponse {
                                refund: Cycles::new(0)
                            },
                            memory_accessor.write(page * 4096, &[value; 4096]),
                        );

                        // Confirm that the write was correct by reading the page.
                        assert_eq!(
                            CallContextAction::Reply {
                                payload: vec![value; 4096],
                                refund: Cycles::new(0)
                            },
                            memory_accessor.read(page * 4096, 4096),
                        );
                        pages[page as usize] = value;
                        dirty[page as usize] = true;
                        // Write uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    },
                    Operation::GrowAndRead => {
                        assert_eq!(
                            CallContextAction::Reply {
                                payload: vec![0; 65536],
                                refund: Cycles::new(0)
                            },
                            memory_accessor.grow_and_read(),
                        );
                        pages.extend(vec![0_u8; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![false; PAGES_PER_WASM_PAGE as usize]);
                    },
                    Operation::GrowAndWrite (value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        assert!(value > 0);
                        assert_eq!(
                            CallContextAction::NoResponse {
                                refund: Cycles::new(0)
                            },
                            memory_accessor.grow_and_write(&[value; WASM_PAGE_SIZE as usize]),
                        );
                        // Confirm that the write was correct by reading the pages.
                        assert_eq!(
                            CallContextAction::Reply {
                                payload: vec![value; WASM_PAGE_SIZE as usize],
                                refund: Cycles::new(0)
                            },
                            memory_accessor.read(pages.len() as i32 * 4096, WASM_PAGE_SIZE),
                        );
                        pages.extend(vec![value; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![true; PAGES_PER_WASM_PAGE as usize]);
                    }
                }
            }
            memory_accessor.verify_dirty_pages(&dirty);
        });
    }
}

// Verify that the `memory.fill` instruction has cost linear with it's size
// argument.
#[test]
fn account_for_size_of_memory_fill_instruction() {
    with_hypervisor(|hypervisor, tmp_path| {
        let mut features = wabt::Features::new();
        features.enable_bulk_memory();
        let binary = wabt::wat2wasm_with_features(
            r#"(module
                          (memory 1)
                          (func (;0;)
                            (memory.fill
                              (i32.const 0)
                              (i32.const 0)
                              (i32.const 1000)))
                          (start 0))"#,
            features,
        )
        .unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();

        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let (_, num_instructions, result) =
            hypervisor.execute_canister_start(canister, execution_parameters);
        result.expect("(start) succeeds");
        println!("remaining instructions: {}", num_instructions);
        assert!((MAX_NUM_INSTRUCTIONS - num_instructions).get() > 1000);
    });
}

// Verify that the `memory.fill` with max u32 bytes triggers the out of
// instructions trap.
#[test]
fn memory_fill_can_trigger_out_of_instructions() {
    with_hypervisor(|hypervisor, tmp_path| {
        let mut features = wabt::Features::new();
        features.enable_bulk_memory();
        let binary = wabt::wat2wasm_with_features(
            r#"(module
                          (memory 65536)
                          (func (;0;)
                            (memory.fill
                              (i32.const 0)
                              (i32.const 0)
                              (i32.const 4294967295))) ;;max u32
                          (start 0))"#,
            features,
        )
        .unwrap();
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();
        let canister = canister_from_exec_state(execution_state, canister_id);
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let (_, _, result) = hypervisor.execute_canister_start(canister, execution_parameters);
        assert_eq!(result, Err(HypervisorError::InstructionLimitExceeded));
    });
}

#[test]
fn broken_wasm_results_in_compilation_error() {
    with_hypervisor(|hypervisor, tmp_path| {
        let binary = vec![0xca, 0xfe, 0xba, 0xbe];

        let result = hypervisor.create_execution_state(binary, tmp_path, canister_test_id(0));

        match result {
            Err(HypervisorError::InvalidWasm(_)) => (),
            val => panic!("Expected a compile error, got: {:?}", val),
        }
    });
}

#[test]
fn can_extract_exported_functions() {
    with_hypervisor(|hypervisor, tmp_path| {
        let execution_state = hypervisor
            .create_execution_state(
                wabt::wat2wasm(
                    r#"
                        (module
                          (func $write)
                          (func $read)
                          (export "canister_update write" (func $write))
                          (export "canister_query read" (func $read))
                          (memory (;0;) 2)
                          (export "memory" (memory 0))
                        )
                    "#,
                )
                .unwrap(),
                tmp_path,
                canister_test_id(0),
            )
            .unwrap();
        let mut expected_exports = BTreeSet::new();
        expected_exports.insert(WasmMethod::Update("write".to_string()));
        expected_exports.insert(WasmMethod::Query("read".to_string()));
        assert_eq!(
            execution_state.exports,
            ExportedFunctions::new(expected_exports)
        );
    });
}
