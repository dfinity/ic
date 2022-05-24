use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_config::execution_environment::Config;
use ic_error_types::{ErrorCode, RejectCode};
use ic_execution_environment::Hypervisor;
use ic_ic00_types::CanisterHttpResponsePayload;
use ic_interfaces::execution_environment::{
    AvailableMemory, ExecutionParameters, HypervisorError, HypervisorError::ContractViolation,
};
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_interfaces::messages::RequestOrIngress;
use ic_metrics::MetricsRegistry;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::CanisterStatus;
use ic_replicated_state::{
    canister_state::execution_state::CustomSectionType, page_map::MemoryRegion,
    testing::CanisterQueuesTesting, CallContextAction, CanisterState, ExportedFunctions, Global,
    NetworkTopology, PageIndex, SubnetTopology, SystemState,
};
use ic_sys::PAGE_SIZE;
use ic_system_api::ApiType;
use ic_test_utilities::execution_environment::{
    assert_empty_reply, check_ingress_status, get_reply, ExecutionTest, ExecutionTestBuilder,
};
use ic_test_utilities::types::messages::IngressBuilder;
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_test_utilities::{
    assert_utils::assert_balance_equals,
    cycles_account_manager::CyclesAccountManagerBuilder,
    metrics::{fetch_histogram_stats, HistogramStats},
    mock_time,
    state::{canister_from_exec_state, SystemStateBuilder},
    types::ids::{call_context_test_id, canister_test_id, subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{
    ingress::WasmResult,
    messages::{RejectContext, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES},
    methods::{FuncRef, WasmClosure, WasmMethod},
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, Time, UserId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};
use std::collections::BTreeSet;
use std::time::Duration;
use std::{convert::TryFrom, sync::Arc};

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const EMPTY_PAYLOAD: Vec<u8> = Vec::new();
const MEMORY_ALLOCATION: NumBytes = NumBytes::new(10_000_000);
const BALANCE_EPSILON: Cycles = Cycles::new(10_000_000);

lazy_static! {
    pub static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}

pub fn execution_parameters_with_unique_subnet_available_memory(
    canister: &CanisterState,
    instruction_limit: NumInstructions,
    subnet_available_memory: SubnetAvailableMemory,
) -> ExecutionParameters {
    ExecutionParameters {
        total_instruction_limit: instruction_limit,
        slice_instruction_limit: instruction_limit,
        canister_memory_limit: canister.memory_limit(NumBytes::new(u64::MAX / 2)),
        subnet_available_memory,
        compute_allocation: canister.scheduler_state.compute_allocation,
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    }
}

pub fn execution_parameters(
    canister: &CanisterState,
    instruction_limit: NumInstructions,
) -> ExecutionParameters {
    execution_parameters_with_unique_subnet_available_memory(
        canister,
        instruction_limit,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    )
}

pub fn test_network_topology() -> Arc<NetworkTopology> {
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
    Arc::new(NetworkTopology {
        routing_table,
        subnets: btreemap! {
            subnet_id => SubnetTopology {
                subnet_type,
                ..SubnetTopology::default()
            },
            subnet_id_2 => SubnetTopology {
                subnet_type: SubnetType::VerifiedApplication,
                ..SubnetTopology::default()
            }
        },
        ..NetworkTopology::default()
    })
}

pub fn with_hypervisor<F, R>(f: F) -> R
where
    F: FnOnce(Hypervisor, std::path::PathBuf) -> R,
{
    with_test_replica_logger(|log| {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            &metrics_registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        f(hypervisor, tmpdir.path().into())
    })
}

fn test_func_ref() -> FuncRef {
    FuncRef::Method(WasmMethod::Update(String::from("test")))
}

fn test_api_type_for_update(caller: Option<PrincipalId>, payload: Vec<u8>) -> ApiType {
    let caller = caller.unwrap_or_else(|| user_test_id(24).get());
    ApiType::update(
        mock_time(),
        payload,
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    )
}

fn test_api_type_for_reject(reject_context: RejectContext) -> ApiType {
    ApiType::reject_callback(
        mock_time(),
        reject_context,
        Cycles::zero(),
        call_context_test_id(13),
        false,
    )
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

    let network_topology = test_network_topology();
    let execution_parameters = execution_parameters(&canister, instructions_limit);
    let (canister, num_instructions_left, action, heap_delta) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Ingress(req),
        time,
        network_topology,
        execution_parameters,
    );

    (canister, num_instructions_left, action, heap_delta)
}

fn execute(
    api_type: ApiType,
    system_state: SystemState,
    wast: &str,
    func_ref: FuncRef,
    network_topology: &NetworkTopology,
) -> Result<Option<WasmResult>, HypervisorError> {
    let mut result = Ok(None);
    let result_ref = &mut result;
    with_hypervisor(move |hypervisor, tmp_path| {
        let wasm_binary = wabt::wat2wasm(wast).unwrap();
        let execution_state = hypervisor
            .create_execution_state(wasm_binary, tmp_path, system_state.canister_id)
            .unwrap();
        let execution_parameters = ExecutionParameters {
            total_instruction_limit: MAX_NUM_INSTRUCTIONS,
            slice_instruction_limit: MAX_NUM_INSTRUCTIONS,
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
                network_topology,
            )
            .0
            .wasm_result;
    });
    result
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
        &test_network_topology(),
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
        &test_network_topology(),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::ContractViolation(
            "function invocation does not match its signature".to_string()
        ))
    );
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
        &test_network_topology(),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::CalledTrap("table!".to_string()))
    );
}

#[test]
fn ic0_canister_status_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_status"
                (func $canister_status (result i32))
            )
            (func (export "canister_update test")
                (if (i32.ne (call $canister_status) (i32.const 1))
                    (then unreachable)
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![0, 1, 2, 3]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_arg_data_size_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_arg_data_size"
                (func $msg_arg_data_size (result i32))
            )
            (func (export "canister_update test")
                (if (i32.ne (call $msg_arg_data_size) (i32.const 4))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![0, 1, 2, 3]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_grow_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_size" (func $stable_size (result i32)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
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
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_write_increases_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    fn wat(bytes: usize) -> String {
        format!(
            r#"(module
                (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                (import "ic0" "stable_write"
                    (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
                )
                (func (export "canister_update test")
                    (drop (call $stable_grow (i32.const 1)))
                    (call $stable_write (i32.const 0) (i32.const 0) (i32.const {}))
                )
                (memory 1)
            )"#,
            bytes
        )
    }
    let canister_id = test.canister_from_wat(wat(4097)).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote more than 1 page but less than 2 pages so we expect 2 pages in
    // heap delta.
    assert_eq!(
        NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
    let canister_id = test.canister_from_wat(wat(8192)).unwrap();
    let heap_delta_estimate_before = test.state().metadata.heap_delta_estimate;
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote exactly 2 pages so we expect 2 pages in heap delta.
    assert_eq!(
        heap_delta_estimate_before + NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn ic0_stable64_write_increases_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    fn wat(bytes: usize) -> String {
        format!(
            r#"(module
                (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                (import "ic0" "stable64_write"
                    (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
                )
                (func (export "canister_update test")
                    (drop (call $stable64_grow (i64.const 1)))
                    (call $stable64_write (i64.const 0) (i64.const 0) (i64.const {}))
                )
                (memory 1)
            )"#,
            bytes
        )
    }
    let canister_id = test.canister_from_wat(wat(4097)).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote more than 1 page but less than 2 pages so we expect 2 pages in
    // heap delta.
    assert_eq!(
        NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
    let canister_id = test.canister_from_wat(wat(8192)).unwrap();
    let heap_delta_estimate_before = test.state().metadata.heap_delta_estimate;
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote exactly 2 pages so we expect 2 pages in heap delta.
    assert_eq!(
        heap_delta_estimate_before + NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn ic0_stable64_grow_does_not_change_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_size" (func $stable64_size (result i64)))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (func (export "canister_update test")
                (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                    (then (unreachable))
                )
                (if (i64.ne (call $stable64_size) (i64.const 1))
                    (then (unreachable))
                )
            )
            (memory 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
}

#[test]
fn ic0_grow_handles_overflow() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_size" (func $stable_size (result i32)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 10 pages.
                (drop (call $stable_grow (i32.const 10)))
                ;; Grow the memory by 2^32-1 pages.
                ;; This should fail since it's bigger than the maximum number of memory
                ;; pages that can be allocated and return -1.
                (if (i32.ne (call $stable_grow (i32.const 4294967295)) (i32.const -1))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_grow_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_size" (func $stable64_size (result i64)))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))

            (func (export "canister_update test")
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
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_grow_by_0_traps_if_memory_exceeds_4gb() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
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
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err
        .description()
        .contains("32 bit stable memory api used on a memory larger than 4GB"));
}

#[test]
fn ic0_stable_grow_traps_if_stable_memory_exceeds_4gb() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
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
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err
        .description()
        .contains("32 bit stable memory api used on a memory larger than 4GB"));
}

#[test]
fn ic0_stable_read_and_write_work() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_update test")
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
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(b"efghabcd".to_vec()), result);
}

#[test]
fn ic0_stable_read_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable_read (i32.const 0) (i32.const 65536) (i32.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_read_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable_grow (i32.const 1)))
                ;; Ensure reading from stable memory with overflow doesn't panic.
                (call $stable_read (i32.const 0) (i32.const 1) (i32.const 4294967295))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_write_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable_write (i32.const 65536) (i32.const 0) (i32.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_write_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable_grow (i32.const 1)))
                ;; Ensure writing to stable memory with overflow doesn't panic.
                (call $stable_write (i32.const 4294967295) (i32.const 0) (i32.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_read_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable_grow (i32.const 2)))
                ;; An attempt to copy a page and a byte to the heap should fail.
                (call $stable_read (i32.const 0) (i32.const 0) (i32.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable_write_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable_grow (i32.const 2)))
                ;; An attempt to copy a page and a byte from the heap should fail.
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable_write_works_at_max_size() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(2_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory to maximum size.
                (drop (call $stable_grow (i32.const 65536)))
                ;; Write to stable memory from position 10 till the end (including).
                (call $stable_write (i32.const 4294967286) (i32.const 0) (i32.const 10))
            )
            (memory 65536)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_read_does_not_trap_if_in_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb).
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory at end of page should not fail.
                (call $stable_read (i32.const 0) (i32.const 0) (i32.const 65536))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_read_works_at_max_size() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(2_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory to maximum size.
                (drop (call $stable_grow (i32.const 65536)))
                ;; Read from position at index 10 till the end of stable memory (including).
                (call $stable_read (i32.const 0) (i32.const 4294967286) (i32.const 10))
            )
            (memory 65536)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_read_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable64_grow (i64.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable64_read (i64.const 0) (i64.const 65536) (i64.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_read_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable64_grow (i64.const 1)))
                ;; Ensure reading from stable memory with overflow doesn't panic.
                (call $stable64_read (i64.const 0) (i64.const 18446744073709551615) (i64.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_write_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable64_grow (i64.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable64_write (i64.const 65536) (i64.const 0) (i64.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_write_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable64_grow (i64.const 1)))
                ;; Ensure writing to stable memory with overflow doesn't panic.
                (call $stable64_write (i64.const 18446744073709551615) (i64.const 0) (i64.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_read_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable64_grow (i64.const 2)))
                ;; An attempt to copy a page and a byte to the heap should fail.
                (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable64_write_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable64_grow (i64.const 2)))
                ;; An attempt to copy a page and a byte from the heap should fail.
                (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable64_read_does_not_trap_if_in_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb).
                (drop (call $stable64_grow (i64.const 1)))
                ;; Reading from stable memory at end of page should succeed.
                (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 65536))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

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
                refund: Cycles::zero(),
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
                refund: Cycles::zero(),
            }
        );
    });
}

#[test]
fn ic0_msg_arg_data_size_is_not_available_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .call_simple(
            callee_id.get(),
            "update",
            call_args()
                .other_side(callee)
                .on_reject(wasm().message_payload().append_and_reply()),
        )
        .build();
    let err = test.ingress(caller_id, "update", caller).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_arg_data_size\" cannot be executed in reject callback mode"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reply_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                (call $msg_reply_data_append (i32.const 4) (i32.const 4))
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "abcdefgh")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(b"abcdefgh".to_vec()), result);
}

#[test]
fn ic0_msg_reply_data_append_has_no_effect_without_ic0_msg_reply() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
            )
            (memory 1 1)
            (data (i32.const 0) "abcdefgh")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_caller_size_and_copy_work_in_update_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().caller().append_and_reply().build();
    let caller = wasm()
        .call_simple(callee_id.get(), "update", call_args().other_side(callee))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(caller_id.get().as_slice().to_vec())
    );
}

#[test]
fn ic0_msg_caller_size_and_copy_work_in_query_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().caller().append_and_reply().build();
    let caller = wasm()
        .call_simple(callee_id.get(), "query", call_args().other_side(callee))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(caller_id.get().as_slice().to_vec())
    );
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
        &test_network_topology(),
    );
    assert_eq!(
        wasm_result,
        Err(HypervisorError::ContractViolation(
            "\"ic0_msg_arg_data_copy\" cannot be executed in reject callback mode".to_string()
        ))
    );
}

#[test]
fn ic0_msg_arg_data_copy_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (import "ic0" "msg_arg_data_copy"
                (func $msg_arg_data_copy (param i32 i32 i32))
            )
            (func (export "canister_update test")
                    (call $msg_arg_data_copy
                        (i32.const 4)     ;; heap dst = 4
                        (i32.const 0)     ;; payload offset = 0
                        (i32.const 4))    ;; length = 4
                    (call $msg_reply_data_append
                        (i32.const 0)     ;; heap offset = 0
                        (i32.const 8))    ;; length = 8
                    (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "xxxxabcd")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let payload = vec![121, 121, 121, 121];
    let result = test.ingress(canister_id, "test", payload).unwrap();
    assert_eq!(WasmResult::Reply(b"xxxxyyyy".to_vec()), result);
}

#[test]
fn ic0_msg_reject_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reject"
                (func $ic0_msg_reject (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
            )
            (memory 1 1)
            (data (i32.const 0) "panic!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reject("panic!".to_string()), result);
}

#[test]
fn ic0_msg_caller_size_is_not_available_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .call_simple(
            callee_id.get(),
            "update",
            call_args()
                .other_side(callee)
                .on_reject(wasm().caller().append_and_reply()),
        )
        .build();
    let err = test.ingress(caller_id, "update", caller).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_caller_size\" cannot be executed in reject callback mode"),
        "Unexpected error message: {}",
        err.description()
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
        &test_network_topology(),
    );
    assert_eq!(
        wasm_result,
        Err(ContractViolation(
            "\"ic0_msg_caller_copy\" cannot be executed in reject callback mode".to_string()
        ))
    );
}

#[test]
fn ic0_msg_reject_fails_if_called_twice() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reject"
                (func $ic0_msg_reject (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
            )
            (memory 1 1)
            (data (i32.const 0) "panic!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.msg_reject: the call is already replied"));
}

#[test]
fn ic0_msg_reject_code_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .call_simple(
            callee_id.get(),
            "update",
            call_args()
                .other_side(callee)
                .on_reject(wasm().reject_code().int_to_blob().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(vec![RejectCode::CanisterReject as u8, 0, 0, 0])
    );
}

#[test]
fn ic0_msg_reject_code_is_not_available_outside_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let payload = wasm()
        .reject_code()
        .int_to_blob()
        .append_and_reply()
        .build();
    let err = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_reject_code\" cannot be executed in update mode"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reject_msg_size_and_copy_work() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .call_simple(
            callee_id.get(),
            "update",
            call_args()
                .other_side(callee.clone())
                .on_reject(wasm().reject_message().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(result, WasmResult::Reply(callee));
}

#[test]
fn ic0_msg_reject_msg_size_is_not_available_outside_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let payload = wasm().reject_message().append_and_reply().build();
    let err = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_reject_msg_size\" cannot be executed in update mode"),
        "Unexpected error message: {}",
        err.description()
    );
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
                refund: Cycles::zero(),
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
        &test_network_topology(),
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
fn ic0_canister_self_size_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_self_size"
                (func $canister_self_size (result i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_update test")
                ;; heap[0] = $canister_self_size()
                (i32.store (i32.const 0) (call $canister_self_size))
                ;; return heap[0]
                (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                (call $msg_reply)
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![10]), result);
}
#[test]
fn ic0_canister_self_copy_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_self_copy"
                (func $canister_self_copy (param i32 i32 i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_update test")
                ;; heap[0..4] = canister_id_bytes[0..4]
                (call $canister_self_copy (i32.const 0) (i32.const 0) (i32.const 4))
                ;; heap[4..10] = canister_id_bytes[4..8]
                (call $canister_self_copy (i32.const 4) (i32.const 4) (i32.const 6))
                ;; return heap[0..10]
                (call $msg_reply_data_append (i32.const 0) (i32.const 10))
                (call $msg_reply)
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(canister_id.get().into_vec()), result);
}

#[test]
fn ic0_call_simple_has_no_effect_on_trap() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_simple"
                (func $ic0_call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32))
            )
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic0_call_simple
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                    )
                drop
                (call $ic_trap (i32.const 0) (i32.const 18))
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn ic0_call_perform_has_no_effect_on_trap() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_data_append"
                (func $ic0_call_data_append (param $src i32) (param $size i32))
            )
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                )
                (drop (call $ic0_call_perform))
                (call $ic_trap (i32.const 0) (i32.const 18))
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn ic0_call_cycles_add_deducts_cycles() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(MAX_NUM_INSTRUCTIONS.get())
        .build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param i64)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (func (export "canister_update test")
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
                drop
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let ingress_status = test.ingress_raw(canister_id, "test", vec![]).1;
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
    assert_eq!(1, test.xnet_messages().len());
    let mgr = test.cycles_account_manager();
    let messaging_fee = mgr.xnet_call_performed_fee()
        + mgr.xnet_call_bytes_transmitted_fee(test.xnet_messages()[0].payload_size_bytes())
        + mgr.xnet_call_bytes_transmitted_fee(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES)
        + mgr.execution_cost(MAX_NUM_INSTRUCTIONS);
    let transferred_cycles = Cycles::new(10_000_000_000);
    assert_eq!(
        initial_cycles - messaging_fee - transferred_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

#[test]
fn ic0_call_cycles_add_has_no_effect_without_ic0_call_perform() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $call_new
                    (param i32 i32)
                    (param $method_name_src i32) (param $method_name_len i32)
                    (param $reply_fun i32)       (param $reply_env i32)
                    (param $reject_fun i32)      (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add" (func $call_cycles_add (param i64)))
            (func (export "canister_update test")
                (call $call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $call_cycles_add
                    (i64.const 10000000000)         ;; amount of cycles used to be transferred
                )
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;

    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(0, test.xnet_messages().len());
    // Cycles deducted by `ic0.call_cycles_add` are refunded.
    assert_eq!(
        initial_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

const MINT_CYCLES: &str = r#"
    (module
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32) (param i32))
        )
        (import "ic0" "mint_cycles"
            (func $mint_cycles (param i64) (result i64))
        )
        (import "ic0" "msg_reply" (func $ic0_msg_reply))

        (func (export "canister_update test")
            (i64.store
                ;; store at the beginning of the heap
                (i32.const 0) ;; store at the beginning of the heap
                (call $mint_cycles (i64.const 10000000000))
            )
            (call $msg_reply_data_append (i32.const 0) (i32.const 8))
            (call $ic0_msg_reply)
        )
        (memory 1 1)
    )"#;

#[test]
fn ic0_mint_cycles_fails_on_application_subnet() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.mint_cycles cannot be executed"));
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles,
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_mint_cycles_fails_on_system_subnet_non_cmc() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.mint_cycles cannot be executed"));
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles,
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_mint_cycles_succeeds_on_cmc() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    // This loop should finish after four iterations.
    while canister_id != CYCLES_MINTING_CANISTER_ID {
        canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    }
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    // ic0_mint() returns the minted amount: hex(10_000_000_000) = 0x2_54_0b_e4_00.
    assert_eq!(WasmResult::Reply(vec![0, 228, 11, 84, 2, 0, 0, 0]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles + Cycles::new(10_000_000_000),
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_call_simple_enqueues_request() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_simple"
                (func $call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32)
                )
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $call_simple
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                )
                drop
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(1, canister_state.system_state.queues().output_queues_len());
}

#[test]
fn ic0_call_perform_enqueues_request() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_data_append"
                (func $call_data_append (param $src i32) (param $size i32))
            )
            (import "ic0" "call_perform" (func $call_perform (result i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $call_data_append
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                )
                (call $call_perform)
                drop
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(1, canister_state.system_state.queues().output_queues_len());
}

#[test]
fn ic0_trap_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic_trap (i32.const 0) (i32.const 3))
            )
            (data (i32.const 0) "Hi!")
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(
        format!("Canister {} trapped explicitly: Hi!", canister_id),
        err.description()
    );
}

#[test]
fn globals_are_updated() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (global.set 0 (i32.const 1))
            )
            (global (export "g") (mut i32) (i32.const 137))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        Global::I32(1),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn comparison_of_non_canonical_nans() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (global.set 0 (f32.eq (f32.const nan:0x1234) (f32.const nan:0x1234)))
            )
            (global (export "g") (mut i32) (i32.const 137))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        Global::I32(0),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn instruction_limit_is_respected() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(3)
        .build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (i32.const 0)
                (i32.const 0)
                (drop)
                (drop)
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());
}

#[test]
fn subnet_available_memory_is_respected_by_memory_grow() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_available_memory(9 * WASM_PAGE_SIZE as i64)
        .build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfMemory, err.code());
}

#[test]
fn subnet_available_memory_is_updated() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 1)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        initial_subnet_available_memory.get_total_memory() - WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_total_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_does_not_change_after_failed_execution() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 1)))
                unreachable
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert_eq!(
        initial_subnet_available_memory.get_total_memory(),
        test.subnet_available_memory().get_total_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn ic0_msg_cycles_available_returns_zero_for_ingress() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_available"
                (func $msg_cycles_available (result i64))
            )
            (func (export "canister_update test")
                block
                    call $msg_cycles_available
                    i64.eqz
                    br_if 0
                    unreachable
                end)
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_cycles_available_works_for_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_available" (func $msg_cycles_available (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                block
                    call $msg_cycles_available
                    i64.const 50
                    i64.eq
                    br_if 0
                    unreachable
                end
                (call $msg_reply)
            )
            (memory 1)
        )"#;
    let callee_id = test.canister_from_wat(wat).unwrap();
    let caller_id = test.universal_canister().unwrap();
    let caller = wasm()
        .call_with_cycles(callee_id.get(), "test", call_args(), (0, 50))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
}

#[test]
fn wasm_page_metrics_are_recorded_even_if_execution_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update write")
                (i32.store
                    (i32.const 0)
                    (i32.add (i32.load (i32.const 70000)) (i32.const 1))
                )
                (unreachable)
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "write", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert_eq!(
        fetch_histogram_stats(test.metrics_registry(), "hypervisor_dirty_pages"),
        Some(HistogramStats { sum: 1.0, count: 1 })
    );
    match fetch_histogram_stats(test.metrics_registry(), "hypervisor_accessed_pages") {
        Some(HistogramStats { sum, count }) => {
            assert_eq!(count, 1);
            assert!(sum >= 2.0);
        }
        None => unreachable!(),
    }
}

#[test]
fn executing_non_existing_method_does_not_consume_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "foo", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
    assert_eq!(NumInstructions::from(0), test.executed_instructions());
}

#[test]
fn grow_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
            )
            (memory 1 2)
        )"#;
    test.canister_from_wat(wat).unwrap();
}

#[test]
fn memory_access_between_min_and_max_canister_start() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func $start
                ;; An attempt to load heap[0..4] which should fail.
                (drop (i32.load (i32.const 65536)))
            )
            (start $start)
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn memory_access_between_min_and_max_ingress() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                ;; An attempt to load heap[0..4] which should fail.
                (drop (i32.load (i32.const 65536)))
            )
            (memory 1 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn upgrade_calls_pre_and_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow"
                (func $stable_grow (param i32) (result i32))
            )
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 8)) ;; length
                (call $msg_reply))
            (func (export "canister_pre_upgrade")
                (drop (call $stable_grow (i32.const 1)))
                ;; Store [1, 0, 0, 0] to heap[0..4]
                (i32.store (i32.const 0) (i32.const 1))
                ;; Copy heap[0..4] to stable_memory[0..4]
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
            )
            (func (export "canister_post_upgrade")
                ;; Copy stable_memory[0..4] to heap[4..8]
                (call $stable_read (i32.const 4) (i32.const 0) (i32.const 4))
            )
            (memory $memory 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0, 0, 0, 0, 0])));
    let result = test.upgrade_canister(canister_id, wabt::wat2wasm(wat).unwrap());
    assert_eq!(Ok(()), result);
    let result = test.ingress(canister_id, "read", vec![]);
    // The Wasm memory changes of `pre_upgrade` must be cleared.
    // The Wasm memory changes of `post_upgrade` must be visible.
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0, 1, 0, 0, 0])));
}

#[test]
fn upgrade_without_pre_and_post_upgrade_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.upgrade_canister(canister_id, wabt::wat2wasm(wat).unwrap());
    assert_eq!(Ok(()), result);
    assert_eq!(NumInstructions::from(0), test.executed_instructions());
}

#[test]
fn install_code_calls_canister_init_and_start() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 8)) ;; length
                (call $msg_reply))
            (func $start
                (i32.store (i32.const 0) (i32.const 1))
            )
            (func (export "canister_init")
                (i32.store (i32.const 4) (i32.const 2))
            )
            (memory $memory 1)
            (start $start)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumInstructions::from(6), test.executed_instructions());
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![1, 0, 0, 0, 2, 0, 0, 0])));
}

#[test]
fn install_code_without_canister_init_and_start_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    test.canister_from_wat(wat).unwrap();
    assert_eq!(NumInstructions::from(0), test.executed_instructions());
}

#[test]
fn canister_init_can_set_mutable_globals() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (global.set 0 (i32.const 42))
            )
            (global (export "globals_must_be_exported") (mut i32) (i32.const 0))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(
        Global::I32(42),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn grow_memory_beyond_max_size_1() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; growing memory past limit does not trigger trap or error
                (drop (memory.grow (i32.const 1)))
                ;; but accessing the memory triggers HeapOutOfBounds
                ;; page(2)[0;4] = 1
                (i32.store (i32.const 65536) (i32.const 1))
            )
            (memory 1 1)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn memory_access_between_min_and_max_canister_init() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; attempt to load page(1)[0;4] which should fail
                (drop (i32.load (i32.const 65536)))
            )
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn grow_memory_beyond_max_size_2() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; growing memory past limit does not trigger trap or error
                (drop (memory.grow (i32.const 100)))
                ;; but accessing the memory triggers HeapOutOfBounds
                ;; page(3)[0;4] = 1
                (i32.store
                    (i32.add (i32.mul (i32.const 65536) (i32.const 2)) (i32.const 1))
                    (i32.const 1)
                )
            )
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn grow_memory_beyond_32_bit_limit_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; 65536 is the maximum number of 32-bit wasm memory pages
                (drop (memory.grow (i32.const 65537)))
                ;; grow failed so accessing the memory triggers HeapOutOfBounds
                (i32.store (i32.const 1) (i32.const 1))
            )
            (memory 0)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

const STABLE_MEMORY_WAT: &str = r#"
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32) (param i32))
    )
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
    (import "ic0" "stable_read"
        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
    )
    (import "ic0" "stable_write"
        (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
    )
    (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
    (func (export "canister_query read")
        ;; heap[8..12] = stable_memory[0..4]
        (call $stable_read (i32.const 8) (i32.const 0) (i32.const 4))
        ;; Return heap[8..12].
        (call $msg_reply_data_append
            (i32.const 8)     ;; heap offset = 8
            (i32.const 4))    ;; length = 4
        (call $msg_reply)     ;; call reply
    )
    (func (export "canister_update write")
        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
    )"#;

#[test]
fn changes_to_stable_memory_in_canister_init_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister(canister_id, wabt::wat2wasm(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(None, test.canister_state(canister_id).execution_state);
}

#[test]
fn changes_to_stable_memory_in_canister_pre_upgrade_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (func (export "canister_pre_upgrade")
                ;; stable_memory[0..4] = heap[0..4] ("abcd")
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
    let err = test
        .upgrade_canister(canister_id, wabt::wat2wasm(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn changes_to_stable_memory_in_canister_post_upgrade_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (func (export "canister_post_upgrade")
                ;; stable_memory[0..4] = heap[0..4] ("abcd")
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
    let err = test
        .upgrade_canister(canister_id, wabt::wat2wasm(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn upgrade_preserves_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "write", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
    test.upgrade_canister(canister_id, wabt::wat2wasm(wat).unwrap())
        .unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
}

#[test]
fn reinstall_clears_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "write", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
    test.reinstall_canister(canister_id, wabt::wat2wasm(wat).unwrap())
        .unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn cannot_execute_update_on_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopping, err.code());
}

#[test]
fn cannot_execute_update_on_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopped, err.code());
}

#[test]
fn cannot_execute_query_on_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopping, err.code());
}

#[test]
fn cannot_execute_query_on_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopped, err.code());
}

#[test]
fn ic0_trap_preserves_some_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            ;; globals must be exported to be accessible to hypervisor or persisted
            (global (export "g1") (mut i32) (i32.const -1))
            (global (export "g2") (mut i64) (i64.const -1))
            (func $func_that_traps
            (call $ic_trap (i32.const 0) (i32.const 12)))

            (memory $memory 1)
            (export "memory" (memory $memory))
            (export "canister_update update" (func $func_that_traps))
            (export "canister_query query" (func $func_that_traps))
            (data (i32.const 0) "Trap called!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    // The $func_that_traps call should be cheap:
    // - call trap -- 21 instructions,
    // - constants -- 2 instructions,
    // - trap data -- 12 instructions.
    let expected_executed_instructions = NumInstructions::from(21 + 2 + 12);
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert_eq!(test.executed_instructions(), expected_executed_instructions);

    let executed_instructions_before = test.executed_instructions();
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert_eq!(
        test.executed_instructions(),
        executed_instructions_before + expected_executed_instructions
    );
}

// If method is not exported, `execute_anonymous_query` fails.
#[test]
fn canister_anonymous_query_method_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (memory $memory 1)
            (export "memory" (memory $memory))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.anonymous_query(canister_id, "http_transform", vec![]);
    assert_eq!(
        result,
        Err(HypervisorError::MethodNotFound(WasmMethod::Query(
            "http_transform".to_string()
        )))
    );
}

// Using `execute_anonymous_query` to execute transform function on a http response succeeds.
#[test]
fn canister_anonymous_query_transform_http_response() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (import "ic0" "msg_arg_data_copy"
                (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
            (import "ic0" "msg_arg_data_size"
                (func $ic0_msg_arg_data_size (result i32)))
            (import "ic0" "msg_reply_data_append"
                (func $ic0_msg_reply_data_append (param i32) (param i32)))
            (func $transform
                ;; Replies with the provided http_reponse argument without any modifcations.
                (call $ic0_msg_arg_data_copy
                    (i32.const 0) ;; dst
                    (i32.const 0) ;; offset
                    (call $ic0_msg_arg_data_size) ;; size
                )
                (call $ic0_msg_reply_data_append
                    (i32.const 0) ;; src
                    (call $ic0_msg_arg_data_size) ;; size
                )
                (call $ic0_msg_reply)
            )
            (memory $memory 1)
            (export "memory" (memory $memory))
            (export "canister_query http_transform" (func $transform))
        )"#;

    let canister_id = test.canister_from_wat(wat).unwrap();
    let canister_http_response = CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![0, 1, 2],
    };
    let payload = Encode!(&canister_http_response).unwrap();
    let result = test.anonymous_query(canister_id, "http_transform", payload);
    let transformed_canister_http_response = Decode!(
        result.unwrap().unwrap().bytes().as_slice(),
        CanisterHttpResponsePayload
    )
    .unwrap();
    assert_eq!(canister_http_response, transformed_canister_http_response)
}

// Tests that execute_update produces a heap delta.
#[test]
fn update_message_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update hello")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "hello", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn canister_start_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (;0;)
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
            (start 0)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.canister_from_wat(wat).unwrap();
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn canister_init_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.canister_from_wat(wat).unwrap();
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
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
    test: ExecutionTest,
    canister_id: CanisterId,
}

impl MemoryAccessor {
    fn new(wasm_pages: i32) -> Self {
        let mut test = ExecutionTestBuilder::new().build();
        let wat = memory_module_wat(wasm_pages);
        let canister_id = test.canister_from_wat(wat).unwrap();
        Self { test, canister_id }
    }

    fn write(&mut self, addr: i32, bytes: &[u8]) {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(bytes.iter());
        let result = self.test.ingress(self.canister_id, "write", payload);
        assert_empty_reply(result);
    }

    fn read(&mut self, addr: i32, size: i32) -> Vec<u8> {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(size.to_le_bytes().to_vec());
        get_reply(self.test.ingress(self.canister_id, "read", payload))
    }

    fn grow_and_read(&mut self) -> Vec<u8> {
        get_reply(self.test.ingress(self.canister_id, "grow_and_read", vec![]))
    }

    fn grow_and_write(&mut self, bytes: &[u8]) {
        let result = self
            .test
            .ingress(self.canister_id, "grow_and_write", bytes.to_vec());
        assert_empty_reply(result);
    }

    fn verify_dirty_pages(&self, is_dirty_page: &[bool]) {
        let execution_state = self.test.execution_state(self.canister_id);
        for (page_index, is_dirty_page) in is_dirty_page.iter().enumerate() {
            match execution_state
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

#[test]
fn write_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.write(memory_size - 8, &[42; 8]);
}

#[test]
fn read_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    assert_eq!(vec![0; 8], memory_accessor.read(memory_size - 8, 8));
}

#[test]
fn write_and_read_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.write(memory_size - 8, &[42; 8]);
    assert_eq!(vec![42; 8], memory_accessor.read(memory_size - 8, 8));
}

#[test]
fn read_after_grow() {
    let wasm_pages = 1;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    // Skip the beginning of the memory because it is used as a scratchpad.
    memory_accessor.write(100, &[42; WASM_PAGE_SIZE as usize - 100]);
    // The new page should have only zeros.
    assert_eq!(vec![0; 65536], memory_accessor.grow_and_read());
}

#[test]
fn write_after_grow() {
    let wasm_pages = 1;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.grow_and_write(&[42; WASM_PAGE_SIZE as usize]);
    assert_eq!(
        vec![42; WASM_PAGE_SIZE as usize],
        memory_accessor.read(wasm_pages * WASM_PAGE_SIZE, 65536),
    );
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

#[test]
fn random_memory_accesses() {
    // Limit the number of cases to keep the running time low.
    let config = ProptestConfig {
        cases: 20,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    runner
        .run(&random_operations(10, 100), |operations| {
            const PAGES_PER_WASM_PAGE: i32 = WASM_PAGE_SIZE / 4096;
            let mut pages = vec![0_u8; 10 * PAGES_PER_WASM_PAGE as usize];
            let mut dirty = vec![false; 10 * PAGES_PER_WASM_PAGE as usize];
            let mut memory_accessor = MemoryAccessor::new(10);
            for op in operations {
                match op {
                    Operation::Read(page) => {
                        prop_assert_eq!(
                            vec![pages[page as usize]; 4096],
                            memory_accessor.read(page * 4096, 4096)
                        );
                        // Read uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::Write(page, value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        prop_assert!(value > 0);
                        memory_accessor.write(page * 4096, &[value; 4096]);

                        // Confirm that the write was correct by reading the page.
                        prop_assert_eq!(vec![value; 4096], memory_accessor.read(page * 4096, 4096));
                        pages[page as usize] = value;
                        dirty[page as usize] = true;
                        // Write uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::GrowAndRead => {
                        prop_assert_eq!(vec![0; 65536], memory_accessor.grow_and_read());
                        pages.extend(vec![0_u8; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![false; PAGES_PER_WASM_PAGE as usize]);
                        // Read uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::GrowAndWrite(value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        prop_assert!(value > 0);
                        memory_accessor.grow_and_write(&[value; WASM_PAGE_SIZE as usize]);
                        // Confirm that the write was correct by reading the pages.
                        prop_assert_eq!(
                            vec![value; WASM_PAGE_SIZE as usize],
                            memory_accessor.read(pages.len() as i32 * 4096, WASM_PAGE_SIZE)
                        );
                        pages.extend(vec![value; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![true; PAGES_PER_WASM_PAGE as usize]);
                        // Write uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                }
            }
            memory_accessor.verify_dirty_pages(&dirty);
            Ok(())
        })
        .unwrap();
}

// Verify that the `memory.fill` instruction has cost linear with it's size
// argument.
#[test]
fn account_for_size_of_memory_fill_instruction() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (memory 1)
            (func (;0;)
            (memory.fill
                (i32.const 0)
                (i32.const 0)
                (i32.const 1000)))
            (start 0)
        )"#;
    assert_eq!(test.executed_instructions(), NumInstructions::from(0));
    test.canister_from_wat(wat).unwrap();
    assert!(test.executed_instructions() > NumInstructions::from(1000));
}

// Verify that the `memory.fill` with max u32 bytes triggers the out of
// instructions trap.
#[test]
fn memory_fill_can_trigger_out_of_instructions() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(4_000_000_000)
        .build();
    let wat = r#"
        (module
            (memory 65536)
            (func (;0;)
            (memory.fill
                (i32.const 0)
                (i32.const 0)
                (i32.const 4294967295))) ;;max u32
            (start 0)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());
}

#[test]
fn broken_wasm_results_in_compilation_error() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = vec![0xca, 0xfe, 0xba, 0xbe];
    let err = test.canister_from_binary(binary).unwrap_err();
    assert_eq!(ErrorCode::CanisterInvalidWasm, err.code());
}

#[test]
fn can_extract_exported_functions() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func $write)
            (func $read)
            (export "canister_update write" (func $write))
            (export "canister_query read" (func $read))
            (memory (;0;) 2)
            (export "memory" (memory 0))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let execution_state = test.execution_state(canister_id);
    let mut expected_exports = BTreeSet::new();
    expected_exports.insert(WasmMethod::Update("write".to_string()));
    expected_exports.insert(WasmMethod::Query("read".to_string()));
    assert_eq!(
        execution_state.exports,
        ExportedFunctions::new(expected_exports)
    );
}

#[test]
fn can_extract_exported_custom_sections() {
    let mut test = ExecutionTestBuilder::new().build();
    // The wasm file below contains the following custom sections
    // Custom start=0x0002586a end=0x00028d92 (size=0x00003528) "name"
    // Custom start=0x00028d98 end=0x00028ddc (size=0x00000044) "icp:public candid:service"
    // Custom start=0x00028de2 end=0x00028dfc (size=0x0000001a) "icp:private candid:args"
    // Custom start=0x00028e02 end=0x00028e30 (size=0x0000002e) "icp:private motoko:stable-types"

    let binary = include_bytes!("test-data/custom_sections.wasm").to_vec();
    let canister_id = test.canister_from_binary(binary).unwrap();
    let execution_state = test.execution_state(canister_id);
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("candid:service")
            .unwrap()
            .visibility,
        CustomSectionType::Public
    );
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("candid:args")
            .unwrap()
            .visibility,
        CustomSectionType::Private
    );
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("motoko:stable-types")
            .unwrap()
            .visibility,
        CustomSectionType::Private
    );
    // Only the valid custom sections names are extracted: icp:public <name> or icp:private <name>.
    assert_eq!(execution_state.metadata.custom_sections().len(), 3);
}

#[test]
fn execute_with_huge_cycle_balance() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init"))
            (memory 0)
        )"#;
    test.canister_from_cycles_and_wat(Cycles::new(1u128 << 100), wat)
        .unwrap();
}

#[test]
fn install_gzip_compressed_module() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $inc
                (i32.store
                    (i32.const 0)
                    (i32.add (i32.load (i32.const 0)) (i32.const 1))))
            (func $read
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 4)) ;; length
                (call $msg_reply))
            (memory $memory 1)
            (export "canister_query read" (func $read))
            (export "canister_update inc" (func $inc))
        )"#;

    let binary = {
        let wasm = wabt::wat2wasm(wat).unwrap();
        let mut encoder = libflate::gzip::Encoder::new(Vec::new()).unwrap();
        std::io::copy(&mut &wasm[..], &mut encoder).unwrap();
        encoder.finish().into_result().unwrap()
    };

    let canister_id = test.canister_from_binary(binary).unwrap();
    let result = test.ingress(canister_id, "inc", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![1, 0, 0, 0])));
}

#[test]
fn cycles_cannot_be_accepted_after_response() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = (initial_cycles.get() / 2) as u64;

    // Canister C simply replies with the message that was sent to it.
    let c = wasm().message_payload().append_and_reply().build();

    // Canister B:
    // 1. Replies to canister A with the message that was sent to it.
    // 2. Calls canister C.
    // 3. In the reply callback accepts `transferred_cycles`.
    let b = wasm()
        .message_payload()
        .append_and_reply()
        .inter_update(
            c_id.get(),
            call_args()
                .other_side(c.clone())
                .on_reply(wasm().accept_cycles(transferred_cycles)),
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()),
            (0, transferred_cycles),
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister A gets a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
    );

    // Canister B doesn't get the transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
    );

    // Canister C pays only for execution.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id)
    );
}

#[test]
fn cycles_are_refunded_if_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = b_to_c_transferred / 2;

    // Canister C accepts some cycles and replies to canister B.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Replies to canister A.
    // 3. Calls canister C.
    // 4. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .call_with_cycles(
            c_id.get(),
            "update",
            call_args().other_side(c.clone()),
            (0, b_to_c_transferred),
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()),
            (0, a_to_b_transferred),
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister A gets a refund for all cycles not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
            - Cycles::new(a_to_b_accepted as u128),
    );

    // Canister B gets all cycles it accepted and a refund for all cycles not
    // accepted by C.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + Cycles::new(a_to_b_accepted as u128)
            - Cycles::new(b_to_c_accepted as u128)
    );

    // Canister C get all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + Cycles::new(b_to_c_accepted as u128)
    );
}

#[test]
fn cycles_are_refunded_if_callee_traps() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Replies to canister A.
    // 3. Calls trap.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .trap()
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reject code and message in the reject callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, a_to_b_transferred),
        )
        .build();

    let result = test.ingress(a_id, "update", a).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got {}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };

    // Canister A gets a refund for all transferred cycles because canister B
    // trapped after accepting.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
    );

    // Canister B doesn't get any transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_even_if_response_callback_traps() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;

    // Canister B accepts cycles and replies.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Calls trap in the reply callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()).on_reply(wasm().trap()),
            (0, a_to_b_transferred),
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());

    // Calling trap in the reply callback shouldn't affect the amount of
    // refunded cycles. Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
            - Cycles::new(a_to_b_accepted as u128),
    );

    // Canister B gets cycles it accepted.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id) + Cycles::new(a_to_b_accepted as u128)
    );
}

// TODO(RUN-175): Enable the test after the bug is fixed.
#[test]
#[ignore]
fn cycles_are_refunded_if_callee_is_a_query() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies to canister A without accepting any cycles.
    // Note that it cannot accept cycles because it runs as a query.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls a query method of canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "query",
            call_args().other_side(b.clone()),
            (0, a_to_b_transferred),
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister should get a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("query", &b)
            - test.reply_fee(&b)
    );

    // Canister B doesn't get any transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_before_execution() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reject code and message in the reject callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, a_to_b_transferred),
        )
        .build();

    // Uninstall canister B before calling it.
    test.uninstall_code(b_id).unwrap();

    // Send a message to canister A which will call canister B.
    let result = test.ingress(a_id, "update", a).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got {}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };

    // Canister A gets a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
    );

    // Canister B doesn't get any cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_after_execution() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters: A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = b_to_c_transferred / 2;

    // Canister C accepts some cycles and replies.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Calls canister C and transfers some cycles to it.
    // 3. Forwards the reply of C to A.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            c_id.get(),
            "update",
            call_args().other_side(c.clone()),
            (0, b_to_c_transferred),
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply of B to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, a_to_b_transferred),
        )
        .build();

    // Execute canisters A and B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    // Uninstall canister B, which generates a reject message for canister A.
    test.uninstall_code(b_id).unwrap();

    // Execute canister C and all the replies.
    let ingress_status = test.execute_all(ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();

    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("Canister has been uninstalled"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
            - Cycles::new(a_to_b_accepted as u128),
    );

    // Canister B gets all cycles it accepted and all cycles that canister C did
    // not accept.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + Cycles::new(a_to_b_accepted as u128)
            - Cycles::new(b_to_c_accepted as u128)
    );

    // Canister C gets all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + Cycles::new(b_to_c_accepted as u128)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_reinstalled() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters: A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = b_to_c_transferred / 2;

    // Canister C accepts some cycles and replies.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Calls canister C and transfers some cycles to it.
    // 3. Forwards the reply of C to A.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            c_id.get(),
            "update",
            call_args().other_side(c.clone()),
            (0, b_to_c_transferred),
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply of B to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, a_to_b_transferred),
        )
        .build();

    // Execute canisters A and B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    // Reinstall canister B with the same code. Since the memory is cleared, the
    // reply callback will trap.
    test.reinstall_canister(b_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Execute canister C and all the replies.
    let ingress_status = test.execute_all(ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("trapped explicitly: panicked at 'get_callback: 1 out of bounds'"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
            - Cycles::new(a_to_b_accepted as u128),
    );

    // Canister B gets all cycles it accepted and all cycles that canister C did
    // not accept.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + Cycles::new(a_to_b_accepted as u128)
            - Cycles::new(b_to_c_accepted as u128)
    );

    // Canister C gets all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + Cycles::new(b_to_c_accepted as u128)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_during_a_self_call() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;
    let a_to_b_accepted = a_to_b_transferred / 2;
    let b_transferred_1 = (initial_cycles.get() / 2) as u64;
    let b_accepted_1 = b_transferred_1 / 2;
    let b_transferred_2 = b_accepted_1;
    let b_accepted_2 = b_transferred_2 / 2;

    // The update method #2 canister B accepts some cycles and then replies.
    let b_2 = wasm()
        .accept_cycles(b_accepted_2)
        .message_payload()
        .append_and_reply()
        .build();

    // The update method #1 of canister B:
    // 1. Accepts some cycles.
    // 2. Call the update method #2 and transfers some cycles.
    // 3. Forwards the reply to the caller.
    let b_1 = wasm()
        .accept_cycles(b_accepted_1)
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b_2.clone()),
            (0, b_transferred_2),
        )
        .build();

    // The update method #0 of canister B:
    // 1. Call the update method #2 and transfers some cycles.
    // 2. Forwards the reject code and message to canister A.
    let b_0 = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b_1.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, b_transferred_1),
        )
        .build();

    // Canister A:
    // 1. Call the update method #0 of B and transfers some cycles.
    // 2. Forwards the reject code and message to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b_0.clone())
                .on_reject(wasm().reject_code().reject_message().reject()),
            (0, a_to_b_transferred),
        )
        .build();

    // Execute canister A and methods #0 and #1 of canister B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    test.execute_message(b_id);

    // Uninstall canister B, which generates reject messages for all call contexts.
    test.uninstall_code(b_id).unwrap();

    // Execute method #2 of canister B and all the replies.
    let ingress_status = test.execute_all(ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("Canister has been uninstalled"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets a refund for all cycles that B did not accept.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b_0)
            - test.reject_fee(reject_message.clone())
            - Cycles::new(a_to_b_accepted as u128)
    );

    // The reject message from method #2 of B to method #1.
    let reject_message_b_2_to_1 = format!(
        "IC0304: Attempt to execute a message on canister {} which contains no Wasm module",
        b_id
    );

    // Canister B gets the cycles it accepted from A.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &b_1)
            - test.call_fee("update", &b_2)
            - test.reject_fee(reject_message)
            - test.reject_fee(reject_message_b_2_to_1)
            + Cycles::new(a_to_b_accepted as u128)
    );
}

#[test]
fn cannot_send_request_to_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();

    // Move canister B to a stopping state before calling it.
    test.stop_canister(b_id);
    assert_matches!(
        test.canister_state(b_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );

    // Send a message to canister A which will call canister B.
    let ingress_status = test.ingress_raw(a_id, "update", a).1;

    // The call gets stuck in the output queue of canister A because we don't
    // induct message to a stopping canister.
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
}

#[test]
fn cannot_send_request_to_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();

    // Stop canister B before calling it.
    test.stop_canister(b_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(b_id).system_state.status
    );

    // Send a message to canister A which will call canister B.
    let ingress_status = test.ingress_raw(a_id, "update", a).1;

    // The call gets stuck in the output queue of canister A because we don't
    // induct message to a stopped canister.
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
}

#[test]
fn cannot_stop_canister_with_open_call_context() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A calls canister B.
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b.clone()))
        .build();

    // Enqueue ingress message to canister A but do not execute it (guaranteed
    // by "manual execution" option of the test).
    let ingress_status = test.ingress_raw(a_id, "update", a).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);

    // Execute the ingress message and induct all messages to get the call
    // message to the input queue of canister B.
    test.execute_message(a_id);
    test.induct_messages();

    // Try to stop canister A.
    test.stop_canister(a_id);
    test.process_stopping_canisters();

    // Canister A cannot transition to the stopped state because it has an open
    // call context.
    assert_matches!(
        test.canister_state(a_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );

    // Execute the call in canister B.
    let ingress_status = test.execute_message(b_id);
    assert_eq!(ingress_status, None);

    // Get the reply back to canister A and execute it.
    test.induct_messages();
    let ingress_status = test.execute_message(a_id).unwrap().1;
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));

    // Now it should be possible to stop canister A.
    test.process_stopping_canisters();
    assert_eq!(
        test.canister_state(a_id).system_state.status,
        CanisterStatus::Stopped
    );
}
