use crate::config;
use ic_embedders::{wasm_executor::WasmExecutor, WasmtimeEmbedder};
use ic_execution_environment::{
    execute as hypervisor_execute, Hypervisor, HypervisorMetrics, QueryExecutionType,
};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorError::ContractViolation, HypervisorResult, SubnetAvailableMemory,
    TrapCode,
};
use ic_interfaces::messages::RequestOrIngress;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::testing::CanisterQueuesTesting, CallContextAction, CallOrigin, CanisterState,
    ExecutionState, Global, NumWasmPages, SystemState,
};
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
use ic_utils::ic_features::cow_state_feature;
use ic_wasm_utils::validation::WasmValidationLimits;
use lazy_static::lazy_static;
use maplit::btreemap;
use std::{collections::BTreeMap, convert::TryFrom, sync::Arc, time::Duration};

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const EMPTY_PAYLOAD: Vec<u8> = Vec::new();
const MEMORY_ALLOCATION: NumBytes = NumBytes::new(10_000_000);
const BALANCE_EPSILON: Cycles = Cycles::new(10_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
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
    let subnet_type = SubnetType::Application;
    let routing_table = Arc::new(RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    }));
    let subnet_records = Arc::new(btreemap! {
        subnet_id => subnet_type,
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
            1,
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
    caller: Option<PrincipalId>,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    execute_update_with_cycles_memory_time(
        hypervisor,
        wast,
        method,
        payload,
        caller,
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
    caller: Option<PrincipalId>,
    instructions_limit: NumInstructions,
    bytes: NumBytes,
    time: Time,
    canister_root: std::path::PathBuf,
) -> (CanisterState, NumInstructions, CallContextAction, NumBytes) {
    let caller = caller.unwrap_or_else(|| user_test_id(24).get());

    let execution_state = ExecutionState::new(
        wabt::wat2wasm(wast).unwrap(),
        canister_root,
        WasmValidationLimits::default(),
    )
    .expect("Failed to create execution state.");
    let mut canister = canister_from_exec_state(execution_state);
    canister.system_state.memory_allocation = MemoryAllocation::try_from(bytes).unwrap();

    let req = IngressBuilder::new()
        .method_name(method.to_string())
        .method_payload(payload)
        .source(UserId::from(caller))
        .build();

    let (_, _, routing_table, subnet_records) = setup();
    let (canister, num_instructions_left, action, heap_delta) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Ingress(req),
        instructions_limit,
        time,
        routing_table,
        subnet_records,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

    let execution_state = ExecutionState::new(
        wabt::wat2wasm(wast).unwrap(),
        canister_root,
        WasmValidationLimits::default(),
    )
    .expect("Failed to create execution state.");
    let canister = canister_from_exec_state(execution_state);

    let req = RequestBuilder::new()
        .method_name(method.to_string())
        .method_payload(payload)
        .sender(caller)
        .receiver(canister.canister_id())
        .payment(payment)
        .build();

    let (_, _, routing_table, subnet_records) = setup();
    let (canister, num_instructions_left, action, _) = hypervisor.execute_update(
        canister,
        RequestOrIngress::Request(req),
        instructions_limit,
        time,
        routing_table,
        subnet_records,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    );

    (canister, num_instructions_left, action)
}

fn execute(
    api_type: ApiType,
    system_state: SystemState,
    wast: &str,
    func_ref: FuncRef,
) -> Result<Option<WasmResult>, HypervisorError> {
    let canister_root = tempfile::Builder::new()
        .prefix("test")
        .tempdir()
        .unwrap()
        .path()
        .into();
    let execution_state = ExecutionState::new(
        wabt::wat2wasm(wast).unwrap(),
        canister_root,
        WasmValidationLimits::default(),
    )
    .unwrap();
    let metrics_registry = MetricsRegistry::new();
    let metrics = Arc::new(HypervisorMetrics::new(&metrics_registry));
    let config = config();

    let mut embedder_config = ic_config::embedders::Config::new();
    embedder_config.persistence_type = config.persistence_type;

    let wasm_embedder = WasmtimeEmbedder::new(embedder_config.clone(), no_op_logger());
    let wasm_executor = WasmExecutor::new(
        wasm_embedder,
        embedder_config.max_globals,
        embedder_config.max_functions,
        &metrics_registry,
    );

    hypervisor_execute(
        api_type,
        system_state,
        MAX_NUM_INSTRUCTIONS,
        NumBytes::from(4 << 30),
        NumBytes::from(0),
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        ComputeAllocation::default(),
        func_ref,
        execution_state,
        Arc::new(CyclesAccountManagerBuilder::new().build()),
        metrics,
        Arc::new(wasm_executor),
    )
    .wasm_result
}

#[test]
// Runs unexported name
fn test_method_not_found_error() {
    with_hypervisor(|hypervisor, tmp_path| {
        assert_eq!(
            execute_update(
                &hypervisor,
                "(module)",
                "test",
                EMPTY_PAYLOAD,
                None,
                tmp_path,
            )
            .2,
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
        let execution_state =
            ExecutionState::new(binary, tmp_path, WasmValidationLimits::default())
                .expect("initialize succeeds");

        let canister = canister_from_exec_state(execution_state);
        hypervisor
            .execute_canister_start(
                canister,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
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
                None,
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
                None,
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
                None,
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
            None,
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

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "write",
            EMPTY_PAYLOAD,
            None,
            tmp_path,
        );
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
            None,
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

        let (_, _, action, delta) = execute_update(
            &hypervisor,
            wasm_module,
            "write",
            EMPTY_PAYLOAD,
            None,
            tmp_path,
        );
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
                        ;; Grow the memory by 100,000 pages.
                        ;; This should fail since it's bigger than the maximum number of memory
                        ;; pages that can be allocated and return -1.
                        (if (i32.ne (call $stable_grow (i32.const 100000)) (i32.const -1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
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
                None,
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
                None,
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
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_read"
                        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))

                    (func $test
                        ;; Reading from stable memory with the maximum possible size.
                        ;; Ensure the function errors gracefully and doesn't panick due to overflow.
                        (call $stable_read (i32.const 0) (i32.const 1) (i32.const 4294967295))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
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
                None,
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
            execute_update(
                &hypervisor,
                r#"
                (module
                    (import "ic0" "stable_write"
                        (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

                    (func $test
                        ;; Writing to stable memory with the maximum possible size.
                        ;; Ensure the function errors gracefully and doesn't panick due to overflow.
                        (call $stable_write (i32.const 1) (i32.const 0) (i32.const 4294967295))
                    )

                    (memory 1)
                    (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
                    (export "canister_update test" (func $test)))"#,
                "test",
                EMPTY_PAYLOAD,
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
            execute_update(
                &hypervisor,
                MSG_CALLER_WAT,
                "update_test",
                EMPTY_PAYLOAD,
                Some(id.clone().get()),
                tmp_path.clone(),
            )
            .2,
            CallContextAction::Reply {
                payload: id.get().into_vec(),
                refund: Cycles::from(0),
            },
        );

        let id = canister_test_id(32);
        assert_eq!(
            execute_update(
                &hypervisor,
                MSG_CALLER_WAT,
                "update_test",
                EMPTY_PAYLOAD,
                Some(id.clone().get()),
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
        let execution_state =
            ExecutionState::new(wasm_binary, tmp_path, WasmValidationLimits::default()).unwrap();
        let _system_state = SystemStateBuilder::default().build();
        let canister = canister_from_exec_state(execution_state);
        let id = user_test_id(12);
        let (canister, _, result) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_test",
            &[],
            id.clone().get(),
            MAX_NUM_INSTRUCTIONS,
            canister,
            None,
            mock_time(),
        );
        assert_eq!(result, Ok(Some(WasmResult::Reply(id.get().into_vec()))));

        let id = canister_test_id(37);
        let (_, _, result) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_test",
            &[],
            id.clone().get(),
            MAX_NUM_INSTRUCTIONS,
            canister,
            None,
            mock_time(),
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
        let source = user_test_id(24);
        assert_eq!(
            execute_update(
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
                Some(source.get()),
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
            None,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("some_remote_method".to_string()),
                refund: Cycles::from(0),
            }
        );
        assert_eq!(canister.system_state.queues.output_queues_len(), 0);
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
            None,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: HypervisorError::CalledTrap("some_remote_method".to_string()),
                refund: Cycles::from(0),
            }
        );
        assert_eq!(canister.system_state.queues.output_queues_len(), 0);
    });
}

#[test]
fn test_call_add_cycles_deducts_cycles() {
    with_hypervisor(|hypervisor, tmp_path| {
        let (canister, instructions_left, action, _) = execute_update(
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
            None,
            tmp_path,
        );

        assert_eq!(action, CallContextAction::NotYetResponded);
        assert_eq!(canister.system_state.queues.output_queues_len(), 1);

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let instructions_executed = MAX_NUM_INSTRUCTIONS - instructions_left;
        let messaging_fee = cycles_account_manager.xnet_call_performed_fee()
            + cycles_account_manager
                .xnet_call_bytes_transmitted_fee(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES)
            + cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS);

        // Amount of cycles used to be transferred.
        let amount_cycles = Cycles::new(10_000_000_000);
        assert_balance_equals(
            INITIAL_CYCLES
                - amount_cycles
                - cycles_account_manager.execution_cost(instructions_executed)
                - messaging_fee,
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
            None,
            tmp_path,
        );

        assert_eq!(canister.system_state.queues.output_queues_len(), 0);

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
        let (canister, _, action, _) = execute_update(
            &hypervisor,
            MINT_CYCLES,
            "test",
            EMPTY_PAYLOAD,
            None,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Fail {
                error: ContractViolation("ic0.mint_cycles cannot be executed. Should only be called by a canister on the NNS subnet: {}".to_string()),
                refund: Cycles::from(0)
            }
        );

        assert_eq!(canister.system_state.queues.output_queues_len(), 0);

        //Not on NNS subnet -> balance remains unchanged
        assert_balance_equals(
            INITIAL_CYCLES,
            canister.system_state.cycles_balance,
            BALANCE_EPSILON,
        );
    });
}

#[test]
fn test_mint_cycles_nns_canister() {
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
            1,
            &metrics_registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        let (canister, _, _, _) = execute_update(
            &hypervisor,
            MINT_CYCLES,
            "test",
            EMPTY_PAYLOAD,
            None,
            tmpdir.path().into(),
        );

        assert_eq!(canister.system_state.queues.output_queues_len(), 0);
        assert_balance_equals(
            INITIAL_CYCLES + Cycles::new(10_000_000_000),
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
            None,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(canister.system_state.queues.output_queues_len(), 1);
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
            None,
            tmp_path,
        );

        assert_eq!(
            action,
            CallContextAction::Reply {
                payload: vec![],
                refund: Cycles::from(0),
            },
        );
        assert_eq!(canister.system_state.queues.output_queues_len(), 1);
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
                None,
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
            None,
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
            None,
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
                // this is not enough for 4 instructions
                NumInstructions::from(3),
                MEMORY_ALLOCATION,
                mock_time(),
                tmp_path,
            )
            .2,
            CallContextAction::Fail {
                error: HypervisorError::OutOfInstructions,
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
                MAX_NUM_INSTRUCTIONS,
                // Only 9 pages available
                ic_replicated_state::num_bytes_from(NumWasmPages::from(9)),
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
                None,
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
                None,
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
            1,
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
                None,
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

        if !cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            // Cow memory does not support absolute accessed pages
            // accounting.
            assert_eq!(
                fetch_histogram_stats(&registry, "hypervisor_accessed_pages"),
                Some(HistogramStats { sum: 2.0, count: 1 })
            );
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
            1,
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
            None,
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

        // Check a query method.
        let (_, num_instructions_left, res) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "foo",
            EMPTY_PAYLOAD.as_slice(),
            test_caller(),
            MAX_NUM_INSTRUCTIONS,
            canister,
            None,
            mock_time(),
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
        let execution_state = ExecutionState::new(
            wabt::wat2wasm(
                r#"
                        (module
                          (func (export "canister_init")
                            (drop (memory.grow (i32.const 1))))
                          (memory 1 2))
                        "#,
            )
            .unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();

        let canister = canister_from_exec_state(execution_state);
        hypervisor
            .execute_canister_init(
                canister,
                user_test_id(0).get(),
                &[],
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .2
            .unwrap();
    });
}

#[test]
fn memory_access_between_min_and_max_canister_start() {
    with_hypervisor(|hypervisor, tmp_path| {
        let execution_state = ExecutionState::new(
            wabt::wat2wasm(
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
            .unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();

        let canister = canister_from_exec_state(execution_state);
        assert_eq!(
            hypervisor
                .execute_canister_start(
                    canister,
                    MAX_NUM_INSTRUCTIONS,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                )
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
                None,
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
        let execution_state =
            ExecutionState::new(binary, tmp_path, WasmValidationLimits::default()).unwrap();

        let canister = canister_from_exec_state(execution_state);

        // Run the system method to increment the counter.
        let (canister, instructions, res) = match system_method {
            SystemMethod::CanisterPostUpgrade => hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterPreUpgrade => hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterInit => hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterStart => hypervisor.execute_canister_start(
                canister,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
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
            MAX_NUM_INSTRUCTIONS,
            canister,
            None,
            mock_time(),
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
        let execution_state =
            ExecutionState::new(binary, tmp_path, WasmValidationLimits::default()).unwrap();

        let canister = canister_from_exec_state(execution_state);

        let (_, _, routing_table, subnet_records) = setup();
        // Run the non-existing system method.
        let (_, cycles, res) = match system_method {
            SystemMethod::CanisterPostUpgrade => hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterPreUpgrade => hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterInit => hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterStart => hypervisor.execute_canister_start(
                canister,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            SystemMethod::CanisterInspectMessage => unimplemented!(),
            SystemMethod::Empty => unimplemented!(),
            SystemMethod::CanisterHeartbeat => hypervisor.execute_canister_heartbeat(
                canister,
                MAX_NUM_INSTRUCTIONS,
                routing_table,
                subnet_records,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

        let canister = canister_from_exec_state(
            ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default()).unwrap(),
        );

        let (canister, _, _) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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
        let execution_state = ExecutionState::new(
            wabt::wat2wasm(
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
            .unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();

        let canister = canister_from_exec_state(execution_state);

        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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
        let execution_state = ExecutionState::new(
            wabt::wat2wasm(
                r#"
                        (module
                          (func (export "canister_init")
                            ;; attempt to load page(1)[0;4] which should fail
                            (drop (i32.load (i32.const 65536))))
                          (memory 1 2))
                        "#,
            )
            .unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();

        let canister = canister_from_exec_state(execution_state);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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
        let execution_state = ExecutionState::new(
            wabt::wat2wasm(
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
            .unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();

        let canister = canister_from_exec_state(execution_state);
        let (_, _, res) = hypervisor.execute_canister_init(
            canister,
            test_caller(),
            EMPTY_PAYLOAD.as_slice(),
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

        let execution_state = ExecutionState::new(
            wabt::wat2wasm(wat).unwrap(),
            tmp_path,
            WasmValidationLimits::default(),
        )
        .unwrap();
        let canister = canister_from_exec_state(execution_state);

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
            canister.system_state.stable_memory_size,
            NumWasmPages::new(0)
        );
    });
}

#[test]
fn changes_to_stable_memory_in_canister_init_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            hypervisor.execute_canister_init(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
        },
    );
}

#[test]
fn changes_to_stable_memory_in_canister_pre_upgrade_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            hypervisor.execute_canister_pre_upgrade(
                canister,
                test_caller(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
        },
    )
}

#[test]
fn changes_to_stable_memory_in_canister_post_upgrade_are_rolled_back_on_failure() {
    test_stable_memory_is_rolled_back_on_failure(
        |hypervisor: &Hypervisor, canister: CanisterState| {
            hypervisor.execute_canister_post_upgrade(
                canister,
                test_caller(),
                EMPTY_PAYLOAD.as_slice(),
                MAX_NUM_INSTRUCTIONS,
                mock_time(),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
        },
    )
}

#[test]
fn cannot_execute_update_on_stopping_canister() {
    with_hypervisor(|hypervisor, _| {
        let canister = get_stopping_canister(canister_test_id(0));
        let (_, _, routing_table, subnet_records) = setup();

        assert_eq!(
            hypervisor
                .execute_update(
                    canister,
                    RequestOrIngress::Ingress(IngressBuilder::new().build()),
                    MAX_NUM_INSTRUCTIONS,
                    mock_time(),
                    routing_table,
                    subnet_records,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

        assert_eq!(
            hypervisor
                .execute_update(
                    canister,
                    RequestOrIngress::Ingress(IngressBuilder::new().build()),
                    MAX_NUM_INSTRUCTIONS,
                    mock_time(),
                    routing_table,
                    subnet_records,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    "query_test",
                    &[],
                    user_test_id(0).get(),
                    MAX_NUM_INSTRUCTIONS,
                    canister,
                    None,
                    mock_time(),
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

        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    "query_test",
                    &[],
                    user_test_id(0).get(),
                    MAX_NUM_INSTRUCTIONS,
                    canister,
                    None,
                    mock_time(),
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

        assert_eq!(
            hypervisor
                .execute_callback(
                    canister,
                    &CallOrigin::CanisterUpdate(canister_test_id(0), CallbackId::from(0)),
                    Callback::new(
                        call_context_test_id(0),
                        Cycles::from(0),
                        WasmClosure::new(0, 0),
                        WasmClosure::new(0, 0),
                        None
                    ),
                    Payload::Data(EMPTY_PAYLOAD),
                    Cycles::from(0),
                    MAX_NUM_INSTRUCTIONS,
                    mock_time(),
                    routing_table,
                    subnet_records,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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
        let (canister, num_instructions_left, action, _) = execute_update(
            &hypervisor,
            wat,
            "update_trap",
            EMPTY_PAYLOAD,
            None,
            tmp_path,
        );
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
            MAX_NUM_INSTRUCTIONS - NumInstructions::new(4)
        );

        // Check a query method.
        let (_, num_instructions_left, res) = hypervisor.execute_query(
            QueryExecutionType::Replicated,
            "query_trap",
            EMPTY_PAYLOAD.as_slice(),
            test_caller(),
            MAX_NUM_INSTRUCTIONS,
            canister,
            None,
            mock_time(),
        );
        assert_eq!(
            res,
            Err(HypervisorError::CalledTrap("Trap called!".to_string()))
        );
        // Check that ic0.trap call wasn't expensive
        assert_eq!(
            num_instructions_left,
            MAX_NUM_INSTRUCTIONS - NumInstructions::new(4)
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

        let execution_state = ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default())
            .expect("Failed to create execution state.");
        let canister = canister_from_exec_state(execution_state);
        let (_, _, routing_table, subnet_records) = setup();

        assert_eq!(
            hypervisor
                .execute_canister_heartbeat(
                    canister,
                    MAX_NUM_INSTRUCTIONS,
                    routing_table,
                    subnet_records,
                    mock_time(),
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
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

        let execution_state = ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default())
            .expect("Failed to create execution state.");
        let canister = canister_from_exec_state(execution_state);
        let (_, _, routing_table, subnet_records) = setup();

        let (_, _, result) = hypervisor.execute_canister_heartbeat(
            canister,
            MAX_NUM_INSTRUCTIONS,
            routing_table,
            subnet_records,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (*PAGE_SIZE) as u64);
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

        let execution_state = ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default())
            .expect("Failed to create execution state.");
        let canister = canister_from_exec_state(execution_state);
        let (_, _, routing_table, subnet_records) = setup();

        let message = RequestOrIngress::Ingress(
            IngressBuilder::new()
                .method_name("hello".to_string())
                .build(),
        );

        let (_, _, _, heap_delta) = hypervisor.execute_update(
            canister,
            message,
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            routing_table,
            subnet_records,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (*PAGE_SIZE) as u64);
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

        let execution_state = ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default())
            .expect("Failed to create execution state.");
        let canister = canister_from_exec_state(execution_state);

        let (_, _, result) = hypervisor.execute_canister_start(
            canister,
            MAX_NUM_INSTRUCTIONS,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (*PAGE_SIZE) as u64);
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

        let execution_state = ExecutionState::new(wasm, tmp_path, WasmValidationLimits::default())
            .expect("Failed to create execution state.");
        let canister = canister_from_exec_state(execution_state);

        let (_, _, result) = hypervisor.execute_canister_init(
            canister,
            user_test_id(0).get(),
            &[],
            MAX_NUM_INSTRUCTIONS,
            mock_time(),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let heap_delta = result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (*PAGE_SIZE) as u64);
    });
}
