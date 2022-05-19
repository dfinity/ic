use std::{collections::BTreeSet, convert::TryFrom, sync::Arc};

use assert_matches::assert_matches;
use candid::Encode;
use lazy_static::lazy_static;
use maplit::btreemap;
use tempfile::TempDir;

use ic_base_types::NumSeconds;
use ic_config::{execution_environment, subnet_config::CyclesAccountManagerConfig};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_execution_environment::{
    util::process_response, ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor,
    IngressHistoryWriterImpl,
};
use ic_ic00_types::{
    self as ic00, CanisterHttpRequestArgs, CanisterIdRecord, CanisterStatusResultV2, EmptyBlob,
    InstallCodeArgs, Method, Payload as Ic00Payload, IC_00,
};
use ic_ic00_types::{CanisterInstallMode, CanisterStatusType, EcdsaCurve, EcdsaKeyId, HttpMethod};
use ic_interfaces::execution_environment::{ExecResult, SubnetAvailableMemory};
use ic_interfaces::{
    execution_environment::{AvailableMemory, ExecuteMessageResult, ExecutionMode},
    messages::CanisterInputMessage,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::WASM_PAGE_SIZE_IN_BYTES, NetworkTopology, SubnetTopology,
};
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    testing::{CanisterQueuesTesting, ReplicatedStateTesting, SystemStateTesting},
    CallContextManager, CallOrigin, CanisterState, CanisterStatus, InputQueueType, ReplicatedState,
    SchedulerState, SystemState,
};
use ic_test_utilities::execution_environment::ExecutionEnvironmentBuilder;
use ic_test_utilities::{
    crypto::mock_random_number_generator,
    cycles_account_manager::CyclesAccountManagerBuilder,
    history::MockIngressHistory,
    metrics::{fetch_histogram_vec_count, metric_vec},
    mock_time,
    state::{
        get_running_canister, get_running_canister_with_args, get_running_canister_with_balance,
        get_stopped_canister, get_stopped_canister_with_controller, get_stopping_canister,
        running_canister_into_stopped, CanisterStateBuilder, ReplicatedStateBuilder,
        SystemStateBuilder,
    },
    types::{
        ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::{IngressBuilder, RequestBuilder, ResponseBuilder, SignedIngressBuilder},
    },
    with_test_replica_logger,
};
use ic_types::{
    canister_http::CanisterHttpMethod,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CallbackId, MessageId, Payload, RejectContext, RequestOrResponse, Response,
        StopCanisterContext, MAX_RESPONSE_COUNT_BYTES,
    },
    methods::{Callback, WasmClosure},
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, QueueIndex, RegistryVersion, SubnetId, Time,
};

pub mod hypervisor;

const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);
lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}
const MAX_NUMBER_OF_CANISTERS: u64 = 0;

fn initial_state(
    subnet_type: SubnetType,
) -> (TempDir, SubnetId, Arc<NetworkTopology>, ReplicatedState) {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    let subnet_id = subnet_test_id(1);
    let routing_table = Arc::new(
        RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        })
        .unwrap(),
    );
    let mut replicated_state = ReplicatedState::new_rooted_at(
        subnet_id,
        SubnetType::Application,
        tmpdir.path().to_path_buf(),
    );
    replicated_state.metadata.network_topology.routing_table = Arc::clone(&routing_table);
    replicated_state.metadata.network_topology.subnets.insert(
        subnet_id,
        SubnetTopology {
            subnet_type,
            ..SubnetTopology::default()
        },
    );
    (
        tmpdir,
        subnet_id,
        Arc::new(replicated_state.metadata.network_topology.clone()),
        replicated_state,
    )
}

pub fn with_setup<F>(subnet_type: SubnetType, f: F)
where
    F: FnOnce(ExecutionEnvironmentImpl, ReplicatedState, SubnetId, Arc<NetworkTopology>),
{
    with_test_replica_logger(|log| {
        let (_, subnet_id, network_topology, state) = initial_state(subnet_type);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = IngressHistoryWriterImpl::new(
            execution_environment::Config::default(),
            log.clone(),
            &metrics_registry,
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            log,
            hypervisor,
            ingress_history_writer,
            &metrics_registry,
            subnet_id,
            subnet_type,
            1,
            execution_environment::Config::default(),
            cycles_account_manager,
        );
        f(exec_env, state, subnet_id, network_topology)
    });
}

fn test_outgoing_messages(
    system_state: SystemState,
    wat: &str,
    test: impl FnOnce(ExecuteMessageResult<CanisterState>),
) {
    let subnet_type = SubnetType::Application;
    with_test_replica_logger(|log| {
        let (_, subnet_id, network_topology, _) = initial_state(subnet_type);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);

        let ingress_history_writer = MockIngressHistory::new();
        let ingress_history_writer = Arc::new(ingress_history_writer);

        let exec_env = ExecutionEnvironmentImpl::new(
            log,
            Arc::clone(&hypervisor) as Arc<_>,
            ingress_history_writer,
            &metrics_registry,
            subnet_id,
            subnet_type,
            1,
            execution_environment::Config::default(),
            cycles_account_manager,
        );
        let wasm_binary = wabt::wat2wasm(wat).unwrap();
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let execution_state = hypervisor
            .create_execution_state(
                wasm_binary,
                tmpdir.path().to_path_buf(),
                system_state.canister_id,
            )
            .unwrap();
        let mut canister = CanisterState {
            system_state,
            execution_state: Some(execution_state),
            scheduler_state: SchedulerState::default(),
        };

        let input_message = canister.system_state.queues_mut().pop_input().unwrap();
        let res = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            input_message,
            mock_time(),
            network_topology,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let res = process_response(res);

        test(res);
    });
}

// A Wasm module calling call_simple
const CALL_SIMPLE_WAT: &str = r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                      (param i32 i32)
                      (param $method_name_src i32)    (param $method_name_len i32)
                      (param $reply_fun i32)          (param $reply_env i32)
                      (param $reject_fun i32)         (param $reject_env i32)
                  ))
                  (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
                  (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
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
                    (call $ic0_call_cycles_add
                        (i64.const 100)
                    )
                    (call $ic0_call_perform)
                    drop)
                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\00\00\00\00\00\00\03\09\01\01")
            )"#;

// A Wasm module calling call_simple and replying
const CALL_SIMPLE_AND_REPLY_WAT: &str = r#"(module
                  (import "ic0" "call_simple"
                    (func $ic0_call_simple
                        (param i32 i32)
                        (param $method_name_src i32)    (param $method_name_len i32)
                        (param $reply_fun i32)          (param $reply_env i32)
                        (param $reject_fun i32)         (param $reject_env i32)
                        (param $data_src i32)           (param $data_len i32)
                        (result i32)))
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32) (param i32)))
                  (func $test
                    (call $ic0_call_simple
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                        (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                        )
                    drop
                    (call $msg_reply_data_append
                        (i32.const 23) (i32.const 8))    ;; refers to "MONOLORD"
                    (call $msg_reply))
                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ MONOLORD")
                  (data (i32.const 100) "\00\00\00\00\00\00\03\09\01\01")
            )"#;

// A Wasm module calling reject
const REJECT_WAT: &str = r#"(module
                  (import "ic0" "msg_reject"
                    (func $reject (param i32) (param i32)))
                  (func $test
                    (call $reject
                        (i32.const 23) (i32.const 8)    ;; refers to "MONOLORD"
                    ))
                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ MONOLORD")
            )"#;

// Calls reject in the callback 0
const REJECT_IN_CALLBACK_WAT: &str = r#"(module
           (import "ic0" "msg_reject"
             (func $reject (param i32 i32)))
           (func $test (param i32)
             (call $reject
                 (i32.const 0) (i32.const 5)))
           (table funcref (elem $test))
           (memory $memory 1)
           (export "memory" (memory $memory))
           (data (i32.const 0) "error"))"#;

fn wat_canister_id() -> CanisterId {
    canister_test_id(777)
}

fn inject_ingress(system_state: &mut SystemState) {
    let msg = IngressBuilder::default()
        .source(user_test_id(2))
        .receiver(canister_test_id(42))
        .method_name("test".to_string())
        .message_id(message_test_id(555))
        .build();
    system_state.queues_mut().push_ingress(msg);
}

fn inject_request(system_state: &mut SystemState) {
    let msg = RequestBuilder::default()
        .receiver(canister_test_id(42))
        .sender(canister_test_id(55))
        .method_name("test".to_string())
        .sender_reply_callback(CallbackId::from(999))
        .build()
        .into();
    system_state
        .queues_mut()
        .push_input(QueueIndex::from(0), msg, InputQueueType::RemoteSubnet)
        .unwrap();
}

fn inject_response(system_state: &mut SystemState, cb_id: CallbackId) {
    let current_canister = system_state.canister_id();
    let partner_canister = canister_test_id(55);
    let request = RequestBuilder::default()
        .sender(current_canister)
        .receiver(partner_canister)
        .build();
    let response = ResponseBuilder::default()
        .originator(current_canister)
        .respondent(partner_canister)
        .originator_reply_callback(cb_id)
        .response_payload(Payload::Data(vec![]))
        .build()
        .into();
    system_state.push_output_request(request).unwrap();
    system_state
        .queues_mut()
        .push_input(QueueIndex::from(0), response, InputQueueType::RemoteSubnet)
        .unwrap();
}

fn assert_correct_request(system_state: &mut SystemState) {
    let dst = wat_canister_id();
    let (_, message) = system_state.queues_mut().pop_canister_output(&dst).unwrap();
    if let RequestOrResponse::Request(msg) = message {
        assert_eq!(msg.receiver, dst);
        assert_eq!(msg.sender, canister_test_id(42));
        assert_eq!(msg.method_name, "some_remote_method");
        assert_eq!(msg.method_payload, b"XYZ");
    } else {
        panic!("unexpected message popped: {:?}", message);
    }
}

#[test]
// Canister gets an ingress message, produces one outgoing request
fn test_ingress_message_side_effects_1() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_ingress(&mut system_state);
    test_outgoing_messages(
        system_state,
        CALL_SIMPLE_WAT,
        |mut execute_message_result| {
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_queues_len(),
                1
            );
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count(),
                1
            );
            assert_correct_request(&mut execute_message_result.canister.system_state);
        },
    );
}

#[test]
// Canister gets an ingress message, produces one outgoing request and replies
fn test_ingress_message_side_effects_2() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_ingress(&mut system_state);
    test_outgoing_messages(
        system_state,
        CALL_SIMPLE_AND_REPLY_WAT,
        |execute_message_result| {
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_queues_len(),
                1
            );
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count(),
                1
            );
            let status = match execute_message_result.result {
                ExecResult::IngressResult((_, status)) => status,
                _ => panic!("Unexpected result variant"),
            };
            assert_eq!(
                status,
                IngressStatus::Known {
                    receiver: canister_test_id(42).get(),
                    user_id: user_test_id(2),
                    time: mock_time(),
                    state: IngressState::Completed(WasmResult::Reply(b"MONOLORD".to_vec())),
                }
            );
        },
    );
}

#[test]
// Canister gets a request message and rejects it
fn test_ingress_message_side_effects_3() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_ingress(&mut system_state);
    test_outgoing_messages(system_state, REJECT_WAT, |execute_message_result| {
        assert_eq!(
            execute_message_result
                .canister
                .system_state
                .queues()
                .output_queues_len(),
            0
        );
        assert_eq!(
            execute_message_result
                .canister
                .system_state
                .queues()
                .output_message_count(),
            0
        );
        let status = match execute_message_result.result {
            ExecResult::IngressResult((_, status)) => status,
            _ => panic!("Unexpected result variant"),
        };
        assert_eq!(
            status,
            IngressStatus::Known {
                receiver: canister_test_id(42).get(),
                user_id: user_test_id(2),
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reject("MONOLORD".to_string())),
            }
        );
    });
}

#[test]
/// Output requests can be enqueued on system subnets, irrespective of memory limits.
fn test_allocate_memory_for_output_request_system_subnet() {
    with_setup(SubnetType::System, |exec_env, _, _, network_topology| {
        // Canister enqueues an outgoing request when its `test()` method is called.
        let wasm_binary = wabt::wat2wasm(CALL_SIMPLE_WAT).unwrap();
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let system_state = SystemStateBuilder::default()
            .freeze_threshold(NumSeconds::from(0))
            .build();

        let execution_state = exec_env
            .hypervisor_for_testing()
            .create_execution_state(
                wasm_binary,
                tmpdir.path().to_path_buf(),
                system_state.canister_id(),
            )
            .unwrap();

        let mut canister = CanisterState {
            system_state,
            execution_state: Some(execution_state),
            scheduler_state: SchedulerState::default(),
        };

        let input_message = CanisterInputMessage::Ingress(
            IngressBuilder::default()
                .method_name("test".to_string())
                .build(),
        );

        let subnet_available_memory: SubnetAvailableMemory = AvailableMemory::new(13, 13).into();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::new(13)).unwrap();
        let execute_message_result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            input_message,
            mock_time(),
            network_topology,
            subnet_available_memory.clone(),
        );
        let execute_message_result = process_response(execute_message_result);
        canister = execute_message_result.canister;
        // There should be one reserved slot in the queues.
        assert_eq!(1, canister.system_state.queues().reserved_slots());
        // Subnet available memory should have remained the same.
        assert_eq!(13, subnet_available_memory.get_total_memory());
        assert_eq!(13, subnet_available_memory.get_message_memory());
        // And the expected request should be enqueued.
        assert_correct_request(&mut canister.system_state);
    });
}

#[test]
/// Output requests use up canister and subnet memory and can't be enqueued if
/// any of them is above the limit.
fn test_allocate_memory_for_output_requests() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, network_topology| {
            // Canister enqueues an outgoing request when its `test()` method is called.
            let wasm_binary = wabt::wat2wasm(CALL_SIMPLE_WAT).unwrap();
            let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

            let system_state = SystemStateBuilder::default()
                .freeze_threshold(NumSeconds::from(0))
                .build();

            let execution_state = exec_env
                .hypervisor_for_testing()
                .create_execution_state(
                    wasm_binary,
                    tmpdir.path().to_path_buf(),
                    system_state.canister_id(),
                )
                .unwrap();

            let mut canister = CanisterState {
                system_state,
                execution_state: Some(execution_state),
                scheduler_state: SchedulerState::default(),
            };

            let input_message = CanisterInputMessage::Ingress(
                IngressBuilder::default()
                    .method_name("test".to_string())
                    .build(),
            );

            // Tiny canister memory allocation prevents enqueuing an output request.
            let subnet_available_memory: SubnetAvailableMemory =
                AvailableMemory::new(1 << 30, 1 << 30).into();
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(13)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message.clone(),
                mock_time(),
                network_topology.clone(),
                subnet_available_memory.clone(),
            );
            let execute_message_result = process_response(execute_message_result);
            canister = execute_message_result.canister;
            assert_eq!(1 << 30, subnet_available_memory.get_total_memory());
            assert_eq!(1 << 30, subnet_available_memory.get_message_memory());
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                assert!(!canister.system_state.queues().has_output());
            } else {
                assert_eq!(1, canister.system_state.queues().reserved_slots());
                assert_correct_request(&mut canister.system_state);
            }

            // Tiny `SubnetAvailableMemory` also prevents enqueuing an output request.
            let subnet_available_memory: SubnetAvailableMemory =
                AvailableMemory::new(13, 1 << 30).into();
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message.clone(),
                mock_time(),
                network_topology.clone(),
                subnet_available_memory.clone(),
            );
            let execute_message_result = process_response(execute_message_result);
            canister = execute_message_result.canister;
            assert_eq!(13, subnet_available_memory.get_total_memory());
            assert_eq!(1 << 30, subnet_available_memory.get_message_memory());
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                assert!(!canister.system_state.queues().has_output());
            } else {
                assert_eq!(2, canister.system_state.queues().reserved_slots());
                assert_correct_request(&mut canister.system_state);
            }

            // Tiny `SubnetAvailableMessageMemory` also prevents enqueuing an output request.
            let subnet_available_memory: SubnetAvailableMemory =
                AvailableMemory::new(1 << 30, 13).into();
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message.clone(),
                mock_time(),
                network_topology.clone(),
                subnet_available_memory.clone(),
            );
            let execute_message_result = process_response(execute_message_result);
            canister = execute_message_result.canister;
            assert_eq!(1 << 30, subnet_available_memory.get_total_memory());
            assert_eq!(13, subnet_available_memory.get_message_memory());
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                assert!(!canister.system_state.queues().has_output());
            } else {
                assert_eq!(3, canister.system_state.queues().reserved_slots());
                assert_correct_request(&mut canister.system_state);
            }

            // But large enough canister memory allocation and `SubnetAvailableMemory` allow
            // enqueuing an outgoing request.
            let subnet_available_memory: SubnetAvailableMemory =
                AvailableMemory::new(1 << 30, 1 << 30).into();
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message,
                mock_time(),
                network_topology,
                subnet_available_memory.clone(),
            );
            let execute_message_result = process_response(execute_message_result);
            canister = execute_message_result.canister;
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                // There should be one reserved slot in the queues.
                assert_eq!(1, canister.system_state.queues().reserved_slots());
                // Subnet available memory should have decreased by `MAX_RESPONSE_COUNT_BYTES`.
                assert_eq!(
                    (1 << 30) - MAX_RESPONSE_COUNT_BYTES as i64,
                    subnet_available_memory.get_total_memory()
                );
                assert_eq!(
                    (1 << 30) - MAX_RESPONSE_COUNT_BYTES as i64,
                    subnet_available_memory.get_message_memory()
                )
            } else {
                assert_eq!(4, canister.system_state.queues().reserved_slots());
                assert_eq!(1 << 30, subnet_available_memory.get_total_memory());
                assert_eq!(1 << 30, subnet_available_memory.get_message_memory());
            }
            // And the expected request should be enqueued.
            assert_correct_request(&mut canister.system_state);
        },
    );
}

#[test]
// Canister gets a request message and produces one outgoing request
fn test_request_message_side_effects_1() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_request(&mut system_state);
    test_outgoing_messages(
        system_state,
        CALL_SIMPLE_WAT,
        |mut execute_message_result| {
            // The extra queue is the empty queue created due to the inter-canister request
            // generated by the Canister.
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_queues_len(),
                2
            );
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count(),
                1
            );
            assert_correct_request(&mut execute_message_result.canister.system_state);
        },
    );
}

#[test]
// Canister gets a request message, produces one outgoing request and replies
fn test_request_message_side_effects_2() {
    let canister_id = canister_test_id(42);
    let mut system_state = SystemStateBuilder::default()
        .canister_id(canister_id)
        .build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_request(&mut system_state);
    test_outgoing_messages(
        system_state,
        CALL_SIMPLE_AND_REPLY_WAT,
        |mut execute_message_result| {
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_queues_len(),
                2
            );
            assert_eq!(
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count(),
                2
            );
            assert_correct_request(&mut execute_message_result.canister.system_state);
            let dst = canister_test_id(55);
            let (_, message) = execute_message_result
                .canister
                .system_state
                .queues_mut()
                .pop_canister_output(&dst)
                .unwrap();
            if let RequestOrResponse::Response(msg) = message {
                assert_eq!(msg.originator, dst);
                assert_eq!(msg.respondent, canister_id);
                assert_eq!(msg.response_payload, Payload::Data(b"MONOLORD".to_vec()));
            } else {
                panic!("unexpected message popped: {:?}", message);
            }
        },
    );
}

#[test]
// Canister gets a request message and rejects it
fn test_request_message_side_effects_3() {
    let canister_id = canister_test_id(42);
    let mut system_state = SystemStateBuilder::default()
        .canister_id(canister_id)
        .build();
    system_state.freeze_threshold = NumSeconds::from(0);
    inject_request(&mut system_state);
    test_outgoing_messages(system_state, REJECT_WAT, |mut execute_message_result| {
        assert_eq!(
            execute_message_result
                .canister
                .system_state
                .queues()
                .output_queues_len(),
            1
        );
        assert_eq!(
            execute_message_result
                .canister
                .system_state
                .queues()
                .output_message_count(),
            1
        );
        let dst = canister_test_id(55);
        let (_, message) = execute_message_result
            .canister
            .system_state
            .queues_mut()
            .pop_canister_output(&dst)
            .unwrap();
        if let RequestOrResponse::Response(msg) = message {
            assert_eq!(msg.originator, dst);
            assert_eq!(msg.respondent, canister_id);
            assert_eq!(
                msg.response_payload,
                Payload::Reject(RejectContext {
                    code: RejectCode::CanisterReject,
                    message: "MONOLORD".to_string()
                })
            );
        } else {
            panic!("unexpected message popped: {:?}", message);
        }
    });
}

#[test]
// Canister gets a response message and calls a callback, which rejects the call
// context
fn test_response_message_side_effects_1() {
    let canister_id = canister_test_id(42);
    let mut system_state = SystemStateBuilder::default()
        .canister_id(canister_id)
        .build();
    let origin_id = canister_test_id(33);
    let origin_cb_id = CallbackId::from(5);
    let call_context_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(origin_id, origin_cb_id),
            Cycles::from(50),
            Time::from_nanos_since_unix_epoch(0),
        );
    let callback_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .register_callback(Callback::new(
            call_context_id,
            Some(origin_id),
            Some(canister_id),
            Cycles::from(0),
            WasmClosure::new(0, 2),
            WasmClosure::new(0, 2),
            None,
        ));
    assert_eq!(
        system_state
            .call_context_manager_mut()
            .unwrap()
            .call_origin(call_context_id)
            .unwrap(),
        CallOrigin::CanisterUpdate(origin_id, origin_cb_id)
    );

    // Make a reservation for the response that the canister will produce
    // for canister 33 when it executes the message above.
    let req = RequestBuilder::default()
        .receiver(canister_id)
        .sender(origin_id)
        .method_name("test".to_string())
        .sender_reply_callback(CallbackId::from(999))
        .build()
        .into();
    system_state
        .queues_mut()
        .push_input(QueueIndex::from(0), req, InputQueueType::RemoteSubnet)
        .unwrap();
    system_state.queues_mut().pop_input().unwrap();

    inject_response(&mut system_state, callback_id);
    test_outgoing_messages(
        system_state,
        REJECT_IN_CALLBACK_WAT,
        |mut execute_message_result| {
            // There should be two messages in the output queues.
            assert_eq!(
                2,
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count()
            );
            assert_eq!(
                2,
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count()
            );
            let dst = origin_id;
            let (_, message) = execute_message_result
                .canister
                .system_state
                .queues_mut()
                .pop_canister_output(&dst)
                .unwrap();
            if let RequestOrResponse::Response(msg) = message {
                assert_eq!(msg.originator, dst);
                assert_eq!(msg.respondent, canister_id);
                assert_eq!(
                    msg.response_payload,
                    Payload::Reject(RejectContext {
                        code: RejectCode::CanisterReject,
                        message: "error".to_string()
                    })
                );
            } else {
                panic!("unexpected message popped: {:?}", message);
            }
        },
    );
}

#[test]
// tests that a canister traps on a reject of an already responded context and
// no outgoing message as a reply is generated anymore
fn test_repeated_response() {
    let canister_id = canister_test_id(42);
    let mut system_state = SystemStateBuilder::default()
        .canister_id(canister_id)
        .build();
    let call_context_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(888)),
            Cycles::from(42),
            Time::from_nanos_since_unix_epoch(0),
        );
    let callback_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .register_callback(Callback::new(
            call_context_id,
            Some(canister_test_id(33)),
            Some(canister_id),
            Cycles::from(0),
            WasmClosure::new(0, 2),
            WasmClosure::new(0, 2),
            None,
        ));
    // mark this call context as responded
    system_state
        .call_context_manager_mut()
        .unwrap()
        .on_canister_result(call_context_id, Ok(Some(WasmResult::Reply(vec![]))));

    inject_response(&mut system_state, callback_id);
    test_outgoing_messages(
        system_state,
        REJECT_IN_CALLBACK_WAT,
        |execute_message_result| {
            // There should be just one message in the output queue.
            assert_eq!(
                1,
                execute_message_result
                    .canister
                    .system_state
                    .queues()
                    .output_message_count()
            );
        },
    );
}

#[test]
fn stopping_canister_rejects_requests() {
    with_setup(
        SubnetType::Application,
        |exec_env, mut state, _, routing_table| {
            // Since we can't enqueue a request into a stopping canister, create a canister
            // that is running and enqueue the request in it.
            let mut canister = get_running_canister(canister_test_id(0));

            let cycles = Cycles::from(40);
            let req = RequestBuilder::new()
                .sender(canister_test_id(13))
                .payment(cycles)
                .build();
            let reply_callback = req.sender_reply_callback;
            canister
                .system_state
                .queues_mut()
                .push_input(
                    QueueIndex::from(0),
                    RequestOrResponse::Request(req),
                    InputQueueType::RemoteSubnet,
                )
                .unwrap();

            state.put_canister_state(canister);

            // Transition the canister into the stopping state.
            let payload = Encode!(&CanisterIdRecord::from(canister_test_id(0))).unwrap();
            let mut state = exec_env
                .execute_subnet_message(
                    CanisterInputMessage::Ingress(
                        IngressBuilder::new()
                            .source(user_test_id(1))
                            .method_payload(payload)
                            .method_name(Method::StopCanister)
                            .build(),
                    ),
                    state,
                    MAX_NUM_INSTRUCTIONS,
                    &mut mock_random_number_generator(),
                    &None,
                    &ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    MAX_NUMBER_OF_CANISTERS,
                )
                .0;

            let mut canister = state.take_canister_state(&canister_test_id(0)).unwrap();

            assert_eq!(
                canister.system_state.status,
                CanisterStatus::Stopping {
                    stop_contexts: vec![StopCanisterContext::Ingress {
                        sender: user_test_id(1),
                        message_id: message_test_id(0),
                    }],
                    call_context_manager: CallContextManager::default(),
                }
            );

            let msg = canister.pop_input().unwrap();
            let canister_id = canister.canister_id();
            let result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                msg,
                mock_time(),
                routing_table,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
            let mut result = process_response(result);
            assert_eq!(
                result
                    .canister
                    .system_state
                    .queues_mut()
                    .pop_canister_output(&canister_test_id(13))
                    .unwrap()
                    .1,
                RequestOrResponse::Response(Response {
                    originator: canister_test_id(13),
                    respondent: canister_test_id(0),
                    originator_reply_callback: reply_callback,
                    refund: cycles,
                    response_payload: Payload::Reject(RejectContext {
                        code: RejectCode::CanisterError,
                        message: format!("IC0509: Canister {} is not running", canister_id),
                    }),
                })
            );
        },
    );
}

#[test]
fn stopping_canister_rejects_ingress() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        let canister = get_stopping_canister(canister_test_id(0));
        let ingress = IngressBuilder::new().build();

        let execute_message_result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            CanisterInputMessage::Ingress(ingress),
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let status = match execute_message_result.result {
            ExecResult::IngressResult((_, status)) => status,
            _ => panic!("Unexpected result variant"),
        };
        assert_eq!(
            status,
            IngressStatus::Known {
                receiver: canister_test_id(0).get(),
                user_id: user_test_id(2),
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterStopping,
                    format!("Canister {} is not running", canister_test_id(0)),
                )),
            },
        );
    })
}

#[test]
fn stopped_canister_rejects_requests() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        // Since we can't enqueue a request into a stopped canister, create a canister
        // that is running and enqueue the request in it.
        let mut canister = get_running_canister(canister_test_id(0));

        let cycles = 30;
        let req = RequestBuilder::new()
            .sender(canister_test_id(13))
            .payment(Cycles::from(cycles))
            .build();
        let reply_callback = req.sender_reply_callback;
        canister
            .system_state
            .queues_mut()
            .push_input(
                QueueIndex::from(0),
                RequestOrResponse::Request(req),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        // Stop the canister. Here we manually stop the canister as opposed
        // to the proper way sending a stop_canister request to exec_env. That way, we
        // get the canister into a state where it is stopped and has requests in its
        // input queue.
        let mut canister = running_canister_into_stopped(canister);

        let msg = canister.pop_input().unwrap();
        let canister_id = canister.canister_id();
        let result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            msg,
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let mut result = process_response(result);
        assert_eq!(
            result
                .canister
                .system_state
                .queues_mut()
                .pop_canister_output(&canister_test_id(13))
                .unwrap()
                .1,
            RequestOrResponse::Response(Response {
                originator: canister_test_id(13),
                respondent: canister_test_id(0),
                originator_reply_callback: reply_callback,
                refund: Cycles::from(cycles),
                response_payload: Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: format!("IC0508: Canister {} is not running", canister_id),
                }),
            })
        );
    });
}

#[test]
fn stopped_canister_rejects_ingress() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        let canister = get_stopped_canister(canister_test_id(0));
        let ingress = IngressBuilder::new().build();
        let result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            CanisterInputMessage::Ingress(ingress),
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );

        let status = match result.result {
            ExecResult::IngressResult((_, status)) => status,
            _ => panic!("Unexpected result variant"),
        };
        assert_eq!(
            status,
            IngressStatus::Known {
                receiver: canister_test_id(0).get(),
                user_id: user_test_id(2),
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterStopped,
                    format!("Canister {} is not running", canister_test_id(0)),
                )),
            }
        );
    });
}

#[test]
fn execute_stop_canister_updates_ingress_history_when_called_on_already_stopped_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let canister = get_stopped_canister(canister_test_id(0));
        state.put_canister_state(canister);

        let payload = Encode!(&CanisterIdRecord::from(canister_test_id(0))).unwrap();
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .source(user_test_id(1))
                        .method_payload(payload)
                        .method_name(Method::StopCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Verify that a response to the message has been written to ingress history.
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: canister_test_id(0).get(),
                user_id: user_test_id(1),
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(EmptyBlob::encode())),
            }
        );
    });
}

#[test]
fn execute_stop_canister_does_not_update_ingress_history_when_called_on_running_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let canister = get_stopping_canister(canister_test_id(0));
        state.put_canister_state(canister);

        let payload = Encode!(&CanisterIdRecord::from(canister_test_id(0))).unwrap();
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .source(user_test_id(1))
                        .method_payload(payload)
                        .method_name(Method::StopCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Unknown
        );
    });
}

#[test]
fn execute_stop_canister_does_not_update_ingress_history_when_called_on_stopping_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let canister = get_stopping_canister(canister_test_id(0));
        state.put_canister_state(canister);

        let payload = Encode!(&CanisterIdRecord::from(canister_test_id(0))).unwrap();
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .source(user_test_id(1))
                        .method_payload(payload)
                        .method_name(Method::StopCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Verify that no response has been written to ingress history.
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Unknown
        );
    });
}

#[test]
fn execute_stop_canister_writes_failure_to_ingress_history_when_called_with_incorrect_controller() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let canister = get_running_canister(canister_test_id(0));
        state.put_canister_state(canister);

        let payload = Encode!(&CanisterIdRecord::from(canister_test_id(0))).unwrap();
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .source(user_test_id(13))
                        .receiver(CanisterId::ic_00())
                        .method_payload(payload)
                        .method_name(Method::StopCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Verify that the response has been written to ingress history.
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Known {
                receiver: CanisterId::ic_00().get(),
                user_id: user_test_id(13),
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Only the controllers of the canister {} can control it.\n\
                        Canister's controllers: {}\n\
                        Sender's ID: {}",
                        canister_test_id(0),
                        user_test_id(1).get(),
                        user_test_id(13).get()
                    )
                )),
            }
        );
    });
}

fn test_canister_status_helper(
    canister: CanisterState,
    expected_status_result: CanisterStatusResultV2,
) {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let controller_id = canister.system_state.controllers.iter().next().unwrap();
        let controller = CanisterId::new(*controller_id).unwrap();
        let canister_id = canister.canister_id();
        let subnet_id = subnet_test_id(1);
        let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        let cycles = 100;

        state.put_canister_state(canister);

        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(controller)
                        .receiver(CanisterId::from(subnet_id))
                        .method_name(Method::CanisterStatus)
                        .method_payload(payload)
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        if let RequestOrResponse::Response(resp) = state
            .subnet_queues_mut()
            .pop_canister_output(&controller)
            .unwrap()
            .1
        {
            if let Payload::Data(payload) = resp.response_payload {
                assert_eq!(
                    CanisterStatusResultV2::decode(&payload).unwrap(),
                    expected_status_result
                );
            } else {
                panic!("invalid payload");
            }
        } else {
            panic!("No response found");
        }
    });
}

fn test_request_nonexistent_canister(method: Method) {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let controller = canister_test_id(1);
        let canister_id = canister_test_id(0);
        let cycles = 42;

        let subnet_id = subnet_test_id(1);
        let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(controller)
                        .receiver(CanisterId::from(subnet_id))
                        .method_name(method)
                        .method_payload(payload)
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state
                .subnet_queues_mut()
                .pop_canister_output(&controller)
                .unwrap()
                .1,
            RequestOrResponse::Response(
                ResponseBuilder::new()
                    .originator(controller)
                    .respondent(CanisterId::new(subnet_id.get()).unwrap())
                    .response_payload(Payload::Reject(RejectContext {
                        code: RejectCode::DestinationInvalid,
                        message: format!("Canister {} not found.", &canister_id)
                    }))
                    .refund(Cycles::from(cycles))
                    .build()
            )
        );
    });
}

#[test]
fn get_running_canister_status_from_another_canister() {
    let memory_allocation = NumBytes::new(1 << 30);
    let expected_idle_cycles_burned_per_second = Cycles::new(127000);
    test_canister_status(memory_allocation, expected_idle_cycles_burned_per_second);
}

#[test]
fn get_canister_status_from_another_canister_when_memory_low() {
    let memory_allocation = NumBytes::new(150);
    let expected_idle_cycles_burned_per_second = Cycles::new(1);
    test_canister_status(memory_allocation, expected_idle_cycles_burned_per_second);
}

fn test_canister_status(memory_allocation: NumBytes, expected_idle_cycles_burned: Cycles) {
    let controller = canister_test_id(1);
    let freezing_threshold = 123;
    let canister = CanisterStateBuilder::new()
        .with_status(CanisterStatusType::Running)
        .with_controller(controller)
        .with_cycles(INITIAL_CYCLES)
        .with_freezing_threshold(freezing_threshold)
        .with_memory_allocation(memory_allocation)
        .build();

    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let idle_cycles_burned_per_second = cycles_account_manager.idle_cycles_burned_rate(
        MemoryAllocation::BestEffort,
        memory_allocation,
        ComputeAllocation::zero(),
    );

    assert_eq!(idle_cycles_burned_per_second, expected_idle_cycles_burned);
    test_canister_status_helper(
        canister,
        CanisterStatusResultV2::new(
            CanisterStatusType::Running,
            None,
            controller.get(),
            vec![controller.get()],
            NumBytes::from(0),
            INITIAL_CYCLES.get(),
            ComputeAllocation::default().as_percent(),
            Some(memory_allocation.get()),
            freezing_threshold,
            idle_cycles_burned_per_second.get(),
        ),
    )
}

#[test]
fn get_stopped_canister_status_from_another_canister() {
    let controller = canister_test_id(1);
    let canister = CanisterStateBuilder::new()
        .with_status(CanisterStatusType::Stopped)
        .with_controller(controller)
        .with_freezing_threshold(123)
        .build();
    test_canister_status_helper(
        canister,
        CanisterStatusResultV2::new(
            CanisterStatusType::Stopped,
            None,
            controller.get(),
            vec![controller.get()],
            NumBytes::from(0),
            INITIAL_CYCLES.get(),
            ComputeAllocation::default().as_percent(),
            None,
            123,
            0,
        ),
    );
}

#[test]
fn get_stopping_canister_status_from_another_canister() {
    let controller = canister_test_id(1);
    let canister = CanisterStateBuilder::new()
        .with_status(CanisterStatusType::Stopping)
        .with_controller(controller)
        .with_freezing_threshold(123)
        .build();
    test_canister_status_helper(
        canister,
        CanisterStatusResultV2::new(
            CanisterStatusType::Stopping,
            None,
            controller.get(),
            vec![controller.get()],
            NumBytes::from(0),
            INITIAL_CYCLES.get(),
            ComputeAllocation::default().as_percent(),
            None,
            123,
            0,
        ),
    );
}

#[test]
fn start_a_non_existing_canister() {
    test_request_nonexistent_canister(Method::StartCanister);
}

#[test]
fn get_canister_status_of_nonexisting_canister() {
    test_request_nonexistent_canister(Method::CanisterStatus);
}

#[test]
fn deposit_cycles_to_non_existing_canister_fails() {
    test_request_nonexistent_canister(Method::DepositCycles);
}

#[test]
fn start_canister_from_another_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let controller = canister_test_id(1);
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister_with_controller(canister_id, *controller.get_ref());
        let cycles = 42;

        // Sanity check that the canister is stopped.
        assert_eq!(canister.status(), CanisterStatusType::Stopped);

        let subnet_id = subnet_test_id(1);
        state.put_canister_state(canister);

        let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(controller)
                        .receiver(CanisterId::from(subnet_id))
                        .method_name(Method::StartCanister)
                        .method_payload(payload)
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state
                .subnet_queues_mut()
                .pop_canister_output(&controller)
                .unwrap()
                .1,
            RequestOrResponse::Response(
                ResponseBuilder::new()
                    .originator(controller)
                    .respondent(CanisterId::new(subnet_id.get()).unwrap())
                    .response_payload(Payload::Data(EmptyBlob::encode()))
                    .refund(Cycles::from(cycles))
                    .build()
            )
        );

        assert_eq!(
            state.take_canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );
    });
}

#[test]
fn stop_canister_from_another_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let controller = canister_test_id(1);
        let canister_id = canister_test_id(0);
        let canister =
            get_running_canister_with_args(canister_id, *controller.get_ref(), INITIAL_CYCLES);
        let cycles = 87;

        // Sanity check that the canister is running.
        assert_eq!(canister.status(), CanisterStatusType::Running);

        let subnet_id = subnet_test_id(1);
        state.put_canister_state(canister);

        // Enqueue a request to stop the canister.
        let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(controller)
                        .receiver(CanisterId::from(subnet_id))
                        .method_name(Method::StopCanister)
                        .method_payload(payload)
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        let canister = state.take_canister_state(&canister_id).unwrap();
        // Canister should now be in the stopping state.
        assert_eq!(
            canister.system_state.status,
            CanisterStatus::Stopping {
                stop_contexts: vec![StopCanisterContext::Canister {
                    sender: controller,
                    reply_callback: CallbackId::from(0),
                    cycles: Cycles::from(cycles),
                }],
                call_context_manager: CallContextManager::default()
            }
        );
        assert!(canister.system_state.ready_to_stop());

        // Since the canister isn't fully stopped yet, there should be no
        // response in the output queue.
        assert!(state
            .subnet_queues_mut()
            .pop_canister_output(&controller)
            .is_none());
    });
}

#[test]
fn starting_a_stopping_canister_succeeds() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let mut canister = get_stopping_canister(canister_test_id(0));

        let stop_msg_ids = [message_test_id(0), message_test_id(1)];

        for msg_id in &stop_msg_ids {
            canister
                .system_state
                .add_stop_context(StopCanisterContext::Ingress {
                    sender: user_test_id(1),
                    message_id: msg_id.clone(),
                });
        }

        // Create a call context. Because there's a call context that isn't cleared the
        // canister should stay in the `Stopping` status indefinitely.
        canister
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::Ingress(user_test_id(13), message_test_id(14)),
                Cycles::from(0),
                Time::from_nanos_since_unix_epoch(0),
            );

        // Ensure that the canister is `Stopping`.
        assert_matches!(canister.status(), CanisterStatusType::Stopping);

        state.put_canister_state(canister);

        // Start the stopping canister.
        let canister_id_record = CanisterIdRecord::from(canister_test_id(0)).encode();
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .message_id(message_test_id(2))
                        .source(user_test_id(1))
                        .receiver(ic00::IC_00)
                        .method_payload(canister_id_record)
                        .method_name(ic00::Method::StartCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Canister should now be running.
        assert_eq!(
            state.canister_state(&canister_test_id(0)).unwrap().status(),
            CanisterStatusType::Running
        );

        // Assert that stop messages have been cancelled.
        for msg_id in &stop_msg_ids {
            assert_matches!(
                state.get_ingress_status(msg_id),
                IngressStatus::Known {
                    user_id: u,
                    state: IngressState::Failed(e),
                    ..
                } if u == user_test_id(1) && e.code() == ErrorCode::CanisterStoppingCancelled
            );
        }
    });
}

#[test]
fn subnet_ingress_message_unknown_method() {
    with_setup(SubnetType::Application, |exec_env, state, _, _| {
        let sender = user_test_id(1);

        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .message_id(MessageId::from([0; 32]))
                        .source(sender)
                        .receiver(ic00::IC_00)
                        .method_payload(EmptyBlob::encode())
                        .method_name("non_existing_method")
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Known {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    "Management canister has no method \'non_existing_method\'"
                )),
            }
        );
    });
}

#[test]
fn subnet_canister_request_unknown_method() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let sender = canister_test_id(1);
        let receiver = CanisterId::new(subnet_test_id(1).get()).unwrap();
        let cycles = 100;

        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(sender)
                        .receiver(receiver)
                        .method_name("non_existing_method".to_string())
                        .method_payload(EmptyBlob::encode())
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state
                .subnet_queues_mut()
                .pop_canister_output(&sender)
                .unwrap()
                .1,
            RequestOrResponse::Response(Response {
                originator: sender,
                respondent: receiver,
                originator_reply_callback: CallbackId::new(0),
                refund: Cycles::from(cycles),
                response_payload: Payload::Reject(RejectContext {
                    code: RejectCode::DestinationInvalid,
                    message: "Management canister has no method \'non_existing_method\'"
                        .to_string(),
                })
            })
        );
    });
}

#[test]
fn subnet_ingress_message_on_create_canister_fails() {
    with_setup(SubnetType::Application, |exec_env, state, _, _| {
        let sender = user_test_id(1);
        let receiver = CanisterId::from(1);
        let install_args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            CanisterId::new(PrincipalId::try_from([1, 2, 3].as_ref()).unwrap()).unwrap(),
            vec![],
            vec![],
            None,
            None,
            None,
        );
        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .message_id(MessageId::from([0; 32]))
                        .source(sender)
                        .receiver(receiver)
                        .method_payload(install_args.encode())
                        .method_name(Method::CreateCanister)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    "create_canister can only be called by other canisters, not via ingress messages."
                )),
            }
        );
    });
}

#[test]
fn subnet_canister_request_bad_candid_payload() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _| {
        let sender = canister_test_id(1);
        let receiver = CanisterId::new(subnet_test_id(1).get()).unwrap();
        let cycles = 1;

        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(
                    RequestBuilder::new()
                        .sender(sender)
                        .receiver(receiver)
                        .method_name(Method::InstallCode)
                        .method_payload(vec![1, 2, 3]) // Invalid candid
                        .payment(Cycles::from(cycles))
                        .build(),
                ),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let mut state = exec_env
            .execute_subnet_message(
                state.subnet_queues_mut().pop_input().unwrap(),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state
                .subnet_queues_mut()
                .pop_canister_output(&sender)
                .unwrap()
                .1,
            RequestOrResponse::Response(Response {
                originator: sender,
                respondent: receiver,
                originator_reply_callback: CallbackId::new(0),
                refund: Cycles::from(cycles),
                response_payload: Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: "Error decoding candid: Cannot parse header 010203".to_string()
                })
            })
        );
    });
}

fn execute_create_canister_request(
    sender: CanisterId,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
) -> ReplicatedState {
    let receiver = canister_test_id(1);
    let cycles = CANISTER_CREATION_FEE + Cycles::from(1);

    let (mut state, exec_env) = ExecutionEnvironmentBuilder::new()
        .with_log(log)
        .with_nns_subnet_id(nns_subnet_id)
        .with_own_subnet_id(own_subnet_id)
        .with_sender_subnet_id(sender_subnet_id)
        .with_subnet_type(own_subnet_type)
        .with_sender_canister(sender)
        .build();

    state
        .subnet_queues_mut()
        .push_input(
            QUEUE_INDEX_NONE,
            RequestOrResponse::Request(
                RequestBuilder::new()
                    .sender(sender)
                    .receiver(receiver)
                    .method_name(Method::CreateCanister)
                    .method_payload(EmptyBlob::encode())
                    .payment(Cycles::from(cycles.get()))
                    .build(),
            ),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0
}

fn check_create_canister_fails(
    sender: CanisterId,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
) {
    let mut state = execute_create_canister_request(
        sender,
        nns_subnet_id,
        own_subnet_id,
        sender_subnet_id,
        own_subnet_type,
        log,
    );

    assert_eq!(
        state.subnet_queues_mut().pop_canister_output(&sender).unwrap().1,
        RequestOrResponse::Response(Response {
            originator: sender,
            respondent: CanisterId::from(own_subnet_id),
            originator_reply_callback: CallbackId::new(0),
            refund: CANISTER_CREATION_FEE + Cycles::from(1),
            response_payload: Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message:
                "Cannot create canister. Sender should be on the same subnet or on the NNS subnet."
                    .to_string()
            })
        })
    );
}

#[test]
fn create_canister_different_subnets_on_nns_and_sender_not_on_nns() {
    with_test_replica_logger(|log| {
        let own_subnet_type = SubnetType::System;
        let sender = canister_test_id(1);
        let nns_subnet_id = subnet_test_id(1);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(2);

        check_create_canister_fails(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            own_subnet_type,
            log,
        );
    });
}

#[test]
fn create_canister_different_subnets_not_on_nns_and_sender_not_on_nns() {
    with_test_replica_logger(|log| {
        let own_subnet_type = SubnetType::Application;
        let sender = canister_test_id(1);
        let nns_subnet_id = subnet_test_id(0);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(2);

        check_create_canister_fails(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            own_subnet_type,
            log,
        );
    });
}

fn check_create_canister_succeeds(
    sender: CanisterId,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
) {
    let mut state = execute_create_canister_request(
        sender,
        nns_subnet_id,
        own_subnet_id,
        sender_subnet_id,
        own_subnet_type,
        log,
    );

    let response = state
        .subnet_queues_mut()
        .pop_canister_output(&sender)
        .unwrap()
        .1;
    match response {
        RequestOrResponse::Response(response) => {
            assert_eq!(response.originator, sender);
            assert_eq!(response.respondent, CanisterId::from(own_subnet_id));
            assert_eq!(response.refund, Cycles::from(0));
            match response.response_payload {
                Payload::Data(_) => (),
                _ => panic!("Failed creating the canister."),
            }
        }
        _ => panic!("Type should be RequestOrResponse::Response"),
    }
}

#[test]
fn create_canister_different_subnets_not_on_nns_sender_on_nns() {
    with_test_replica_logger(|log| {
        let own_subnet_type = SubnetType::Application;
        let sender = canister_test_id(1);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(2); // sender is on nns

        check_create_canister_succeeds(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            own_subnet_type,
            log,
        );
    });
}

#[test]
fn create_canister_same_subnets_not_nns() {
    with_test_replica_logger(|log| {
        let own_subnet_type = SubnetType::Application;
        let sender = canister_test_id(7);
        let nns_subnet_id = subnet_test_id(0);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(1);

        check_create_canister_succeeds(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            own_subnet_type,
            log,
        );
    });
}

#[test]
fn create_canister_same_subnets_on_nns() {
    with_test_replica_logger(|log| {
        let own_subnet_type = SubnetType::System;
        let sender = canister_test_id(7);
        let nns_subnet_id = subnet_test_id(1);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(1);

        check_create_canister_succeeds(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            own_subnet_type,
            log,
        );
    });
}

fn execute_setup_initial_dkg_request(
    sender: CanisterId,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    subnet_type: SubnetType,
    log: ReplicaLogger,
) -> ReplicatedState {
    let receiver = canister_test_id(1);
    let cycles = CANISTER_CREATION_FEE;

    let (mut state, exec_env) = ExecutionEnvironmentBuilder::new()
        .with_nns_subnet_id(nns_subnet_id)
        .with_own_subnet_id(own_subnet_id)
        .with_sender_subnet_id(sender_subnet_id)
        .with_subnet_type(subnet_type)
        .with_log(log)
        .build();

    let node_ids = vec![node_test_id(1)];
    let request_payload = ic00::SetupInitialDKGArgs::new(node_ids, RegistryVersion::new(1));
    state
        .subnet_queues_mut()
        .push_input(
            QUEUE_INDEX_NONE,
            RequestOrResponse::Request(
                RequestBuilder::new()
                    .sender(sender)
                    .receiver(receiver)
                    .method_name(Method::SetupInitialDKG)
                    .method_payload(Encode!(&request_payload).unwrap())
                    .payment(Cycles::from(cycles.get()))
                    .build(),
            ),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0
}

#[test]
fn setup_initial_dkg_sender_on_nns() {
    with_test_replica_logger(|log| {
        let subnet_type = SubnetType::Application;
        let sender = canister_test_id(1);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = nns_subnet_id;

        let mut state = execute_setup_initial_dkg_request(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            subnet_type,
            log,
        );

        assert_eq!(state.subnet_queues_mut().pop_canister_output(&sender), None);
    });
}

#[test]
fn setup_initial_dkg_sender_not_on_nns() {
    with_test_replica_logger(|log| {
        let subnet_type = SubnetType::Application;
        let sender = canister_test_id(10);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = own_subnet_id;

        let mut state = execute_setup_initial_dkg_request(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            subnet_type,
            log,
        );

        let response = state
            .subnet_queues_mut()
            .pop_canister_output(&sender)
            .unwrap()
            .1;
        assert_eq!(
            response,
            RequestOrResponse::Response(Response {
                originator: sender,
                respondent: CanisterId::from(own_subnet_id),
                originator_reply_callback: CallbackId::new(0),
                refund: CANISTER_CREATION_FEE,
                response_payload: Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: format!(
                        "{} is called by {}. It can only be called by NNS.",
                        ic00::Method::SetupInitialDKG,
                        sender,
                    )
                })
            })
        );
    });
}

#[test]
fn install_code_fails_on_invalid_compute_allocation() {
    with_setup(SubnetType::Application, |exec_env, state, _, _| {
        let install_args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            CanisterId::new(PrincipalId::try_from([1, 2, 3].as_ref()).unwrap()).unwrap(),
            vec![],
            vec![],
            Some(1000), // <-- Invalid. Should fail.
            None,
            None,
        );

        let sender = user_test_id(1);

        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .message_id(MessageId::from([0; 32]))
                        .source(sender)
                        .receiver(ic00::IC_00)
                        .method_payload(install_args.encode())
                        .method_name(Method::InstallCode)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Known {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "ComputeAllocation expected to be in the range [0..100], got 1_000"
                )),
            }
        );
    });
}

#[test]
fn install_code_fails_on_invalid_memory_allocation() {
    with_setup(SubnetType::Application, |exec_env, state, _, _| {
        let install_args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            CanisterId::new(PrincipalId::try_from([1, 2, 3].as_ref()).unwrap()).unwrap(),
            vec![],
            vec![],
            None,
            Some(u64::MAX), // <-- Invalid. Should fail.
            None,
        );

        let sender = user_test_id(1);

        let state = exec_env
            .execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .message_id(MessageId::from([0; 32]))
                        .source(sender)
                        .receiver(ic00::IC_00)
                        .method_payload(install_args.encode())
                        .method_name(Method::InstallCode)
                        .build(),
                ),
                state,
                MAX_NUM_INSTRUCTIONS,
                &mut mock_random_number_generator(),
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Known {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "MemoryAllocation expected to be in the range [0..12_884_901_888], got 18_446_744_073_709_551_615"
                )),
            });
    });
}

#[test]
fn metrics_are_observed_for_subnet_messages() {
    let mut csprng = mock_random_number_generator();
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let metrics_registry = MetricsRegistry::new();
        let subnet_type = SubnetType::Application;
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = IngressHistoryWriterImpl::new(
            execution_environment::Config::default(),
            log.clone(),
            &metrics_registry,
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            log,
            hypervisor,
            ingress_history_writer,
            &metrics_registry,
            subnet_id,
            subnet_type,
            1,
            execution_environment::Config::default(),
            cycles_account_manager,
        );

        // Send a subnet message to some of the ic:00 methods, but with malformed
        // candid. The request should fail and an error should be observed in metrics.
        let (_, _, _, state) = initial_state(subnet_type);

        let methods: [ic00::Method; 6] = [
            ic00::Method::CreateCanister,
            ic00::Method::InstallCode,
            ic00::Method::SetController,
            ic00::Method::StartCanister,
            ic00::Method::StopCanister,
            ic00::Method::DeleteCanister,
        ];

        for method in methods.iter() {
            exec_env.execute_subnet_message(
                CanisterInputMessage::Ingress(
                    IngressBuilder::new()
                        .receiver(ic00::IC_00)
                        .method_payload(vec![]) // Empty payload (invalid Candid)
                        .method_name(*method)
                        .build(),
                ),
                state.clone(),
                MAX_NUM_INSTRUCTIONS,
                &mut csprng,
                &None,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            );
        }

        // Send subnet message with unknown method name.
        exec_env.execute_subnet_message(
            CanisterInputMessage::Ingress(
                IngressBuilder::new()
                    .receiver(ic00::IC_00)
                    .method_payload(vec![]) // Empty payload (invalid Candid)
                    .method_name("method_that_doesnt_exist".to_string())
                    .build(),
            ),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut csprng,
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        );

        assert_eq!(
            metric_vec(&[
                (
                    &[
                        ("method_name", "ic00_create_canister"),
                        ("outcome", "error"),
                        ("status", "CanisterMethodNotFound"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "ic00_install_code"),
                        ("outcome", "error"),
                        ("status", "CanisterContractViolation"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "ic00_set_controller"),
                        ("outcome", "error"),
                        ("status", "CanisterContractViolation"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "ic00_start_canister"),
                        ("outcome", "error"),
                        ("status", "CanisterContractViolation"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "ic00_stop_canister"),
                        ("outcome", "error"),
                        ("status", "CanisterContractViolation"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "ic00_delete_canister"),
                        ("outcome", "error"),
                        ("status", "CanisterContractViolation"),
                    ],
                    1
                ),
                (
                    &[
                        ("method_name", "unknown_method"),
                        ("outcome", "error"),
                        ("status", "CanisterMethodNotFound"),
                    ],
                    1
                ),
            ]),
            fetch_histogram_vec_count(
                &metrics_registry,
                "execution_subnet_message_duration_seconds"
            )
        );
    });
}

#[test]
fn can_update_canisters_cycles_account_when_an_ingress_is_executed() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        let canister = get_running_canister(canister_test_id(0));
        let initial_cycles_balance = canister.system_state.balance();
        let ingress = IngressBuilder::new().build();

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            CanisterInputMessage::Ingress(ingress),
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );

        assert_eq!(
            result.canister.system_state.balance(),
            initial_cycles_balance
                - cycles_account_manager
                    .execution_cost(MAX_NUM_INSTRUCTIONS - result.num_instructions_left,),
        );
    });
}

#[test]
fn can_reject_a_request_when_canister_is_out_of_cycles() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        // Set the canister's cycles balance to a low value to force the request to be
        // rejected.
        let available_cycles = Cycles::from(1000);
        let mut canister = get_running_canister_with_balance(canister_test_id(0), available_cycles);
        canister.system_state.freeze_threshold = NumSeconds::from(0);
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());

        let cycles = 50;
        let req = RequestBuilder::new()
            .sender(canister_test_id(13))
            .payment(Cycles::from(cycles))
            .build();
        let reply_callback = req.sender_reply_callback;
        canister
            .system_state
            .queues_mut()
            .push_input(
                QueueIndex::from(0),
                RequestOrResponse::Request(req),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();

        let msg = canister.pop_input().unwrap();
        let canister_id = canister.canister_id();
        let result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            msg,
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let mut result = process_response(result);
        assert_eq!(
            result
                .canister
                .system_state
                .queues_mut()
                .pop_canister_output(&canister_test_id(13))
                .unwrap()
                .1,
            RequestOrResponse::Response(Response {
                originator: canister_test_id(13),
                respondent: canister_test_id(0),
                originator_reply_callback: reply_callback,
                refund: Cycles::from(cycles),
                response_payload: Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: format!(
                        "IC0501: Canister {} is out of cycles: requested {} cycles but the available balance is {} cycles and the freezing threshold {} cycles",
                        canister_id,
                        cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS),
                        available_cycles,
                        Cycles::from(0),
                    ),
                }),
            })
        );
        // Verify the canister's cycles balance is still the same.
        assert_eq!(result.canister.system_state.balance(), Cycles::from(1000));
    });
}

#[test]
fn can_reject_an_ingress_when_canister_is_out_of_cycles() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        // Set the canister's cycles balance to a low value to force the request to be
        // rejected.
        let available_cycles = Cycles::from(1000);
        let canister = get_running_canister_with_balance(canister_test_id(0), available_cycles);
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let ingress = IngressBuilder::new().build();
        let source = ingress.source;

        let canister_id = canister.canister_id();
        let result = exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            CanisterInputMessage::Ingress(ingress),
            mock_time(),
            routing_table,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        let status = match result.result {
            ExecResult::IngressResult(status) => status,
            _ => panic!("Unexpected result variant"),
        };
        assert_eq!(
            status,
            (MessageId::from([0; 32]), IngressStatus::Known {
                receiver: canister_id.get(),
                user_id: source,
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterOutOfCycles,
                    format!(
                        "Canister {} is out of cycles: requested {} cycles but the available balance is {} cycles and the freezing threshold {} cycles",
                        canister_id,
                        cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS),
                        available_cycles,
                        Cycles::from(0),
                    ))),
                }
            )
        );
        // Verify the canister's cycles balance is still the same.
        assert_eq!(result.canister.system_state.balance(), Cycles::from(1000));
    });
}

#[test]
fn message_to_canister_with_not_enough_balance_is_rejected() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let canister_id = canister_test_id(0);
        let ingress = SignedIngressBuilder::new()
            .canister_id(canister_id)
            .build()
            .content()
            .clone();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let ingress_induction_cost = cycles_account_manager
            .ingress_induction_cost(&ingress)
            .unwrap()
            .cost();
        let available = ingress_induction_cost - Cycles::from(1);
        assert_eq!(
            exec_env
                .should_accept_ingress_message(
                    Arc::new(
                        ReplicatedStateBuilder::default()
                            .with_canister(
                                CanisterStateBuilder::default()
                                    .with_canister_id(canister_id)
                                    // Just under the cycles required to accept the message.
                                    .with_cycles(available)
                                    .build()
                            )
                            .build()
                    ),
                    &ProvisionalWhitelist::new_empty(),
                    &ingress,
                    ExecutionMode::NonReplicated,
                )
                .unwrap_err()
                .code(),
            ErrorCode::CanisterOutOfCycles,
        );
    });
}

#[test]
fn message_to_canister_with_enough_balance_is_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        let ingress = SignedIngressBuilder::new()
            .canister_id(canister_test_id(0))
            .build()
            .content()
            .clone();
        let config = CyclesAccountManagerConfig::application_subnet();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        assert_eq!(
            exec_env.should_accept_ingress_message(
                Arc::new(
                    ReplicatedStateBuilder::default()
                        .with_canister(
                            CanisterStateBuilder::default()
                                .with_canister_id(canister_test_id(0))
                                // Exactly the amount of cycles needed to accept
                                // the message plus a bit extra for the canister's storage
                                .with_cycles(
                                    cycles_account_manager
                                        .ingress_induction_cost(&ingress,)
                                        .unwrap()
                                        .cost()
                                        + config.gib_storage_per_second_fee * Cycles::from(10)
                                )
                                .with_wasm(vec![1, 2, 3])
                                .build()
                        )
                        .build()
                ),
                &ProvisionalWhitelist::new_empty(),
                &ingress,
                ExecutionMode::NonReplicated,
            ),
            Ok(())
        );
    });
}

#[test]
fn management_message_to_canister_with_enough_balance_is_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
                .build();
            assert_eq!(
                exec_env.should_accept_ingress_message(
                    Arc::new(
                        ReplicatedStateBuilder::default()
                            .with_canister(
                                CanisterStateBuilder::default()
                                    .with_canister_id(canister_test_id(0))
                                    .with_controller(user_test_id(0).get())
                                    .with_cycles(u128::MAX)
                                    .with_wasm(vec![1, 2, 3])
                                    .build()
                            )
                            .build()
                    ),
                    &ProvisionalWhitelist::new_empty(),
                    ingress.content(),
                    ExecutionMode::NonReplicated,
                ),
                Ok(())
            );
        }
    });
}

#[test]
fn management_message_to_canister_with_not_enough_balance_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let canister_id = canister_test_id(0);
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(CanisterIdRecord::from(canister_id).encode())
                .build();
            assert_eq!(
                exec_env
                    .should_accept_ingress_message(
                        Arc::new(
                            ReplicatedStateBuilder::default()
                                .with_canister(
                                    CanisterStateBuilder::default()
                                        .with_canister_id(canister_id)
                                        .with_controller(user_test_id(0).get())
                                        .with_cycles(0)
                                        .with_wasm(vec![1, 2, 3])
                                        .build()
                                )
                                .build()
                        ),
                        &ProvisionalWhitelist::new_empty(),
                        ingress.content(),
                        ExecutionMode::NonReplicated,
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::CanisterOutOfCycles,
            );
        }
    });
}

#[test]
fn management_message_to_canister_that_doesnt_exist_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
                .build();
            assert_eq!(
                exec_env
                    .should_accept_ingress_message(
                        Arc::new(ReplicatedStateBuilder::default().build()),
                        &ProvisionalWhitelist::new_empty(),
                        ingress.content(),
                        ExecutionMode::NonReplicated,
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::CanisterNotFound,
            );
        }
    });
}

#[test]
fn management_message_with_invalid_payload_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(vec![]) // an invalid payload
                .build();
            assert_eq!(
                exec_env
                    .should_accept_ingress_message(
                        Arc::new(ReplicatedStateBuilder::default().build()),
                        &ProvisionalWhitelist::new_empty(),
                        ingress.content(),
                        ExecutionMode::NonReplicated,
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidManagementPayload
            );
        }
    });
}

#[test]
fn management_message_with_invalid_method_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("invalid_method")
                .build();
            assert_eq!(
                exec_env
                    .should_accept_ingress_message(
                        Arc::new(ReplicatedStateBuilder::default().build()),
                        &ProvisionalWhitelist::new_empty(),
                        ingress.content(),
                        ExecutionMode::NonReplicated,
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::CanisterMethodNotFound,
            );
        }
    });
}

// A Wasm module that allocates 10 wasm pages of heap memory and 10 wasm
// pages of stable memory and then (optionally) traps.
const MEMORY_ALLOCATION_WAT: &str = r#"(module
      (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
      (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))

      (func $test_without_trap
        ;; Grow heap by 10 pages.
        (if (i32.ne (memory.grow (i32.const 10)) (i32.const 1))
          (then (unreachable))
        )
        ;; Grow stable memory by 10 pages.
        (if (i64.ne (call $stable64_grow (i64.const 10)) (i64.const 0))
          (then (unreachable))
        )
      )
      (func $test_with_trap
        ;; Grow memory.
        (call $test_without_trap)

        ;; Trap to trigger a failed execution
        (call $ic_trap (i32.const 0) (i32.const 15))
      )
      (export "canister_update test_without_trap" (func $test_without_trap))
      (export "canister_update test_with_trap" (func $test_with_trap))
      (memory $memory 1)
      (export "memory" (memory $memory))
      (data (i32.const 0) "This is a trap!")
)"#;

/// This test verifies that if the canister allocates memory during message
/// execution and the message fails, the allocated memory is returned to the
/// subnet's available memory.
#[test]
fn subnet_available_memory_reclaimed_when_execution_fails() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        let wasm_binary = wabt::wat2wasm(MEMORY_ALLOCATION_WAT).unwrap();
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let system_state = SystemStateBuilder::default()
            .freeze_threshold(NumSeconds::from(0))
            .build();

        let execution_state = exec_env
            .hypervisor_for_testing()
            .create_execution_state(
                wasm_binary,
                tmpdir.path().to_path_buf(),
                system_state.canister_id(),
            )
            .unwrap();

        let mut canister = CanisterState {
            system_state,
            execution_state: Some(execution_state),
            scheduler_state: SchedulerState::default(),
        };

        let input_message = CanisterInputMessage::Ingress(
            IngressBuilder::default()
                .method_name("test_with_trap".to_string())
                .build(),
        );

        let subnet_available_memory_bytes_num = 1 << 30;
        let subnet_available_memory: SubnetAvailableMemory = AvailableMemory::new(
            subnet_available_memory_bytes_num,
            subnet_available_memory_bytes_num,
        )
        .into();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
        process_response(exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            input_message,
            mock_time(),
            routing_table,
            subnet_available_memory.clone(),
        ));
        assert_eq!(
            subnet_available_memory_bytes_num,
            subnet_available_memory.get_total_memory()
        );
        assert_eq!(
            subnet_available_memory_bytes_num,
            subnet_available_memory.get_message_memory()
        );
    });
}

#[test]
fn test_allocating_memory_reduces_subnet_available_memory() {
    with_setup(SubnetType::Application, |exec_env, _, _, routing_table| {
        let wasm_binary = wabt::wat2wasm(MEMORY_ALLOCATION_WAT).unwrap();
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let system_state = SystemStateBuilder::default()
            .freeze_threshold(NumSeconds::from(0))
            .build();

        let execution_state = exec_env
            .hypervisor_for_testing()
            .create_execution_state(
                wasm_binary,
                tmpdir.path().to_path_buf(),
                system_state.canister_id(),
            )
            .unwrap();

        let mut canister = CanisterState {
            system_state,
            execution_state: Some(execution_state),
            scheduler_state: SchedulerState::default(),
        };

        let input_message = CanisterInputMessage::Ingress(
            IngressBuilder::default()
                .method_name("test_without_trap".to_string())
                .build(),
        );

        let subnet_available_memory_bytes_num = 1 << 30;
        let subnet_available_memory: SubnetAvailableMemory = AvailableMemory::new(
            subnet_available_memory_bytes_num,
            subnet_available_memory_bytes_num,
        )
        .into();
        canister.system_state.memory_allocation =
            MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
        process_response(exec_env.execute_canister_message(
            canister,
            MAX_NUM_INSTRUCTIONS,
            input_message,
            mock_time(),
            routing_table,
            subnet_available_memory.clone(),
        ));
        // The canister allocates 10 wasm pages in the heap and 10 wasm pages of stable
        // memory.
        let new_memory_allocated = 20 * WASM_PAGE_SIZE_IN_BYTES as i64;
        assert_eq!(
            subnet_available_memory_bytes_num - new_memory_allocated,
            subnet_available_memory.get_total_memory()
        );
        assert_eq!(
            subnet_available_memory_bytes_num,
            subnet_available_memory.get_message_memory()
        );
    });
}

#[test]
fn execute_canister_http_request() {
    with_test_replica_logger(|log| {
        let (mut state, exec_env) = ExecutionEnvironmentBuilder::new().with_log(log).build();
        // Enable http requests feature.
        state.metadata.own_subnet_features.http_requests = true;

        // Create payload of the request.
        let url = "https::/".to_string();
        let transform_method_name = Some("transform".to_string());
        let request_payload = CanisterHttpRequestArgs {
            url: url.clone(),
            headers: Vec::new(),
            body: None,
            http_method: HttpMethod::GET,
            transform_method_name: transform_method_name.clone(),
        };

        // Create request to HTTP_REQUEST method.
        let sender = canister_test_id(257);
        let request = RequestBuilder::new()
            .sender(sender)
            .receiver(IC_00)
            .method_name(Method::HttpRequest)
            .method_payload(Encode!(&request_payload).unwrap())
            .build();

        // Push the request in the subnet queue.
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(request.clone()),
                InputQueueType::LocalSubnet,
            )
            .unwrap();

        // Execute IC00::HTTP_REQUEST.
        let (new_state, _) = exec_env.execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        );

        // Check that the SubnetCallContextManager contains the request.
        let canister_http_request_contexts = new_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;
        assert_eq!(canister_http_request_contexts.len(), 1);

        let http_request_context = canister_http_request_contexts
            .get(&CallbackId::from(0))
            .unwrap();
        assert_eq!(http_request_context.url, url);
        assert_eq!(
            http_request_context.transform_method_name,
            transform_method_name
        );
        assert_eq!(http_request_context.http_method, CanisterHttpMethod::GET);
        assert_eq!(http_request_context.request, request);
    });
}

#[test]
fn execute_canister_http_request_disabled() {
    with_test_replica_logger(|log| {
        let (mut state, exec_env) = ExecutionEnvironmentBuilder::new().with_log(log).build();
        // Enable http requests feature.
        state.metadata.own_subnet_features.http_requests = false;

        // Create payload of the request.
        let request_payload = CanisterHttpRequestArgs {
            url: "https::/".to_string(),
            headers: Vec::new(),
            body: None,
            http_method: HttpMethod::GET,
            transform_method_name: Some("transform".to_string()),
        };

        // Create request to HTTP_REQUEST method.
        let sender = canister_test_id(257);
        let request = RequestBuilder::new()
            .sender(sender)
            .receiver(IC_00)
            .method_name(Method::HttpRequest)
            .method_payload(Encode!(&request_payload).unwrap())
            .build();

        // Push the request in the subnet queue.
        state
            .subnet_queues_mut()
            .push_input(
                QUEUE_INDEX_NONE,
                RequestOrResponse::Request(request),
                InputQueueType::LocalSubnet,
            )
            .unwrap();

        // Execute IC00::HTTP_REQUEST.
        let (new_state, _) = exec_env.execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        );

        // Check that the SubnetCallContextManager does not contains any request.
        let canister_http_request_contexts = new_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;
        assert_eq!(canister_http_request_contexts.len(), 0);
    });
}

fn execute_compute_initial_ecdsa_dealings(
    sender: CanisterId,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    own_subnet_is_ecdsa_enabled: bool,
    key_id: EcdsaKeyId,
    log: ReplicaLogger,
) -> ReplicatedState {
    let receiver = canister_test_id(1);

    let (mut state, exec_env) = ExecutionEnvironmentBuilder::new()
        .with_log(log)
        .with_nns_subnet_id(nns_subnet_id)
        .with_own_subnet_id(own_subnet_id)
        .with_sender_subnet_id(sender_subnet_id)
        .with_sender_canister(sender)
        .build();

    state.metadata.own_subnet_features.ecdsa_signatures = own_subnet_is_ecdsa_enabled;

    let node_ids = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let request_payload = ic00::ComputeInitialEcdsaDealingsArgs::new(
        key_id,
        None,
        node_ids,
        RegistryVersion::from(100),
    );
    state
        .subnet_queues_mut()
        .push_input(
            QUEUE_INDEX_NONE,
            RequestOrResponse::Request(
                RequestBuilder::new()
                    .sender(sender)
                    .receiver(receiver)
                    .method_name(Method::ComputeInitialEcdsaDealings)
                    .method_payload(Encode!(&request_payload).unwrap())
                    .payment(Cycles::from(0u64))
                    .build(),
            ),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0
}

fn get_reject_message(response: RequestOrResponse) -> String {
    match response {
        RequestOrResponse::Request(_) => panic!("Expected Response"),
        RequestOrResponse::Response(resp) => match resp.response_payload {
            Payload::Data(_) => panic!("Expected Reject"),
            Payload::Reject(reject) => reject.message,
        },
    }
}

fn make_key(name: &str) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    }
}

#[test]
fn compute_initial_ecdsa_dealings_sender_on_nns() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(0x10);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = nns_subnet_id;

        let mut state = execute_compute_initial_ecdsa_dealings(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            true,
            make_key("secp256k1"),
            log,
        );

        assert_eq!(state.subnet_queues_mut().pop_canister_output(&sender), None);
    });
}

#[test]
fn compute_initial_ecdsa_dealings_sender_not_on_nns() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(0x10);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(3); // sender not on nns subnet

        let mut state = execute_compute_initial_ecdsa_dealings(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            true,
            make_key("secp256k1"),
            log,
        );

        let (_refund, response) = state
            .subnet_queues_mut()
            .pop_canister_output(&sender)
            .unwrap();

        assert_eq!(
            get_reject_message(response),
            format!(
                "{} is called by {sender}. It can only be called by NNS.",
                Method::ComputeInitialEcdsaDealings
            )
        )
    });
}

#[test]
fn compute_initial_ecdsa_dealings_without_ecdsa_enabled() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(0x10);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = nns_subnet_id;

        let mut state = execute_compute_initial_ecdsa_dealings(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            false,
            make_key("secp256k1"),
            log,
        );

        let (_refund, response) = state
            .subnet_queues_mut()
            .pop_canister_output(&sender)
            .unwrap();

        assert_eq!(
            get_reject_message(response),
            format!(
                "The {} API is not enabled on this subnet.",
                Method::ComputeInitialEcdsaDealings
            )
        )
    });
}

// TODO EXC-1060: After supporting multiple keys, execution will know which key_ids are
// supported and can send the correct rejection message.
#[test]
#[ignore]
fn compute_initial_ecdsa_dealings_with_unknown_key() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(0x10);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = nns_subnet_id;

        let mut state = execute_compute_initial_ecdsa_dealings(
            sender,
            nns_subnet_id,
            own_subnet_id,
            sender_subnet_id,
            true,
            make_key("foo"),
            log,
        );

        let (_refund, response) = state
            .subnet_queues_mut()
            .pop_canister_output(&sender)
            .unwrap();

        assert_eq!(
            get_reject_message(response),
            "key_id must be \"secp256k1\"".to_string()
        )
    });
}

fn execute_ecdsa_signing(
    sender: CanisterId,
    ecdsa_signature_fee: Cycles,
    payment: Cycles,
    sender_is_nns: bool,
    log: ReplicaLogger,
) -> ReplicatedState {
    let nns_subnet = subnet_test_id(2);
    let sender_subnet = if sender_is_nns {
        subnet_test_id(2)
    } else {
        subnet_test_id(1)
    };
    let (mut state, exec_env) = ExecutionEnvironmentBuilder::new()
        .with_log(log)
        .with_sender_subnet_id(sender_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_sender_canister(sender)
        .with_ecdsa_signature_fee(ecdsa_signature_fee)
        .build();

    state.metadata.own_subnet_features.ecdsa_signatures = true;

    let request_payload = ic00::SignWithECDSAArgs {
        message_hash: [1; 32].to_vec(),
        derivation_path: vec![],
        key_id: make_key("secp256k1"),
    };
    state
        .subnet_queues_mut()
        .push_input(
            QUEUE_INDEX_NONE,
            RequestOrResponse::Request(
                RequestBuilder::new()
                    .sender(sender)
                    .method_name(Method::SignWithECDSA)
                    .method_payload(Encode!(&request_payload).unwrap())
                    .payment(payment)
                    .build(),
            ),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();

    exec_env
        .execute_subnet_message(
            state.subnet_queues_mut().pop_input().unwrap(),
            state,
            MAX_NUM_INSTRUCTIONS,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            MAX_NUMBER_OF_CANISTERS,
        )
        .0
}

#[test]
fn ecdsa_signature_fee_charged() {
    with_test_replica_logger(|log| {
        let fee = Cycles::from(1_000_000u64);
        let payment = Cycles::from(2_000_000u64);
        let sender = canister_test_id(1);
        let mut state = execute_ecdsa_signing(sender, fee, payment, false, log);

        assert_eq!(state.subnet_queues_mut().pop_canister_output(&sender), None);
        let (_, context) = state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .iter()
            .next()
            .unwrap();
        assert_eq!(context.request.payment, payment - fee)
    });
}

#[test]
fn ecdsa_signature_rejected_without_fee() {
    with_test_replica_logger(|log| {
        let fee = Cycles::from(2_000_000u64);
        let payment = fee - Cycles::from(1);
        let sender = canister_test_id(1);
        let mut state = execute_ecdsa_signing(sender, fee, payment, false, log);

        let (_refund, response) = state
            .subnet_queues_mut()
            .pop_canister_output(&sender)
            .unwrap();

        assert_eq!(
            get_reject_message(response),
            "sign_with_ecdsa request sent with 1999999 cycles, but 2000000 cycles are required."
                .to_string()
        )
    });
}

#[test]
fn ecdsa_signature_fee_ignored_for_nns() {
    with_test_replica_logger(|log| {
        let fee = Cycles::from(1_000_000u64);
        let payment = Cycles::zero();
        let sender = canister_test_id(1);
        let mut state = execute_ecdsa_signing(sender, fee, payment, true, log);

        assert_eq!(state.subnet_queues_mut().pop_canister_output(&sender), None);
        let (_, context) = state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .iter()
            .next()
            .unwrap();
        assert_eq!(context.request.payment, payment)
    });
}
