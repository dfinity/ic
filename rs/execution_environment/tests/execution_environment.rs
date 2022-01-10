use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::NumSeconds;
use ic_config::{execution_environment, subnet_config::CyclesAccountManagerConfig};
use ic_execution_environment::{
    ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor, IngressHistoryWriterImpl,
};
use ic_interfaces::{
    execution_environment::{
        CanisterHeartbeatError, CanisterOutOfCyclesError, ExecuteMessageResult, ExecutionMode,
        SubnetAvailableMemory,
    },
    messages::CanisterInputMessage,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    testing::{CanisterQueuesTesting, ReplicatedStateTesting, SystemStateTesting},
    CallContextManager, CallOrigin, CanisterState, CanisterStatus, InputQueueType, ReplicatedState,
    SchedulerState, SystemState,
};
use ic_test_utilities::state::get_stopping_canister_on_nns;
use ic_test_utilities::{
    crypto::mock_random_number_generator,
    cycles_account_manager::CyclesAccountManagerBuilder,
    history::MockIngressHistory,
    metrics::{fetch_histogram_vec_count, metric_vec},
    mock_time,
    state::{
        get_running_canister, get_running_canister_with_args, get_running_canister_with_balance,
        get_stopped_canister, get_stopped_canister_on_system_subnet,
        get_stopped_canister_with_controller, get_stopping_canister, running_canister_into_stopped,
        CanisterStateBuilder, ReplicatedStateBuilder, SystemStateBuilder,
    },
    types::{
        ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::{IngressBuilder, RequestBuilder, ResponseBuilder, SignedIngressBuilder},
    },
    with_test_replica_logger,
};
use ic_types::{
    canonical_error::{not_found_error, permission_denied_error},
    ic00,
    ic00::{
        CanisterIdRecord, CanisterStatusResultV2, EmptyBlob, InstallCodeArgs, Method,
        Payload as Ic00Payload, IC_00,
    },
    ingress::{IngressStatus, WasmResult},
    messages::{
        CallbackId, CanisterInstallMode, MessageId, Payload, RejectContext, RequestOrResponse,
        Response, StopCanisterContext, MAX_RESPONSE_COUNT_BYTES,
    },
    methods::{Callback, WasmClosure},
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, CanisterStatusType, ComputeAllocation, Cycles, MemoryAllocation, NumBytes,
    NumInstructions, PrincipalId, QueueIndex, RegistryVersion, SubnetId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    sync::Arc,
};
use tempfile::TempDir;

const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);
lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX / 2);
}
const MAX_NUMBER_OF_CANISTERS: u64 = 0;

fn initial_state(
    subnet_type: SubnetType,
) -> (
    TempDir,
    SubnetId,
    Arc<RoutingTable>,
    Arc<BTreeMap<SubnetId, SubnetType>>,
    ReplicatedState,
) {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    let subnet_id = subnet_test_id(1);
    let routing_table = Arc::new(RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    }));
    let subnet_records = Arc::new(btreemap! {
        subnet_id => subnet_type,
    });
    let mut replicated_state = ReplicatedState::new_rooted_at(
        subnet_id,
        SubnetType::Application,
        tmpdir.path().to_path_buf(),
    );
    replicated_state.metadata.network_topology.routing_table = Arc::clone(&routing_table);
    (
        tmpdir,
        subnet_id,
        routing_table,
        subnet_records,
        replicated_state,
    )
}

pub fn with_setup<F>(subnet_type: SubnetType, f: F)
where
    F: FnOnce(
        ExecutionEnvironmentImpl,
        ReplicatedState,
        SubnetId,
        Arc<RoutingTable>,
        Arc<BTreeMap<SubnetId, SubnetType>>,
    ),
{
    with_test_replica_logger(|log| {
        let (_, subnet_id, routing_table, subnet_records, state) = initial_state(subnet_type);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = IngressHistoryWriterImpl::new(log.clone(), &metrics_registry);
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
        f(exec_env, state, subnet_id, routing_table, subnet_records)
    });
}

fn test_outgoing_messages(
    system_state: SystemState,
    wat: &str,
    test: impl FnOnce(ExecuteMessageResult<CanisterState>),
) {
    let subnet_type = SubnetType::Application;
    with_test_replica_logger(|log| {
        let (_, subnet_id, routing_table, subnet_records, _) = initial_state(subnet_type);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build(),
        );
        let hypervisor = Hypervisor::new(
            execution_environment::Config::default(),
            1,
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
            routing_table,
            subnet_records,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );

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
            let (_, status) = execute_message_result.ingress_status.unwrap();
            assert_eq!(
                status,
                IngressStatus::Completed {
                    receiver: canister_test_id(42).get(),
                    user_id: user_test_id(2),
                    result: WasmResult::Reply(b"MONOLORD".to_vec()),
                    time: mock_time(),
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
        let (_, status) = execute_message_result.ingress_status.unwrap();
        assert_eq!(
            status,
            IngressStatus::Completed {
                receiver: canister_test_id(42).get(),
                user_id: user_test_id(2),
                result: WasmResult::Reject("MONOLORD".to_string()),
                time: mock_time()
            }
        );
    });
}

#[test]
/// Output requests use up canister and subnet memory and can't be enqueued if
/// any of them is above the limit.
fn test_allocate_memory_for_output_requests() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
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
            let subnet_available_memory = SubnetAvailableMemory::new(1 << 30);
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(13)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message.clone(),
                mock_time(),
                Arc::clone(&routing_table),
                subnet_records.clone(),
                subnet_available_memory.clone(),
            );
            canister = execute_message_result.canister;
            assert_eq!(1 << 30, subnet_available_memory.get());
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                assert!(!canister.system_state.queues().has_output());
            } else {
                assert_eq!(1, canister.system_state.queues().reserved_slots());
                assert_correct_request(&mut canister.system_state);
            }

            // Tiny `SubnetAvailableMemory` also prevents enqueuing an output request.
            let subnet_available_memory = SubnetAvailableMemory::new(13);
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message.clone(),
                mock_time(),
                Arc::clone(&routing_table),
                subnet_records.clone(),
                subnet_available_memory.clone(),
            );
            canister = execute_message_result.canister;
            assert_eq!(13, subnet_available_memory.get());
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                assert!(!canister.system_state.queues().has_output());
            } else {
                assert_eq!(2, canister.system_state.queues().reserved_slots());
                assert_correct_request(&mut canister.system_state);
            }

            // But large enough canister memory allocation and `SubnetAvailableMemory` allow
            // enqueuing an outgoing request.
            let subnet_available_memory = SubnetAvailableMemory::new(1 << 30);
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            let execute_message_result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message,
                mock_time(),
                routing_table,
                subnet_records,
                subnet_available_memory.clone(),
            );
            canister = execute_message_result.canister;
            if ENFORCE_MESSAGE_MEMORY_USAGE {
                // There should be one reserved slot in the queues.
                assert_eq!(1, canister.system_state.queues().reserved_slots());
                // Subnet available memory should have decreased by `MAX_RESPONSE_COUNT_BYTES`.
                assert_eq!(
                    (1 << 30) - MAX_RESPONSE_COUNT_BYTES as i64,
                    subnet_available_memory.get()
                );
            } else {
                assert_eq!(3, canister.system_state.queues().reserved_slots());
                assert_eq!(1 << 30, subnet_available_memory.get());
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
    let cc_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(origin_id, origin_cb_id),
            Cycles::from(50),
        );
    let cb_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .register_callback(Callback::new(
            cc_id,
            Cycles::from(0),
            WasmClosure::new(0, 2),
            WasmClosure::new(0, 2),
            None,
        ));
    assert_eq!(
        system_state
            .call_context_manager_mut()
            .unwrap()
            .call_origin(cc_id)
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

    inject_response(&mut system_state, cb_id);
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
    let cc_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(888)),
            Cycles::from(42),
        );
    let cb_id = system_state
        .call_context_manager_mut()
        .unwrap()
        .register_callback(Callback::new(
            cc_id,
            Cycles::from(0),
            WasmClosure::new(0, 2),
            WasmClosure::new(0, 2),
            None,
        ));
    // mark this call context as responded
    system_state
        .call_context_manager_mut()
        .unwrap()
        .on_canister_result(cc_id, Ok(Some(WasmResult::Reply(vec![]))));

    inject_response(&mut system_state, cb_id);
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
        |exec_env, mut state, _, routing_table, subnet_records| {
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
            let mut result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                msg,
                mock_time(),
                routing_table,
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
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
                        code: RejectCode::SysFatal,
                        message: format!("Canister {} is not running", canister_id),
                    }),
                })
            );
        },
    );
}

#[test]
fn stopping_canister_rejects_ingress() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
            let canister = get_stopping_canister(canister_test_id(0));
            let ingress = IngressBuilder::new().build();

            assert_eq!(
                exec_env
                    .execute_canister_message(
                        canister,
                        MAX_NUM_INSTRUCTIONS,
                        CanisterInputMessage::Ingress(ingress),
                        mock_time(),
                        routing_table,
                        subnet_records,
                        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    )
                    .ingress_status
                    .unwrap()
                    .1,
                IngressStatus::Failed {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(2),
                    error: UserError::new(
                        ErrorCode::CanisterStopped,
                        format!(
                            "Canister {} is not running and cannot accept ingress messages.",
                            canister_test_id(0)
                        ),
                    ),
                    time: mock_time(),
                }
            );
        },
    );
}

#[test]
fn stopped_canister_rejects_requests() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
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
            let mut result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                msg,
                mock_time(),
                routing_table,
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
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
                        code: RejectCode::SysFatal,
                        message: format!("Canister {} is not running", canister_id),
                    }),
                })
            );
        },
    );
}

#[test]
fn stopped_canister_rejects_ingress() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
            let canister = get_stopped_canister(canister_test_id(0));
            let ingress = IngressBuilder::new().build();
            let result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                CanisterInputMessage::Ingress(ingress),
                mock_time(),
                routing_table,
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );

            assert_eq!(
                result.ingress_status.unwrap().1,
                IngressStatus::Failed {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(2),
                    error: UserError::new(
                        ErrorCode::CanisterStopped,
                        format!(
                            "Canister {} is not running and cannot accept ingress messages.",
                            canister_test_id(0)
                        ),
                    ),
                    time: mock_time(),
                }
            );
        },
    );
}

#[test]
fn execute_stop_canister_updates_ingress_history_when_called_on_already_stopped_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Verify that a response to the message has been written to ingress history.
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Completed {
                receiver: canister_test_id(0).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(EmptyBlob::encode()),
                time: mock_time(),
            }
        );
    });
}

#[test]
fn execute_stop_canister_does_not_update_ingress_history_when_called_on_running_canister() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        // Verify that the response has been written to ingress history.
        assert_eq!(
            state.get_ingress_status(&message_test_id(0)),
            IngressStatus::Failed {
                receiver: CanisterId::ic_00().get(),
                user_id: user_test_id(13),
                error: UserError::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Only the controllers of the canister {} can control it.\n\
                        Canister's controllers: {}\n\
                        Sender's ID: {}",
                        canister_test_id(0),
                        user_test_id(1).get(),
                        user_test_id(13).get()
                    )
                ),
                time: mock_time(),
            }
        );
    });
}

fn test_canister_status_helper(
    canister: CanisterState,
    expected_status_result: CanisterStatusResultV2,
) {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    let controller = canister_test_id(1);
    let canister = CanisterStateBuilder::new()
        .with_status(CanisterStatusType::Running)
        .with_controller(controller)
        .with_cycles(INITIAL_CYCLES)
        .with_freezing_threshold(123)
        .build();
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
            None,
            123,
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
                IngressStatus::Failed {
                    user_id: u,
                    error: e,
                    ..
                } if u == user_test_id(1) && e.code() == ErrorCode::CanisterStoppingCancelled
            );
        }
    });
}

#[test]
fn subnet_ingress_message_unknown_method() {
    with_setup(SubnetType::Application, |exec_env, state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Failed {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                error: UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    "Management canister has no method \'non_existing_method\'"
                ),
                time: mock_time(),
            }
        );
    });
}

#[test]
fn subnet_canister_request_unknown_method() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Failed {
                receiver: receiver.get(),
                user_id: sender,
                error: UserError::new(
                    ErrorCode::CanisterMethodNotFound,
                    "create_canister can only be called by other canisters, not via ingress messages."
                ),
                time: mock_time(),
            }
        );
    });
}

#[test]
fn subnet_canister_request_bad_candid_payload() {
    with_setup(SubnetType::Application, |exec_env, mut state, _, _, _| {
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

fn get_execution_environment(
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    subnet_type: SubnetType,
    log: ReplicaLogger,
) -> (ReplicatedState, ExecutionEnvironmentImpl) {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

    let routing_table = Arc::new(RoutingTable(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => own_subnet_id,
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => sender_subnet_id,
    }));

    let mut state =
        ReplicatedState::new_rooted_at(own_subnet_id, subnet_type, tmpdir.path().to_path_buf());
    state.metadata.network_topology.routing_table = routing_table;
    state.metadata.network_topology.nns_subnet_id = nns_subnet_id;

    let metrics_registry = MetricsRegistry::new();
    let cycles_account_manager = Arc::new(
        CyclesAccountManagerBuilder::new()
            .with_subnet_type(subnet_type)
            .build(),
    );
    let hypervisor = Hypervisor::new(
        execution_environment::Config::default(),
        1,
        &metrics_registry,
        own_subnet_id,
        subnet_type,
        log.clone(),
        Arc::clone(&cycles_account_manager),
    );
    let hypervisor = Arc::new(hypervisor);
    let ingress_history_writer = IngressHistoryWriterImpl::new(log.clone(), &metrics_registry);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    let exec_env = ExecutionEnvironmentImpl::new(
        log,
        hypervisor,
        ingress_history_writer,
        &metrics_registry,
        own_subnet_id,
        subnet_type,
        1,
        execution_environment::Config::default(),
        cycles_account_manager,
    );
    (state, exec_env)
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

    let (mut state, exec_env) = get_execution_environment(
        nns_subnet_id,
        own_subnet_id,
        sender_subnet_id,
        own_subnet_type,
        log,
    );

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
        let sender = canister_test_id(257); // sender not on nns
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
        let sender = canister_test_id(257); // sender not on NNS
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
        let sender = canister_test_id(257);
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

    let (mut state, exec_env) = get_execution_environment(
        nns_subnet_id,
        own_subnet_id,
        sender_subnet_id,
        subnet_type,
        log,
    );

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
        let sender = canister_test_id(257);
        let nns_subnet_id = subnet_test_id(2);
        let own_subnet_id = subnet_test_id(1);
        let sender_subnet_id = subnet_test_id(2); // sender on nns subnet

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
        let sender_subnet_id = subnet_test_id(1); // sender not on nns subnet

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
                        ic00::Method::SetupInitialDKG.to_string(),
                        sender,
                    )
                })
            })
        );
    });
}

#[test]
fn install_code_fails_on_invalid_compute_allocation() {
    with_setup(SubnetType::Application, |exec_env, state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Failed {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                error: UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "ComputeAllocation expected to be in the range [0..100], got 1_000"
                ),
                time: mock_time(),
            }
        );
    });
}

#[test]
fn install_code_fails_on_invalid_memory_allocation() {
    with_setup(SubnetType::Application, |exec_env, state, _, _, _| {
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
                &ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                MAX_NUMBER_OF_CANISTERS,
            )
            .0;

        assert_eq!(
            state.get_ingress_status(&MessageId::from([0; 32])),
            IngressStatus::Failed {
                receiver: ic00::IC_00.get(),
                user_id: sender,
                error: UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "MemoryAllocation expected to be in the range [0..12_884_901_888], got 18_446_744_073_709_551_615"
                ),
                time: mock_time(),
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
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = IngressHistoryWriterImpl::new(log.clone(), &metrics_registry);
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
        let (_, _, _, _, state) = initial_state(subnet_type);

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
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
            let canister = get_running_canister(canister_test_id(0));
            let initial_cycles_balance = canister.system_state.cycles_balance;
            let ingress = IngressBuilder::new().build();

            let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
            let result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                CanisterInputMessage::Ingress(ingress),
                mock_time(),
                routing_table,
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );

            assert_eq!(
                result.canister.system_state.cycles_balance,
                initial_cycles_balance
                    - cycles_account_manager
                        .execution_cost(MAX_NUM_INSTRUCTIONS - result.num_instructions_left,),
            );
        },
    );
}

#[test]
fn can_reject_a_request_when_canister_is_out_of_cycles() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
            // Set the canister's cycles balance to a low value to force the request to be
            // rejected.
            let available_cycles = Cycles::from(1000);
            let mut canister =
                get_running_canister_with_balance(canister_test_id(0), available_cycles);
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
            let mut result = exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                msg,
                mock_time(),
                routing_table,
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
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
                    code: RejectCode::SysTransient,
                    message: format!(
                        "Canister {} is out of cycles: requested {} cycles but the available balance is {} cycles and the freezing threshold {} cycles",
                        canister_id,
                        cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS),
                        available_cycles,
                        Cycles::from(0),
                    ),
                }),
            })
        );
            // Verify the canister's cycles balance is still the same.
            assert_eq!(
                result.canister.system_state.cycles_balance,
                Cycles::from(1000)
            );
        },
    );
}

#[test]
fn can_reject_an_ingress_when_canister_is_out_of_cycles() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
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
                subnet_records,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
            assert_eq!(
            result.ingress_status,
            Some((MessageId::from([0; 32]), IngressStatus::Failed {
                receiver: canister_id.get(),
                user_id: source,
                error: UserError::new(
                    ErrorCode::CanisterOutOfCycles,
                    format!(
                        "Canister {} is out of cycles: requested {} cycles but the available balance is {} cycles and the freezing threshold {} cycles",
                        canister_id,
                        cycles_account_manager.execution_cost(MAX_NUM_INSTRUCTIONS),
                        available_cycles,
                        Cycles::from(0),
                    ),
                ),
                time: mock_time(),
            }))
        );
            // Verify the canister's cycles balance is still the same.
            assert_eq!(
                result.canister.system_state.cycles_balance,
                Cycles::from(1000)
            );
        },
    );
}

#[test]
fn canister_heartbeat_doesnt_run_when_canister_is_stopped() {
    with_setup(
        SubnetType::System,
        |exec_env, _, _, routing_table, subnet_records| {
            let canister = get_stopped_canister_on_system_subnet(canister_test_id(0));

            let result = exec_env
                .execute_canister_heartbeat(
                    canister,
                    MAX_NUM_INSTRUCTIONS,
                    routing_table,
                    subnet_records,
                    mock_time(),
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                )
                .2;

            assert_eq!(
                result,
                Err(CanisterHeartbeatError::CanisterNotRunning {
                    status: CanisterStatusType::Stopped,
                })
            );
        },
    );
}

#[test]
fn canister_heartbeat_doesnt_run_when_canister_is_stopping() {
    with_setup(
        SubnetType::System,
        |exec_env, _, _, routing_table, subnet_records| {
            let canister = get_stopping_canister_on_nns(canister_test_id(0));

            let result = exec_env
                .execute_canister_heartbeat(
                    canister,
                    MAX_NUM_INSTRUCTIONS,
                    routing_table,
                    subnet_records,
                    mock_time(),
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                )
                .2;

            assert_eq!(
                result,
                Err(CanisterHeartbeatError::CanisterNotRunning {
                    status: CanisterStatusType::Stopping,
                })
            );
        },
    );
}

#[test]
fn message_to_canister_with_not_enough_balance_is_rejected() {
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
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
            exec_env.should_accept_ingress_message(
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
            ),
            Err(permission_denied_error(
                &CanisterOutOfCyclesError {
                    canister_id,
                    available,
                    requested: ingress_induction_cost,
                    threshold: Cycles::from(0),
                }
                .to_string()
            )),
        );
    });
}

#[test]
fn message_to_canister_with_enough_balance_is_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
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
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let canister_id = canister_test_id(0);
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(CanisterIdRecord::from(canister_id).encode())
                .build();
            let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
            let ingress_induction_cost = cycles_account_manager
                .ingress_induction_cost(ingress.content())
                .unwrap()
                .cost();
            assert_eq!(
                exec_env.should_accept_ingress_message(
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
                ),
                Err(permission_denied_error(
                    &CanisterOutOfCyclesError {
                        canister_id,
                        available: Cycles::from(0),
                        requested: ingress_induction_cost,
                        threshold: Cycles::from(381000),
                    }
                    .to_string()
                )),
            );
        }
    });
}

#[test]
fn management_message_to_canister_that_doesnt_exist_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
                .build();
            assert_eq!(
                exec_env.should_accept_ingress_message(
                    Arc::new(ReplicatedStateBuilder::default().build()),
                    &ProvisionalWhitelist::new_empty(),
                    ingress.content(),
                    ExecutionMode::NonReplicated,
                ),
                Err(not_found_error("Requested canister does not exist")),
            );
        }
    });
}

#[test]
fn management_message_with_invalid_payload_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("start_canister")
                .method_payload(vec![]) // an invalid payload
                .build();
            assert_eq!(
                exec_env.should_accept_ingress_message(
                    Arc::new(ReplicatedStateBuilder::default().build()),
                    &ProvisionalWhitelist::new_empty(),
                    ingress.content(),
                    ExecutionMode::NonReplicated,
                ),
                Err(permission_denied_error(
                    "Requested canister rejected the message"
                )),
            );
        }
    });
}

#[test]
fn management_message_with_invalid_method_is_not_accepted() {
    with_setup(SubnetType::Application, |exec_env, _, _, _, _| {
        for receiver in [IC_00, CanisterId::from(subnet_test_id(1))].iter() {
            let ingress = SignedIngressBuilder::new()
                .sender(user_test_id(0))
                .canister_id(*receiver)
                .method_name("invalid_method")
                .build();
            assert_eq!(
                exec_env.should_accept_ingress_message(
                    Arc::new(ReplicatedStateBuilder::default().build()),
                    &ProvisionalWhitelist::new_empty(),
                    ingress.content(),
                    ExecutionMode::NonReplicated,
                ),
                Err(permission_denied_error(
                    "Requested canister rejected the message"
                )),
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
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
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
            let subnet_available_memory =
                SubnetAvailableMemory::new(subnet_available_memory_bytes_num);
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message,
                mock_time(),
                routing_table,
                subnet_records,
                subnet_available_memory.clone(),
            );
            assert_eq!(
                subnet_available_memory_bytes_num,
                subnet_available_memory.get()
            );
        },
    );
}

#[test]
fn test_allocating_memory_reduces_subnet_available_memory() {
    with_setup(
        SubnetType::Application,
        |exec_env, _, _, routing_table, subnet_records| {
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
            let subnet_available_memory =
                SubnetAvailableMemory::new(subnet_available_memory_bytes_num);
            canister.system_state.memory_allocation =
                MemoryAllocation::try_from(NumBytes::new(1 << 30)).unwrap();
            exec_env.execute_canister_message(
                canister,
                MAX_NUM_INSTRUCTIONS,
                input_message,
                mock_time(),
                routing_table,
                subnet_records,
                subnet_available_memory.clone(),
            );
            // The canister allocates 10 wasm pages in the heap and 10 wasm pages of stable
            // memory.
            let new_memory_allocated = 20 * WASM_PAGE_SIZE_IN_BYTES as i64;
            assert_eq!(
                subnet_available_memory_bytes_num - new_memory_allocated,
                subnet_available_memory.get()
            );
        },
    );
}
