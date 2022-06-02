use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::NumSeconds;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_execution_environment::execution::response::ExecutionCyclesRefund;
use ic_ic00_types::{
    self as ic00, CanisterHttpRequestArgs, CanisterIdRecord, CanisterStatusResultV2,
    CanisterStatusType, EcdsaCurve, EcdsaKeyId, EmptyBlob, HttpMethod, Method,
    Payload as Ic00Payload, IC_00,
};
use ic_interfaces::execution_environment::{ExecResult, HypervisorError};

use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::WASM_PAGE_SIZE_IN_BYTES,
    testing::{CanisterQueuesTesting, SystemStateTesting},
    CanisterStatus, SystemState,
};
use ic_test_utilities::{
    execution_environment::{
        assert_empty_reply, check_ingress_status, get_reply, ExecutionTest, ExecutionTestBuilder,
    },
    metrics::{fetch_histogram_vec_count, metric_vec},
    mock_time,
    types::{
        ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::ResponseBuilder,
    },
    universal_canister::{call_args, wasm},
};
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES;
use ic_types::{
    canister_http::CanisterHttpMethod,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CallbackId, Payload, RejectContext, RequestOrResponse, Response, MAX_RESPONSE_COUNT_BYTES,
    },
    CanisterId, Cycles, RegistryVersion, Time,
};

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

fn wat_canister_id() -> CanisterId {
    canister_test_id(777)
}

fn call_canister_via_uc(test: &mut ExecutionTest, uc: CanisterId, canister_id: CanisterId) {
    let call = wasm()
        .call_simple(canister_id.get(), "test", call_args())
        .build();
    test.ingress_raw(uc, "update", call);
    test.execute_message(uc);
    test.induct_messages();
    test.execute_message(canister_id);
}

fn assert_correct_request(system_state: &mut SystemState, canister_id: CanisterId) {
    let dst = wat_canister_id();
    let (_, message) = system_state.queues_mut().pop_canister_output(&dst).unwrap();
    if let RequestOrResponse::Request(msg) = message {
        assert_eq!(msg.receiver, dst);
        assert_eq!(msg.sender, canister_id);
        assert_eq!(msg.method_name, "some_remote_method");
        assert_eq!(msg.method_payload, b"XYZ");
    } else {
        panic!("unexpected message popped: {:?}", message);
    }
}

#[test]
fn ingress_can_produce_output_request() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    assert_correct_request(system_state, canister_id);
}

#[test]
fn ingress_can_reply_and_produce_output_request() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_AND_REPLY_WAT).unwrap();
    let ingress_id = test.ingress_raw(canister_id, "test", vec![]).0;
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    assert_correct_request(system_state, canister_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: mock_time(),
            state: IngressState::Completed(WasmResult::Reply(b"MONOLORD".to_vec())),
        }
    );
}

#[test]
fn ingress_can_reject() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(REJECT_WAT).unwrap();
    let ingress_id = test.ingress_raw(canister_id, "test", vec![]).0;
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(0, system_state.queues().output_queues_len());
    assert_eq!(0, system_state.queues().output_message_count());
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: mock_time(),
            state: IngressState::Completed(WasmResult::Reject("MONOLORD".to_string())),
        }
    );
}

#[test]
fn output_requests_on_system_subnet_ignore_memory_limits() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_subnet_total_memory(13)
        .with_subnet_message_memory(13)
        .with_manual_execution()
        .build();
    let min_canister_memory = 65793;
    let canister_id = test.create_canister(Cycles::new(1_000_000_000));
    test.install_canister_with_allocation(
        canister_id,
        wabt::wat2wasm(CALL_SIMPLE_WAT).unwrap(),
        None,
        Some(min_canister_memory + 13),
    )
    .unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    assert_eq!(13, test.subnet_available_memory().get_total_memory());
    assert_eq!(13, test.subnet_available_memory().get_message_memory());
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(1, system_state.queues().reserved_slots());
    assert_correct_request(system_state, canister_id);
}

#[test]
fn output_requests_on_application_subnets_respect_canister_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let min_canister_memory = 65793;
    test.install_canister_with_allocation(
        canister_id,
        wabt::wat2wasm(CALL_SIMPLE_WAT).unwrap(),
        None,
        Some(min_canister_memory + 13),
    )
    .unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    assert_eq!(
        initial_subnet_available_memory.get_total_memory(),
        test.subnet_available_memory().get_total_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    );
    let system_state = &test.canister_state(canister_id).system_state;
    assert!(!system_state.queues().has_output());
}

#[test]
fn output_requests_on_application_subnets_respect_subnet_total_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(13)
        .with_subnet_message_memory(1 << 30)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    assert_eq!(13, test.subnet_available_memory().get_total_memory());
    assert_eq!(1 << 30, test.subnet_available_memory().get_message_memory());
    let system_state = &test.canister_state(canister_id).system_state;
    assert!(!system_state.queues().has_output());
}

#[test]
fn output_requests_on_application_subnets_respect_subnet_message_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(1 << 30)
        .with_subnet_message_memory(13)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    assert_eq!(1 << 30, test.subnet_available_memory().get_total_memory());
    assert_eq!(13, test.subnet_available_memory().get_message_memory());
    let system_state = &test.canister_state(canister_id).system_state;
    assert!(!system_state.queues().has_output());
}

#[test]
fn output_requests_on_application_subnets_update_subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(1 << 30)
        .with_subnet_message_memory(1 << 30)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    let subnet_total_memory = test.subnet_available_memory().get_total_memory();
    let subnet_message_memory = test.subnet_available_memory().get_message_memory();
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    // There should be one reserved slot in the queues.
    assert_eq!(1, system_state.queues().reserved_slots());
    // Subnet available memory should have decreased by `MAX_RESPONSE_COUNT_BYTES`.
    assert_eq!(
        (1 << 30) - MAX_RESPONSE_COUNT_BYTES as i64,
        subnet_total_memory
    );
    assert_eq!(
        (1 << 30) - MAX_RESPONSE_COUNT_BYTES as i64,
        subnet_message_memory
    );
    assert_correct_request(system_state, canister_id);
}

#[test]
fn callee_can_produce_output_request() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    let uc = test.universal_canister().unwrap();
    call_canister_via_uc(&mut test, uc, canister_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    // The extra queue is the empty queue created due to the inter-canister request
    // generated by the Canister.
    assert_eq!(2, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    assert_correct_request(system_state, canister_id);
}

#[test]
fn callee_can_reply_and_produce_output_request() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_AND_REPLY_WAT).unwrap();
    let uc = test.universal_canister().unwrap();
    call_canister_via_uc(&mut test, uc, canister_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(2, system_state.queues().output_queues_len());
    assert_eq!(2, system_state.queues().output_message_count());
    assert_correct_request(system_state, canister_id);
    let (_, message) = system_state.queues_mut().pop_canister_output(&uc).unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, uc);
        assert_eq!(msg.respondent, canister_id);
        assert_eq!(msg.response_payload, Payload::Data(b"MONOLORD".to_vec()));
    } else {
        panic!("unexpected message popped: {:?}", message);
    }
}

#[test]
fn callee_can_reject() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(REJECT_WAT).unwrap();
    let uc = test.universal_canister().unwrap();
    call_canister_via_uc(&mut test, uc, canister_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    let (_, message) = system_state.queues_mut().pop_canister_output(&uc).unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, uc);
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
}

#[test]
fn response_callback_can_reject() {
    // Test scenario:
    // 1. Canister A calls canister B.
    // 2. Canister B calls canister C.
    // 3. Canister C replies to canister B.
    // 4. The response callback of canister B rejects the call of canister A.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    let c = wasm().reply().build();
    let b_callback = wasm().push_bytes("error".as_bytes()).reject().build();
    let b = wasm()
        .call_simple(
            c_id.get(),
            "update",
            call_args().other_side(c).on_reply(b_callback),
        )
        .build();
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();

    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    test.execute_message(c_id);
    test.induct_messages();
    test.execute_message(b_id);

    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(2, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    let (_, message) = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
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
}

#[test]
fn canister_cannot_reply_twice() {
    // Test scenario:
    // 1. Canister A calls canister B.
    // 2. Canister B replies to canister A and calls canister C.
    // 3. Canister C replies to canister B.
    // 4. The response callback of canister B rejects the call of canister A.
    //    The reply should fail with a trap.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    let c = wasm().reply().build();
    let b_callback = wasm().push_bytes("error".as_bytes()).reject().build();
    let b = wasm()
        .reply()
        .call_simple(
            c_id.get(),
            "update",
            call_args().other_side(c).on_reply(b_callback),
        )
        .build();
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();

    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    test.execute_message(c_id);
    test.induct_messages();
    test.execute_message(b_id);
    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(2, system_state.queues().output_queues_len());
    assert_eq!(0, system_state.queues().output_message_count());
}

#[test]
fn stopping_canister_rejects_requests() {
    // Test scenario:
    // 1. Canister A sends a request to canister B.
    // 2. Canister B transitions to the stopping state.
    // 3. Canister B rejects the incoming request.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let b = wasm().reply().build();
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();
    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.stop_canister(b_id);
    assert_matches!(
        test.canister_state(b_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    test.execute_message(b_id);
    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    let (_, message) = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message: format!("IC0509: Canister {} is not running", b_id)
            })
        );
    } else {
        panic!("unexpected message popped: {:?}", message);
    }
}

#[test]
fn stopped_canister_rejects_requests() {
    // Test scenario:
    // 1. Canister A sends a request to canister B.
    // 2. Canister B is stopped.
    // 3. Canister B rejects the incoming request.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let b = wasm().reply().build();
    let a = wasm()
        .call_simple(b_id.get(), "update", call_args().other_side(b))
        .build();
    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.stop_canister(b_id);
    test.process_stopping_canisters();
    assert_eq!(
        test.canister_state(b_id).system_state.status,
        CanisterStatus::Stopped
    );
    test.execute_message(b_id);
    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_message_count());
    let (_, message) = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message: format!("IC0508: Canister {} is not running", b_id)
            })
        );
    } else {
        panic!("unexpected message popped: {:?}", message);
    }
}

#[test]
fn stopping_an_already_stopped_canister_succeeds() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    test.process_stopping_canisters();
    let ingress_status = test.ingress_status(ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Completed(WasmResult::Reply(EmptyBlob::encode())),
        }
    );
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    test.process_stopping_canisters();
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Completed(WasmResult::Reply(EmptyBlob::encode())),
        }
    );
}

#[test]
fn stopping_a_running_canister_does_not_update_ingress_history() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    assert_eq!(ingress_status, IngressStatus::Unknown);
}

#[test]
fn stopping_a_stopping_canister_does_not_update_ingress_history() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    assert_eq!(ingress_status, IngressStatus::Unknown);
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    assert_eq!(ingress_status, IngressStatus::Unknown);
}

#[test]
fn stopping_a_canister_with_incorrect_controller_fails() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let controller = test.user_id();
    test.set_user_id(user_test_id(13));
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: user_test_id(13),
            time: test.time(),
            state: IngressState::Failed(UserError::new(
                ErrorCode::CanisterInvalidController,
                format!(
                    "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
                    canister_id,
                    controller.get(),
                    user_test_id(13).get()
                )
            )),
        }
    );
}

#[test]
fn get_running_canister_status_from_another_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = test.universal_canister().unwrap();
    let canister_status_args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let get_canister_status = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterStatus,
            call_args().other_side(canister_status_args),
        )
        .build();
    test.set_controller(canister, controller.get()).unwrap();
    let result = test.ingress(controller, "update", get_canister_status);
    let reply = get_reply(result);
    let csr = CanisterStatusResultV2::decode(&reply).unwrap();
    assert_eq!(csr.status(), CanisterStatusType::Running);
    assert_eq!(csr.controllers(), vec![controller.get()]);
    assert_eq!(
        Cycles::new(csr.cycles()),
        test.canister_state(canister).system_state.balance()
    );
    assert_eq!(csr.freezing_threshold(), 2_592_000);
    assert_eq!(
        csr.memory_size(),
        test.execution_state(canister).memory_usage()
    );
    assert_eq!(
        Cycles::new(csr.idle_cycles_burned_per_second()),
        test.idle_cycles_burned_per_second(canister)
    );
}

#[test]
fn get_canister_status_from_another_canister_when_memory_low() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let binary = wabt::wat2wasm("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    test.install_canister_with_allocation(canister, binary, None, Some(150))
        .unwrap();
    let canister_status_args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let get_canister_status = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterStatus,
            call_args().other_side(canister_status_args),
        )
        .build();
    test.set_controller(canister, controller.get()).unwrap();
    let result = test.ingress(controller, "update", get_canister_status);
    let reply = get_reply(result);
    let csr = CanisterStatusResultV2::decode(&reply).unwrap();
    assert_eq!(csr.idle_cycles_burned_per_second(), 1);
}

#[test]
fn get_stopped_canister_status_from_another_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = test.universal_canister().unwrap();
    let canister_status_args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let get_canister_status = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterStatus,
            call_args().other_side(canister_status_args),
        )
        .build();
    test.stop_canister(canister);
    test.process_stopping_canisters();
    test.set_controller(canister, controller.get()).unwrap();
    let result = test.ingress(controller, "update", get_canister_status);
    let reply = get_reply(result);
    let csr = CanisterStatusResultV2::decode(&reply).unwrap();
    assert_eq!(csr.status(), CanisterStatusType::Stopped);
}

#[test]
fn get_stopping_canister_status_from_another_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = test.universal_canister().unwrap();
    let canister_status_args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let get_canister_status = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterStatus,
            call_args().other_side(canister_status_args),
        )
        .build();
    test.stop_canister(canister);
    test.set_controller(canister, controller.get()).unwrap();
    let result = test.ingress(controller, "update", get_canister_status);
    let reply = get_reply(result);
    let csr = CanisterStatusResultV2::decode(&reply).unwrap();
    assert_eq!(csr.status(), CanisterStatusType::Stopping);
}

#[test]
fn start_a_non_existing_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test.start_canister(canister_test_id(10)).unwrap_err();
    assert_eq!(ErrorCode::CanisterNotFound, err.code());
}

#[test]
fn get_canister_status_of_nonexisting_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test.canister_status(canister_test_id(10)).unwrap_err();
    assert_eq!(ErrorCode::CanisterNotFound, err.code());
}

#[test]
fn deposit_cycles_to_non_existing_canister_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = canister_test_id(10);
    let args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let deposit = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::DepositCycles,
            call_args()
                .other_side(args)
                .on_reject(wasm().reject_message().reject()),
            (0, 1),
        )
        .build();
    let result = test.ingress(controller, "update", deposit).unwrap();
    assert_eq!(
        WasmResult::Reject(format!("Canister {} not found.", canister)),
        result
    );
}

#[test]
fn start_canister_from_another_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = test.universal_canister().unwrap();
    let args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let start = wasm()
        .call_simple(
            ic00::IC_00,
            Method::StartCanister,
            call_args().other_side(args),
        )
        .build();
    test.stop_canister(canister);
    test.set_controller(canister, controller.get()).unwrap();
    let result = test.ingress(controller, "update", start).unwrap();
    assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
    assert_eq!(
        CanisterStatusType::Running,
        test.canister_state(canister).status(),
    );
}

#[test]
fn stop_canister_from_another_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let canister = test.universal_canister().unwrap();
    let args = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    let stop = wasm()
        .call_simple(
            ic00::IC_00,
            Method::StopCanister,
            call_args().other_side(args),
        )
        .build();
    test.set_controller(canister, controller.get()).unwrap();
    let (ingress_id, ingress_status) = test.ingress_raw(controller, "update", stop);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: controller.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister).status()
    );
    assert!(test.canister_state(canister).system_state.ready_to_stop());
    test.process_stopping_canisters();
    test.execute_all();
    let ingress_status = test.ingress_status(ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
}

#[test]
fn starting_a_stopping_canister_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    let ingress_id1 = test.stop_canister(canister);
    let ingress_id2 = test.stop_canister(canister);
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister).status()
    );
    test.start_canister(canister).unwrap();
    assert_eq!(
        CanisterStatusType::Running,
        test.canister_state(canister).status()
    );
    // Assert that stop messages have been cancelled.
    for ingress_id in [ingress_id1, ingress_id2] {
        let ingress_status = test.ingress_status(ingress_id);
        let err = check_ingress_status(ingress_status).unwrap_err();
        assert_eq!(ErrorCode::CanisterStoppingCancelled, err.code());
    }
}

#[test]
fn subnet_ingress_message_unknown_method() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message("unknown", EmptyBlob::encode())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
    assert_eq!(
        "Management canister has no method \'unknown\'",
        err.description()
    );
}

#[test]
fn subnet_canister_request_unknown_method() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    let run = wasm()
        .call_simple(
            ic00::IC_00,
            "unknown",
            call_args()
                .other_side(EmptyBlob::encode())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let (_, ingress_status) = test.ingress_raw(canister, "update", run);

    // The routing::resolve_destination() returns an error for unknown methods
    // of the IC management canisters. This means that `IC_00` is not replaced
    // with the destination subnet id and the request is treated as a cross-
    // subnet request.
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    let xnet_messages = test.xnet_messages();
    assert_eq!(1, xnet_messages.len());
    match &xnet_messages[0] {
        RequestOrResponse::Request(request) => {
            assert_eq!(request.receiver, ic00::IC_00);
            assert_eq!(request.sender, canister);
        }
        RequestOrResponse::Response(_) => unreachable!("Expected request, but got a response"),
    }
}

#[test]
fn subnet_ingress_message_on_create_canister_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message(Method::CreateCanister, EmptyBlob::encode())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
    assert_eq!(
        "create_canister can only be called by other canisters, not via ingress messages.",
        err.description()
    );
}

#[test]
fn subnet_canister_request_bad_candid_payload() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message(Method::InstallCode, vec![1, 2, 3])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "Error decoding candid: Cannot parse header 010203",
        err.description()
    );
}

#[test]
fn create_canister_xnet_to_nns_called_from_non_nns() {
    let own_subnet = subnet_test_id(1);
    let other_subnet = subnet_test_id(2);
    let other_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(own_subnet)
        .with_caller(other_subnet, other_canister)
        .build();

    test.inject_call_to_ic00(
        Method::CreateCanister,
        EmptyBlob::encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        "Cannot create canister. Sender should be on the same subnet or on the NNS subnet."
            .to_string()
    );
}

#[test]
fn create_canister_xnet_called_from_non_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let other_subnet = subnet_test_id(3);
    let other_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(other_subnet, other_canister)
        .build();

    test.inject_call_to_ic00(
        Method::CreateCanister,
        EmptyBlob::encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        "Cannot create canister. Sender should be on the same subnet or on the NNS subnet."
            .to_string()
    );
}

#[test]
fn create_canister_xnet_called_from_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .build();

    test.inject_call_to_ic00(
        Method::CreateCanister,
        EmptyBlob::encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    match response {
        RequestOrResponse::Response(response) => {
            assert_eq!(response.originator, nns_canister);
            assert_eq!(response.respondent, CanisterId::from(own_subnet));
            assert_eq!(response.refund, Cycles::new(0));
            match response.response_payload {
                Payload::Data(_) => (),
                _ => panic!("Failed creating the canister."),
            }
        }
        _ => panic!("Type should be RequestOrResponse::Response"),
    }
}

#[test]
fn setup_initial_dkg_sender_on_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .build();
    let nodes = vec![node_test_id(1)];
    let args = ic00::SetupInitialDKGArgs::new(nodes, RegistryVersion::new(1));
    test.inject_call_to_ic00(
        Method::SetupInitialDKG,
        args.encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn setup_initial_dkg_sender_not_on_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let other_subnet = subnet_test_id(3);
    let other_canister = canister_test_id(10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(other_subnet, other_canister)
        .build();
    let nodes = vec![node_test_id(1)];
    let args = ic00::SetupInitialDKGArgs::new(nodes, RegistryVersion::new(1));
    test.inject_call_to_ic00(
        Method::SetupInitialDKG,
        args.encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        response,
        RequestOrResponse::Response(Response {
            originator: other_canister,
            respondent: CanisterId::from(own_subnet),
            originator_reply_callback: CallbackId::new(0),
            refund: test.canister_creation_fee(),
            response_payload: Payload::Reject(RejectContext {
                code: RejectCode::CanisterError,
                message: format!(
                    "{} is called by {}. It can only be called by NNS.",
                    ic00::Method::SetupInitialDKG,
                    other_canister,
                )
            })
        })
    );
}

#[test]
fn install_code_fails_on_invalid_compute_allocation() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = wabt::wat2wasm("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister_with_allocation(canister, binary, Some(1_000), None)
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "ComputeAllocation expected to be in the range [0..100], got 1_000",
        err.description()
    );
}

#[test]
fn install_code_fails_on_invalid_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = wabt::wat2wasm("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister_with_allocation(canister, binary, None, Some(u64::MAX))
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "MemoryAllocation expected to be in the range [0..12_884_901_888], got 18_446_744_073_709_551_615",
        err.description()
    );
}

#[test]
fn metrics_are_observed_for_subnet_messages() {
    let mut test = ExecutionTestBuilder::new().build();
    let methods: [ic00::Method; 6] = [
        ic00::Method::CreateCanister,
        ic00::Method::InstallCode,
        ic00::Method::SetController,
        ic00::Method::StartCanister,
        ic00::Method::StopCanister,
        ic00::Method::DeleteCanister,
    ];

    for method in methods.iter() {
        test.subnet_message(method, EmptyBlob::encode())
            .unwrap_err();
    }

    test.subnet_message("nonexisting", EmptyBlob::encode())
        .unwrap_err();

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
            test.metrics_registry(),
            "execution_subnet_message_duration_seconds"
        )
    );
}

#[test]
fn ingress_deducts_execution_cost_from_canister_balance() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    let run = wasm().message_payload().append_and_reply().build();
    let balance_before = test.canister_state(canister).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(canister);
    test.ingress(canister, "update", run).unwrap();
    let balance_after = test.canister_state(canister).system_state.balance();
    let execution_cost_after = test.canister_execution_cost(canister);
    assert_eq!(
        balance_before - balance_after,
        execution_cost_after - execution_cost_before
    );
    // Ensure that we charged some cycles. The actual value is unknown to us at
    // this point but it is definitely larger that 1000.
    assert!(execution_cost_after - execution_cost_before > Cycles::new(1_000));
}

#[test]
fn can_reject_a_request_when_canister_is_out_of_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let b = wasm()
        .accept_cycles(1_000_000)
        .message_payload()
        .append_and_reply()
        .build();
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().append_and_reply()),
            (0, 1_000_000),
        )
        .build();
    test.canister_state_mut(b_id).system_state.freeze_threshold = NumSeconds::from(0);
    *test.canister_state_mut(b_id).system_state.balance_mut() = Cycles::new(1_000);
    let result = test.ingress(a_id, "update", a);
    let reply = get_reply(result);
    let error = std::str::from_utf8(&reply).unwrap();
    assert!(
        error.contains("out of cycles"),
        "Unexpected error: {}",
        error
    );
}

#[test]
fn can_reject_an_ingress_when_canister_is_out_of_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let id = test.universal_canister().unwrap();
    test.canister_state_mut(id).system_state.freeze_threshold = NumSeconds::from(0);
    *test.canister_state_mut(id).system_state.balance_mut() = Cycles::new(1_000);
    let run = wasm().message_payload().append_and_reply().build();
    let err = test.ingress(id, "update", run).unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
    assert_eq!(
        Cycles::new(1_000),
        test.canister_state(id).system_state.balance()
    );
}

#[test]
fn message_to_canister_with_not_enough_balance_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    *test.canister_state_mut(canister).system_state.balance_mut() = Cycles::new(1_000);
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
}

#[test]
fn message_to_canister_with_enough_balance_is_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    let result = test.should_accept_ingress_message(canister, "", vec![]);
    assert_eq!(Ok(()), result);
}

#[test]
fn management_message_to_canister_with_enough_balance_is_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let own_subnet_id = test.state().metadata.own_subnet_id;
    let canister = test.universal_canister().unwrap();

    for receiver in [IC_00, CanisterId::from(own_subnet_id)].iter() {
        let payload = CanisterIdRecord::from(canister).encode();
        let result = test.should_accept_ingress_message(*receiver, Method::StartCanister, payload);
        assert_eq!(Ok(()), result);
    }
}

#[test]
fn management_message_to_canister_with_not_enough_balance_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let own_subnet_id = test.state().metadata.own_subnet_id;
    let canister = test.universal_canister().unwrap();
    *test.canister_state_mut(canister).system_state.balance_mut() = Cycles::new(1_000);

    for receiver in [IC_00, CanisterId::from(own_subnet_id)].iter() {
        let payload = CanisterIdRecord::from(canister).encode();
        let err = test
            .should_accept_ingress_message(*receiver, Method::StartCanister, payload)
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
    }
}

#[test]
fn management_message_to_canister_that_doesnt_exist_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let own_subnet_id = test.state().metadata.own_subnet_id;

    for receiver in [IC_00, CanisterId::from(own_subnet_id)].iter() {
        let payload = CanisterIdRecord::from(canister_test_id(0)).encode();
        let err = test
            .should_accept_ingress_message(*receiver, Method::StartCanister, payload)
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterNotFound, err.code());
    }
}

#[test]
fn management_message_with_invalid_payload_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let own_subnet_id = test.state().metadata.own_subnet_id;

    for receiver in [IC_00, CanisterId::from(own_subnet_id)].iter() {
        let err = test
            .should_accept_ingress_message(*receiver, Method::StartCanister, vec![])
            .unwrap_err();
        assert_eq!(ErrorCode::InvalidManagementPayload, err.code());
    }
}

#[test]
fn management_message_with_invalid_method_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let own_subnet_id = test.state().metadata.own_subnet_id;

    for receiver in [IC_00, CanisterId::from(own_subnet_id)].iter() {
        let err = test
            .should_accept_ingress_message(*receiver, "invalid_method", vec![])
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
    }
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
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(1 << 30)
        .with_subnet_message_memory(1 << 30)
        .build();
    let id = test.canister_from_wat(MEMORY_ALLOCATION_WAT).unwrap();
    let err = test.ingress(id, "test_with_trap", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let memory = test.subnet_available_memory();
    assert_eq!(1 << 30, memory.get_total_memory());
    assert_eq!(1 << 30, memory.get_message_memory());
}

#[test]
fn test_allocating_memory_reduces_subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(1 << 30)
        .with_subnet_message_memory(1 << 30)
        .build();
    let id = test.canister_from_wat(MEMORY_ALLOCATION_WAT).unwrap();
    let result = test.ingress(id, "test_without_trap", vec![]);
    assert_empty_reply(result);
    // The canister allocates 10 pages in Wasm memory and stable memory.
    let new_memory_allocated = 20 * WASM_PAGE_SIZE_IN_BYTES as i64;
    let memory = test.subnet_available_memory();
    assert_eq!(1 << 30, memory.get_total_memory() + new_memory_allocated);
    assert_eq!(1 << 30, memory.get_message_memory());
}

#[test]
fn execute_canister_http_request() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();
    test.state_mut().metadata.own_subnet_features.http_requests = true;

    // Create payload of the request.
    let url = "https://".to_string();
    let transform_method_name = Some("transform".to_string());
    let args = CanisterHttpRequestArgs {
        url: url.clone(),
        headers: Vec::new(),
        body: None,
        http_method: HttpMethod::GET,
        transform_method_name: transform_method_name.clone(),
    };

    // Create request to HTTP_REQUEST method.
    test.inject_call_to_ic00(Method::HttpRequest, args.encode(), Cycles::new(0));
    test.execute_all();
    // Check that the SubnetCallContextManager contains the request.
    let canister_http_request_contexts = &test
        .state()
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
    assert_eq!(http_request_context.request.sender, caller_canister);
}

#[test]
fn execute_canister_http_request_disabled() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();
    test.state_mut().metadata.own_subnet_features.http_requests = false;

    // Create payload of the request.
    let url = "https://".to_string();
    let transform_method_name = Some("transform".to_string());
    let args = CanisterHttpRequestArgs {
        url,
        headers: Vec::new(),
        body: None,
        http_method: HttpMethod::GET,
        transform_method_name,
    };

    // Create request to HTTP_REQUEST method.
    test.inject_call_to_ic00(Method::HttpRequest, args.encode(), Cycles::new(0));
    test.execute_all();
    // Check that the SubnetCallContextManager contains the request.
    let canister_http_request_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;
    assert_eq!(canister_http_request_contexts.len(), 0);
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
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_ecdsa_signature_fee(0)
        .build();

    let node_ids = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let args = ic00::ComputeInitialEcdsaDealingsArgs::new(
        make_key("secp256k1"),
        None,
        node_ids,
        RegistryVersion::from(100),
    );
    test.inject_call_to_ic00(
        Method::ComputeInitialEcdsaDealings,
        args.encode(),
        Cycles::new(0),
    );
    test.execute_all();
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn compute_initial_ecdsa_dealings_sender_not_on_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let other_subnet = subnet_test_id(3);
    let other_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(other_subnet, other_canister)
        .with_ecdsa_signature_fee(0)
        .build();

    let node_ids = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let args = ic00::ComputeInitialEcdsaDealingsArgs::new(
        make_key("secp256k1"),
        None,
        node_ids,
        RegistryVersion::from(100),
    );
    test.inject_call_to_ic00(
        Method::ComputeInitialEcdsaDealings,
        args.encode(),
        Cycles::new(0),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        format!(
            "{} is called by {other_canister}. It can only be called by NNS.",
            Method::ComputeInitialEcdsaDealings
        )
    );
}

#[test]
fn compute_initial_ecdsa_dealings_without_ecdsa_enabled() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .build();

    let node_ids = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let args = ic00::ComputeInitialEcdsaDealingsArgs::new(
        make_key("secp256k1"),
        None,
        node_ids,
        RegistryVersion::from(100),
    );
    test.inject_call_to_ic00(
        Method::ComputeInitialEcdsaDealings,
        args.encode(),
        Cycles::new(0),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        format!(
            "The {} API is not enabled on this subnet.",
            Method::ComputeInitialEcdsaDealings
        )
    );
}

// TODO EXC-1060: After supporting multiple keys, execution will know which key_ids are
// supported and can send the correct rejection message.
#[test]
#[ignore]
fn compute_initial_ecdsa_dealings_with_unknown_key() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_ecdsa_signature_fee(0)
        .build();

    let node_ids = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let args = ic00::ComputeInitialEcdsaDealingsArgs::new(
        make_key("foo"),
        None,
        node_ids,
        RegistryVersion::from(100),
    );
    test.inject_call_to_ic00(
        Method::ComputeInitialEcdsaDealings,
        args.encode(),
        Cycles::new(0),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        "key_id must be \"secp256k1\"".to_string()
    )
}

#[test]
fn ecdsa_signature_fee_charged() {
    let fee = 1_000_000;
    let payment = 2_000_000;
    let ecdsa_key = make_key("secp256k1");
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_own_subnet_id(subnet_test_id(1))
        .with_nns_subnet_id(subnet_test_id(2))
        .with_ecdsa_signature_fee(fee)
        .with_ecdsa_key(ecdsa_key.clone())
        .build();
    let canister_id = test.universal_canister().unwrap();
    let esda_args = ic00::SignWithECDSAArgs {
        message_hash: [1; 32].to_vec(),
        derivation_path: vec![],
        key_id: ecdsa_key,
    };
    let run = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::SignWithECDSA,
            call_args()
                .other_side(esda_args.encode())
                .on_reject(wasm().reject_message().reject()),
            (0, payment),
        )
        .build();

    let (_, ingress_status) = test.ingress_raw(canister_id, "update", run);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    let (_, context) = test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts
        .iter()
        .next()
        .unwrap();
    assert_eq!(context.request.payment.get(), payment as u128 - fee);
}

#[test]
fn ecdsa_signature_rejected_without_fee() {
    let fee = 2_000_000;
    let ecdsa_key = make_key("secp256k1");
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_own_subnet_id(subnet_test_id(1))
        .with_nns_subnet_id(subnet_test_id(2))
        .with_ecdsa_signature_fee(fee)
        .with_ecdsa_key(ecdsa_key.clone())
        .build();
    let canister_id = test.universal_canister().unwrap();
    let esda_args = ic00::SignWithECDSAArgs {
        message_hash: [1; 32].to_vec(),
        derivation_path: vec![],
        key_id: ecdsa_key,
    };
    let run = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::SignWithECDSA,
            call_args()
                .other_side(esda_args.encode())
                .on_reject(wasm().reject_message().reject()),
            (0, fee as u64 - 1),
        )
        .build();

    let result = test.ingress(canister_id, "update", run).unwrap();
    assert_eq!(
        WasmResult::Reject(
            "sign_with_ecdsa request sent with 1999999 cycles, but 2000000 cycles are required."
                .into()
        ),
        result
    );
}

#[test]
fn ecdsa_signature_fee_ignored_for_nns() {
    let ecdsa_key = make_key("secp256k1");
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_own_subnet_id(subnet_test_id(1))
        .with_nns_subnet_id(subnet_test_id(1))
        .with_ecdsa_signature_fee(1_000_000)
        .with_ecdsa_key(ecdsa_key.clone())
        .build();
    let canister_id = test.universal_canister().unwrap();
    let esda_args = ic00::SignWithECDSAArgs {
        message_hash: [1; 32].to_vec(),
        derivation_path: vec![],
        key_id: ecdsa_key,
    };
    let run = wasm()
        .call_simple(
            ic00::IC_00,
            Method::SignWithECDSA,
            call_args()
                .other_side(esda_args.encode())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();

    let (_, ingress_status) = test.ingress_raw(canister_id, "update", run);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    let (_, context) = test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts
        .iter()
        .next()
        .unwrap();
    assert_eq!(context.request.payment, Cycles::zero());
}

#[test]
fn execute_response_with_incorrect_canister_status() {
    let response = ResponseBuilder::new().build();

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

    // Execute response when canister status is not Running.
    let (refund_cycles, exec_result) = test.execute_response(canister_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::No);
    assert_eq!(exec_result, ExecResult::Empty);
}

#[test]
fn execute_response_with_unknown_callback_id() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let response = ResponseBuilder::new().build();

    assert_eq!(
        test.canister_state(canister_id).status(),
        CanisterStatusType::Running
    );
    if let CanisterStatus::Running {
        call_context_manager,
    } = &test.canister_state(canister_id).system_state.status
    {
        // Unknown callback id.
        assert_eq!(
            call_context_manager.callback(&response.originator_reply_callback),
            None
        )
    }

    // Execute response when callback id cannot be found.
    let (refund_cycles, exec_result) = test.execute_response(canister_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::No);
    assert_eq!(exec_result, ExecResult::Empty);
}

#[test]
fn execute_response_refunds_cycles() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B.
    let cycles_sent = Cycles::new(1_000_000);
    let wasm_payload = wasm()
        .call_with_cycles(b_id.get(), "update", call_args(), cycles_sent.into_parts())
        .build();

    // Enqueue ingress message to canister A and execute it.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .refund(Cycles::new(2) * cycles_sent)
        .build();

    // Compute the response transmission refund.
    let mgr = test.cycles_account_manager();
    let response_transmission_refund =
        mgr.xnet_call_bytes_transmitted_fee(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES);
    mgr.xnet_call_bytes_transmitted_fee(response.payload_size_bytes());

    // Execute response.
    let balance_before = test.canister_state(a_id).system_state.balance();
    test.execute_response(a_id, response);
    let balance_after = test.canister_state(a_id).system_state.balance();

    // The balance is equivalent to the amount of cycles before executing`execute_response`
    // plus the unaccepted cycles (no more the cycles sent via request)
    // and the refunded transmission fee.
    assert_eq!(
        balance_after,
        balance_before + cycles_sent + response_transmission_refund
    );
}

#[test]
fn execute_response_when_call_context_deleted() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B.
    let wasm_payload = wasm()
        .call_simple(b_id.get(), "update", call_args())
        .build();

    // Enqueue ingress message to canister A and execute it.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .build();

    // Call context is not deleted.
    assert!(!test
        .get_call_context(a_id, response.originator_reply_callback)
        .is_deleted());

    // Call context is deleted after uninstall.
    test.uninstall_code(a_id).unwrap();
    assert_eq!(
        test.canister_state(a_id).status(),
        CanisterStatusType::Running
    );
    assert!(test
        .get_call_context(a_id, response.originator_reply_callback)
        .is_deleted());

    // Execute response with deleted call context.
    let (refund_cycles, exec_result) = test.execute_response(a_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::Yes);
    assert_eq!(exec_result, ExecResult::Empty);
}

#[test]
fn execute_response_successfully() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B.
    let wasm_payload = wasm()
        .call_simple(b_id.get(), "update", call_args())
        .build();

    // Enqueue ingress message to canister A and execute it.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .build();

    // Check canister's status and call context.
    assert_eq!(
        test.canister_state(a_id).status(),
        CanisterStatusType::Running
    );
    assert!(!test
        .get_call_context(a_id, response.originator_reply_callback)
        .is_deleted(),);

    // Execute response returns successfully.
    let (refund_cycles, exec_result) = test.execute_response(a_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::Yes);
    match exec_result {
        ExecResult::IngressResult((_, ingress_status)) => {
            let user_id = ingress_status.user_id().unwrap();
            assert_eq!(
                ingress_status,
                IngressStatus::Known {
                    state: IngressState::Completed(WasmResult::Reply(vec![])),
                    receiver: a_id.get(),
                    time: Time::from_nanos_since_unix_epoch(0),
                    user_id
                }
            );
        }
        ExecResult::ResponseResult(_) | ExecResult::Empty => panic!("Wrong execution result"),
    }
}

#[test]
fn execute_response_traps() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B, traps when executing reply closure.
    let wasm_payload = wasm()
        .inter_update(b_id.get(), call_args().on_reply(wasm().trap()))
        .build();

    // Enqueue ingress message to canister A and execute it.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .build();

    // Execute response returns failed status due to trap.
    let (refund_cycles, exec_result) = test.execute_response(a_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::Yes);
    match exec_result {
        ExecResult::IngressResult((_, ingress_status)) => {
            let user_id = ingress_status.user_id().unwrap();
            assert_eq!(
                ingress_status,
                IngressStatus::Known {
                    state: IngressState::Failed(
                        HypervisorError::CalledTrap(String::new()).into_user_error(&a_id)
                    ),
                    receiver: a_id.get(),
                    time: Time::from_nanos_since_unix_epoch(0),
                    user_id
                }
            );
        }
        ExecResult::ResponseResult(_) | ExecResult::Empty => panic!("Wrong execution result."),
    }
}

#[test]
fn execute_response_with_trapping_cleanup() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B, traps when executing cleanup.
    let wasm_payload = wasm()
        .inter_update(
            b_id.get(),
            call_args()
                .on_reply(wasm().trap())
                .on_cleanup(wasm().trap()),
        )
        .build();

    // Enqueue ingress message to canister A and execute it.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_eq!(ingress_status, IngressStatus::Unknown);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .build();

    // Execute response returns failed status due to trap.
    let (refund_cycles, exec_result) = test.execute_response(a_id, response);
    assert_eq!(refund_cycles, ExecutionCyclesRefund::Yes);
    match exec_result {
        ExecResult::IngressResult((_, ingress_status)) => {
            let user_id = ingress_status.user_id().unwrap();
            let err_trapped = Box::new(HypervisorError::CalledTrap(String::new()));
            assert_eq!(
                ingress_status,
                IngressStatus::Known {
                    state: IngressState::Failed(
                        HypervisorError::Cleanup {
                            callback_err: err_trapped.clone(),
                            cleanup_err: err_trapped
                        }
                        .into_user_error(&a_id)
                    ),
                    receiver: a_id.get(),
                    time: Time::from_nanos_since_unix_epoch(0),
                    user_id
                }
            );
        }
        ExecResult::ResponseResult(_) | ExecResult::Empty => panic!("Wrong execution result."),
    }
}
