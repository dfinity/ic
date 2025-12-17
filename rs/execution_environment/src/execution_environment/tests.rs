use candid::{Decode, Encode};
use ic_base_types::{NumBytes, NumSeconds};
use ic_btc_interface::NetworkInRequest;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_management_canister_types_private::{
    self as ic00, BitcoinGetUtxosArgs, BoundedHttpHeaders, CanisterChange, CanisterHttpRequestArgs,
    CanisterIdRecord, CanisterMetadataRequest, CanisterMetadataResponse, CanisterStatusResultV2,
    CanisterStatusType, DerivationPath, EcdsaCurve, EcdsaKeyId, EmptyBlob,
    FetchCanisterLogsRequest, HttpMethod, IC_00, LogVisibilityV2, MasterPublicKeyId, Method,
    Payload as Ic00Payload, ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs,
    SchnorrAlgorithm, SchnorrKeyId, TakeCanisterSnapshotArgs, TransformContext, TransformFunc,
    UploadChunkArgs, VetKdCurve, VetKdKeyId,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, canister_id_into_u64};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterStatus, ReplicatedState, SystemState,
    canister_state::{
        DEFAULT_QUEUE_CAPACITY, WASM_PAGE_SIZE_IN_BYTES, system_state::CyclesUseCase,
    },
    testing::{CanisterQueuesTesting, SystemStateTesting},
};
use ic_test_utilities::assert_utils::assert_balance_equals;
use ic_test_utilities_execution_environment::{
    ExecutionTest, ExecutionTestBuilder, check_ingress_status, expect_canister_did_not_reply,
    get_reject, get_reply,
};
use ic_test_utilities_metrics::{fetch_histogram_vec_count, metric_vec};
use ic_types::{
    CanisterId, CountBytes, Cycles, PrincipalId, RegistryVersion,
    batch::CanisterCyclesCostSchedule,
    canister_http::{CanisterHttpMethod, Transform},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CallbackId, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE, Payload, RejectContext,
        RequestOrResponse, Response,
    },
    nominal_cycles::NominalCycles,
    time::UNIX_EPOCH,
};
use ic_types_test_utils::ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id};
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, call_args, wasm};
use maplit::btreemap;
use more_asserts::assert_gt;
use std::mem::size_of;

#[cfg(test)]
mod canister_task;

#[cfg(test)]
mod canister_snapshots;
#[cfg(test)]
mod compilation;

const BALANCE_EPSILON: Cycles = Cycles::new(12_000_000);
const ONE_GIB: u64 = 1 << 30;
const LOG_MEMORY_USAGE: i64 = 3 * 4096;

// A Wasm module calling call_perform
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
                    (drop (call $ic0_call_perform))
                  )
                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\00\00\00\00\00\00\03\09\01\01")
            )"#;

// A Wasm module making a best-effort call.
const CALL_BEST_EFFORT_WAT: &str = r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                      (param i32 i32)
                      (param $method_name_src i32)    (param $method_name_len i32)
                      (param $reply_fun i32)          (param $reply_env i32)
                      (param $reject_fun i32)         (param $reject_env i32)
                  ))
                  (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
                  (import "ic0" "call_with_best_effort_response" (func $ic0_call_with_best_effort_response (param $timeout_seconds i32)))
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
                    (call $ic0_call_with_best_effort_response
                        (i32.const 10)
                    )
                    (drop (call $ic0_call_perform))
                  )
                  (export "canister_update test" (func $test))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (data (i32.const 0) "some_remote_method XYZ")
                  (data (i32.const 100) "\00\00\00\00\00\00\03\09\01\01")
            )"#;

// A Wasm module calling call_perform and replying
const CALL_SIMPLE_AND_REPLY_WAT: &str = r#"(module
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                      (param i32 i32)
                      (param $method_name_src i32)    (param $method_name_len i32)
                      (param $reply_fun i32)          (param $reply_env i32)
                      (param $reject_fun i32)         (param $reject_env i32)
                  ))
                  (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32) (param i32)))
                  (func $test
                    (call $ic0_call_new
                        (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                        (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                        (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                        (i32.const 33) (i32.const 44))  ;; fictive on_reject closure
                    (call $ic0_call_data_append
                        (i32.const 19) (i32.const 3))   ;; refers to "XYZ" on the heap
                    (drop (call $ic0_call_perform))
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
    let call = wasm().call_simple(canister_id, "test", call_args()).build();
    test.ingress_raw(uc, "update", call);
    test.execute_message(uc);
    test.induct_messages();
    test.execute_message(canister_id);
}

fn assert_correct_request(system_state: &mut SystemState, canister_id: CanisterId) {
    let dst = wat_canister_id();
    let message = system_state.queues_mut().pop_canister_output(&dst).unwrap();
    if let RequestOrResponse::Request(msg) = message {
        assert_eq!(msg.receiver, dst);
        assert_eq!(msg.sender, canister_id);
        assert_eq!(msg.method_name, "some_remote_method");
        assert_eq!(msg.method_payload, b"XYZ");
    } else {
        panic!("unexpected message popped: {message:?}");
    }
}

fn sign_with_threshold_key_payload(method: Method, key_id: MasterPublicKeyId) -> Vec<u8> {
    match method {
        Method::SignWithECDSA => ic00::SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(vec![]),
            key_id: into_inner_ecdsa(key_id),
        }
        .encode(),
        Method::SignWithSchnorr => ic00::SignWithSchnorrArgs {
            message: vec![],
            derivation_path: DerivationPath::new(vec![]),
            key_id: into_inner_schnorr(key_id),
            aux: None,
        }
        .encode(),
        Method::VetKdDeriveKey => ic00::VetKdDeriveKeyArgs {
            input: vec![],
            transport_public_key: [
                // Generated via TransportSecretKey::from_seed(vec![0; 32]).unwrap().public_key()
                178, 211, 206, 216, 102, 5, 127, 108, 175, 41, 31, 129, 99, 3, 1, 87, 24, 22, 102,
                58, 81, 137, 170, 178, 61, 6, 208, 161, 20, 14, 134, 241, 34, 50, 176, 194, 32, 5,
                19, 249, 66, 219, 9, 120, 165, 15, 9, 211,
            ],
            context: vec![],
            key_id: into_inner_vetkd(key_id),
        }
        .encode(),
        _ => panic!("unexpected method"),
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
    assert_eq!(1, system_state.queues().output_queues_message_count());
    assert_correct_request(system_state, canister_id);
}

#[test]
fn ingress_can_reply_and_produce_output_request() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_AND_REPLY_WAT).unwrap();
    let ingress_id = test.ingress_raw(canister_id, "test", vec![]).0;
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());
    assert_correct_request(system_state, canister_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: UNIX_EPOCH,
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
    let ingress_status = test.ingress_status(&ingress_id);
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(0, system_state.queues().output_queues_len());
    assert_eq!(0, system_state.queues().output_queues_message_count());
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: UNIX_EPOCH,
            state: IngressState::Completed(WasmResult::Reject("MONOLORD".to_string())),
        }
    );
}

#[test]
fn output_requests_on_system_subnet_ignore_memory_limits() {
    let log_memory_usage = 3 * 4096;
    let canister_memory: u64 = 1 << 30;
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        // subnet memory capacity is exactly equal to canister memory allocation + log memory usage
        .with_subnet_execution_memory(canister_memory + log_memory_usage)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(13)
        .with_resource_saturation_scaling(1)
        .with_manual_execution()
        .build();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000), None, Some(canister_memory))
        .unwrap();
    test.install_canister(canister_id, wat::parse_str(CALL_SIMPLE_WAT).unwrap())
        .unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);

    assert_eq!(test.subnet_available_memory().get_execution_memory(), 0);
    assert_eq!(
        test.subnet_available_memory()
            .get_guaranteed_response_message_memory(),
        13
    );
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    assert_eq!(
        1,
        system_state
            .queues()
            .guaranteed_response_memory_reservations()
    );
    assert_correct_request(system_state, canister_id);
}

#[test]
fn output_requests_on_application_subnets_respect_subnet_message_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(13)
        .with_resource_saturation_scaling(1)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    let available_memory_after_create = test.subnet_available_memory().get_execution_memory();
    assert_eq!(
        available_memory_after_create + test.state().memory_taken().execution().get() as i64,
        ONE_GIB as i64,
    );
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    assert_eq!(
        available_memory_after_create,
        test.subnet_available_memory().get_execution_memory()
            + test
                .canister_state(canister_id)
                .log_memory_store_memory_usage()
                .get() as i64,
    );
    assert_eq!(
        13,
        test.subnet_available_memory()
            .get_guaranteed_response_message_memory()
    );
    let system_state = &test.canister_state(canister_id).system_state;
    assert!(!system_state.queues().has_output());
}

#[test]
fn output_requests_on_application_subnets_update_subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(ONE_GIB)
        .with_resource_saturation_scaling(1)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    let available_memory_after_create = test.subnet_available_memory().get_execution_memory();
    assert_eq!(
        available_memory_after_create + test.state().memory_taken().execution().get() as i64,
        ONE_GIB as i64
    );
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    let subnet_total_memory = test.subnet_available_memory().get_execution_memory();
    let subnet_message_memory = test
        .subnet_available_memory()
        .get_guaranteed_response_message_memory();
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    // There should be one response memory reservation in the queues.
    assert_eq!(
        1,
        system_state
            .queues()
            .guaranteed_response_memory_reservations()
    );
    // Subnet available memory should have decreased by `MAX_RESPONSE_COUNT_BYTES` and by default log memory usage.
    assert_eq!(
        available_memory_after_create - LOG_MEMORY_USAGE,
        subnet_total_memory
    );
    assert_eq!(
        (ONE_GIB - MAX_RESPONSE_COUNT_BYTES as u64) as i64,
        subnet_message_memory
    );
    assert_correct_request(system_state, canister_id);
}

#[test]
fn output_best_effort_requests_on_application_subnets_update_subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(ONE_GIB)
        .with_resource_saturation_scaling(1)
        .with_manual_execution()
        .build();
    let canister_id = test.canister_from_wat(CALL_BEST_EFFORT_WAT).unwrap();
    let initial_available_memory = test.subnet_available_memory().get_execution_memory();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    let subnet_total_memory = test.subnet_available_memory().get_execution_memory();
    let subnet_message_memory = test
        .subnet_available_memory()
        .get_guaranteed_response_message_memory();
    let log_memory_usage = test
        .canister_state(canister_id)
        .log_memory_store_memory_usage()
        .get() as i64;
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    // There should be no response memory reservation in the queues.
    assert_eq!(
        0,
        system_state
            .queues()
            .guaranteed_response_memory_reservations()
    );
    // But there should be one response slot reservation.
    assert_eq!(1, system_state.queues().input_queues_reserved_slots());
    // Subnet available memory only changes due to log memory usage.
    assert_eq!(
        initial_available_memory,
        subnet_total_memory + log_memory_usage
    );
    // Message memory should be unchanged.
    assert_eq!(ONE_GIB as i64, subnet_message_memory);
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
    assert_eq!(1, system_state.queues().output_queues_message_count());
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
    assert_eq!(2, system_state.queues().output_queues_message_count());
    assert_correct_request(system_state, canister_id);
    let message = system_state.queues_mut().pop_canister_output(&uc).unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, uc);
        assert_eq!(msg.respondent, canister_id);
        assert_eq!(msg.response_payload, Payload::Data(b"MONOLORD".to_vec()));
    } else {
        panic!("unexpected message popped: {message:?}");
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
    assert_eq!(1, system_state.queues().output_queues_message_count());
    let message = system_state.queues_mut().pop_canister_output(&uc).unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, uc);
        assert_eq!(msg.respondent, canister_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext::new(RejectCode::CanisterReject, "MONOLORD"))
        );
    } else {
        panic!("unexpected message popped: {message:?}");
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
        .inter_update(c_id, call_args().other_side(c).on_reply(b_callback))
        .build();
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();

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
    assert_eq!(1, system_state.queues().output_queues_message_count());
    let message = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext::new(RejectCode::CanisterReject, "error"))
        );
    } else {
        panic!("unexpected message popped: {message:?}");
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
        .inter_update(c_id, call_args().other_side(c).on_reply(b_callback))
        .build();
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();

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
    assert_eq!(0, system_state.queues().output_queues_message_count());
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
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();
    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.stop_canister(b_id);
    assert_eq!(
        test.canister_state(b_id).system_state.status(),
        CanisterStatusType::Stopping
    );
    test.execute_message(b_id);
    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());
    let message = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!("IC0509: Canister {b_id} is not running")
            ))
        );
    } else {
        panic!("unexpected message popped: {message:?}");
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
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();
    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.stop_canister(b_id);
    test.process_stopping_canisters();
    assert_eq!(
        test.canister_state(b_id).system_state.status(),
        CanisterStatusType::Stopped
    );
    test.execute_message(b_id);
    let system_state = &mut test.canister_state_mut(b_id).system_state;
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());
    let message = system_state
        .queues_mut()
        .pop_canister_output(&a_id)
        .unwrap();
    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(
            msg.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!("IC0508: Canister {b_id} is not running")
            ))
        );
    } else {
        panic!("unexpected message popped: {message:?}");
    }
}

#[test]
fn stopping_an_already_stopped_canister_succeeds() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    test.process_stopping_canisters();
    let ingress_status = test.ingress_status(&ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Completed(WasmResult::Reply(EmptyBlob.encode())),
        }
    );
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    test.process_stopping_canisters();
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Completed(WasmResult::Reply(EmptyBlob.encode())),
        }
    );
}

#[test]
fn stopping_a_running_canister_updates_ingress_history() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
}

#[test]
fn stopping_a_stopping_canister_updates_ingress_history() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
}

#[test]
fn stopping_a_canister_with_incorrect_controller_fails() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let canister_id = test.universal_canister().unwrap();
    let controller = test.user_id();
    test.set_user_id(user_test_id(13));
    let ingress_id = test.stop_canister(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    let IngressStatus::Known {
        receiver,
        user_id,
        time,
        state: IngressState::Failed(error),
    } = ingress_status
    else {
        panic!("Unexpected ingress status {ingress_status:?}")
    };
    assert_eq!(receiver, ic00::IC_00.get());
    assert_eq!(user_id, user_test_id(13));
    assert_eq!(time, test.time());
    error.assert_contains(
        ErrorCode::CanisterInvalidController,
        &format!(
            "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
            canister_id,
            controller.get(),
            user_test_id(13).get()
        ),
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
    let canister_state = test.canister_state(canister);
    assert_eq!(csr.status(), CanisterStatusType::Running);
    assert_eq!(csr.controllers(), vec![controller.get()]);
    assert_eq!(
        Cycles::new(csr.cycles()),
        canister_state.system_state.balance()
    );
    assert_eq!(csr.freezing_threshold(), 2_592_000);
    assert_eq!(csr.memory_allocation(), 0);
    assert_eq!(
        csr.memory_size(),
        test.execution_state(canister).memory_usage()
            + canister_state.canister_history_memory_usage()
            + canister_state.log_memory_store_memory_usage()
    );
    assert_eq!(
        Cycles::new(csr.idle_cycles_burned_per_day()),
        test.idle_cycles_burned_per_day(canister)
    );
}

#[test]
fn get_canister_status_from_another_canister_when_memory_low() {
    let mut test = ExecutionTestBuilder::new().build();
    let controller = test.universal_canister().unwrap();
    let binary = wat::parse_str("(module)").unwrap();
    let canister = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000), None, None)
        .unwrap();
    test.install_canister(canister, binary).unwrap();
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
    let one_gib: u128 = ONE_GIB as u128;
    let seconds_per_day = 24 * 3600;
    assert_eq!(
        csr.idle_cycles_burned_per_day(),
        (csr.memory_size().get() as u128
            * seconds_per_day
            * test
                .cycles_account_manager()
                .gib_storage_per_second_fee(test.subnet_size(), CanisterCyclesCostSchedule::Normal)
                .get())
            / one_gib
    );
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
fn get_canister_status_memory_metrics() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();

    let wasm_memory_size = csr.wasm_memory_size();
    let stable_memory_size = csr.stable_memory_size();
    let global_memory_size = csr.global_memory_size();
    let wasm_binary_size = csr.wasm_binary_size();
    let custom_sections_size = csr.custom_sections_size();

    let execution_memory_size = wasm_memory_size
        + stable_memory_size
        + global_memory_size
        + wasm_binary_size
        + custom_sections_size;

    let canister_history_size = csr.canister_history_size();
    let wasm_chunk_store_size = csr.wasm_chunk_store_size();
    let log_memory_store_size = csr.log_memory_store_size();
    let snapshots_size = csr.snapshots_size();

    let system_memory_size =
        canister_history_size + wasm_chunk_store_size + snapshots_size + log_memory_store_size;

    let memory_size = csr.memory_size();
    assert_eq!(memory_size, execution_memory_size + system_memory_size);
}

#[test]
fn get_canister_status_memory_metrics_wasm_memory_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();

    assert_eq!(
        test.canister_status(canister_id)
            .unwrap()
            .wasm_memory_size(),
        csr.wasm_memory_size()
    );

    let canister_status_args = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
    let get_canister_status = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterStatus,
            call_args().other_side(canister_status_args),
        )
        .build();
    let result = test.ingress(canister_id, "update", get_canister_status);
    let reply = get_reply(result);
    let updated_csr = CanisterStatusResultV2::decode(&reply).unwrap();

    assert_gt!(updated_csr.wasm_memory_size(), csr.wasm_memory_size());
}

#[test]
fn get_canister_status_memory_metrics_stable_memory_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    test.ingress(
        canister_id,
        "update",
        wasm()
            .stable64_grow(1)
            .stable64_read(WASM_PAGE_SIZE_IN_BYTES as u64 - 1, 1)
            .push_bytes(&[])
            .append_and_reply()
            .build(),
    )
    .unwrap();
    assert_eq!(
        test.canister_status(canister_id)
            .unwrap()
            .stable_memory_size(),
        csr.stable_memory_size() + NumBytes::from(WASM_PAGE_SIZE_IN_BYTES as u64)
    );
}

#[test]
fn get_canister_status_memory_metrics_global_memory_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    let exported_globals = test.execution_state(canister_id).exported_globals.clone();
    assert_eq!(
        csr.global_memory_size(),
        NumBytes::new(32 * exported_globals.len() as u64)
    );
}

#[test]
fn get_canister_status_memory_metrics_wasm_binary_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    assert_eq!(
        csr.wasm_binary_size(),
        NumBytes::new(UNIVERSAL_CANISTER_WASM.len() as u64)
    );
}

#[test]
fn get_canister_status_memory_metrics_custom_sections_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    let metadata = test.execution_state(canister_id).metadata.clone();
    assert_eq!(
        csr.custom_sections_size(),
        NumBytes::new(
            metadata
                .custom_sections()
                .iter()
                .map(|(k, v)| k.len() + v.count_bytes())
                .sum::<usize>() as u64
        ),
    );
}

#[test]
fn get_canister_status_memory_metrics_canister_history_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    test.set_controller(canister_id, test.user_id().get())
        .unwrap();
    let memory_difference =
        NumBytes::from((size_of::<CanisterChange>() + size_of::<PrincipalId>()) as u64);
    assert_eq!(
        test.canister_status(canister_id)
            .unwrap()
            .canister_history_size(),
        csr.canister_history_size() + memory_difference
    );
}

#[test]
fn get_canister_status_memory_metrics_wasm_chunk_store_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    test.subnet_message(
        "upload_chunk",
        UploadChunkArgs {
            canister_id: canister_id.into(),
            chunk: vec![1, 2, 3, 4, 5],
        }
        .encode(),
    )
    .unwrap();
    assert_gt!(
        test.canister_status(canister_id)
            .unwrap()
            .wasm_chunk_store_size(),
        csr.wasm_chunk_store_size()
    );
}

#[test]
fn get_canister_status_memory_metrics_snapshots_size() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let csr = test.canister_status(canister_id).unwrap();
    test.subnet_message(
        "take_canister_snapshot",
        TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        }
        .encode(),
    )
    .unwrap();
    assert_gt!(
        test.canister_status(canister_id).unwrap().snapshots_size(),
        csr.snapshots_size()
    );
}

// A Wasm module with custom sections
const CUSTOM_SECTIONS_WAT: &str = r#"(module
(memory $memory 1)
(export "memory" (memory $memory))
(@custom "icp:public my_public_section" "my_public_section_value✅")
(@custom "icp:private my_private_section" "my_private_section_value")
)"#;

#[test]
fn get_canister_metadata_success() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.canister_from_wat(CUSTOM_SECTIONS_WAT).unwrap();
    let caller = test.universal_canister().unwrap();

    let canister_metadata_args =
        CanisterMetadataRequest::new(canister, "my_public_section".to_string()).encode();
    let get_canister_metadata = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterMetadata,
            call_args().other_side(canister_metadata_args),
        )
        .build();
    let result = test.ingress(caller, "update", get_canister_metadata);
    let reply = get_reply(result);
    let response = CanisterMetadataResponse::decode(&reply).unwrap();

    assert_eq!(response.value(), b"my_public_section_value\xE2\x9C\x85");
}

#[test]
fn get_canister_metadata_no_execution_state_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.create_canister_with_default_cycles();
    let caller = test.universal_canister().unwrap();

    let canister_metadata_args =
        CanisterMetadataRequest::new(canister, "my_public_section".to_string()).encode();
    let get_canister_metadata = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterMetadata,
            call_args()
                .other_side(canister_metadata_args)
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let result = test.ingress(caller, "update", get_canister_metadata);

    let reject = get_reject(result);
    assert!(
        reject.contains("has no Wasm module and hence no metadata is available")
            && reject.contains(&canister.to_string())
    );
}

#[test]
fn get_canister_metadata_not_found_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.canister_from_wat(CUSTOM_SECTIONS_WAT).unwrap();
    let caller = test.universal_canister().unwrap();

    let canister_metadata_args =
        CanisterMetadataRequest::new(canister, "my_not_found_section".to_string()).encode();
    let get_canister_metadata = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterMetadata,
            call_args()
                .other_side(canister_metadata_args)
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let result = test.ingress(caller, "update", get_canister_metadata);

    let reject = get_reject(result);
    assert!(
        reject.contains("has no metadata section with the name my_not_found_section")
            && reject.contains(&canister.to_string())
    );
}

#[test]
fn get_canister_metadata_private_section_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.canister_from_wat(CUSTOM_SECTIONS_WAT).unwrap();
    let caller = test.universal_canister().unwrap();

    let canister_metadata_args =
        CanisterMetadataRequest::new(canister, "my_private_section".to_string()).encode();
    let get_canister_metadata = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterMetadata,
            call_args()
                .other_side(canister_metadata_args)
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let result = test.ingress(caller, "update", get_canister_metadata);

    let reject = get_reject(result);
    assert!(
        reject.contains("has no metadata section with the name my_private_section")
            && reject.contains(&canister.to_string())
    );
}

#[test]
fn get_canister_metadata_private_section_succeeds_for_controller() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller = test.universal_canister().unwrap();
    let canister = test.canister_from_wat(CUSTOM_SECTIONS_WAT).unwrap();
    test.canister_update_controller(canister, vec![caller.get()])
        .unwrap();

    let canister_metadata_args =
        CanisterMetadataRequest::new(canister, "my_private_section".to_string()).encode();
    let get_canister_metadata = wasm()
        .call_simple(
            ic00::IC_00,
            Method::CanisterMetadata,
            call_args().other_side(canister_metadata_args),
        )
        .build();
    let result = test.ingress(caller, "update", get_canister_metadata);

    let reply = get_reply(result);
    let response = CanisterMetadataResponse::decode(&reply).unwrap();
    assert_eq!(response.value(), b"my_private_section_value");
}

#[test]
fn deposit_cycles_to_non_existing_canister_fails() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_u128 << 62)
        .build();
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
            Cycles::from((1_u128 << 61) + (1_u128 << 60)),
        )
        .build();
    let result = test.ingress(controller, "update", deposit).unwrap();
    assert_eq!(
        WasmResult::Reject(format!("Canister {canister} not found.")),
        result
    );
    let controller_balance = test.canister_state(controller).system_state.balance().get();
    assert!(controller_balance <= 1_u128 << 62);
    assert!(controller_balance >= (1_u128 << 62) - 100_000_000_000);
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
    assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
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
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
}

#[test]
fn stop_canister_creates_entry_in_subnet_call_context_manager() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // SubnetCallContextManager does not contain any stop canister requests before executing the message.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        0
    );

    // Inject a stop canister request.
    test.inject_call_to_ic00(
        Method::StopCanister,
        Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
        Cycles::new(1_000_000_000),
    );
    assert_eq!(
        CanisterStatusType::Running,
        test.canister_state(canister_id).status()
    );

    test.execute_subnet_message();
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id).status()
    );
    assert!(
        test.canister_state(canister_id)
            .system_state
            .ready_to_stop()
    );
    // SubnetCallContextManager contains a stop canister requests after executing the message.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        1
    );

    // Inject another stop canister request.
    // Executing this request will add another entry in the SubnetCallContextManager.
    test.inject_call_to_ic00(
        Method::StopCanister,
        Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id).status()
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        2
    );

    // Stops canister and removes all the stop canister requests from SubnetCallContextManager.
    test.process_stopping_canisters();

    // SubnetCallContextManager does not contain any stop canister requests after processing the requests.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        0
    );

    // Test metrics are observed for stopping canister functionality.
    assert_eq!(
        metric_vec(&[
            (
                &[
                    (
                        "method_name",
                        "ic00_provisional_create_canister_with_cycles"
                    ),
                    ("outcome", "finished"),
                    ("status", "success"),
                    ("speed", "fast"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "ic00_stop_canister"),
                    ("outcome", "finished"),
                    ("status", "success"),
                    ("speed", "slow"),
                ],
                2
            ),
            (
                &[
                    ("method_name", "ic00_update_settings"),
                    ("outcome", "finished"),
                    ("status", "success"),
                    ("speed", "fast"),
                ],
                1
            )
        ]),
        fetch_histogram_vec_count(
            test.metrics_registry(),
            "execution_subnet_message_duration_seconds"
        )
    );
}

#[test]
fn clean_in_progress_stop_canister_calls_from_subnet_call_context_manager() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create two canisters.
    let canister_id_1 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();
    let canister_id_2 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    // Set controllers.
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id_1, controllers.clone())
        .unwrap();
    test.canister_update_controller(canister_id_2, controllers)
        .unwrap();

    // SubnetCallContextManager does not contain any entries before executing the messages.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        0
    );

    //
    // Test stop canister call with canister request origin.
    //

    // `stop_canister()` only puts the canister in state `Stopping`. The state gets
    // changed from `Stopping` to `Stopped` (if there are no open call contexts) at
    // the end of the round, but the test never executes a full round.
    test.inject_call_to_ic00(
        Method::StopCanister,
        Encode!(&CanisterIdRecord::from(canister_id_1)).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Canister 1 is now in state `Stopping`.
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id_1).status()
    );
    // And `SubnetCallContextManager` contains one `StopCanisterCall`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        1
    );

    // Helper function for invoking `after_split()`.
    fn after_split(state: &mut ReplicatedState) {
        state.metadata.split_from = Some(state.metadata.own_subnet_id);
        state.after_split();
    }

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `StopCanisterCall` and does not produce a response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        1
    );
    assert!(!test.state().subnet_queues().has_output());

    // Simulate a subnet split that migrates canister 1 to another subnet.
    test.state_mut().take_canister_state(&canister_id_1);
    after_split(test.state_mut());

    // Should have removed the `StopCanisterCall` and produced a reject response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        0
    );
    assert!(test.state().subnet_queues().has_output());

    //
    // Test stop canister call with ingress origin.
    //
    let ingress_id = test.stop_canister(canister_id_2);

    // Canister 2 is now in state `Stopping`.
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id_2).status()
    );
    // And `SubnetCallContextManager` contains one `StopCanisterCall`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        1
    );

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `StopCanisterCall` and does not change the ingress state.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        1
    );
    assert_eq!(
        test.ingress_status(&ingress_id),
        IngressStatus::Known {
            receiver: ic00::IC_00.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        } // As opposed to `Known::Failed`.
    );

    // Simulate a subnet split that migrates canister 2 to another subnet.
    test.state_mut().take_canister_state(&canister_id_2);
    after_split(test.state_mut());

    // Should have removed the `StopCanisterCall` and set the ingress state to `Failed`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .stop_canister_calls_len(),
        0
    );
    assert_eq!(
        check_ingress_status(test.ingress_status(&ingress_id)),
        Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id_2} migrated during a subnet split"),
        ))
    );
}

/// Ensures that in-progress stop canister calls are left in a consistent state
/// after a subnet split: i.e. there is no stop canister call that is tracked by
/// a canister, but not by the subnet call context manager; or the other way
/// around.
#[test]
fn consistent_stop_canister_calls_after_split() {
    let subnet_a = subnet_test_id(1);
    let subnet_b = subnet_test_id(2);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(subnet_a)
        .with_manual_execution()
        .with_caller(subnet_a, caller_canister)
        .build();

    // Create two canisters.
    let canister_id_1 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();
    let canister_id_2 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    // Set controllers.
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id_1, controllers.clone())
        .unwrap();
    test.canister_update_controller(canister_id_2, controllers)
        .unwrap();

    // No in-progress stop canister calls across the subnet.
    assert_consistent_stop_canister_calls(test.state(), 0);

    // Start executing one stop canister call as canister request on each canister.
    //
    // `stop_canister()` only puts the canister in state `Stopping`. The state gets
    // changed from `Stopping` to `Stopped` (if there are no open call contexts) at
    // the end of the round, but the test never executes a full round.
    test.inject_call_to_ic00(
        Method::StopCanister,
        Encode!(&CanisterIdRecord::from(canister_id_1)).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();
    test.inject_call_to_ic00(
        Method::StopCanister,
        Encode!(&CanisterIdRecord::from(canister_id_2)).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Start executing one stop canister call as ingress message on each canister.
    test.stop_canister(canister_id_1);
    test.stop_canister(canister_id_2);

    // 4 in-progress stop canister calls across the subnet.
    assert_consistent_stop_canister_calls(test.state(), 4);

    // Retain canister 1 on subnet A, migrate canister 2 to subnet B.
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {start: canister_id_1, end: canister_id_1} => subnet_a,
        CanisterIdRange {start: canister_id_2, end: canister_id_2} => subnet_b,
    })
    .unwrap();

    // Split subnet A'.
    let mut state_a = test
        .state()
        .clone()
        .split(subnet_a, &routing_table, None)
        .unwrap();

    // Restore consistency between stop canister calls tracked by canisters and subnet.
    state_a.after_split();

    // 2 in-progress stop canister calls across subnet A'.
    assert_consistent_stop_canister_calls(&state_a, 2);

    // Split subnet B.
    let mut state_b = test
        .state()
        .clone()
        .split(subnet_b, &routing_table, None)
        .unwrap();

    // Restore consistency between stop canister calls tracked by canisters and subnet.
    state_b.after_split();

    // 0 in-progress stop canister calls across subnet B.
    assert_consistent_stop_canister_calls(&state_b, 0);
}

#[test]
fn canister_snapshots_after_split() {
    let subnet_a = subnet_test_id(1);
    let subnet_b = subnet_test_id(2);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(subnet_a)
        .with_manual_execution()
        .with_caller(subnet_a, caller_canister)
        .build();

    // Create two universal canisters.
    let canister_id_1 = test
        .universal_canister_with_cycles(Cycles::new(1_000_000_000_000_000))
        .unwrap();
    let canister_id_2 = test
        .universal_canister_with_cycles(Cycles::new(1_000_000_000_000_000))
        .unwrap();

    // Set controllers.
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id_1, controllers.clone())
        .unwrap();
    test.canister_update_controller(canister_id_2, controllers)
        .unwrap();

    // The snapshots do not exist in the replicated state before the requests.
    assert_eq!(
        test.state()
            .canister_snapshots
            .list_snapshots(canister_id_1)
            .len(),
        0
    );
    assert_eq!(
        test.state()
            .canister_snapshots
            .list_snapshots(canister_id_2)
            .len(),
        0
    );

    // Take canister snapshot for each canister.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id_1, None, None, None);
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        Encode!(&args).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id_2, None, None, None);
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        Encode!(&args).unwrap(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Verify the snapshots exist in the replicated state.
    assert_eq!(
        test.state()
            .canister_snapshots
            .list_snapshots(canister_id_1)
            .len(),
        1
    );
    assert_eq!(
        test.state()
            .canister_snapshots
            .list_snapshots(canister_id_2)
            .len(),
        1
    );

    // Simulate that there's a checkpoint right before starting the subnet split.
    // For the purpose of this test, we need to clear heap_delta_estimate and
    // expected_compiled_wasms cache (a subnet split assumes it happens after a
    // checkpoint round where these two happen among other things).
    test.state_mut().metadata.heap_delta_estimate = NumBytes::from(0);
    test.state_mut().metadata.expected_compiled_wasms.clear();

    // Retain canister 1 on subnet A, migrate canister 2 to subnet B.
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {start: canister_id_1, end: canister_id_1} => subnet_a,
        CanisterIdRange {start: canister_id_2, end: canister_id_2} => subnet_b,
    })
    .unwrap();

    // Split subnet A'.
    let mut state_a = test
        .state()
        .clone()
        .split(subnet_a, &routing_table, None)
        .unwrap();

    // Restore consistency between canister snapshots tracked by canisters and subnet.
    state_a.after_split();

    // Split subnet B.
    let mut state_b = test
        .state()
        .clone()
        .split(subnet_b, &routing_table, None)
        .unwrap();

    // Restore consistency between canister snapshots tracked by canisters and subnet.
    state_b.after_split();

    // Splitting the original subnet into subnet A' and subnet B,
    // canister snapshots should also be moved to the correct subnet.

    assert_eq!(
        state_a
            .canister_snapshots
            .list_snapshots(canister_id_1)
            .len(),
        1
    );
    assert_eq!(
        state_a
            .canister_snapshots
            .list_snapshots(canister_id_2)
            .len(),
        0
    );

    assert_eq!(
        state_b
            .canister_snapshots
            .list_snapshots(canister_id_2)
            .len(),
        1
    );
    assert_eq!(
        state_b
            .canister_snapshots
            .list_snapshots(canister_id_1)
            .len(),
        0
    );
}

/// Helper function asserting that there is an exact match between in-progress
/// stop canister calls tracked by the subnet call context manager on the one
/// hand; and by the canisters, on the other.
fn assert_consistent_stop_canister_calls(state: &ReplicatedState, expected_calls: usize) {
    // Collect all `StopCanisterContexts` from all stopping canisters.
    let canister_stop_canister_contexts: Vec<_> = state
        .canister_states
        .values()
        .filter_map(|canister| {
            if let CanisterStatus::Stopping {
                call_context_manager: _,
                stop_contexts,
            } = canister.system_state.get_status()
            {
                Some(stop_contexts.iter().cloned())
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert_eq!(expected_calls, canister_stop_canister_contexts.len());

    // Clone the `SubnetCallContextManager` and remove all calls collected above from it.
    let mut subnet_call_context_manager = state.metadata.subnet_call_context_manager.clone();
    for context in canister_stop_canister_contexts {
        subnet_call_context_manager
            .remove_stop_canister_call(context.call_id().unwrap())
            .unwrap_or_else(|| {
                panic!(
                    "Canister StopCanisterContext without matching subnet StopCanisterCall: {context:?}"
                )
            });
    }

    // And ensure that no `StopCanisterCalls` are left over in the `SubnetCallContextManager`.
    assert!(
        subnet_call_context_manager.stop_canister_calls_len() == 0,
        "StopCanisterCalls in SubnetCallContextManager without matching canister StopCanisterContexts: {:?}",
        subnet_call_context_manager.remove_non_local_stop_canister_calls(|_| false)
    );
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
        let ingress_status = test.ingress_status(&ingress_id);
        let err = check_ingress_status(ingress_status).unwrap_err();
        assert_eq!(ErrorCode::CanisterStoppingCancelled, err.code());
    }
}

#[test]
fn subnet_ingress_message_unknown_method() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message("unknown", EmptyBlob.encode())
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
                .other_side(EmptyBlob.encode())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    assert_eq!(
        test.ingress(canister, "update", run).unwrap(),
        WasmResult::Reject("IC0536: Management canister has no method 'unknown'".to_string())
    );
}

#[test]
fn subnet_ingress_message_on_create_canister_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message(Method::CreateCanister, EmptyBlob.encode())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "create_canister cannot be called by a user.",
        err.description()
    );
}

#[test]
fn subnet_canister_request_bad_candid_payload() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .subnet_message(Method::InstallCode, vec![1, 2, 3])
        .unwrap_err();
    assert_eq!(ErrorCode::InvalidManagementPayload, err.code());
    assert_eq!(
        err.description(),
        "Error decoding candid: Cannot parse header 010203: binary parser error: io error"
    );
}

#[test]
fn management_canister_xnet_to_nns_called_from_non_nns() {
    let own_subnet = subnet_test_id(1);
    let other_subnet = subnet_test_id(2);
    let other_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(own_subnet)
        .with_caller(other_subnet, other_canister)
        .build();
    test.state_mut().metadata.own_subnet_features.http_requests = true;

    test.inject_call_to_ic00(
        Method::CreateCanister,
        EmptyBlob.encode(),
        test.canister_creation_fee(),
    );
    test.inject_call_to_ic00(Method::RawRand, EmptyBlob.encode(), Cycles::from(0_u64));
    test.inject_call_to_ic00(
        Method::HttpRequest,
        EmptyBlob.encode(),
        test.http_request_fee(NumBytes::from(0), None),
    );
    test.execute_all();
    for response in test.xnet_messages().clone() {
        assert_eq!(
            get_reject_message(response),
            format!(
                "Incorrect sender subnet id: {other_subnet}. Sender should be on the same subnet or on the NNS subnet."
            )
        );
    }
}

#[test]
fn http_request_bound_holds() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        // set number of max in-flight calls to 10
        .with_max_canister_http_requests_in_flight(10)
        .build();
    test.state_mut().metadata.own_subnet_features.http_requests = true;

    // Create payload of the request.
    let url = "https://".to_string();
    let response_size_limit = 1000u64;
    let transform_method_name = "transform".to_string();
    let transform_context = vec![0, 1, 2];
    let args = CanisterHttpRequestArgs {
        url: url.clone(),
        max_response_bytes: Some(response_size_limit),
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: caller_canister.get().0,
                method: transform_method_name.clone(),
            }),
            context: transform_context.clone(),
        }),
        is_replicated: None,
        pricing_version: None,
    };

    // Create request to HTTP_REQUEST method.
    let payload = args.clone().encode();
    test.inject_call_to_ic00(Method::HttpRequest, payload, Cycles::new(1_000_000_000));
    test.execute_all();
    // Check that the SubnetCallContextManager contains the request.
    let canister_http_request_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;
    assert_eq!(canister_http_request_contexts.len(), 1);

    // Now we try to inject more than the maximum number of requests we allow to be in-flight

    for _ in 0..15 {
        let payload = args.clone().encode();
        test.inject_call_to_ic00(Method::HttpRequest, payload, Cycles::new(1_000_000_000));
    }

    test.execute_all();
    let canister_http_request_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;

    // Check that the SubnetCallContextManager contains the maximum number but not more
    assert_eq!(canister_http_request_contexts.len(), 10);
}

#[test]
fn management_canister_xnet_called_from_non_nns() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let other_subnet = subnet_test_id(3);
    let other_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(other_subnet, other_canister)
        .build();
    test.state_mut().metadata.own_subnet_features.http_requests = true;

    test.inject_call_to_ic00(
        Method::CreateCanister,
        EmptyBlob.encode(),
        test.canister_creation_fee(),
    );
    test.inject_call_to_ic00(Method::RawRand, EmptyBlob.encode(), Cycles::from(0_u64));
    test.inject_call_to_ic00(
        Method::HttpRequest,
        EmptyBlob.encode(),
        test.http_request_fee(NumBytes::from(0), None),
    );
    test.execute_all();
    for response in test.xnet_messages().clone() {
        assert_eq!(
            get_reject_message(response),
            format!(
                "Incorrect sender subnet id: {other_subnet}. Sender should be on the same subnet or on the NNS subnet."
            )
        );
    }
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
        EmptyBlob.encode(),
        test.canister_creation_fee(),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    let RequestOrResponse::Response(response) = response else {
        panic!("Type should be RequestOrResponse::Response");
    };
    assert_eq!(response.originator, nns_canister);
    assert_eq!(response.respondent, CanisterId::from(own_subnet));
    assert_eq!(response.refund, Cycles::new(0));
    let Payload::Data(_) = response.response_payload else {
        panic!("Failed creating the canister.");
    };
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
        Response {
            originator: other_canister,
            respondent: CanisterId::from(own_subnet),
            originator_reply_callback: CallbackId::new(0),
            refund: test.canister_creation_fee(),
            response_payload: Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!(
                    "{} is called by {}. It can only be called by NNS.",
                    ic00::Method::SetupInitialDKG,
                    other_canister,
                )
            )),
            deadline: NO_DEADLINE,
        }
        .into()
    );
}

#[test]
fn metrics_are_observed_for_subnet_messages() {
    let mut test = ExecutionTestBuilder::new().build();
    let methods: [ic00::Method; 5] = [
        ic00::Method::CreateCanister,
        ic00::Method::InstallCode,
        ic00::Method::StartCanister,
        ic00::Method::StopCanister,
        ic00::Method::DeleteCanister,
    ];

    for method in methods.iter() {
        test.subnet_message(method, EmptyBlob.encode()).unwrap_err();
    }

    test.subnet_message("nonexisting", EmptyBlob.encode())
        .unwrap_err();

    assert_eq!(
        metric_vec(&[
            (
                &[
                    ("method_name", "ic00_create_canister"),
                    ("outcome", "error"),
                    ("status", "CanisterContractViolation"),
                    ("speed", "fast"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "ic00_install_code"),
                    ("outcome", "error"),
                    ("status", "InvalidManagementPayload"),
                    ("speed", "slow"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "ic00_start_canister"),
                    ("outcome", "error"),
                    ("status", "InvalidManagementPayload"),
                    ("speed", "fast"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "ic00_stop_canister"),
                    ("outcome", "error"),
                    ("status", "InvalidManagementPayload"),
                    ("speed", "slow"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "ic00_delete_canister"),
                    ("outcome", "error"),
                    ("status", "InvalidManagementPayload"),
                    ("speed", "fast"),
                ],
                1
            ),
            (
                &[
                    ("method_name", "unknown_method"),
                    ("outcome", "error"),
                    ("status", "CanisterMethodNotFound"),
                    ("speed", "unknown_speed"),
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
        .accept_cycles(Cycles::from(1_000_000u128))
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
            Cycles::from(1_000_000u128),
        )
        .build();
    test.canister_state_mut(b_id).system_state.freeze_threshold = NumSeconds::from(0);
    test.canister_state_mut(b_id)
        .system_state
        .set_balance(Cycles::new(1_000));
    let result = test.ingress(a_id, "update", a);
    let reply = get_reply(result);
    let error = std::str::from_utf8(&reply).unwrap();
    assert!(error.contains("out of cycles"), "Unexpected error: {error}");
}

#[test]
fn can_reject_an_ingress_when_canister_is_out_of_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let id = test.universal_canister().unwrap();
    test.canister_state_mut(id).system_state.freeze_threshold = NumSeconds::from(0);
    test.canister_state_mut(id)
        .system_state
        .set_balance(Cycles::new(1_000));
    let run = wasm().message_payload().append_and_reply().build();
    let err = test.ingress(id, "update", run).unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
    assert_eq!(
        Cycles::new(1_000),
        test.canister_state(id).system_state.balance()
    );
}

#[test]
fn message_to_empty_canister_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));

    let test_empty_canister = |test: &mut ExecutionTest| {
        let err = test
            .should_accept_ingress_message(canister, "query", vec![])
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterWasmModuleNotFound, err.code());
        let err = test
            .non_replicated_query(canister, "query", wasm().reply().build())
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterWasmModuleNotFound, err.code());
    };

    test_empty_canister(&mut test);

    test.install_canister(canister, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    test.should_accept_ingress_message(canister, "query", vec![])
        .unwrap();
    test.non_replicated_query(canister, "query", wasm().reply().build())
        .unwrap();

    test.uninstall_code(canister).unwrap();

    test_empty_canister(&mut test);
}

#[test]
fn message_to_deleted_canister_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));

    test.stop_canister(canister);
    test.process_stopping_canisters();
    test.delete_canister(canister).unwrap();
    let err = test
        .should_accept_ingress_message(canister, "query", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterNotFound, err.code());
    let err = test
        .non_replicated_query(canister, "query", wasm().reply().build())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterNotFound, err.code());
}

#[test]
fn can_reject_all_ingress_messages() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm().set_inspect_message(wasm().build()).reply().build(),
    )
    .unwrap();
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterRejectedMessage, err.code());

    // Inter-canister calls still work.
    let caller = test.universal_canister().unwrap();
    let res = test
        .ingress(
            caller,
            "update",
            wasm().inter_update(canister, CallArgs::default()).build(),
        )
        .unwrap();
    let expected_reply = [
        b"Hello ",
        caller.get().as_slice(),
        b" this is ",
        canister.get().as_slice(),
    ]
    .concat();
    match res {
        WasmResult::Reply(data) => assert_eq!(data, expected_reply),
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };
}

#[test]
fn trap_instead_of_accepting_message() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm()
            .set_inspect_message(wasm().trap().build())
            .reply()
            .build(),
    )
    .unwrap();
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
}

#[test]
fn inspect_method_name() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm()
            .set_inspect_message(
                wasm()
                    .msg_method_name()
                    .trap_if_eq("update", "no no no")
                    .accept_message()
                    .build(),
            )
            .reply()
            .build(),
    )
    .unwrap();
    let err = test
        .should_accept_ingress_message(canister, "update", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    test.should_accept_ingress_message(canister, "", vec![])
        .unwrap();
}

#[test]
fn inspect_caller() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm()
            .set_inspect_message(
                wasm()
                    .caller()
                    .trap_if_eq(user_test_id(0).get(), "no no no")
                    .accept_message()
                    .build(),
            )
            .reply()
            .build(),
    )
    .unwrap();
    test.set_user_id(user_test_id(0));
    let err = test
        .should_accept_ingress_message(canister, "update", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    test.set_user_id(user_test_id(1));
    test.should_accept_ingress_message(canister, "", vec![])
        .unwrap();
}

#[test]
fn inspect_arg_data() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm()
            .set_inspect_message(
                wasm()
                    .msg_arg_data_copy(0, 3)
                    .trap_if_eq(b"arg", "no no no")
                    .accept_message()
                    .build(),
            )
            .reply()
            .build(),
    )
    .unwrap();
    let err = test
        .should_accept_ingress_message(canister, "update", b"arg".to_vec())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    test.should_accept_ingress_message(canister, "update", b"foo".to_vec())
        .unwrap();
}

#[test]
fn cannot_accept_message_twice() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.ingress(
        canister,
        "update",
        wasm()
            .set_inspect_message(wasm().accept_message().accept_message().build())
            .reply()
            .build(),
    )
    .unwrap();
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
}

#[test]
fn message_to_canister_with_not_enough_balance_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.canister_state_mut(canister)
        .system_state
        .set_balance(Cycles::new(1_000));
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
}

#[test]
fn message_to_stopping_canister_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.stop_canister(canister);
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterStopping, err.code());
}

#[test]
fn message_to_stopped_canister_is_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.stop_canister(canister);
    test.process_stopping_canisters();
    let err = test
        .should_accept_ingress_message(canister, "", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterStopped, err.code());
}

#[test]
fn should_accept_ingress_filters_correctly_on_method_type() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();

    let result = test.should_accept_ingress_message(canister, "update", vec![]);
    assert_eq!(Ok(()), result);

    let result = test.should_accept_ingress_message(canister, "query", vec![]);
    assert_eq!(Ok(()), result);

    let err = test
        .should_accept_ingress_message(canister, "composite_query", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CompositeQueryCalledInReplicatedMode, err.code());
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
    let canister = test.universal_canister().unwrap();

    let payload = CanisterIdRecord::from(canister).encode();
    let result = test.should_accept_ingress_message(IC_00, Method::StartCanister, payload);
    assert_eq!(Ok(()), result);
}

#[test]
fn management_message_to_canister_with_not_enough_balance_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister = test.universal_canister().unwrap();
    test.canister_state_mut(canister)
        .system_state
        .set_balance(Cycles::new(1_000));

    let payload = CanisterIdRecord::from(canister).encode();
    let err = test
        .should_accept_ingress_message(IC_00, Method::StartCanister, payload)
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());
}

#[test]
fn management_message_to_canister_that_doesnt_exist_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();

    let payload = CanisterIdRecord::from(canister_test_id(0)).encode();
    let err = test
        .should_accept_ingress_message(IC_00, Method::StartCanister, payload)
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterNotFound, err.code());
}

#[test]
fn management_message_with_invalid_payload_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();

    let err = test
        .should_accept_ingress_message(IC_00, Method::StartCanister, vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::InvalidManagementPayload, err.code());
}

#[test]
fn management_message_with_invalid_method_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();

    let err = test
        .should_accept_ingress_message(IC_00, "invalid_method", vec![])
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
}

#[test]
fn management_message_with_forbidden_method_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();

    for forbidden_method in [
        "raw_rand",
        "http_request",
        "ecdsa_public_key",
        "sign_with_ecdsa",
        "deposit_cycles",
    ] {
        let err = test
            .should_accept_ingress_message(IC_00, forbidden_method, vec![])
            .unwrap_err();
        assert_eq!(ErrorCode::CanisterRejectedMessage, err.code());
    }
}

#[test]
fn management_message_with_invalid_sender_is_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    test.set_user_id(user_test_id(0));
    let canister = test.universal_canister().unwrap();
    test.set_user_id(user_test_id(1));
    let arg: CanisterIdRecord = canister.into();
    let err = test
        .should_accept_ingress_message(IC_00, "canister_status", Encode!(&arg).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterInvalidController, err.code());
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
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(ONE_GIB)
        .with_resource_saturation_scaling(1)
        .build();
    let id = test.canister_from_wat(MEMORY_ALLOCATION_WAT).unwrap();
    let memory_after_create = test.state().memory_taken().execution().get() as i64;
    assert_eq!(
        test.subnet_available_memory().get_execution_memory() + memory_after_create,
        ONE_GIB as i64,
    );
    let err = test.ingress(id, "test_with_trap", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let memory = test.subnet_available_memory();
    assert_eq!(
        memory.get_execution_memory() + memory_after_create + LOG_MEMORY_USAGE,
        ONE_GIB as i64
    );
    assert_eq!(
        memory.get_guaranteed_response_message_memory(),
        ONE_GIB as i64
    );
}

#[test]
fn test_allocating_memory_reduces_subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(ONE_GIB)
        .with_resource_saturation_scaling(1)
        .build();
    let id = test.canister_from_wat(MEMORY_ALLOCATION_WAT).unwrap();
    let memory_after_create = test.state().memory_taken().execution().get() as i64;
    assert_eq!(
        test.subnet_available_memory().get_execution_memory() + memory_after_create,
        ONE_GIB as i64,
    );
    let result = test.ingress(id, "test_without_trap", vec![]);
    expect_canister_did_not_reply(result);
    // The canister allocates 10 pages in Wasm memory and stable memory.
    // In addition, the `log_memory_store` allocates some memory.
    let new_memory_allocated = 20 * WASM_PAGE_SIZE_IN_BYTES as i64 + LOG_MEMORY_USAGE;
    let memory = test.subnet_available_memory();
    assert_eq!(
        memory.get_execution_memory() + new_memory_allocated + memory_after_create,
        ONE_GIB as i64,
    );
    assert_eq!(
        ONE_GIB as i64,
        memory.get_guaranteed_response_message_memory()
    );
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
    let response_size_limit = 1000u64;
    let transform_method_name = "transform".to_string();
    let transform_context = vec![0, 1, 2];
    let args = CanisterHttpRequestArgs {
        url: url.clone(),
        max_response_bytes: Some(response_size_limit),
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: caller_canister.get().0,
                method: transform_method_name.clone(),
            }),
            context: transform_context.clone(),
        }),
        is_replicated: None,
        pricing_version: None,
    };

    // Create request to HTTP_REQUEST method.
    let payment = Cycles::new(1_000_000_000);
    let payload = args.encode();
    test.inject_call_to_ic00(Method::HttpRequest, payload, payment);
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
        http_request_context.transform,
        Some(Transform {
            method_name: transform_method_name,
            context: transform_context,
        })
    );
    assert_eq!(http_request_context.http_method, CanisterHttpMethod::GET);
    assert_eq!(http_request_context.request.sender, caller_canister);
    let fee = test.http_request_fee(
        http_request_context.variable_parts_size(),
        Some(NumBytes::from(response_size_limit)),
    );
    assert_eq!(http_request_context.request.payment, payment - fee);

    assert_eq!(
        NominalCycles::from(fee),
        test.state()
            .metadata
            .subnet_metrics
            .consumed_cycles_http_outcalls
    );

    assert_eq!(
        NominalCycles::from(fee),
        *test
            .state()
            .metadata
            .subnet_metrics
            .get_consumed_cycles_by_use_case()
            .get(&CyclesUseCase::HTTPOutcalls)
            .unwrap()
    );
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
    let args = CanisterHttpRequestArgs {
        url,
        max_response_bytes: None,
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: caller_canister.get().0,
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        is_replicated: None,
        pricing_version: None,
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
        RequestOrResponse::Response(resp) => match &resp.response_payload {
            Payload::Data(_) => panic!("Expected Reject"),
            Payload::Reject(reject) => reject.message().clone(),
        },
    }
}

fn make_ecdsa_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    })
}

fn make_ed25519_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: name.to_string(),
    })
}

fn make_bip340_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: name.to_string(),
    })
}

fn make_vetkd_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: name.to_string(),
    })
}

fn into_inner_ecdsa(key_id: MasterPublicKeyId) -> EcdsaKeyId {
    match key_id {
        MasterPublicKeyId::Ecdsa(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

fn into_inner_schnorr(key_id: MasterPublicKeyId) -> SchnorrKeyId {
    match key_id {
        MasterPublicKeyId::Schnorr(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

fn into_inner_vetkd(key_id: MasterPublicKeyId) -> VetKdKeyId {
    match key_id {
        MasterPublicKeyId::VetKd(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

#[test]
fn canister_output_queue_does_not_overflow_when_calling_ic00() {
    let own_subnet = subnet_test_id(1);
    let other_subnet = subnet_test_id(2);
    let other_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(own_subnet)
        .with_caller(other_subnet, other_canister)
        .with_initial_canister_cycles(1_000_000_000_000_000_000)
        .with_manual_execution()
        .build();

    let uc = test.universal_canister().unwrap();

    for i in 1..=2 * DEFAULT_QUEUE_CAPACITY {
        let target = if i < DEFAULT_QUEUE_CAPACITY / 2 {
            other_subnet.get()
        } else {
            ic00::IC_00.get()
        };
        let args = Encode!(&CanisterIdRecord::from(other_canister)).unwrap();
        let payload = wasm()
            .call_simple(
                target,
                Method::CanisterStatus,
                call_args().other_side(args.clone()),
            )
            .build();
        let (message_id, _) = test.ingress_raw(uc, "update", payload);
        test.execute_message(uc);
        if i > DEFAULT_QUEUE_CAPACITY {
            let IngressState::Failed(ingress_state) = test.ingress_state(&message_id) else {
                panic!("Unexpected state {:?}", test.ingress_state(&message_id));
            };
            ingress_state.assert_contains(
                ErrorCode::CanisterCalledTrap,
                &format!(
                    "Error from Canister {uc}: Canister called `ic0.trap` \
                    with message: 'call_perform failed"
                ),
            );
        } else {
            assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        }
        let system_state = &mut test.canister_state_mut(uc).system_state;
        assert_eq!(1, system_state.queues().output_queues_len());
        assert_eq!(
            i.min(DEFAULT_QUEUE_CAPACITY),
            system_state.queues().output_queues_message_count()
        );
    }
}

fn send_messages_to_bitcoin_canister_until_capacity(
    test: &mut ExecutionTest,
    bitcoin_canister: CanisterId,
    network: NetworkInRequest,
) {
    let uc = test.universal_canister().unwrap();

    for i in 1..=2 * DEFAULT_QUEUE_CAPACITY {
        let target = if i < DEFAULT_QUEUE_CAPACITY / 2 {
            bitcoin_canister.get()
        } else {
            ic00::IC_00.get()
        };
        let args = Encode!(&BitcoinGetUtxosArgs {
            network,
            address: String::from(""),
            filter: None,
        })
        .unwrap();
        let payload = wasm()
            .call_simple(
                target,
                Method::BitcoinGetUtxos,
                call_args().other_side(args.clone()),
            )
            .build();
        let (message_id, _) = test.ingress_raw(uc, "update", payload);
        test.execute_message(uc);
        if i > DEFAULT_QUEUE_CAPACITY {
            let IngressState::Failed(ingress_state) = test.ingress_state(&message_id) else {
                panic!("Unexpected state {:?}", test.ingress_state(&message_id));
            };
            ingress_state.assert_contains(
                ErrorCode::CanisterCalledTrap,
                &format!(
                    "Error from Canister {uc}: Canister called `ic0.trap` \
                    with message: 'call_perform failed"
                ),
            );
        } else {
            assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        }
        let system_state = &mut test.canister_state_mut(uc).system_state;
        assert_eq!(1, system_state.queues().output_queues_len());
        assert_eq!(
            i.min(DEFAULT_QUEUE_CAPACITY),
            system_state.queues().output_queues_message_count()
        );
    }
}

#[test]
fn canister_output_queue_does_not_overflow_when_calling_bitcoin_mainnet_canister() {
    let own_subnet = subnet_test_id(1);
    let bitcoin_mainnet_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(own_subnet)
        .with_initial_canister_cycles(1_000_000_000_000_000_000)
        .with_bitcoin_mainnet_canister_id(Some(bitcoin_mainnet_canister))
        .with_manual_execution()
        .build();

    send_messages_to_bitcoin_canister_until_capacity(
        &mut test,
        bitcoin_mainnet_canister,
        NetworkInRequest::Mainnet,
    );
}

#[test]
fn canister_output_queue_does_not_overflow_when_calling_bitcoin_testnet_canister() {
    let own_subnet = subnet_test_id(1);
    let bitcoin_testnet_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(own_subnet)
        .with_initial_canister_cycles(1_000_000_000_000_000_000)
        .with_bitcoin_testnet_canister_id(Some(bitcoin_testnet_canister))
        .with_manual_execution()
        .build();

    send_messages_to_bitcoin_canister_until_capacity(
        &mut test,
        bitcoin_testnet_canister,
        NetworkInRequest::Testnet,
    );
}

#[test]
fn can_refund_cycles_after_successful_provisional_create_canister() {
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build();
    let canister = test.universal_canister().unwrap();
    let payment = 10_000_000_000u128;
    let args = Encode!(&ProvisionalCreateCanisterWithCyclesArgs::new(None, None)).unwrap();
    let create_canister = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            call_args().other_side(args),
            Cycles::from(payment),
        )
        .build();

    let initial_cycles_balance = test.canister_state(canister).system_state.balance();

    let result = test.ingress(canister, "update", create_canister).unwrap();
    let new_canister = match result {
        WasmResult::Reply(bytes) => Decode!(&bytes, CanisterIdRecord).unwrap(),
        WasmResult::Reject(err) => {
            panic!("Expected ProvisionalCreateCanisterWithCycles to succeed but got {err}")
        }
    };
    assert_eq!(
        CanisterStatusType::Running,
        test.canister_state(new_canister.get_canister_id()).status(),
    );
    assert_balance_equals(
        initial_cycles_balance,
        test.canister_state(canister).system_state.balance(),
        BALANCE_EPSILON,
    );
}

fn create_canister_with_specified_id(
    test: &mut ExecutionTest,
    canister: &CanisterId,
    specified_id: Option<PrincipalId>,
) -> CanisterIdRecord {
    let args = Encode!(&ProvisionalCreateCanisterWithCyclesArgs::new(
        None,
        specified_id
    ))
    .unwrap();

    let create_canister = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            call_args().other_side(args),
            Cycles::from(10_000_000_000u128),
        )
        .build();

    let result = test.ingress(*canister, "update", create_canister).unwrap();
    match result {
        WasmResult::Reply(bytes) => Decode!(&bytes, CanisterIdRecord).unwrap(),
        WasmResult::Reject(err) => {
            panic!("Expected ProvisionalCreateCanisterWithCycles to succeed but got {err}")
        }
    }
}

#[test]
fn can_create_canister_with_specified_id() {
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build_with_routing_table_for_specified_ids();

    let canister = test.universal_canister().unwrap();

    let range = CanisterIdRange {
        start: CanisterId::from(0),
        end: CanisterId::from(u64::MAX / 2),
    };

    let specified_id = range.end;

    let new_canister =
        create_canister_with_specified_id(&mut test, &canister, Some(specified_id.get()));

    assert_eq!(specified_id, new_canister.get_canister_id());

    // creating a canister with the same `specified_id` again is an error
    let args = Encode!(&ProvisionalCreateCanisterWithCyclesArgs::new(
        None,
        Some(specified_id.into()),
    ))
    .unwrap();
    let err = test
        .subnet_message("provisional_create_canister_with_cycles", args)
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterAlreadyInstalled, err.code());
    assert!(
        err.description()
            .contains(&format!("Canister {specified_id} is already installed."))
    );
}

// Returns CanisterId by formula 'range_start + (range_end - range_start) * percentile'
fn get_canister_id_as_percentile_of_range(
    range_start: CanisterId,
    range_end: CanisterId,
    percentile: &f64,
) -> CanisterId {
    let start_u64 = canister_id_into_u64(range_start);
    let end_u64 = canister_id_into_u64(range_end);
    let shift = ((end_u64 - start_u64) as f64 * percentile) as u64;
    (start_u64 + shift).into()
}

fn inc(canister_id: CanisterId) -> CanisterId {
    (canister_id_into_u64(canister_id) + 1).into()
}

#[test]
fn create_multiple_canisters_with_specified_id() {
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build_with_routing_table_for_specified_ids();

    let canister = test.universal_canister().unwrap();

    // At the start create the canister without a specified ID.
    let first_canister_without_specified_id =
        create_canister_with_specified_id(&mut test, &canister, None);

    let range = CanisterIdRange {
        start: CanisterId::from(0),
        end: CanisterId::from(u64::MAX / 2),
    };

    // Percentiles of the range [start, end] that will be used to get their
    // respective CanisterIds for the creation of canisters with specified Ids.
    let percentiles = [0.0, 0.1, 0.3, 0.5, 0.6, 0.9];

    for percentile in percentiles.iter() {
        let specified_id =
            get_canister_id_as_percentile_of_range(range.start, range.end, percentile);
        let new_canister =
            create_canister_with_specified_id(&mut test, &canister, Some(specified_id.get()));
        assert_eq!(specified_id, new_canister.get_canister_id());
    }

    // Create the second canister without a specified ID, and
    // check if the first and second have consecutive Canister IDs.
    let second_canister_without_specified_id =
        create_canister_with_specified_id(&mut test, &canister, None);

    assert_eq!(
        inc(first_canister_without_specified_id.get_canister_id()),
        second_canister_without_specified_id.get_canister_id()
    );
}

#[test]
fn create_canister_with_invalid_specified_id() {
    // First determine an invalid `specified_id` by creating a canister on a test instance
    // whose canister ID belongs to the canister allocation ranges of the test instance.
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build_with_routing_table_for_specified_ids();
    let _proxy_canister_id = test.universal_canister().unwrap();
    let specified_id = test.universal_canister().unwrap();
    drop(test);

    // Now create a fresh test instance with the same topology.
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build_with_routing_table_for_specified_ids();

    // Using the invalid `specified_id` should result in an error.
    let args = Encode!(&ProvisionalCreateCanisterWithCyclesArgs::new(
        None,
        Some(specified_id.into()),
    ))
    .unwrap();
    let expected_err = format!(
        "The `specified_id` {specified_id} is invalid because it belongs to the canister allocation ranges of the test environment.\nUse a `specified_id` that matches a canister ID on the ICP mainnet and a test environment that supports canister creation with `specified_id` (e.g., PocketIC)."
    );

    // Both in an ingress message to create a canister
    let err = test
        .subnet_message("provisional_create_canister_with_cycles", args.clone())
        .unwrap_err();
    assert_eq!(ErrorCode::InvalidManagementPayload, err.code());
    assert_eq!(err.description(), expected_err,);

    // as well as in an inter-canister call to create a canister.
    let create_canister = wasm()
        .call_simple(
            ic00::IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            call_args()
                .other_side(args)
                .on_reject(wasm().reject_message().reject()),
        )
        .build();

    let proxy_canister_id = test.universal_canister().unwrap();
    let result = test
        .ingress(proxy_canister_id, "update", create_canister)
        .unwrap();
    match result {
        WasmResult::Reply(bytes) => panic!("Unexpected reply: {bytes:?}"),
        WasmResult::Reject(err) => assert_eq!(err, expected_err),
    };
}

#[test]
fn can_refund_cycles_after_successful_provisional_topup_canister() {
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build();
    let canister_1 = test.universal_canister().unwrap();
    let canister_2 = test.universal_canister().unwrap();
    let payment = 10_000_000_000u128;
    let top_up = 1_000_000_000;
    let args = Encode!(&ProvisionalTopUpCanisterArgs::new(canister_2, top_up)).unwrap();
    let top_up_canister = wasm()
        .call_with_cycles(
            ic00::IC_00,
            Method::ProvisionalTopUpCanister,
            call_args().other_side(args),
            Cycles::from(payment),
        )
        .build();

    let initial_cycles_balance_1 = test.canister_state(canister_1).system_state.balance();
    let initial_cycles_balance_2 = test.canister_state(canister_2).system_state.balance();

    let result = test.ingress(canister_1, "update", top_up_canister).unwrap();

    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
    assert_balance_equals(
        initial_cycles_balance_1,
        test.canister_state(canister_1).system_state.balance(),
        BALANCE_EPSILON,
    );

    assert_balance_equals(
        initial_cycles_balance_2 + Cycles::new(top_up),
        test.canister_state(canister_2).system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn bitcoin_get_successors_cannot_be_called_by_non_bitcoin_canisters() {
    let mut test = ExecutionTestBuilder::new()
        .with_provisional_whitelist_all()
        .build();
    let uni = test.universal_canister().unwrap();
    let call = wasm()
        .call_simple(
            ic00::IC_00,
            Method::BitcoinGetSuccessors,
            call_args()
                .other_side(vec![])
                .on_reject(wasm().reject_message().reject()),
        )
        .build();

    let result = test.ingress(uni, "update", call).unwrap();
    assert_eq!(result, WasmResult::Reject("Permission denied.".to_string()));
}

#[test]
fn replicated_query_refunds_all_sent_cycles() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let transferred_cycles = Cycles::from(1_000_000u128);

    let b_callback = wasm().message_payload().append_and_reply().build();

    let a_payload = wasm()
        .call_with_cycles(
            b_id,
            "query",
            call_args().other_side(b_callback.clone()),
            transferred_cycles,
        )
        .build();

    let (message_id, _) = test.ingress_raw(a_id, "update", a_payload);

    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);

    let system_state = &mut test.canister_state_mut(b_id).system_state;

    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());

    let message = system_state
        .queues_mut()
        .clone()
        .pop_canister_output(&a_id)
        .unwrap();

    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(msg.refund, transferred_cycles);
        assert!(matches!(msg.response_payload, Payload::Data(..)));
    } else {
        panic!("unexpected message popped: {message:?}");
    }

    test.induct_messages();
    test.execute_message(a_id);

    let ingress_state = test.ingress_state(&message_id);

    if let IngressState::Completed(wasm_result) = ingress_state {
        match wasm_result {
            WasmResult::Reject(result) => panic!("unexpected result {result}"),
            WasmResult::Reply(_) => (),
        }
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    }

    // Canister A gets a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("query", &b_callback)
            - test.reply_fee(&b_callback)
    );

    // Canister B doesn't get the transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn replicated_query_can_accept_cycles() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let transferred_cycles = Cycles::from(1_000_000u128);

    // Canister B attempts to accept cycles in a replicated query. Should succeed.
    let b_callback = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a_payload = wasm()
        .call_with_cycles(
            b_id,
            "query",
            call_args().other_side(b_callback.clone()),
            transferred_cycles,
        )
        .build();

    let (message_id, _) = test.ingress_raw(a_id, "update", a_payload);

    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);

    let system_state = &mut test.canister_state_mut(b_id).system_state;

    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());

    let message = system_state
        .queues_mut()
        .clone()
        .pop_canister_output(&a_id)
        .unwrap();

    let response_payload = if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(msg.refund, Cycles::zero());
        if let Payload::Data(payload) = msg.response_payload.clone() {
            payload
        } else {
            panic!("unexpected response: {msg:?}");
        }
    } else {
        panic!("unexpected message popped: {message:?}");
    };

    test.induct_messages();
    test.execute_message(a_id);

    let ingress_state = test.ingress_state(&message_id);

    if let IngressState::Completed(wasm_result) = ingress_state {
        match wasm_result {
            WasmResult::Reject(_) => panic!("expected result"),
            WasmResult::Reply(_) => (),
        }
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    };

    // Canister A loses `transferred_cycles` since B accepted all cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("query", &b_callback)
            - test.reply_fee(&response_payload)
            - transferred_cycles
    );

    // Canister B gets the transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id) + transferred_cycles
    );
}

#[test]
fn replicated_query_does_not_accept_cycles_on_trap() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let transferred_cycles = Cycles::from(1_000_000u128);

    // Canister B attempts to accept cycles in a replicated query. Should succeed.
    let b_callback = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .trap()
        .build();

    let a_payload = wasm()
        .call_with_cycles(
            b_id,
            "query",
            call_args().other_side(b_callback.clone()),
            transferred_cycles,
        )
        .build();

    let (message_id, _) = test.ingress_raw(a_id, "update", a_payload);

    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);

    let system_state = &mut test.canister_state_mut(b_id).system_state;

    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());

    let message = system_state
        .queues_mut()
        .clone()
        .pop_canister_output(&a_id)
        .unwrap();

    let reject_message = if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert_eq!(msg.refund, transferred_cycles);
        if let Payload::Reject(context) = msg.response_payload.clone() {
            context.message().clone()
        } else {
            panic!("unexpected response: {msg:?}");
        }
    } else {
        panic!("unexpected message popped: {message:?}");
    };

    test.induct_messages();
    test.execute_message(a_id);

    let ingress_state = test.ingress_state(&message_id);

    if let IngressState::Completed(wasm_result) = ingress_state {
        match wasm_result {
            WasmResult::Reject(_) => (),
            WasmResult::Reply(_) => panic!("expected reject"),
        }
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    };

    // Canister A does not lose `transferred_cycles` since B trapped after accepting.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("query", &b_callback)
            - test.reject_fee(reject_message)
    );

    // Canister B does not get any cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn replicated_query_can_burn_cycles() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let canister_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let cycles_to_burn = Cycles::new(10_000_000u128);

    let payload = wasm().cycles_burn128(cycles_to_burn).reply().build();
    let (message_id, _) = test.ingress_raw(canister_id, "query", payload);
    test.execute_message(canister_id);

    let ingress_state = test.ingress_state(&message_id);
    if let IngressState::Completed(wasm_result) = ingress_state {
        match wasm_result {
            WasmResult::Reject(_) => panic!("expected result"),
            WasmResult::Reply(_) => (),
        }
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    };

    // Canister A loses `cycles_to_burn` from its balance (in addition to execution cost)...
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(canister_id) - cycles_to_burn
    );

    // ...and the burned cycles are accounted for in the canister's metrics.
    let burned_cycles = *test
        .canister_state(canister_id)
        .system_state
        .canister_metrics
        .get_consumed_cycles_by_use_cases()
        .get(&CyclesUseCase::BurnedCycles)
        .unwrap();
    assert_eq!(burned_cycles, NominalCycles::from(cycles_to_burn));
}

#[test]
fn replicated_query_does_not_burn_cycles_on_trap() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let canister_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let cycles_to_burn = Cycles::new(10_000_000u128);

    let payload = wasm().cycles_burn128(cycles_to_burn).reply().trap().build();
    let (message_id, _) = test.ingress_raw(canister_id, "query", payload);
    test.execute_message(canister_id);

    let ingress_state = test.ingress_state(&message_id);
    if let IngressState::Failed(user_error) = ingress_state {
        assert_eq!(user_error.code(), ErrorCode::CanisterCalledTrap);
        assert!(
            user_error
                .description()
                .contains("Canister called `ic0.trap`"),
        );
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    };

    // Canister A only loses cycles due to executing but not `cycles_to_burn` (since it trapped)...
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(canister_id)
    );

    // ...and no burned cycles are accounted for in the canister's metrics.
    assert!(
        test.canister_state(canister_id)
            .system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .get(&CyclesUseCase::BurnedCycles)
            .is_none()
    );
}

#[test]
fn test_consumed_cycles_by_use_case_with_refund() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let transferred_cycles = Cycles::new(1_000_000);

    let b_callback = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a_payload = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b_callback.clone()),
            transferred_cycles,
        )
        .build();

    let (message_id, _) = test.ingress_raw(a_id, "update", a_payload);
    // Canister A sends the message to canister B.
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);

    let system_state = &mut test.canister_state_mut(b_id).system_state;
    // Check that canister B has produced the response.
    assert_eq!(1, system_state.queues().output_queues_len());
    assert_eq!(1, system_state.queues().output_queues_message_count());

    let message = system_state
        .queues_mut()
        .clone()
        .pop_canister_output(&a_id)
        .unwrap();

    if let RequestOrResponse::Response(msg) = message {
        assert_eq!(msg.originator, a_id);
        assert_eq!(msg.respondent, b_id);
        assert!(matches!(msg.response_payload, Payload::Data(..)));
    } else {
        panic!("unexpected message popped: {message:?}");
    }

    // Get consumption for 'RequestAndResponseTransmission' and 'Instructions'
    // before receiving a response on canister A.
    let transmission_consumption_before_response = *test
        .canister_state(a_id)
        .system_state
        .canister_metrics
        .get_consumed_cycles_by_use_cases()
        .get(&CyclesUseCase::RequestAndResponseTransmission)
        .unwrap();
    let instruction_consumption_before_response = *test
        .canister_state(a_id)
        .system_state
        .canister_metrics
        .get_consumed_cycles_by_use_cases()
        .get(&CyclesUseCase::Instructions)
        .unwrap();

    assert!(transmission_consumption_before_response.get() > 0);
    assert!(instruction_consumption_before_response.get() > 0);

    // Check that canister A's balance is decremented for consumed cycles
    // plus transferred cycles to canister B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - Cycles::from(transmission_consumption_before_response.get())
            - Cycles::from(instruction_consumption_before_response.get())
            - transferred_cycles
    );

    // Canister A executed the response.
    test.induct_messages();
    test.execute_message(a_id);

    let ingress_state = test.ingress_state(&message_id);

    if let IngressState::Completed(wasm_result) = ingress_state {
        match wasm_result {
            WasmResult::Reject(result) => panic!("unexpected result {result}"),
            WasmResult::Reply(_) => (),
        }
    } else {
        panic!("unexpected ingress state {ingress_state:?}");
    }

    let transmission_cost = test.call_fee("update", &b_callback) + test.reply_fee(&b_callback);

    let execution_cost = test.canister_execution_cost(a_id);

    // Check that canister A's balance is updated correctly.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - execution_cost - transmission_cost - transferred_cycles
    );

    assert_eq!(
        test.canister_state(a_id)
            .system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .len(),
        2
    );

    let transmission_consumption_after_response = *test
        .canister_state(a_id)
        .system_state
        .canister_metrics
        .get_consumed_cycles_by_use_cases()
        .get(&CyclesUseCase::RequestAndResponseTransmission)
        .unwrap();
    let instruction_consumption_after_response = *test
        .canister_state(a_id)
        .system_state
        .canister_metrics
        .get_consumed_cycles_by_use_cases()
        .get(&CyclesUseCase::Instructions)
        .unwrap();

    // Check that consumed cycles are correct for both use cases.
    assert_eq!(
        transmission_consumption_after_response,
        NominalCycles::from(transmission_cost)
    );

    assert_eq!(
        instruction_consumption_after_response,
        NominalCycles::from(execution_cost)
    );

    // Consumed cycles after the response should be smaller than before
    // the response because we expect a refund for prepaid cycles.
    assert!(transmission_consumption_after_response < transmission_consumption_before_response);
    assert!(instruction_consumption_after_response < instruction_consumption_before_response);

    // Check that canister B's balance is updated correctly.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id) + transferred_cycles
    );

    // Check that consumed cycles are correct only for the `Instructions` use case.
    assert_eq!(
        test.canister_state(b_id)
            .system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .len(),
        1
    );

    assert_eq!(
        *test
            .canister_state(b_id)
            .system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .get(&CyclesUseCase::Instructions)
            .unwrap(),
        NominalCycles::from(test.canister_execution_cost(b_id))
    );
}

#[test]
fn output_requests_on_application_subnets_update_subnet_available_memory_reserved() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(ONE_GIB)
        .with_subnet_memory_reservation(0)
        .with_subnet_guaranteed_response_message_memory(ONE_GIB)
        .with_resource_saturation_scaling(1)
        .with_manual_execution()
        .with_initial_canister_cycles(1_000_000_000_000_000)
        .build();
    let canister_id = test.canister_from_wat(CALL_SIMPLE_WAT).unwrap();
    test.canister_update_allocations_settings(canister_id, None, Some(1_000_000))
        .unwrap();
    test.ingress_raw(canister_id, "test", vec![]);
    test.execute_message(canister_id);
    let subnet_message_memory = test
        .subnet_available_memory()
        .get_guaranteed_response_message_memory();
    let system_state = &mut test.canister_state_mut(canister_id).system_state;
    // There should be one response memory reservation in the queues.
    assert_eq!(
        1,
        system_state
            .queues()
            .guaranteed_response_memory_reservations()
    );
    assert_eq!(
        (ONE_GIB - MAX_RESPONSE_COUNT_BYTES as u64) as i64,
        subnet_message_memory
    );
    assert_correct_request(system_state, canister_id);
}

#[test]
fn test_canister_settings_log_visibility_default_controllers() {
    // Arrange.
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000));
    // Act.
    let canister_status = test.canister_status(canister_id).unwrap();
    // Assert.
    assert_eq!(
        canister_status.settings().log_visibility(),
        &LogVisibilityV2::Controllers
    );
}

#[test]
fn test_canister_settings_log_visibility_create_with_settings() {
    // Arrange.
    let mut test = ExecutionTestBuilder::new().build();
    // Act.
    let canister_id = test
        .create_canister_with_settings(
            Cycles::new(1_000_000_000),
            ic00::CanisterSettingsArgsBuilder::new()
                .with_log_visibility(LogVisibilityV2::Public)
                .build(),
        )
        .unwrap();
    let canister_status = test.canister_status(canister_id).unwrap();
    // Assert.
    assert_eq!(
        canister_status.settings().log_visibility(),
        &LogVisibilityV2::Public
    );
}

#[test]
fn test_canister_settings_log_visibility_set_to_public() {
    // Arrange.
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000));
    // Act.
    test.set_log_visibility(canister_id, LogVisibilityV2::Public)
        .unwrap();
    let canister_status = test.canister_status(canister_id).unwrap();
    // Assert.
    assert_eq!(
        canister_status.settings().log_visibility(),
        &LogVisibilityV2::Public
    );
}

#[test]
fn test_fetch_canister_logs_should_accept_ingress_message() {
    // Arrange.
    // Set the log visibility to public so any user can read the logs.
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let not_a_controller = user_test_id(42);
    test.set_log_visibility(canister_id, LogVisibilityV2::Public)
        .unwrap();
    // Act.
    test.set_user_id(not_a_controller);
    let result = test.should_accept_ingress_message(
        IC_00,
        Method::FetchCanisterLogs,
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    // Assert.
    // Expect error since `fetch_canister_logs` can not be called via ingress messages.
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "ic00 method fetch_canister_logs can not be called via ingress messages"
        ))
    );
}

#[test]
fn test_sign_with_schnorr_api_is_enabled() {
    // TODO(EXC-1629): upgrade to more of e2e test with mocking the response
    // from consensus and producing the response to the canister.

    let test_cases = [
        make_ed25519_key("correct_ed25519_key"),
        make_bip340_key("correct_bip340_key"),
    ];

    for key_id in &test_cases {
        // Arrange.
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let nns_canister = canister_test_id(0x10);
        let mut test = ExecutionTestBuilder::new()
            .with_own_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_caller(nns_subnet, nns_canister)
            .with_chain_key(key_id.clone())
            .build();
        let canister_id = test.universal_canister().unwrap();
        // Check that the SubnetCallContextManager is empty.
        assert_eq!(
            test.state()
                .metadata
                .subnet_call_context_manager
                .sign_with_threshold_contexts_count(key_id),
            0
        );

        // Act.
        let method = Method::SignWithSchnorr;
        let run = wasm()
            .call_with_cycles(
                ic00::IC_00,
                method,
                call_args()
                    .other_side(sign_with_threshold_key_payload(method, key_id.clone()))
                    .on_reject(wasm().reject_message().reject()),
                Cycles::from(100_000_000_000u128),
            )
            .build();
        let (_, ingress_status) = test.ingress_raw(canister_id, "update", run);

        // Assert.
        // Check that the request is accepted and processing.
        assert_eq!(
            ingress_status,
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id: test.user_id(),
                time: test.time(),
                state: IngressState::Processing,
            }
        );
        // Check that the SubnetCallContextManager contains the request.
        assert_eq!(
            test.state()
                .metadata
                .subnet_call_context_manager
                .sign_with_threshold_contexts_count(key_id),
            1
        );
    }
}

#[test]
fn test_ecdsa_public_key_api_is_enabled() {
    let key_id = make_ecdsa_key("correct_key");
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_chain_key(key_id.clone())
        .build();

    let nonexistent_key_id = into_inner_ecdsa(make_ecdsa_key("nonexistent_key_id"));
    test.inject_call_to_ic00(
        Method::ECDSAPublicKey,
        ic00::ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::default(),
            key_id: nonexistent_key_id.clone(),
        }
        .encode(),
        Cycles::new(0),
    );
    test.inject_call_to_ic00(
        Method::ECDSAPublicKey,
        ic00::ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::default(),
            key_id: into_inner_ecdsa(key_id),
        }
        .encode(),
        Cycles::new(0),
    );
    test.execute_all();

    // Check, that call fails for a key that doesn't exist
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        format!("Subnet {own_subnet} does not hold threshold key ecdsa:{nonexistent_key_id}."),
    );

    let response = test.xnet_messages()[1].clone();
    let RequestOrResponse::Response(response) = response else {
        panic!("expected a response");
    };
    assert_eq!(response.originator, nns_canister);
    assert_eq!(response.respondent, own_subnet.into());
}

#[test]
fn test_schnorr_public_key_api_is_enabled() {
    let test_cases = [
        (
            make_bip340_key("correct_key"),
            make_bip340_key("nonexistent_key_id"),
        ),
        (
            make_ed25519_key("correct_key"),
            make_ed25519_key("nonexistent_key_id"),
        ),
    ];

    for (key_id, nonexistent_key_id) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let nns_canister = canister_test_id(0x10);
        let mut test = ExecutionTestBuilder::new()
            .with_own_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_caller(nns_subnet, nns_canister)
            .with_chain_key(key_id.clone())
            .build();

        let nonexistent_key_id = into_inner_schnorr(nonexistent_key_id);
        test.inject_call_to_ic00(
            Method::SchnorrPublicKey,
            ic00::SchnorrPublicKeyArgs {
                canister_id: None,
                derivation_path: DerivationPath::default(),
                key_id: nonexistent_key_id.clone(),
            }
            .encode(),
            Cycles::new(0),
        );
        test.inject_call_to_ic00(
            Method::SchnorrPublicKey,
            ic00::SchnorrPublicKeyArgs {
                canister_id: None,
                derivation_path: DerivationPath::default(),
                key_id: into_inner_schnorr(key_id),
            }
            .encode(),
            Cycles::new(0),
        );
        test.execute_all();

        // Check, that call fails for a key that doesn't exist
        let response = test.xnet_messages()[0].clone();
        assert_eq!(
            get_reject_message(response),
            format!(
                "Subnet {own_subnet} does not hold threshold key schnorr:{nonexistent_key_id}."
            ),
        );

        let response = test.xnet_messages()[1].clone();
        let RequestOrResponse::Response(response) = response else {
            panic!("expected a response");
        };
        assert_eq!(response.originator, nns_canister);
        assert_eq!(response.respondent, own_subnet.into());
    }
}

#[test]
fn test_vetkd_public_key_api_is_enabled() {
    let key_id = make_vetkd_key("correct_key");
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_chain_key(key_id.clone())
        .build();

    let nonexistent_key_id = into_inner_vetkd(make_vetkd_key("nonexistent_key_id"));
    test.inject_call_to_ic00(
        Method::VetKdPublicKey,
        ic00::VetKdPublicKeyArgs {
            canister_id: None,
            context: vec![],
            key_id: nonexistent_key_id.clone(),
        }
        .encode(),
        Cycles::new(0),
    );
    test.inject_call_to_ic00(
        Method::VetKdPublicKey,
        ic00::VetKdPublicKeyArgs {
            canister_id: None,
            context: vec![],
            key_id: into_inner_vetkd(key_id),
        }
        .encode(),
        Cycles::new(0),
    );
    test.execute_all();

    // Check, that call fails for a key that doesn't exist
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        format!("Subnet {own_subnet} does not hold threshold key vetkd:{nonexistent_key_id}."),
    );

    let response = test.xnet_messages()[1].clone();
    let RequestOrResponse::Response(response) = response else {
        panic!("expected a response");
    };
    assert_eq!(response.originator, nns_canister);
    assert_eq!(response.respondent, own_subnet.into());
}

#[test]
fn test_vetkd_derive_key_api_is_disabled_without_key() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .build();
    let method = Method::VetKdDeriveKey;
    test.inject_call_to_ic00(
        method,
        sign_with_threshold_key_payload(method, make_vetkd_key("some_key")),
        Cycles::new(0),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        "Subnet yndj2-3ybaa-aaaaa-aaaap-yai does not hold threshold key vetkd:Bls12_381_G2:some_key.",
    )
}

#[test]
fn test_vetkd_derive_key_rejects_invalid_transport_keys() {
    let key_id = make_vetkd_key("some_key");
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_chain_key(key_id.clone())
        .build();
    let method = Method::VetKdDeriveKey;
    let args = ic00::VetKdDeriveKeyArgs {
        input: vec![],
        // invalid transport key
        transport_public_key: [1; 48],
        context: vec![],
        key_id: into_inner_vetkd(key_id),
    };
    test.inject_call_to_ic00(method, args.encode(), Cycles::new(0));
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        "The provided transport public key is invalid.",
    )
}

#[test]
fn test_vetkd_derive_key_api_is_enabled() {
    // Arrange.
    let key_id = make_vetkd_key("some_key");
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .with_chain_key(key_id.clone())
        .build();
    let canister_id = test.universal_canister().unwrap();
    // Check that the SubnetCallContextManager is empty.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts_count(&key_id),
        0
    );

    // Act.
    let method = Method::VetKdDeriveKey;
    let run = wasm()
        .call_with_cycles(
            ic00::IC_00,
            method,
            call_args()
                .other_side(sign_with_threshold_key_payload(method, key_id.clone()))
                .on_reject(wasm().reject_message().reject()),
            Cycles::from(100_000_000_000u128),
        )
        .build();
    let (_, ingress_status) = test.ingress_raw(canister_id, "update", run);

    // Assert.
    // Check that the request is accepted and processing.
    assert_eq!(
        ingress_status,
        IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: test.user_id(),
            time: test.time(),
            state: IngressState::Processing,
        }
    );
    // Check that the SubnetCallContextManager contains the request.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts_count(&key_id),
        1
    );
}

#[test]
fn reshare_chain_key_api_is_disabled() {
    let own_subnet = subnet_test_id(1);
    let nns_subnet = subnet_test_id(2);
    let nns_canister = canister_test_id(0x10);
    let nodes = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let registry_version = RegistryVersion::from(100);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_nns_subnet_id(nns_subnet)
        .with_caller(nns_subnet, nns_canister)
        .build();
    let method = Method::ReshareChainKey;
    let key = make_vetkd_key("some_key");
    test.inject_call_to_ic00(
        method,
        ic00::ReshareChainKeyArgs::new(key.clone(), nns_subnet, nodes, registry_version).encode(),
        Cycles::new(0),
    );
    test.execute_all();
    let response = test.xnet_messages()[0].clone();
    assert_eq!(
        get_reject_message(response),
        format!("Subnet {own_subnet} does not hold threshold key {key}."),
    )
}

#[test]
fn cannot_accept_cycles_after_replying() {
    let mut test = ExecutionTestBuilder::new()
        .with_manual_execution()
        .with_subnet_type(SubnetType::System)
        .build();
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let d_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let transferred_cycles = Cycles::from(1_000_000u128);

    // Canister C and D simply reply with the payload they were called with.
    let c_callback = wasm().message_payload().append_and_reply().build();
    let d_callback = wasm().message_payload().append_and_reply().build();

    // Canister B accepts half of the cycles when receiving a call, then calls C and D,
    // then replies to A and finally tries to accept the remaining cycles after replying.
    // It should not be able to accept any more cycles after replying.
    let b_callback = wasm()
        .accept_cycles(transferred_cycles / 2u64)
        .message_payload()
        .append_and_reply()
        .call_simple(
            c_id,
            "update",
            call_args()
                .other_side(c_callback)
                .on_reply(wasm().accept_cycles(transferred_cycles / 2u64).build()),
        )
        .call_simple(d_id, "update", call_args().other_side(d_callback))
        .build();

    let a_payload = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b_callback)
                .on_reply(wasm().msg_cycles_refunded().reply_int64().build()),
            transferred_cycles,
        )
        .build();

    let _ = test.ingress_raw(a_id, "update", a_payload);

    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    // B replied to A and called C and D.
    test.execute_message(a_id);
    test.execute_message(c_id);
    test.induct_messages();
    // C replied to B, try to accept more cycles. Should not be able to.
    test.execute_message(b_id);

    // Execute remaining messages.
    test.execute_all();

    // Canister A loses `transferred_cycles / 2` since B accepted half of them before replying.
    // The remaining was refunded as part of the reply delivered to A.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - (transferred_cycles / 2u64)
    );

    // Canister B gets half of transferred_cycles that it accepted before replying.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles + (transferred_cycles / 2u64)
    );
}
