use crate::execution::test_utilities::{check_ingress_status, ExecutionTest, ExecutionTestBuilder};
use crate::ExecutionResponse;
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_error_types::ErrorCode;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::HypervisorError;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::{CanisterStatus, NumWasmPages};
use ic_test_utilities::types::messages::ResponseBuilder;
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, MessageId},
    CanisterId, Cycles, Time,
};
use ic_types::{messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, NumInstructions};
use ic_universal_canister::{call_args, wasm};

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
    let result = test.execute_response(canister_id, response);
    assert_matches!(result, ExecutionResponse::Empty);
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
    let result = test.execute_response(canister_id, response);
    assert_matches!(result, ExecutionResponse::Empty);
}

#[test]
fn execute_response_refunds_cycles() {
    // This test uses manual execution to get finer control over the execution.
    let instruction_limit = 1_000_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_manual_execution()
        .build();
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
        .refund(cycles_sent * 2u64)
        .build();
    let response_payload_size = response.payload_size_bytes();

    // Execute response.
    let balance_before = test.canister_state(a_id).system_state.balance();
    let instructions_before = test.canister_executed_instructions(a_id);
    test.execute_response(a_id, response);
    let instructions_after = test.canister_executed_instructions(a_id);
    let instructions_executed = instructions_after - instructions_before;
    let balance_after = test.canister_state(a_id).system_state.balance();

    // The balance is equivalent to the amount of cycles before executing`execute_response`
    // plus the unaccepted cycles (no more the cycles sent via request),
    // the execution cost refund and the refunded transmission fee.
    // Compute the response transmission refund.
    let mgr = test.cycles_account_manager();
    let response_transmission_refund = mgr
        .xnet_call_bytes_transmitted_fee(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, test.subnet_size());
    mgr.xnet_call_bytes_transmitted_fee(response_payload_size, test.subnet_size());
    let instructions_left = NumInstructions::from(instruction_limit) - instructions_executed;
    let execution_refund = mgr.convert_instructions_to_cycles(instructions_left);
    assert_eq!(
        balance_after,
        balance_before + cycles_sent + response_transmission_refund + execution_refund
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
    let result = test.execute_response(a_id, response);
    assert_matches!(result, ExecutionResponse::Empty);
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
    let result = test.execute_response(a_id, response);
    match result {
        ExecutionResponse::Ingress((_, ingress_status)) => {
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
        ExecutionResponse::Request(_) | ExecutionResponse::Empty => {
            panic!("Wrong execution result")
        }
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
    let result = test.execute_response(a_id, response);
    match result {
        ExecutionResponse::Ingress((_, ingress_status)) => {
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
        ExecutionResponse::Request(_) | ExecutionResponse::Empty => {
            panic!("Wrong execution result.")
        }
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
    let result = test.execute_response(a_id, response);
    match result {
        ExecutionResponse::Ingress((_, ingress_status)) => {
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
        ExecutionResponse::Request(_) | ExecutionResponse::Empty => {
            panic!("Wrong execution result.")
        }
    }
}

#[test]
fn cycles_correct_if_response_fails() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().reply_data_append().trap()),
            (0, transferred_cycles),
        )
        .build();
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    let execution_cost_before = test.canister_execution_cost(a_id);
    test.execute_message(a_id);
    let execution_cost_after = test.canister_execution_cost(a_id);
    assert!(execution_cost_after > execution_cost_before);
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterCalledTrap);
}

#[test]
fn cycles_correct_if_cleanup_fails() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    // 3. Traps in the cleanup callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().reply_data_append().trap())
                .on_cleanup(wasm().trap()),
            (0, transferred_cycles),
        )
        .build();
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    let execution_cost_before = test.canister_execution_cost(a_id);
    test.execute_message(a_id);
    let execution_cost_after = test.canister_execution_cost(a_id);
    assert!(execution_cost_after > execution_cost_before);
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterCalledTrap);
}

#[test]
fn dts_works_in_response_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        // TODO: RUN-454: This fails after changing the UC
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_reply(
                    wasm()
                        .set_global_data(&[0; 100])
                        .message_payload()
                        .reply_data_append()
                        .reply()
                        .build(),
                ),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Keep executing until callback finishes.
    while test.canister_state(a_id).next_execution() == NextExecution::ContinueLong {
        // The canister state should be clean. Specifically, no changes in the
        // cycles balance and call contexts.
        assert_eq!(
            test.canister_state(a_id).system_state.balance(),
            original_system_state.balance()
        );
        assert_eq!(
            test.canister_state(a_id)
                .system_state
                .call_context_manager(),
            original_system_state.call_context_manager()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));
}

#[test]
fn dts_works_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_cleanup(wasm().stable_grow(1).stable64_fill(0, 0, 1000)),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Keep executing until callback finishes.
    while test.canister_state(a_id).next_execution() == NextExecution::ContinueLong {
        // The canister state should be clean. Specifically, no changes in the
        // cycles balance and call contexts.
        assert_eq!(
            test.canister_state(a_id).system_state.balance(),
            original_system_state.balance()
        );
        assert_eq!(
            test.canister_state(a_id)
                .system_state
                .call_context_manager(),
            original_system_state.call_context_manager()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
}

#[test]
fn dts_out_of_subnet_memory_in_response_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(100 * 1024 * 1024)
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(2_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    // on reply grow by roughly 80 mb
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .message_payload()
                        .append_and_reply(),
                ),
            (0, 2000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Create a new canister allocating half of subnet memory
    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(50 * 1024 * 1024),
    )
    .unwrap();
    let available_memory_before_finishing_callback =
        test.subnet_available_memory().get_total_memory();

    // Keep executing until callback finishes.
    while test.canister_state(a_id).next_execution() == NextExecution::ContinueLong {
        // The canister state should be clean. Specifically, no changes in the
        // cycles balance and call contexts.
        assert_eq!(
            test.canister_state(a_id).system_state.balance(),
            original_system_state.balance()
        );
        assert_eq!(
            test.canister_state(a_id)
                .system_state
                .call_context_manager(),
            original_system_state.call_context_manager()
        );
        // memory changes not reflected in global state
        assert_eq!(
            available_memory_before_finishing_callback,
            test.subnet_available_memory().get_total_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfMemory);
    // verify that cleanup was in fact unable to allocate over subnet memory limit
    assert_eq!(
        available_memory_before_finishing_callback,
        test.subnet_available_memory().get_total_memory()
    );
}

#[test]
fn dts_out_of_subnet_memory_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(100 * 1024 * 1024)
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    // on cleanup grow by roughly 80 mb
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_cleanup(wasm().stable_grow(1280).stable64_fill(0, 0, 1000)),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(50 * 1024 * 1024),
    )
    .unwrap();

    let available_memory_before_finishing_callback =
        test.subnet_available_memory().get_total_memory();

    // Keep executing until callback finishes.
    while test.canister_state(a_id).next_execution() == NextExecution::ContinueLong {
        // The canister state should be clean. Specifically, no changes in the
        // cycles balance and call contexts.
        assert_eq!(
            test.canister_state(a_id).system_state.balance(),
            original_system_state.balance()
        );
        assert_eq!(
            test.canister_state(a_id)
                .system_state
                .call_context_manager(),
            original_system_state.call_context_manager()
        );
        // memory changes not reflected in global state
        assert_eq!(
            available_memory_before_finishing_callback,
            test.subnet_available_memory().get_total_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // verify that cleanup was in fact unable to allocate over subnet memory limit
    assert_eq!(
        available_memory_before_finishing_callback,
        test.subnet_available_memory().get_total_memory()
    )
}

#[test]
fn dts_abort_works_in_response_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        // TODO: RUN-454: This fails after changing the UC
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_reply(
                    wasm()
                        .set_global_data(&[0; 100])
                        .message_payload()
                        .reply_data_append()
                        .reply()
                        .build(),
                ),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // The canister state should be clean. Specifically, no changes in the
    // cycles balance and call contexts.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        original_system_state.balance()
    );
    assert_eq!(
        test.canister_state(a_id)
            .system_state
            .call_context_manager(),
        original_system_state.call_context_manager()
    );

    // Aborting doesn't change the clean canister state.
    test.abort_all_paused_executions();
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        original_system_state.balance()
    );
    assert_eq!(
        test.canister_state(a_id)
            .system_state
            .call_context_manager(),
        original_system_state.call_context_manager()
    );

    // Execute the response callback again and it should succeeed.
    test.execute_message(a_id);
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));
}

#[test]
fn dts_abort_works_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_cleanup(wasm().stable_grow(1).stable64_fill(0, 0, 1000)),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Start executing the response callback.
    let original_system_state = test.canister_state(a_id).system_state.clone();

    // For a DTS execution that takes `N` rounds, try aborting after each round
    // `i` for `i` in `0..N`. To avoid hardcoding `N`, we just try each `i`
    // until there are no more slices.
    let mut i = 0;
    'outer: loop {
        for _ in 0..i {
            test.execute_slice(a_id);
            if test.canister_state(a_id).next_execution() == NextExecution::None {
                break 'outer;
            }
            // The canister state should be clean. Specifically, no changes in the
            // cycles balance and call contexts.
            assert_eq!(
                test.canister_state(a_id).system_state.balance(),
                original_system_state.balance()
            );
            assert_eq!(
                test.canister_state(a_id)
                    .system_state
                    .call_context_manager(),
                original_system_state.call_context_manager()
            );
        }
        // Aborting doesn't change the clean canister state.
        test.abort_all_paused_executions();
        assert_eq!(
            test.canister_state(a_id).system_state.balance(),
            original_system_state.balance()
        );
        assert_eq!(
            test.canister_state(a_id)
                .system_state
                .call_context_manager(),
            original_system_state.call_context_manager()
        );
        i += 1;
    }
    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
}

fn successful_response_scenario(test: &mut ExecutionTest) -> (CanisterId, MessageId) {
    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let b = wasm()
        .accept_cycles(1000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_code().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1)
                        .stable64_fill(0, 0, 1)
                        .message_payload()
                        .append_and_reply(),
                ),
            (0, 1000),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    test.execute_message(a_id);

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));
    (a_id, ingress_id)
}

fn response_fail_scenario(test: &mut ExecutionTest) -> (CanisterId, MessageId) {
    let initial_cycles = Cycles::new(1_000_000_000_000);

    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(
                    wasm()
                        .stable_grow(1)
                        .stable64_fill(0, 0, 1)
                        .reply_data_append()
                        .trap(),
                )
                .on_cleanup(wasm().stable_grow(1).stable64_fill(0, 0, 1)),
            (0, transferred_cycles),
        )
        .build();
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    let execution_cost_before = test.canister_execution_cost(a_id);
    test.execute_message(a_id);
    let execution_cost_after = test.canister_execution_cost(a_id);
    assert!(execution_cost_after > execution_cost_before);

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterCalledTrap);

    (a_id, ingress_id)
}

fn cleanup_fail_scenario(test: &mut ExecutionTest) -> (CanisterId, MessageId) {
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters A, B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    // 3. Traps in the cleanup callback.
    let a = wasm()
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(
                    wasm()
                        .stable_grow(1)
                        .stable64_fill(0, 0, 1)
                        .reply_data_append()
                        .trap(),
                )
                .on_cleanup(wasm().stable_grow(1).stable64_fill(0, 0, 1).trap()),
            (0, transferred_cycles),
        )
        .build();
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    let execution_cost_before = test.canister_execution_cost(a_id);
    test.execute_message(a_id);
    let execution_cost_after = test.canister_execution_cost(a_id);
    assert!(execution_cost_after > execution_cost_before);

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterCalledTrap);

    (a_id, ingress_id)
}

#[test]
fn dts_and_nondts_cycles_match_after_response() {
    let mut test_a = ExecutionTestBuilder::new().with_manual_execution().build();
    let start_time = test_a.state().time();
    let (a_id, amsg_id) = successful_response_scenario(&mut test_a);

    let mut test_b = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let (b_id, bmsg_id) = successful_response_scenario(&mut test_b);

    let status_a = test_a.ingress_status(&amsg_id);
    let status_b = test_b.ingress_status(&bmsg_id);
    assert_eq!(status_a, status_b);
    let time_a = match status_a {
        IngressStatus::Known {
            receiver: _,
            user_id: _,
            time,
            state: _,
        } => time,
        _ => unreachable!(),
    };
    let time_b = match status_b {
        IngressStatus::Known {
            receiver: _,
            user_id: _,
            time,
            state: _,
        } => time,
        _ => unreachable!(),
    };
    assert_eq!(time_a, time_b);
    assert_eq!(start_time, time_a);
    assert!(
        test_a.state().time() < test_b.state().time(),
        "Time should have progressed further in DTS"
    );
    assert_eq!(
        test_a.canister_state(a_id).system_state.balance(),
        test_b.canister_state(b_id).system_state.balance(),
    );
}

#[test]
fn dts_and_nondts_cycles_match_if_response_fails() {
    let mut test_a = ExecutionTestBuilder::new().with_manual_execution().build();
    let (a_id, amsg_id) = response_fail_scenario(&mut test_a);

    let mut test_b = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let (b_id, bmsg_id) = response_fail_scenario(&mut test_b);

    let status_a = test_a.ingress_status(&amsg_id);
    let status_b = test_b.ingress_status(&bmsg_id);
    assert_eq!(status_a, status_b);
    assert!(
        test_a.state().time() < test_b.state().time(),
        "Time should have progressed further in DTS"
    );
    assert_eq!(
        test_a.canister_state(a_id).system_state.balance(),
        test_b.canister_state(b_id).system_state.balance(),
    );
}

#[test]
fn dts_and_nondts_cycles_match_if_cleanup_fails() {
    let mut test_a = ExecutionTestBuilder::new().with_manual_execution().build();
    let (a_id, amsg_id) = cleanup_fail_scenario(&mut test_a);

    let mut test_b = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let (b_id, bmsg_id) = cleanup_fail_scenario(&mut test_b);

    let status_a = test_a.ingress_status(&amsg_id);
    let status_b = test_b.ingress_status(&bmsg_id);
    assert_eq!(status_a, status_b);
    assert!(
        test_a.state().time() < test_b.state().time(),
        "Time should have progressed further in DTS"
    );

    assert_eq!(
        test_a.canister_state(a_id).system_state.balance(),
        test_b.canister_state(b_id).system_state.balance(),
    );
}

#[test]
fn dts_response_concurrent_cycles_change_succeeds() {
    // Test steps:
    // 1. Canister A calls canister B.
    // 2. Canister B replies to canister A.
    // 3. The response callback of canister A runs in multiple slices.
    // 4. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `cycles_debit`).
    // 5. The response callback resumes and calls B transferring 1000 cycles.
    // 6. The response callback succeeds because there are enough cycles
    //    in the canister balance to cover both the call and cycles debit.

    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles128(transferred_cycles.into_parts())
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()).on_reply(
                wasm()
                    .stable64_grow(1)
                    .stable64_fill(0, 0, 10_000)
                    .call_with_cycles(
                        b_id.get(),
                        "update",
                        call_args().other_side(b.clone()),
                        transferred_cycles.into_parts(),
                    ),
            ),
        )
        .build();

    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();
    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    *test.canister_state_mut(a_id).system_state.balance_mut() = initial_cycles;

    // Execute one slice of the response callback.
    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles,
    );

    // Emulate a postponed charge.
    let cycles_debit = Cycles::new(1000);
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_cycles_debit(cycles_debit);

    // Complete the response callback execution.
    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles + refund - call_charge - cycles_debit
            + (max_execution_cost - (test.canister_execution_cost(a_id) - initial_execution_cost))
    );
}

#[test]
fn dts_response_concurrent_cycles_change_fails() {
    // Test steps:
    // 1. Canister A calls canister B.
    // 2. Canister B replies to canister A.
    // 3. The response callback of canister A runs in multiple slices.
    // 4. While canister A is paused, we emulate a postponed charge
    //    of the entire cycles balance of canister A.
    // 5. The response callback resumes and calls B transferring 1000 cycles.
    // 6. The response callback fails because there are not enough cycles
    //    in the canister balance to cover both the call and cycles debit.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles128(transferred_cycles.into_parts())
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()).on_reply(
                wasm()
                    .stable64_grow(1)
                    .stable64_fill(0, 0, 10_000)
                    .call_with_cycles(
                        b_id.get(),
                        "update",
                        call_args().other_side(b.clone()),
                        transferred_cycles.into_parts(),
                    ),
            ),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();
    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    *test.canister_state_mut(a_id).system_state.balance_mut() = initial_cycles;

    // Execute one slice of the response callback.
    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles,
    );

    // Emulate a postponed charge.
    let cycles_debit = test.canister_state(a_id).system_state.balance();
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);

    assert_eq!(
        err.description(),
        format!(
            "Canister {} is out of cycles: \
             requested {} cycles but the available balance \
             is {} cycles and the freezing threshold {} cycles",
            a_id,
            call_charge,
            initial_cycles + refund - cycles_debit,
            freezing_threshold
        )
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles + refund - cycles_debit
            + (max_execution_cost - (test.canister_execution_cost(a_id) - initial_execution_cost))
    );
}

#[test]
fn dts_response_with_cleanup_concurrent_cycles_change_fails() {
    // Test steps:
    // 1. Canister A calls canister B.
    // 2. Canister B replies to canister A.
    // 3. The response callback of canister A runs in multiple slices.
    // 4. While canister A is paused, we emulate a postponed charge
    //    of almost entire cycles balance of canister A.
    // 5. The response callback resumes and calls B transferring 1000 cycles.
    // 6. The response callback fails because there are not enough cycles
    //    in the canister balance to cover both the call and cycles debit.
    // 7. The cleanup callback of canister A runs in multiple slices.
    // 8. While canister A is paused, we emulate more postponed charges.
    // 9. The cleanup callback resumes and succeeds because it cannot change the
    //    cycles balance of the canister.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles128(transferred_cycles.into_parts())
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(
                    wasm()
                        .stable64_grow(1)
                        .stable64_fill(0, 0, 10_000)
                        .call_with_cycles(
                            b_id.get(),
                            "update",
                            call_args().other_side(b.clone()),
                            transferred_cycles.into_parts(),
                        ),
                )
                .on_cleanup(wasm().stable64_grow(2).stable64_fill(0, 0, 10_000)),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();
    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    *test.canister_state_mut(a_id).system_state.balance_mut() = initial_cycles;

    // Execute one slice of the response callback.
    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles,
    );

    // Emulate a postponed charge.
    let mut cycles_debit = test.canister_state(a_id).system_state.balance() - Cycles::new(1000);
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_cycles_debit(cycles_debit);

    // We don't know when the response callback finishes and the cleanup
    // callback starts running, so we execute each slice one by one and
    // add 1 cycle to `cycles_debit`.
    test.execute_slice(a_id);
    while test.canister_state(a_id).next_execution() != NextExecution::None {
        test.canister_state_mut(a_id)
            .system_state
            .add_postponed_charge_to_cycles_debit(Cycles::new(1));
        cycles_debit += Cycles::new(1);
        test.execute_slice(a_id);
    }

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles + refund - cycles_debit
            + (max_execution_cost - (test.canister_execution_cost(a_id) - initial_execution_cost))
    );

    // Check that the cleanup callback did run.
    assert_eq!(
        test.execution_state(a_id).stable_memory.size,
        NumWasmPages::from(2)
    );
}

#[test]
fn cleanup_callback_cannot_accept_cycles() {
    let mut test = ExecutionTestBuilder::new().build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm().message_payload().append_and_reply().build();

    let a = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_cleanup(wasm().accept_cycles(0)),
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // DTS of response execution relies on the fact that the cleanup callback
    // cannot accept cycles.
    assert!(err
        .description()
        .contains("\"ic0_msg_cycles_accept\" cannot be executed in cleanup mode"));
}

#[test]
fn cleanup_callback_cannot_make_calls() {
    let mut test = ExecutionTestBuilder::new().build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm().message_payload().append_and_reply().build();

    let a = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().trap())
                .on_cleanup(wasm().call_simple(b_id.get(), "update", call_args().other_side(b))),
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // DTS of response execution relies on the fact that the cleanup callback
    // cannot make calls and send cycles.
    assert!(err
        .description()
        .contains("\"ic0_call_new\" cannot be executed in cleanup mode"));
}

#[test]
fn dts_uninstall_with_aborted_response() {
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let wasm_payload = wasm()
        .call_simple(
            b_id.get(),
            "update",
            call_args()
                .other_side(wasm().push_bytes(&[42]).append_and_reply())
                .on_reply(
                    wasm()
                        .stable64_grow(1)
                        .stable64_fill(0, 0, 10_000)
                        .stable64_fill(0, 0, 10_000)
                        .stable64_fill(0, 0, 10_000)
                        .stable64_fill(0, 0, 10_000),
                ),
        )
        .build();

    // Enqueue ingress message to canister A and execute it.
    let (ingress, _) = test.ingress_raw(a_id, "update", wasm_payload);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.abort_all_paused_executions();

    test.uninstall_code(a_id).unwrap();

    test.execute_message(a_id);

    // Execute response with deleted call context.
    let err = check_ingress_status(test.ingress_status(&ingress)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterRejectedMessage);
    assert_eq!(err.description(), "Canister has been uninstalled.");
}
