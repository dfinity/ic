use assert_matches::assert_matches;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::HypervisorError;

use ic_execution_environment::ExecutionResponse;
use ic_replicated_state::CanisterStatus;
use ic_test_utilities::{
    execution_environment::ExecutionTestBuilder,
    types::messages::ResponseBuilder,
    universal_canister::{call_args, wasm},
};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::CallbackId,
    Cycles, Time,
};
use ic_types::{messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, NumInstructions};

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
