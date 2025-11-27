use assert_matches::assert_matches;
use ic_base_types::{NumBytes, NumSeconds};
use ic_error_types::ErrorCode;
use ic_interfaces::execution_environment::MessageMemoryUsage;
use ic_management_canister_types_private::CanisterStatusType;
use ic_replicated_state::NumWasmPages;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::testing::SystemStateTesting;
use ic_test_utilities_execution_environment::{
    ExecutionResponse, ExecutionTest, ExecutionTestBuilder, check_ingress_status,
};
use ic_test_utilities_metrics::fetch_int_counter;
use ic_test_utilities_types::messages::ResponseBuilder;
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::messages::NO_DEADLINE;
use ic_types::{
    CanisterId, Cycles, Time,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, MessageId},
};
use ic_types::{ComputeAllocation, MemoryAllocation};
use ic_types::{NumInstructions, messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES};
use ic_universal_canister::{call_args, wasm};

#[test]
fn execute_response_when_stopping_status() {
    // This test uses manual execution to get finer control over the execution.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister A calls canister B.
    let wasm_payload = wasm().inter_update(b_id, call_args()).build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    test.execute_message(a_id);
    test.stop_canister(a_id);

    let callback_id = CallbackId::from(1);
    // Check canister's status and call context.
    assert_matches!(
        test.canister_state(a_id).status(),
        CanisterStatusType::Stopping
    );

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(callback_id)
        .build();

    // Execute response when canister status is Stopping.
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
        .call_with_cycles(b_id, "update", call_args(), cycles_sent)
        .build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .refund(cycles_sent / 2u64)
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
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let mgr = test.cycles_account_manager();
    let response_transmission_refund = mgr.xnet_call_bytes_transmitted_fee(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        test.subnet_size(),
        cost_schedule,
    );
    mgr.xnet_call_bytes_transmitted_fee(response_payload_size, test.subnet_size(), cost_schedule);
    let instructions_left = NumInstructions::from(instruction_limit) - instructions_executed;
    let execution_refund = mgr
        .convert_instructions_to_cycles(instructions_left, test.canister_wasm_execution_mode(a_id));
    assert_eq!(
        balance_after,
        balance_before + cycles_sent / 2u64 + response_transmission_refund + execution_refund
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
    let wasm_payload = wasm().inter_update(b_id, call_args()).build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    test.execute_message(a_id);

    // Create response from canister B to canister A.
    let response = ResponseBuilder::new()
        .originator(a_id)
        .respondent(b_id)
        .originator_reply_callback(CallbackId::from(1))
        .build();

    // Call context is not deleted.
    assert!(
        !test
            .get_call_context(a_id, response.originator_reply_callback)
            .is_deleted()
    );

    // Call context is deleted after uninstall.
    test.uninstall_code(a_id).unwrap();
    assert_eq!(
        test.canister_state(a_id).status(),
        CanisterStatusType::Running
    );
    assert!(
        test.get_call_context(a_id, response.originator_reply_callback)
            .is_deleted()
    );

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
    let wasm_payload = wasm().inter_update(b_id, call_args()).build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
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
    assert!(
        !test
            .get_call_context(a_id, response.originator_reply_callback)
            .is_deleted(),
    );

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
        .inter_update(b_id, call_args().on_reply(wasm().trap()))
        .build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
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
        ExecutionResponse::Ingress((
            _,
            IngressStatus::Known {
                state: IngressState::Failed(user_error),
                receiver,
                time,
                user_id: _,
            },
        )) => {
            assert_eq!(time, Time::from_nanos_since_unix_epoch(0));
            assert_eq!(receiver, a_id.get());
            user_error.assert_contains(
                ErrorCode::CanisterCalledTrap,
                "Canister called `ic0.trap` with message: ",
            );
        }
        _ => {
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
            b_id,
            call_args()
                .on_reply(wasm().trap())
                .on_cleanup(wasm().trap()),
        )
        .build();

    // Enqueue ingress message to canister A and execute it.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
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
        ExecutionResponse::Ingress((
            _,
            IngressStatus::Known {
                state: IngressState::Failed(user_error),
                receiver,
                time,
                user_id: _,
            },
        )) => {
            assert_eq!(time, Time::from_nanos_since_unix_epoch(0));
            assert_eq!(receiver, a_id.get());
            user_error.assert_contains(
                ErrorCode::CanisterCalledTrap,
                "Canister called `ic0.trap` with message: ",
            );
            user_error
                .assert_contains(ErrorCode::CanisterCalledTrap, "all_on_cleanup also failed:");
        }
        _ => {
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

    let transferred_cycles = initial_cycles.get() / 2;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().reply_data_append().trap()),
            Cycles::from(transferred_cycles),
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

    let transferred_cycles = initial_cycles.get() / 2;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    // 3. Traps in the cleanup callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().reply_data_append().trap())
                .on_cleanup(wasm().trap()),
            Cycles::from(transferred_cycles),
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
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply()
                        .build(),
                ),
            Cycles::from(1000u128),
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
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(wasm().instruction_counter_is_at_least(1_000_000)),
            Cycles::from(1000u128),
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
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 40 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On reply grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
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
        test.subnet_available_memory().get_execution_memory();

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
            test.subnet_available_memory().get_execution_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfMemory);
    // verify that cleanup was in fact unable to allocate over subnet memory limit
    assert_eq!(
        available_memory_before_finishing_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn dts_out_of_subnet_memory_in_cleanup_callback() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 40 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On cleanup grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000),
                ),
            Cycles::from(1000u128),
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
        test.subnet_available_memory().get_execution_memory();

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
            test.subnet_available_memory().get_execution_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // verify that cleanup was in fact unable to allocate over subnet memory limit
    assert_eq!(
        available_memory_before_finishing_callback,
        test.subnet_available_memory().get_execution_memory()
    )
}

#[test]
fn dts_abort_works_in_response_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply()
                        .build(),
                ),
            Cycles::from(1000u128),
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

    // Execute the response callback again and it should succeed.
    test.execute_message(a_id);
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));
}

#[test]
fn dts_abort_works_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(wasm().instruction_counter_is_at_least(1_000_000)),
            Cycles::from(1000u128),
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
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(1000u128),
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

    let transferred_cycles = initial_cycles.get() / 2;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .reply_data_append()
                        .trap(),
                )
                .on_cleanup(wasm().stable_grow(1).stable64_fill(0, 0, 1)),
            Cycles::from(transferred_cycles),
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

    let transferred_cycles = initial_cycles.get() / 2;

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Traps in the response callback.
    // 3. Traps in the cleanup callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .reply_data_append()
                        .trap(),
                )
                .on_cleanup(wasm().instruction_counter_is_at_least(1_000_000).trap()),
            Cycles::from(transferred_cycles),
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
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let (b_id, bmsg_id) = successful_response_scenario(&mut test_b);

    let status_a = test_a.ingress_status(&amsg_id);
    let status_b = test_b.ingress_status(&bmsg_id);
    assert_eq!(status_a, status_b);
    let IngressStatus::Known { time: time_a, .. } = status_a else {
        unreachable!();
    };
    let IngressStatus::Known { time: time_b, .. } = status_b else {
        unreachable!();
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
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
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
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
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

    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args().other_side(b.clone()).on_reply(
                wasm()
                    .instruction_counter_is_at_least(1_000_000)
                    .call_with_cycles(
                        b_id,
                        "update",
                        call_args().other_side(b.clone()),
                        transferred_cycles,
                    ),
            ),
        )
        .build();

    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(a_id),
    );

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    test.canister_state_mut(a_id)
        .system_state
        .set_balance(initial_cycles);

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
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

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
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args().other_side(b.clone()).on_reply(
                wasm()
                    .instruction_counter_is_at_least(1_000_000)
                    .call_with_cycles(
                        b_id,
                        "update",
                        call_args().other_side(b.clone()),
                        transferred_cycles,
                    ),
            ),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(a_id),
    );

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    test.canister_state_mut(a_id)
        .system_state
        .set_balance(initial_cycles);

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
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterContractViolation);

    assert_eq!(
        err.description(),
        format!(
            "Error from Canister {a_id}: Canister {a_id} is out of cycles: \
             please top up the canister with at least {} additional cycles",
            (freezing_threshold + call_charge) - (initial_cycles + refund - cycles_debit)
        )
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles + refund - cycles_debit
            + (max_execution_cost - (test.canister_execution_cost(a_id) - initial_execution_cost))
    );
}

#[test]
fn dts_response_with_cleanup_concurrent_cycles_change_succeeds() {
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
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1_000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args()
                .other_side(b.clone())
                .on_reply(
                    wasm()
                        .instruction_counter_is_at_least(1_000_000)
                        .call_with_cycles(
                            b_id,
                            "update",
                            call_args().other_side(b.clone()),
                            transferred_cycles,
                        ),
                )
                .on_cleanup(
                    wasm()
                        .stable64_grow(2)
                        .stable64_fill(0, 0, 10_000)
                        .instruction_counter_is_at_least(1_000_000),
                ),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    // The test setup is done by this point.
    // Now we start testing the response callback.
    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(a_id),
    );

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let refund = test.max_response_fee() - test.reply_fee(&b);

    // Reset the cycles balance of canister A to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + additional_freezing_threshold + call_charge - refund;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    test.canister_state_mut(a_id)
        .system_state
        .set_balance(initial_cycles);

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
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    // We don't know when the response callback finishes and the cleanup
    // callback starts running, so we execute each slice one by one and
    // add 1 cycle to `ingress_induction_cycles_debit`.
    test.execute_slice(a_id);
    while test.canister_state(a_id).next_execution() != NextExecution::None {
        test.canister_state_mut(a_id)
            .system_state
            .add_postponed_charge_to_ingress_induction_cycles_debit(Cycles::new(1));
        cycles_debit += Cycles::new(1);
        test.execute_slice(a_id);
    }

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterContractViolation);

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
fn dts_response_with_cleanup_concurrent_cycles_change_is_capped() {
    // Test steps:
    // 1. Canister A calls canister B.
    // 2. Canister B replies to canister A.
    // 3. The response callback of canister A traps.
    // 4. The cleanup callback of canister A runs in multiple slices.
    // 5. While canister A is paused, we emulate more postponed charges.
    // 6. The cleanup callback resumes and succeeds because it cannot change the
    //    cycles balance of the canister.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_subnet_memory_threshold(100 * 1024 * 1024)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1_000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args()
                .other_side(b.clone())
                .on_reply(
                    wasm()
                        // Fail the response callback to trigger the cleanup callback.
                        .trap(),
                )
                .on_cleanup(
                    wasm()
                        // Grow by enough pages to trigger a cycles reservation for the extra storage.
                        .stable64_grow(1_300)
                        .instruction_counter_is_at_least(1_000_000),
                ),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    // The test setup is done by this point.

    // Execute one slice of the canister. This will run the response callback in full as
    // it immediately traps and will start the first slice of the cleanup callback.
    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Emulate a postponed charge that drives the cycles balance of the canister to zero.
    let cycles_debit = test.canister_state(a_id).system_state.balance();
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    // Keep running the cleanup callback until it finishes.
    test.execute_slice(a_id);
    while test.canister_state(a_id).next_execution() != NextExecution::None {
        test.execute_slice(a_id);
    }

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);

    // Check that the cleanup callback did run.
    assert_eq!(
        test.execution_state(a_id).stable_memory.size,
        NumWasmPages::from(1300)
    );

    // Even though the emulated ingress induction debit was set to be equal to the
    // canister's balance, it's going to be capped by the amount removed from the
    // balance during Wasm execution, so the canister will maintain a positive
    // balance.
    assert!(test.canister_state(a_id).system_state.balance() > Cycles::zero());
}

#[test]
fn cleanup_callback_cannot_accept_cycles() {
    let mut test = ExecutionTestBuilder::new().build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm().message_payload().append_and_reply().build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_cleanup(wasm().accept_cycles(Cycles::from(0u128))),
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // DTS of response execution relies on the fact that the cleanup callback
    // cannot accept cycles.
    assert!(
        err.description()
            .contains("\"ic0_msg_cycles_accept128\" cannot be executed in cleanup mode")
    );
}

#[test]
fn cleanup_callback_cannot_make_calls() {
    let mut test = ExecutionTestBuilder::new().build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm().message_payload().append_and_reply().build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args()
                .other_side(b.clone())
                .on_reply(wasm().trap())
                .on_cleanup(wasm().inter_update(b_id, call_args().other_side(b))),
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    // DTS of response execution relies on the fact that the cleanup callback
    // cannot make calls and send cycles.
    assert!(
        err.description()
            .contains("\"ic0_call_new\" cannot be executed in cleanup mode")
    );
}

#[test]
fn dts_uninstall_with_aborted_response() {
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let wasm_payload = wasm()
        .inter_update(
            b_id,
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

/// The test makes sure cleanup callback has at least `cleanup_reservation_percentage` instructions reserved
/// from a total `instruction_limit` to execute the cleanup callback.
fn reserve_instructions_for_cleanup_callback_scenario(
    test: &mut ExecutionTest,
    instruction_limit: u64,
) {
    let cleanup_reservation_percentage = 5;
    let cleanup_instructions_reserved = (instruction_limit * cleanup_reservation_percentage) / 100;

    let initial_cycles = Cycles::new(1_000_000_000_000);
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies with the message that was sent to it.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. In the response callback exhausts all the available instructions.
    // 3. In the cleanup callback exhausts almost all the instructions and writes to the stable memory.
    let unreachable_instructions_amount = 2 * instruction_limit;
    let stable_grow_and_write_instructions = 20_000;
    let stable_memory_data = b"x";
    let transferred_cycles = initial_cycles.get() / 2;
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(
                    // In response callback exhaust all the instructions available to cause a cleanup callback.
                    wasm()
                        .instruction_counter_is_at_least(unreachable_instructions_amount)
                        .trap(),
                )
                .on_cleanup(
                    // In cleanup callback exhaust reserved instructions and write to the stable memory
                    // to make sure that cleanup callback was executed fully and successfully.
                    wasm()
                        .instruction_counter_is_at_least(
                            cleanup_instructions_reserved - stable_grow_and_write_instructions,
                        )
                        .stable_grow(1)
                        .stable_write(0, stable_memory_data),
                ),
            Cycles::from(transferred_cycles),
        )
        .build();
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    // Canister A calls canister B.
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None
    );
    test.induct_messages();

    // Canister B replies.
    test.execute_message(b_id);
    test.induct_messages();

    // Canister A:
    // - executes a response callback which fails with exceeding instructions limit
    // - executes a cleanup callback which exhausts all the instructions and writes to stable memory
    let execution_cost_before = test.canister_execution_cost(a_id);
    test.execute_message(a_id);
    let execution_cost_after = test.canister_execution_cost(a_id);
    assert!(execution_cost_after > execution_cost_before);

    // Assert that the response failed with exceeding instructions limit.
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterInstructionLimitExceeded);

    // Assert that cleanup callback was executed fully and successfully by reading from stable memory.
    let (ingress_id, _) = test.ingress_raw(
        a_id,
        "query",
        wasm().stable_read(0, 1).append_and_reply().build(),
    );
    test.execute_message(a_id);
    test.induct_messages();
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(stable_memory_data.to_vec()));
}

#[test]
fn reserve_instructions_for_cleanup_callback() {
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_manual_execution()
        .build();

    reserve_instructions_for_cleanup_callback_scenario(&mut test, instruction_limit);
}

#[test]
fn reserve_instructions_for_cleanup_callback_with_dts() {
    let instruction_limit = 1_000_000;
    let slice_instruction_limit = 10_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(slice_instruction_limit)
        .with_manual_execution()
        .build();

    reserve_instructions_for_cleanup_callback_scenario(&mut test, instruction_limit);
}

#[test]
fn response_callback_succeeds_with_memory_reservation() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On reply grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response callback.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    // Create a new canister allocating 10MB. It is expected to succeed.
    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(10 * 1024 * 1024),
    )
    .unwrap();

    // Create a new canister allocating 10MB. It is expected to fail.
    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(10 * 1024 * 1024),
    )
    .unwrap_err();

    let available_memory_before_finishing_callback =
        test.subnet_available_memory().get_execution_memory();

    assert!(available_memory_before_finishing_callback >= 0);

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
        // Memory changes not reflected in global state.
        assert_eq!(
            available_memory_before_finishing_callback,
            test.subnet_available_memory().get_execution_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    // Verify that the response callback allocated at least 80MB.
    assert!(
        available_memory_before_finishing_callback
            > test.subnet_available_memory().get_execution_memory() + 80 * 1024 * 1024
    );
}

#[test]
fn cleanup_callback_succeeds_with_memory_reservation() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On cleanup grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000),
                ),
            Cycles::from(1000u128),
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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response and cleanup callbacks.
    let original_system_state: ic_replicated_state::SystemState =
        test.canister_state(a_id).system_state.clone();
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    // Create a new canister allocating 10MB. It is expected to succeed.
    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(10 * 1024 * 1024),
    )
    .unwrap();

    // Create a new canister allocating 10MB. It is expected to fail.
    test.create_canister_with_allocation(
        Cycles::new(1_000_000_000_000_000),
        None,
        Some(10 * 1024 * 1024),
    )
    .unwrap_err();

    let available_memory_before_finishing_callback =
        test.subnet_available_memory().get_execution_memory();

    assert!(available_memory_before_finishing_callback >= 0);

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
        // Memory changes not reflected in global state.
        assert_eq!(
            available_memory_before_finishing_callback,
            test.subnet_available_memory().get_execution_memory()
        );
        test.execute_slice(a_id);
    }

    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    // The response callback calls trap and that is returned even after the
    // cleanup callback runs.
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);

    // Verify that the cleanup callback allocated at least 80MB.
    assert!(
        available_memory_before_finishing_callback
            > test.subnet_available_memory().get_execution_memory() + 80 * 1024 * 1024
    )
}

#[test]
fn subnet_available_memory_does_not_change_on_response_abort() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On reply grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
        )
        .build();

    test.ingress_raw(a_id, "update", a);

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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response callback.
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    test.abort_all_paused_executions();

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn subnet_available_memory_does_not_change_on_cleanup_abort() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On cleanup grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000),
                ),
            Cycles::from(1000u128),
        )
        .build();

    test.ingress_raw(a_id, "update", a);

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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response and cleanup callbacks.
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    test.abort_all_paused_executions();

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn subnet_available_memory_does_not_change_on_response_validation_failure() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(100 * 1024 * 1024)
        .with_subnet_memory_reservation(80 * 1024 * 1024)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On reply grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
        )
        .build();

    test.ingress_raw(a_id, "update", a);

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

    // Uninstall canister A to mark its call context as deleted.
    test.uninstall_code(a_id).unwrap();

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response callback.
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn subnet_available_memory_does_not_change_on_response_resume_failure() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On reply grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
        )
        .build();

    test.ingress_raw(a_id, "update", a);

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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response callback.
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    // Change the cycles balance to force the response resuming to fail.
    test.canister_state_mut(a_id)
        .system_state
        .burn_remaining_balance_for_uninstall();

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn subnet_available_memory_does_not_change_on_cleanup_resume_failure() {
    let scaling_factor = 4;
    let subnet_execution_memory_per_thread = 100 * 1024 * 1024;
    let subnet_memory_reservation_per_thread = 80 * 1024 * 1024;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling_factor * subnet_execution_memory_per_thread)
        .with_subnet_memory_reservation(scaling_factor * subnet_memory_reservation_per_thread)
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_resource_saturation_scaling(scaling_factor as usize)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // On cleanup grows memory by roughly 80MB.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reply(wasm().trap())
                .on_reject(wasm().reject_message().reject())
                .on_cleanup(
                    wasm()
                        .stable_grow(1280)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000),
                ),
            Cycles::from(1000u128),
        )
        .build();

    test.ingress_raw(a_id, "update", a);

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

    let available_memory_before_starting_callback =
        test.subnet_available_memory().get_execution_memory();

    // Start executing the response and cleanup callbacks.
    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );

    // Change the cycles balance to force the cleanup resuming to fail.
    test.canister_state_mut(a_id)
        .system_state
        .burn_remaining_balance_for_uninstall();

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        available_memory_before_starting_callback,
        test.subnet_available_memory().get_execution_memory()
    );
}

#[test]
fn cycles_balance_changes_applied_correctly() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(20_000_000_000)
        .build();
    let a_id = test
        .universal_canister_with_cycles(Cycles::new(10_000_000_000_000))
        .unwrap();
    let b_id = test
        .universal_canister_with_cycles(Cycles::new(301_000_000_000))
        .unwrap();

    test.ingress(
        b_id,
        "update",
        wasm()
            .call_with_cycles(
                a_id,
                "update",
                call_args().other_side(wasm().accept_cycles(Cycles::new(u128::MAX))),
                Cycles::new(60_000_000_000),
            )
            .build(),
    )
    .unwrap();

    let mut b = wasm().accept_cycles(Cycles::new(u128::MAX));

    for _ in 0..4 {
        b = b.inter_update(a_id, call_args());
    }

    let b = b.push_int(42).reply_int().build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()),
            Cycles::new(10_000_000_000_000),
        )
        .build();
    let a_balance_old = test.canister_state(a_id).system_state.balance();
    let b_balance_old = test.canister_state(b_id).system_state.balance();
    let res = test.ingress(a_id, "update", a).unwrap();
    match res {
        WasmResult::Reply(_) => {}
        WasmResult::Reject(msg) => unreachable!("rejected : {}", msg),
    }
    let a_balance_new = test.canister_state(a_id).system_state.balance();
    let b_balance_new = test.canister_state(b_id).system_state.balance();

    assert!(a_balance_old + b_balance_old > a_balance_new + b_balance_new);
}

#[test]
fn test_cycles_burn() {
    let test = ExecutionTestBuilder::new().build();

    let canister_memory_usage = NumBytes::from(1_000_000);
    let canister_message_memory_usage = MessageMemoryUsage::ZERO;

    let amount = 1_000_000_000;
    let mut balance = Cycles::new(amount);
    let amount_to_burn = Cycles::new(amount / 10);

    let burned = test.cycles_account_manager().cycles_burn(
        &mut balance,
        amount_to_burn,
        ic_config::execution_environment::Config::default().default_freeze_threshold,
        MemoryAllocation::default(),
        canister_memory_usage,
        canister_message_memory_usage,
        ComputeAllocation::zero(),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        Cycles::zero(),
    );

    assert_eq!(burned, amount_to_burn);
    assert_eq!(balance.get() + burned.get(), amount);
}

#[test]
fn cycles_burn_up_to_the_threshold_on_not_enough_cycles() {
    let test = ExecutionTestBuilder::new().build();

    let canister_memory_usage = NumBytes::from(1_000_000);
    let canister_message_memory_usage = MessageMemoryUsage::ZERO;

    let freezing_threshold_cycles = test.cycles_account_manager().freeze_threshold_cycles(
        ic_config::execution_environment::Config::default().default_freeze_threshold,
        MemoryAllocation::default(),
        canister_memory_usage,
        canister_message_memory_usage,
        ComputeAllocation::zero(),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        Cycles::zero(),
    );

    let amount = 1_000_000_000;
    let mut balance = Cycles::new(amount);

    let burned = test.cycles_account_manager().cycles_burn(
        &mut balance,
        Cycles::new(10 * amount),
        ic_config::execution_environment::Config::default().default_freeze_threshold,
        MemoryAllocation::default(),
        canister_memory_usage,
        canister_message_memory_usage,
        ComputeAllocation::zero(),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        Cycles::zero(),
    );

    assert_eq!(burned.get(), amount - freezing_threshold_cycles.get());
    assert_eq!(balance.get() + burned.get(), amount);
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_ok_response() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A, B and C.
    // The canister C is to keep the call context open even after the canister B response.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    // Canister A calls canister B and C.
    let wasm_payload = wasm()
        .inter_update(b_id, call_args())
        .inter_update(c_id, call_args())
        .build();

    // Enqueue ingress message to canister A.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    test.induct_messages();
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(1));

    // Make sure the `instructions_executed` is updated.
    let instructions_executed_a_1 = call_context.instructions_executed();
    assert!(instructions_executed_a_1 > 0.into());

    // Execute canister B message.
    test.execute_message(b_id);
    test.induct_messages();

    // Execute canister A on reply callback.
    test.execute_message(a_id);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 3);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(2));

    // Make sure the `instructions_executed` has increased.
    let instructions_executed_a_2 = call_context.instructions_executed();
    assert!(instructions_executed_a_2 > instructions_executed_a_1);
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_err_response() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A, B and C.
    // The canister C is to keep the call context open even after the canister B response.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    // Canister A calls canister B and C, the canister B on reply traps.
    let wasm_payload = wasm()
        .inter_update(b_id, call_args().on_reply(wasm().trap()))
        .inter_update(c_id, call_args())
        .build();

    // Enqueue ingress message to canister A.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    test.induct_messages();
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(1));

    // Make sure the `instructions_executed` is updated.
    let instructions_executed_a_1 = call_context.instructions_executed();
    assert!(instructions_executed_a_1 > 0.into());

    // Execute canister B message.
    test.execute_message(b_id);
    test.induct_messages();

    // Execute canister A on reply callback.
    test.execute_message(a_id);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was not ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(2));

    // Make sure the `instructions_executed` has increased.
    let instructions_executed_a_2 = call_context.instructions_executed();
    assert!(instructions_executed_a_2 > instructions_executed_a_1);
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_ok_cleanup() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A, B and C.
    // The canister C is to keep the call context open even after the canister B response.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    // Canister A calls canister B and C, the canister B on reply traps.
    let wasm_payload = wasm()
        .inter_update(b_id, call_args().on_reply(wasm().trap()).on_cleanup(wasm()))
        .inter_update(c_id, call_args())
        .build();

    // Enqueue ingress message to canister A.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    test.induct_messages();
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(1));

    // Make sure the `instructions_executed` is updated.
    let instructions_executed_a_1 = call_context.instructions_executed();
    assert!(instructions_executed_a_1 > 0.into());

    // Execute canister B message.
    test.execute_message(b_id);
    test.induct_messages();

    // Execute canister A on reply callback.
    test.execute_message(a_id);
    // The cleanup execution increases the canister version.
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 3);

    // Make sure the execution was not ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(2));

    // Make sure the `instructions_executed` has increased.
    let instructions_executed_a_2 = call_context.instructions_executed();
    assert!(instructions_executed_a_2 > instructions_executed_a_1);
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_err_cleanup() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A, B and C.
    // The canister C is to keep the call context open even after the canister B response.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    // Canister A calls canister B and C, the canister B on reply and on cleanup trap.
    let wasm_payload = wasm()
        .inter_update(
            b_id,
            call_args()
                .on_reply(wasm().trap())
                .on_cleanup(wasm().trap()),
        )
        .inter_update(c_id, call_args())
        .build();

    // Enqueue ingress message to canister A.
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    test.induct_messages();
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(1));

    // Make sure the `instructions_executed` is updated.
    let instructions_executed_a_1 = call_context.instructions_executed();
    assert!(instructions_executed_a_1 > 0.into());

    // Execute canister B message.
    test.execute_message(b_id);
    test.induct_messages();

    // Execute canister A on reply callback.
    test.execute_message(a_id);
    // The cleanup traps, so the canister version is unchanged.
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was not ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(2));

    // Make sure the `instructions_executed` has increased.
    let instructions_executed_a_2 = call_context.instructions_executed();
    assert!(instructions_executed_a_2 > instructions_executed_a_1);
}

#[test]
fn test_call_context_performance_counter_correctly_reported_on_reply() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Counter a.0
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .inter_update(
            b_id,
            call_args().on_reply(
                wasm()
                    // Counter a.2
                    .performance_counter(1)
                    .int64_to_blob()
                    .append_to_global_data()
                    .inter_update(
                        b_id,
                        call_args().on_reply(
                            wasm()
                                .get_global_data()
                                .reply_data_append()
                                // Counter a.3
                                .performance_counter(1)
                                .reply_int64(),
                        ),
                    ),
            ),
        )
        // Counter a.1
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();

    let counters = result
        .bytes()
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    assert!(counters[0] < counters[1]);
    assert!(counters[1] < counters[2]);
    assert!(counters[2] < counters[3]);
}

#[test]
fn test_call_context_performance_counter_correctly_reported_on_reject() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Counter a.0
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .inter_update(
            b_id,
            call_args().other_side(wasm().trap()).on_reject(
                wasm()
                    // Counter a.2
                    .performance_counter(1)
                    .int64_to_blob()
                    .append_to_global_data()
                    .inter_update(
                        b_id,
                        call_args().other_side(wasm().trap()).on_reject(
                            wasm()
                                .get_global_data()
                                .reply_data_append()
                                // Counter a.3
                                .performance_counter(1)
                                .reply_int64(),
                        ),
                    ),
            ),
        )
        // Counter a.1
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();

    let counters = result
        .bytes()
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    assert!(counters[0] < counters[1]);
    assert!(counters[1] < counters[2]);
    assert!(counters[2] < counters[3]);
}

#[test]
fn test_call_context_performance_counter_correctly_reported_on_cleanup() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();

    let a = wasm()
        .stable_grow(1)
        .stable64_write(2, &[3, 4])
        // Counter a.0
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .call_simple(
            a_id.get(),
            "non-existent",
            call_args().on_reject(wasm().trap()).on_cleanup(
                wasm()
                    // Counter a.2
                    .performance_counter(1)
                    .int64_to_blob()
                    .append_to_global_data()
                    // Write the global data to the stable memory.
                    .push_int(0)
                    .get_global_data()
                    .stable_write_offset_blob(),
            ),
        )
        // Counter a.1
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .build();
    // The canister explicitly traps.
    let _err = test.ingress(a_id, "update", a).unwrap_err();

    let state = test.canister_state(a_id);
    let stable_memory = &state.execution_state.as_ref().unwrap().stable_memory;
    let page = stable_memory.page_map.get_page(0.into());
    let counters = page[0..(std::mem::size_of::<u64>() * 3)]
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    assert!(counters[0] < counters[1]);
    assert!(counters[1] < counters[2]);
}

#[test]
fn test_best_effort_responses() {
    let mut test = ExecutionTestBuilder::new().build();

    let a_id = test
        .universal_canister_with_cycles(Cycles::new(10_000_000_000_000))
        .unwrap();
    let b_id = test
        .universal_canister_with_cycles(Cycles::new(10_000_000_000_000))
        .unwrap();

    let result = test.ingress(
        b_id,
        "update",
        wasm()
            .call_simple_with_cycles_and_best_effort_response(
                a_id,
                "update",
                call_args().other_side(wasm().accept_cycles(Cycles::new(6_000_000))),
                Cycles::new(6_000_000),
                100,
            )
            .reply()
            .build(),
    );
    assert_eq!(result, Ok(WasmResult::Reply(vec![])))
}

#[test]
fn test_ic0_msg_deadline_best_effort_responses() {
    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test
        .universal_canister_with_cycles(Cycles::new(10_000_000_000_000))
        .unwrap();

    let result = test.ingress(
        canister_id,
        "update",
        wasm().msg_deadline().reply_int64().build(),
    );

    let no_deadline = Time::from(NO_DEADLINE).as_nanos_since_unix_epoch();
    assert_eq!(
        result,
        Ok(WasmResult::Reply(no_deadline.to_le_bytes().into()))
    );
}
