use ic_base_types::NumSeconds;
use ic_config::subnet_config::{
    CyclesAccountManagerConfig, DEFAULT_REFERENCE_SUBNET_SIZE, SEV_REFERENCE_SUBNET_SIZE,
};
use ic_cycles_account_manager::{
    CyclesAccountManager, CyclesAccountManagerSubnetConfig, IngressInductionCost,
    ResourceSaturation,
};
use ic_interfaces::execution_environment::{CanisterOutOfCyclesError, MessageMemoryUsage};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::{CanisterIdRecord, IC_00, Payload};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    SystemState,
    canister_state::execution_state::WasmExecutionMode,
    testing::{OutputRequestBuilder, SystemStateTesting},
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::{
    SystemStateBuilder, new_canister_state, new_canister_state_with_execution,
};
use ic_test_utilities_types::{
    ids::{canister_test_id, user_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    ComputeAllocation, MemoryAllocation, NumBytes, NumInstructions,
    messages::{
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, Payload as ResponsePayload, SignedIngress,
        extract_effective_canister_id,
    },
    time::{CoarseTime, UNIX_EPOCH},
};
use ic_types_cycles::{
    CanisterCyclesCostSchedule, CompoundCycles, Cycles, CyclesUseCase, Instructions, Memory,
    NominalCycles, NominalCyclesTesting, Uninstall,
};
use prometheus::IntCounter;
use std::{cmp::Ordering, convert::TryFrom, time::Duration};

const WASM_EXECUTION_MODE: WasmExecutionMode = WasmExecutionMode::Wasm32;

#[test]
fn xnet_call_total_fee_free() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    assert_eq!(
        Cycles::new(0),
        cam.xnet_call_total_fee(
            NumBytes::new(9999),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
                DEFAULT_REFERENCE_SUBNET_SIZE
            ),
            WasmExecutionMode::Wasm32,
        ),
    );
}

#[test]
fn test_can_charge_application_subnets() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    with_test_replica_logger(|log| {
        for subnet_type in &[
            SubnetType::Application,
            SubnetType::System,
            SubnetType::VerifiedApplication,
        ] {
            for memory_allocation in &[
                MemoryAllocation::from(NumBytes::from(0)),
                MemoryAllocation::from(NumBytes::from(1 << 20)),
            ] {
                for freeze_threshold in &[NumSeconds::from(1000), NumSeconds::from(0)] {
                    let cycles_account_manager = CyclesAccountManagerBuilder::new()
                        .with_subnet_type(*subnet_type)
                        .build();
                    let compute_allocation = ComputeAllocation::try_from(20).unwrap();
                    let mut canister = new_canister_state_with_execution(
                        canister_test_id(1),
                        canister_test_id(2).get(),
                        Cycles::zero(),
                        *freeze_threshold,
                    );
                    canister.system_state.memory_allocation = *memory_allocation;
                    canister.system_state.compute_allocation = compute_allocation;
                    let duration = Duration::from_secs(1);

                    // Ensure that we are not losing test coverage due to the memory usage
                    // collapsing with the memory allocation.
                    assert_ne!(
                        canister.memory_usage(),
                        memory_allocation.pre_allocated_bytes()
                    );

                    let memory = memory_allocation.allocated_bytes(canister.memory_usage());
                    let expected_fee = cycles_account_manager
                        .compute_allocation_cost(compute_allocation, duration, subnet_cycles_config)
                        .real()
                        + cycles_account_manager
                            .memory_cost(memory, duration, subnet_cycles_config)
                            .real()
                        + cycles_account_manager
                            .canister_base_cost(memory, duration, subnet_cycles_config)
                            .real();
                    let initial_cycles = expected_fee;
                    canister.system_state.add_cycles(initial_cycles);
                    assert_eq!(canister.system_state.balance(), initial_cycles);
                    cycles_account_manager
                        .charge_canister_for_resource_allocation_and_usage(
                            &log,
                            &mut canister,
                            duration,
                            subnet_cycles_config,
                        )
                        .unwrap();
                    assert_eq!(canister.system_state.balance(), Cycles::zero());
                }
            }
        }
    })
}

#[test]
fn withdraw_cycles_with_not_enough_balance_returns_error() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let initial_cycles = Cycles::new(100_000);
    let memory_usage = NumBytes::from(4 << 30);
    let message_memory_usage = MessageMemoryUsage {
        guaranteed_response: NumBytes::new(6 << 20),
        best_effort: NumBytes::new(2 << 20),
    };
    let amount = Cycles::new(200);
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id(),
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                MessageMemoryUsage::ZERO,
                ComputeAllocation::default(),
                &mut new_balance,
                amount,
                subnet_cycles_config,
                system_state.reserved_balance(),
                false,
            ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            subnet_cycles_config,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(60),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id(),
                system_state.freeze_threshold,
                system_state.memory_allocation,
                NumBytes::from(0),
                MessageMemoryUsage::ZERO,
                ComputeAllocation::default(),
                &mut new_balance,
                amount,
                subnet_cycles_config,
                system_state.reserved_balance(),
                false,
            ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            subnet_cycles_config,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(0),
        );
        let mut new_balance = system_state.balance();
        assert_eq!(
            CyclesAccountManagerBuilder::new()
                .build()
                .withdraw_cycles_for_transfer(
                    system_state.canister_id(),
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    message_memory_usage,
                    ComputeAllocation::default(),
                    &mut new_balance,
                    amount,
                    subnet_cycles_config,
                    system_state.reserved_balance(),
                    false,
                ),
            Ok(())
        );
        system_state.set_balance(new_balance);
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            memory_usage,
            message_memory_usage,
            ComputeAllocation::default(),
            subnet_cycles_config,
            system_state.reserved_balance(),
        );
        assert_eq!(system_state.balance(), initial_cycles - threshold - amount);
    }

    {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemState::new_running_for_testing(
            canister_test_id(1),
            canister_test_id(2).get(),
            initial_cycles,
            NumSeconds::from(30),
        );
        let mut balance = system_state.balance();
        assert_eq!(
            cycles_account_manager.withdraw_cycles_for_transfer(
                system_state.canister_id(),
                system_state.freeze_threshold,
                system_state.memory_allocation,
                memory_usage,
                message_memory_usage,
                ComputeAllocation::default(),
                &mut balance,
                amount,
                subnet_cycles_config,
                system_state.reserved_balance(),
                false,
            ),
            Err(CanisterOutOfCyclesError {
                canister_id: canister_test_id(1),
                available: initial_cycles,
                requested: amount,
                threshold: cycles_account_manager.freeze_threshold_cycles(
                    system_state.freeze_threshold,
                    system_state.memory_allocation,
                    memory_usage,
                    message_memory_usage,
                    ComputeAllocation::default(),
                    subnet_cycles_config,
                    system_state.reserved_balance(),
                ),
                reveal_top_up: false,
            })
        );
    }
}

#[test]
fn verify_no_cycles_charged_for_message_execution_on_system_subnets() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        subnet_size,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let initial_balance = system_state.balance();
    let cycles = cycles_account_manager
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
            subnet_cycles_config,
            false,
            WASM_EXECUTION_MODE,
        )
        .unwrap();
    assert_eq!(system_state.balance(), initial_balance);

    let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
    cycles_account_manager.refund_unused_execution_cycles(
        &mut system_state,
        NumInstructions::from(1_000_000),
        NumInstructions::from(1_000_000),
        cycles,
        &no_op_counter,
        subnet_cycles_config,
        WASM_EXECUTION_MODE,
        &no_op_logger(),
    );
    assert_eq!(system_state.balance(), initial_balance);
}

#[test]
fn verify_no_cycles_charged_for_message_execution_on_free_schedule() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        subnet_size,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_balance = system_state.balance();
    let cycles = cycles_account_manager
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
            subnet_cycles_config,
            false,
            WASM_EXECUTION_MODE,
        )
        .unwrap();
    assert_eq!(system_state.balance(), initial_balance);

    let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
    cycles_account_manager.refund_unused_execution_cycles(
        &mut system_state,
        NumInstructions::from(1_000_000),
        NumInstructions::from(1_000_000),
        cycles,
        &no_op_counter,
        subnet_cycles_config,
        WASM_EXECUTION_MODE,
        &no_op_logger(),
    );
    assert_eq!(system_state.balance(), initial_balance);
}

/// The instruction limit used by the response execution tests below. The
/// prepayment for a response execution covers exactly this many instructions.
const RESPONSE_EXECUTION_INSTRUCTION_LIMIT: NumInstructions = NumInstructions::new(1_000_000_000);

/// A cost schedule and a Wasm execution mode, as in effect at one point in time.
#[derive(Copy, Clone, Debug)]
struct ResponseExecutionSetting {
    cost_schedule: CanisterCyclesCostSchedule,
    wasm_execution_mode: WasmExecutionMode,
}

const NORMAL_WASM32: ResponseExecutionSetting = ResponseExecutionSetting {
    cost_schedule: CanisterCyclesCostSchedule::Normal,
    wasm_execution_mode: WasmExecutionMode::Wasm32,
};
const NORMAL_WASM64: ResponseExecutionSetting = ResponseExecutionSetting {
    cost_schedule: CanisterCyclesCostSchedule::Normal,
    wasm_execution_mode: WasmExecutionMode::Wasm64,
};
const FREE_WASM32: ResponseExecutionSetting = ResponseExecutionSetting {
    cost_schedule: CanisterCyclesCostSchedule::Free,
    wasm_execution_mode: WasmExecutionMode::Wasm32,
};
const FREE_WASM64: ResponseExecutionSetting = ResponseExecutionSetting {
    cost_schedule: CanisterCyclesCostSchedule::Free,
    wasm_execution_mode: WasmExecutionMode::Wasm64,
};

/// All the settings a canister can be in.
const RESPONSE_EXECUTION_SETTINGS: [ResponseExecutionSetting; 4] =
    [NORMAL_WASM32, NORMAL_WASM64, FREE_WASM32, FREE_WASM64];

/// Every combination of the cost schedule and the Wasm execution mode a canister
/// had when it performed a call (and hence prepaid for the response execution)
/// with the ones in effect when the response arrives.
///
/// The Wasm execution modes differ whenever the canister is upgraded across the
/// call. The cost schedules differ only if the cost schedule of the canister's
/// subnet changed across the call, which no proposal does today, though the
/// registry does not enforce that a canister migration keeps it either. The
/// accounting must not depend on it: it settles the prepayment recorded in the
/// callback, which carries the cost schedule in effect at the call, against a
/// requirement derived from the cost schedule in effect at the response.
fn response_execution_settings() -> Vec<(ResponseExecutionSetting, ResponseExecutionSetting)> {
    RESPONSE_EXECUTION_SETTINGS
        .into_iter()
        .flat_map(|at_call| {
            RESPONSE_EXECUTION_SETTINGS
                .into_iter()
                .map(move |at_response| (at_call, at_response))
        })
        .collect()
}

fn cycles_account_manager() -> CyclesAccountManager {
    CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_max_num_instructions(RESPONSE_EXECUTION_INSTRUCTION_LIMIT)
        .build()
}

fn subnet_cycles_config(
    cost_schedule: CanisterCyclesCostSchedule,
) -> CyclesAccountManagerSubnetConfig {
    CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    )
}

/// The consumed cycles gauge and the monotonic consumed cycles counter of the
/// given use case.
fn consumed_cycles(
    system_state: &SystemState,
    use_case: CyclesUseCase,
) -> (NominalCycles, NominalCycles) {
    let gauge = system_state
        .canister_metrics()
        .consumed_cycles_by_use_cases()
        .get(&use_case)
        .copied()
        .unwrap_or_else(NominalCycles::zero);
    let counter = system_state
        .canister_metrics()
        .consumed_cycles_by_use_cases_monotonic()
        .get(&use_case)
        .copied()
        .unwrap_or_else(NominalCycles::zero);
    (gauge, counter)
}

fn consumed_cycles_for_instructions(system_state: &SystemState) -> (NominalCycles, NominalCycles) {
    consumed_cycles(system_state, CyclesUseCase::Instructions)
}

/// A canister whose cost schedule or Wasm execution mode changed across a call
/// pays for its response execution, and has that execution reported in the
/// consumed cycles metrics, exactly as if it had performed the call under the cost
/// schedule and in the Wasm execution mode in which the response is executed.
///
/// Checked at the two points of the prepay, adjust and refund sequence at which
/// the cycles the canister has paid are determined: right after the adjustment,
/// where it must have paid the prepayment required at response time in both its
/// real and its nominal part, and after the cycles for the instructions the
/// callback did not execute are refunded, where it must have paid for the
/// instructions it did execute.
///
/// The canister starts out with just enough cycles to cover the larger of the
/// prepayment and the requirement, so that it has none to spare once it prepaid
/// and the adjustment withdrew the cycles missing from the prepayment, if any.
/// The adjustment withdraws `required - prepaid`, which saturates part by part,
/// without comparing the two first; any other withdrawal, in particular one
/// attempted where the prepayment covers the requirement in the real part, fails
/// here for lack of cycles instead of going unnoticed.
#[test]
fn response_execution_cycles_match_response_execution_setting() {
    const EXECUTED_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000);

    for (at_call, at_response) in response_execution_settings() {
        let cycles_account_manager = cycles_account_manager();
        let config_at_call = subnet_cycles_config(at_call.cost_schedule);
        let config_at_response = subnet_cycles_config(at_response.cost_schedule);
        let context = format!("{at_call:?} at call, {at_response:?} at response");

        // When the call was performed, the canister prepaid for executing the
        // response under the cost schedule and in the Wasm execution mode in
        // effect at that time. Now that the response has arrived, the prepayment
        // is adjusted to the cost schedule and the Wasm execution mode in effect
        // by now.
        let prepaid = cycles_account_manager
            .prepayment_for_response_execution(config_at_call, at_call.wasm_execution_mode);
        let required = cycles_account_manager
            .prepayment_for_response_execution(config_at_response, at_response.wasm_execution_mode);

        // Once the canister has paid the prepayment, its balance covers exactly the
        // cycles missing from it, if any, so that any withdrawal beyond those fails.
        let mut system_state = SystemStateBuilder::new()
            .initial_cycles(prepaid.real().max(required.real()))
            .build();
        let initial_balance = system_state.balance();
        system_state.consume_cycles(prepaid);

        let adjusted = cycles_account_manager
            .adjust_prepayment_for_response_execution(
                &mut system_state,
                prepaid,
                config_at_response,
                at_response.wasm_execution_mode,
                false,
            )
            .unwrap();

        assert_eq!(adjusted, required, "unexpected prepayment for {context}");
        // Whichever prepayment the canister made, it has now paid the adjusted one:
        // the missing cycles were withdrawn or the excess ones were refunded.
        assert_eq!(
            system_state.balance() + required.real(),
            initial_balance,
            "unexpected balance after the adjustment for {context}"
        );
        // The consumed cycles metrics report the adjusted prepayment as well. The
        // counter is only updated once the prepayment is refunded, i.e. not yet.
        assert_eq!(
            consumed_cycles_for_instructions(&system_state),
            (required.nominal(), NominalCycles::zero()),
            "unexpected consumed cycles after the adjustment for {context}"
        );

        // Refund the cycles for the instructions the callback did not execute.
        let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
        cycles_account_manager.refund_unused_execution_cycles(
            &mut system_state,
            RESPONSE_EXECUTION_INSTRUCTION_LIMIT - EXECUTED_INSTRUCTIONS,
            RESPONSE_EXECUTION_INSTRUCTION_LIMIT,
            adjusted,
            &no_op_counter,
            config_at_response,
            at_response.wasm_execution_mode,
            &no_op_logger(),
        );

        // The canister is charged, and reported to have consumed, the fixed
        // per-message execution fee plus the cost of the instructions it executed
        // in the Wasm execution mode it executed them in.
        let expected = cycles_account_manager.execution_cost(
            EXECUTED_INSTRUCTIONS,
            config_at_response,
            at_response.wasm_execution_mode,
        );
        assert_eq!(
            system_state.balance() + expected.real(),
            initial_balance,
            "unexpected balance after the refund for {context}"
        );
        assert_eq!(
            consumed_cycles_for_instructions(&system_state),
            (expected.nominal(), expected.nominal()),
            "unexpected consumed cycles after the refund for {context}"
        );
    }
}

/// If the canister's balance does not cover the cycles missing from the
/// prepayment, then the adjustment fails and leaves the canister state unchanged:
/// neither the balance nor the consumed cycles metrics move. That is a requirement
/// of `adjust_prepayment_for_response_execution` which its callers rely on.
///
/// In the second setting below the prepayment falls short of the requirement in
/// the real part while exceeding it in the nominal one, so that the excess to be
/// refunded is not zero. That is what pins down the order of the two: were the
/// refund performed before the failing withdrawal, it would lower the consumed
/// cycles gauge by that excess.
#[test]
fn adjust_prepayment_for_response_execution_leaves_state_unchanged_on_failure() {
    // The third component is the direction of the nominal part of the prepayment
    // relative to the nominal part of the requirement.
    const SETTINGS: [(ResponseExecutionSetting, ResponseExecutionSetting, Ordering); 2] = [
        // Prepaid in the cheaper Wasm execution mode, so that the requirement in
        // the more expensive one exceeds the prepayment in both parts.
        (NORMAL_WASM32, NORMAL_WASM64, Ordering::Less),
        // Prepaid under the free cost schedule, so that the requirement exceeds the
        // prepayment in the real part; prepaid in the more expensive Wasm execution
        // mode, so that the prepayment exceeds the requirement in the nominal part.
        (FREE_WASM64, NORMAL_WASM32, Ordering::Greater),
    ];

    for (at_call, at_response, nominal_direction) in SETTINGS {
        let cycles_account_manager = cycles_account_manager();
        let config_at_call = subnet_cycles_config(at_call.cost_schedule);
        let config_at_response = subnet_cycles_config(at_response.cost_schedule);
        let context = format!("{at_call:?} at call, {at_response:?} at response");

        let prepaid = cycles_account_manager
            .prepayment_for_response_execution(config_at_call, at_call.wasm_execution_mode);
        let required = cycles_account_manager
            .prepayment_for_response_execution(config_at_response, at_response.wasm_execution_mode);
        let missing = required.real() - prepaid.real();
        assert!(missing > Cycles::zero(), "nothing missing for {context}");
        assert_eq!(
            prepaid.nominal().cmp(&required.nominal()),
            nominal_direction,
            "unexpected direction of the nominal part for {context}"
        );

        // Once the canister has paid the prepayment, its balance covers all but one
        // cycle of the cycles missing from it.
        let balance = missing - Cycles::new(1);
        let mut system_state = SystemStateBuilder::new()
            .initial_cycles(balance + prepaid.real())
            .build();
        system_state.consume_cycles(prepaid);
        assert_eq!(system_state.balance(), balance);
        let consumed_before = consumed_cycles_for_instructions(&system_state);

        let err = cycles_account_manager
            .adjust_prepayment_for_response_execution(
                &mut system_state,
                prepaid,
                config_at_response,
                at_response.wasm_execution_mode,
                false,
            )
            .unwrap_err();

        assert_eq!(err.requested, missing, "unexpected shortfall for {context}");
        assert_eq!(
            system_state.balance(),
            balance,
            "unexpected balance for {context}"
        );
        assert_eq!(
            consumed_cycles_for_instructions(&system_state),
            consumed_before,
            "unexpected consumed cycles for {context}"
        );
    }
}

/// A response whose callback is not executed at all costs the fixed per-message
/// execution fee only, no matter what the cost schedule and the Wasm execution
/// mode were when the cycles were prepaid and what they are when the response
/// arrives.
///
/// The prepayment is never topped up here, so the canister is charged at most what
/// it prepaid: a canister whose subnet switched from the free to the normal cost
/// schedule across the call prepaid nothing real and hence pays nothing real.
#[test]
fn settle_prepayment_for_unexecuted_response_charges_only_the_base_fee() {
    for (at_call, at_response) in response_execution_settings() {
        let cycles_account_manager = cycles_account_manager();
        let config_at_call = subnet_cycles_config(at_call.cost_schedule);
        let config_at_response = subnet_cycles_config(at_response.cost_schedule);
        let context = format!("{at_call:?} at call, {at_response:?} at response");
        let mut system_state = SystemStateBuilder::new().build();
        let balance_before = system_state.balance();

        let prepaid = cycles_account_manager
            .prepayment_for_response_execution(config_at_call, at_call.wasm_execution_mode);
        system_state.consume_cycles(prepaid);

        cycles_account_manager.settle_prepayment_for_unexecuted_response(
            &mut system_state,
            prepaid,
            config_at_response,
            at_response.wasm_execution_mode,
        );

        // No instructions were executed, hence only the fixed per-message
        // execution fee is due; the rest of the prepayment is refunded. The
        // canister is charged at most what it prepaid, in each of the two parts.
        let base_fee = cycles_account_manager.execution_cost(
            NumInstructions::from(0),
            config_at_response,
            at_response.wasm_execution_mode,
        );
        let charged = prepaid.component_wise_min(base_fee);
        assert_eq!(
            system_state.balance() + charged.real(),
            balance_before,
            "unexpected balance for {context}"
        );
        let (gauge, counter) = consumed_cycles_for_instructions(&system_state);
        assert_eq!(
            (gauge, counter),
            (charged.nominal(), charged.nominal()),
            "unexpected consumed cycles for {context}"
        );
    }
}

/// The cycles prepaid for transmitting a response are settled by refunding the part
/// of the prepayment that the transmission did not cost. That path never tops up the
/// prepayment either: the refund is `prepaid - cost`, which saturates part by part,
/// so the refund never exceeds the prepayment, as `refund_cycles` requires, and the
/// canister is charged at most what it prepaid in each of the two parts.
///
/// Checked for every combination of the cost schedule at the call with the one at the
/// response: the canister pays the real transmission cost capped at what it prepaid,
/// i.e. nothing at all if either of the two schedules is the free one, while the
/// consumed cycles metrics report the nominal transmission cost, which does not
/// depend on the cost schedule. The Wasm execution mode plays no role here, since the
/// transmission fees do not depend on it.
#[test]
fn response_transmission_refund_never_exceeds_the_prepayment() {
    const COST_SCHEDULES: [CanisterCyclesCostSchedule; 2] = [
        CanisterCyclesCostSchedule::Normal,
        CanisterCyclesCostSchedule::Free,
    ];
    let response_sizes = [
        NumBytes::new(0),
        NumBytes::new(1_024),
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    ];

    for at_call in COST_SCHEDULES {
        for at_response in COST_SCHEDULES {
            for response_size in response_sizes {
                let cycles_account_manager = cycles_account_manager();
                let config_at_call = subnet_cycles_config(at_call);
                let config_at_response = subnet_cycles_config(at_response);
                let context = format!(
                    "{at_call:?} at call, {at_response:?} at response, {response_size} bytes"
                );

                // The canister prepaid for transmitting a response of the maximum
                // size under the cost schedule in effect when it performed the call.
                let prepaid =
                    cycles_account_manager.prepayment_for_response_transmission(config_at_call);
                let mut system_state = SystemStateBuilder::new()
                    .initial_cycles(prepaid.real())
                    .build();
                let initial_balance = system_state.balance();
                system_state.consume_cycles(prepaid);

                let response = ResponsePayload::Data(vec![0; response_size.get() as usize]);
                let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
                let refund = cycles_account_manager.refund_for_response_transmission(
                    &no_op_logger(),
                    &no_op_counter,
                    &response,
                    prepaid,
                    config_at_response,
                );
                // Fails the debug assertions of `refund_cycles` were the refund to
                // exceed the prepayment in either of the two parts.
                system_state.refund_cycles(prepaid, refund);

                let cost = cycles_account_manager
                    .xnet_call_bytes_transmitted_fee(response_size, config_at_response);
                let charged = prepaid.component_wise_min(cost);
                assert_eq!(
                    system_state.balance() + charged.real(),
                    initial_balance,
                    "unexpected balance for {context}"
                );
                assert_eq!(
                    consumed_cycles(&system_state, CyclesUseCase::RequestAndResponseTransmission),
                    (charged.nominal(), charged.nominal()),
                    "unexpected consumed cycles for {context}"
                );
                // The nominal parts do not depend on the cost schedule, so the
                // reported amount is the nominal transmission cost whatever the cost
                // schedules at the call and at the response are.
                assert_eq!(
                    charged.nominal(),
                    cost.nominal(),
                    "unexpected nominal charge for {context}"
                );
            }
        }
    }
}
/// The instruction limit used by the aborted execution tests below.
const ABORTED_EXECUTION_INSTRUCTION_LIMIT: NumInstructions = NumInstructions::new(1_000_000_000);

/// The conditions that the cycles for an execution are prepaid under: the subnet
/// configuration that scales the fees and the canister's Wasm execution mode.
#[derive(Copy, Clone, Debug)]
struct AbortedExecutionSetting {
    subnet_config: CyclesAccountManagerSubnetConfig,
    wasm_execution_mode: WasmExecutionMode,
}

/// The subnet configurations an execution can be prepaid under. They differ in the
/// three quantities that scale the execution fees, one at a time: the subnet size,
/// the reference subnet size that the fees are scaled against, and the cost
/// schedule.
///
/// All three are read from the registry at the version of the batch whose round
/// executes the message, so all three can differ between the round that prepaid an
/// execution and the round that restarts it after an abort.
fn aborted_execution_subnet_configs() -> [CyclesAccountManagerSubnetConfig; 4] {
    [
        // An application subnet of the default size.
        CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        ),
        // A larger subnet, e.g. one that nodes were added to, whose fees are scaled
        // up proportionally.
        CyclesAccountManagerSubnetConfig::new(
            2 * SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        ),
        // A SEV-enabled subnet, whose fees are scaled against a smaller reference
        // subnet size.
        CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            SEV_REFERENCE_SUBNET_SIZE,
        ),
        // A subnet on the free cost schedule, which charges nothing real.
        CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Free,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        ),
    ]
}

/// Every combination of the subnet configuration and the Wasm execution mode an
/// execution can be prepaid under.
fn aborted_execution_settings() -> Vec<AbortedExecutionSetting> {
    aborted_execution_subnet_configs()
        .into_iter()
        .flat_map(|subnet_config| {
            [WasmExecutionMode::Wasm32, WasmExecutionMode::Wasm64]
                .into_iter()
                .map(move |wasm_execution_mode| AbortedExecutionSetting {
                    subnet_config,
                    wasm_execution_mode,
                })
        })
        .collect()
}

/// An execution that is aborted and restarted is paid for, and reported in the
/// consumed cycles metrics, exactly as if it had been prepaid under the conditions
/// in effect when it is restarted.
///
/// An aborted execution carries the cycles it prepaid over to its restart instead
/// of prepaying again, while the refund of the unused instructions is computed
/// under the conditions in effect when the restarted execution finishes. Adjusting
/// the carried-over prepayment to those conditions is what keeps the two in line.
///
/// Checked at the two points of the prepay, adjust and refund sequence at which the
/// cycles the canister has paid are determined: right after the adjustment, where
/// it must have paid the prepayment required at the restart in both its real and
/// its nominal part, and after the cycles for the instructions the execution did
/// not use are refunded, where it must have paid for the instructions it did use.
///
/// The canister starts out with just enough cycles to cover the larger of the
/// prepayment and the requirement, so that it has none to spare once it prepaid and
/// the adjustment withdrew the cycles missing from the prepayment, if any. The
/// adjustment withdraws `required - prepaid`, which saturates part by part, without
/// comparing the two first; any other withdrawal, in particular one attempted where
/// the prepayment covers the requirement in the real part, fails here for lack of
/// cycles instead of going unnoticed.
#[test]
fn restarted_execution_cycles_match_restart_setting() {
    const EXECUTED_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000);
    const LIMIT: NumInstructions = ABORTED_EXECUTION_INSTRUCTION_LIMIT;

    for before_abort in aborted_execution_settings() {
        for at_restart in aborted_execution_settings() {
            let cycles_account_manager = cycles_account_manager();
            let context =
                format!("{before_abort:?} before the abort, {at_restart:?} at the restart");

            // The aborted execution prepaid under the conditions in effect back
            // then; the restarted one requires the prepayment matching the
            // conditions in effect now.
            let prepaid = cycles_account_manager.execution_cost(
                LIMIT,
                before_abort.subnet_config,
                before_abort.wasm_execution_mode,
            );
            let required = cycles_account_manager.execution_cost(
                LIMIT,
                at_restart.subnet_config,
                at_restart.wasm_execution_mode,
            );

            // Once the canister has paid the prepayment, its balance covers exactly
            // the cycles missing from it, if any, so that any withdrawal beyond
            // those fails.
            let mut system_state = SystemStateBuilder::new()
                .initial_cycles(prepaid.real().max(required.real()))
                .build();
            let initial_balance = system_state.balance();
            system_state.consume_cycles(prepaid);

            let adjusted = cycles_account_manager
                .adjust_prepaid_execution_cycles(
                    &mut system_state,
                    prepaid,
                    NumBytes::from(0),
                    MessageMemoryUsage::ZERO,
                    ComputeAllocation::default(),
                    LIMIT,
                    at_restart.subnet_config,
                    false,
                    at_restart.wasm_execution_mode,
                )
                .unwrap();

            assert_eq!(adjusted, required, "unexpected prepayment for {context}");
            // Whichever prepayment the aborted execution made, the canister has now
            // paid the adjusted one: the missing cycles were withdrawn or the excess
            // ones were refunded.
            assert_eq!(
                system_state.balance() + required.real(),
                initial_balance,
                "unexpected balance after the adjustment for {context}"
            );
            // The consumed cycles metrics report the adjusted prepayment as well.
            // The counter is only updated once the prepayment is refunded, i.e. not
            // yet.
            assert_eq!(
                consumed_cycles_for_instructions(&system_state),
                (required.nominal(), NominalCycles::zero()),
                "unexpected consumed cycles after the adjustment for {context}"
            );

            // Refund the cycles for the instructions the restarted execution did not
            // use.
            let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
            cycles_account_manager.refund_unused_execution_cycles(
                &mut system_state,
                LIMIT - EXECUTED_INSTRUCTIONS,
                LIMIT,
                adjusted,
                &no_op_counter,
                at_restart.subnet_config,
                at_restart.wasm_execution_mode,
                &no_op_logger(),
            );

            // The canister is charged, and reported to have consumed, the fixed
            // per-message execution fee plus the cost of the instructions it
            // executed, both under the conditions in effect at the restart.
            let expected = cycles_account_manager.execution_cost(
                EXECUTED_INSTRUCTIONS,
                at_restart.subnet_config,
                at_restart.wasm_execution_mode,
            );
            assert_eq!(
                system_state.balance() + expected.real(),
                initial_balance,
                "unexpected balance after the refund for {context}"
            );
            assert_eq!(
                consumed_cycles_for_instructions(&system_state),
                (expected.nominal(), expected.nominal()),
                "unexpected consumed cycles after the refund for {context}"
            );
        }
    }
}

/// If the canister's balance does not cover the cycles missing from the prepayment
/// that an aborted execution carried over, then the adjustment fails and refunds
/// that prepayment in full: the restarted execution does not run, so the canister
/// ends up charged nothing at all and reported to have consumed nothing, exactly as
/// if prepaying the execution from scratch had failed.
///
/// That sets the failure apart from the one of
/// `adjust_prepayment_for_response_execution`, which leaves the canister state
/// unchanged: a response execution that is not run still settles its prepayment
/// afterwards, while the caller of this adjustment drops the message right away.
///
/// In the second setting below the prepayment falls short of the requirement in the
/// real part while exceeding it in the nominal one, so that the excess that a
/// successful adjustment would refund is not zero. That is what pins down the order
/// of the withdrawal and the refund: were the excess refunded before the failing
/// withdrawal, the prepayment would be refunded twice over in the nominal part.
#[test]
fn adjust_prepaid_execution_cycles_refunds_the_prepayment_on_failure() {
    const LIMIT: NumInstructions = ABORTED_EXECUTION_INSTRUCTION_LIMIT;

    let normal = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let larger = CyclesAccountManagerSubnetConfig::new(
        2 * SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let free = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Free,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );

    // The third component is the direction of the nominal part of the prepayment
    // relative to the nominal part of the requirement.
    let settings = [
        // Prepaid on the smaller subnet, so that the requirement on the larger one
        // exceeds the prepayment in both parts.
        (
            AbortedExecutionSetting {
                subnet_config: normal,
                wasm_execution_mode: WasmExecutionMode::Wasm32,
            },
            AbortedExecutionSetting {
                subnet_config: larger,
                wasm_execution_mode: WasmExecutionMode::Wasm32,
            },
            Ordering::Less,
        ),
        // Prepaid under the free cost schedule, so that the requirement exceeds the
        // prepayment in the real part; prepaid in the more expensive Wasm execution
        // mode, so that the prepayment exceeds the requirement in the nominal part.
        (
            AbortedExecutionSetting {
                subnet_config: free,
                wasm_execution_mode: WasmExecutionMode::Wasm64,
            },
            AbortedExecutionSetting {
                subnet_config: normal,
                wasm_execution_mode: WasmExecutionMode::Wasm32,
            },
            Ordering::Greater,
        ),
    ];

    for (before_abort, at_restart, nominal_direction) in settings {
        let cycles_account_manager = cycles_account_manager();
        let context = format!("{before_abort:?} before the abort, {at_restart:?} at the restart");

        let prepaid = cycles_account_manager.execution_cost(
            LIMIT,
            before_abort.subnet_config,
            before_abort.wasm_execution_mode,
        );
        let required = cycles_account_manager.execution_cost(
            LIMIT,
            at_restart.subnet_config,
            at_restart.wasm_execution_mode,
        );
        let missing = required.real() - prepaid.real();
        assert!(missing > Cycles::zero(), "nothing missing for {context}");
        assert_eq!(
            prepaid.nominal().cmp(&required.nominal()),
            nominal_direction,
            "unexpected direction of the nominal part for {context}"
        );

        // Once the canister has paid the prepayment, its balance covers all but one
        // cycle of the cycles missing from it.
        let balance = missing - Cycles::new(1);
        let mut system_state = SystemStateBuilder::new()
            .initial_cycles(balance + prepaid.real())
            .build();
        let initial_balance = system_state.balance();
        system_state.consume_cycles(prepaid);
        assert_eq!(system_state.balance(), balance);

        let err = cycles_account_manager
            .adjust_prepaid_execution_cycles(
                &mut system_state,
                prepaid,
                NumBytes::from(0),
                MessageMemoryUsage::ZERO,
                ComputeAllocation::default(),
                LIMIT,
                at_restart.subnet_config,
                false,
                at_restart.wasm_execution_mode,
            )
            .unwrap_err();

        assert_eq!(err.requested, missing, "unexpected shortfall for {context}");
        // The prepayment is refunded in full, so the canister is back to the balance
        // it had before the aborted execution prepaid.
        assert_eq!(
            system_state.balance(),
            initial_balance,
            "unexpected balance for {context}"
        );
        assert_eq!(
            consumed_cycles_for_instructions(&system_state),
            (NominalCycles::zero(), NominalCycles::zero()),
            "unexpected consumed cycles for {context}"
        );
    }
}

/// The cycles missing from the prepayment that an aborted execution carried over
/// are withdrawn while respecting the freezing threshold, exactly as prepaying the
/// execution from scratch would: a canister that cannot cover the shortfall out of
/// the balance it holds above its freezing threshold fails the adjustment, even
/// though it does hold the cycles further down.
///
/// Checked at the boundary, i.e. with the balance leaving the canister one cycle
/// short of the shortfall above its freezing threshold and then with the balance
/// leaving it exactly the shortfall. A withdrawal that ignored the freezing
/// threshold would succeed in both cases.
#[test]
fn adjust_prepaid_execution_cycles_respects_the_freezing_threshold() {
    const LIMIT: NumInstructions = ABORTED_EXECUTION_INSTRUCTION_LIMIT;
    // A non-zero memory usage, so that the canister has a non-zero freezing
    // threshold to begin with.
    const MEMORY_USAGE: NumBytes = NumBytes::new(1024 * 1024);

    let cycles_account_manager = cycles_account_manager();
    let config_before_abort = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    // The subnet grew across the abort, so the restarted execution requires more
    // than the aborted one prepaid.
    let config_at_restart = CyclesAccountManagerSubnetConfig::new(
        2 * SMALL_APP_SUBNET_MAX_SIZE,
        CanisterCyclesCostSchedule::Normal,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );

    let prepaid =
        cycles_account_manager.execution_cost(LIMIT, config_before_abort, WASM_EXECUTION_MODE);
    let required =
        cycles_account_manager.execution_cost(LIMIT, config_at_restart, WASM_EXECUTION_MODE);
    let missing = required.real() - prepaid.real();
    assert!(missing > Cycles::zero());

    // `covered` is the part of the shortfall that the canister holds above its
    // freezing threshold once it has paid the prepayment.
    for covered in [missing - Cycles::new(1), missing] {
        let mut system_state = SystemStateBuilder::new()
            .freeze_threshold(NumSeconds::from(1_000))
            .build();
        let threshold = cycles_account_manager.freeze_threshold_cycles(
            system_state.freeze_threshold,
            system_state.memory_allocation,
            MEMORY_USAGE,
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            config_at_restart,
            system_state.reserved_balance(),
        );
        assert!(threshold > Cycles::zero(), "zero freezing threshold");

        system_state.set_balance(prepaid.real() + threshold + covered);
        let initial_balance = system_state.balance();
        system_state.consume_cycles(prepaid);

        let result = cycles_account_manager.adjust_prepaid_execution_cycles(
            &mut system_state,
            prepaid,
            MEMORY_USAGE,
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            LIMIT,
            config_at_restart,
            false,
            WASM_EXECUTION_MODE,
        );

        if covered < missing {
            // The canister holds the missing cycles, but not above its freezing
            // threshold, so the adjustment fails and refunds the prepayment in full.
            let err = result.unwrap_err();
            assert_eq!(err.requested, missing);
            assert_eq!(err.threshold, threshold);
            assert_eq!(system_state.balance(), initial_balance);
            assert_eq!(
                consumed_cycles_for_instructions(&system_state),
                (NominalCycles::zero(), NominalCycles::zero()),
            );
        } else {
            // The canister covers the shortfall above its freezing threshold, so the
            // adjustment succeeds and leaves it frozen but not below the threshold.
            assert_eq!(result.unwrap(), required);
            assert_eq!(system_state.balance(), threshold);
            assert_eq!(
                consumed_cycles_for_instructions(&system_state),
                (required.nominal(), NominalCycles::zero()),
            );
        }
    }
}

#[test]
fn ingress_induction_cost_valid_subnet_message() {
    for cost_schedule in [
        CanisterCyclesCostSchedule::Normal,
        CanisterCyclesCostSchedule::Free,
    ] {
        let msg: SignedIngress = SignedIngressBuilder::new()
            .sender(user_test_id(0))
            .canister_id(IC_00)
            .method_name("start_canister")
            .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
            .build();
        let signed_ingress_content = &msg.content();
        let effective_canister_id = extract_effective_canister_id(signed_ingress_content).unwrap();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let num_bytes = msg.binary().len();
        let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            cost_schedule,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        );

        let cost = cycles_account_manager
            .ingress_induction_cost_from_bytes(
                NumBytes::from(num_bytes as u64),
                subnet_cycles_config,
            )
            .real();
        if let CanisterCyclesCostSchedule::Free = cost_schedule {
            assert_eq!(cost, Cycles::new(0));
        }
        assert_eq!(
            cycles_account_manager.ingress_induction_cost(
                &msg,
                effective_canister_id,
                subnet_cycles_config,
            ),
            IngressInductionCost::Fee {
                payer: canister_test_id(0),
                cost
            }
        );
    }
}

#[test]
fn charging_removes_canisters_with_insufficient_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    with_test_replica_logger(|log| {
        let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
        let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
            subnet_size,
            cost_schedule,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        );
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(u128::MAX),
            NumSeconds::from(0),
        );
        canister.system_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation = MemoryAllocation::from(NumBytes::from(1 << 30));
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
                subnet_cycles_config,
            )
            .unwrap();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::zero(),
            NumSeconds::from(0),
        );
        canister.system_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation = MemoryAllocation::from(NumBytes::from(1 << 30));
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
                subnet_cycles_config,
            )
            .unwrap_err();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::new(100),
            NumSeconds::from(0),
        );
        canister.system_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation = MemoryAllocation::from(NumBytes::from(1 << 30));
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                Duration::from_secs(1),
                subnet_cycles_config,
            )
            .unwrap_err();
    })
}

#[test]
fn charge_canister_for_memory_usage() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    with_test_replica_logger(|log| {
        const INITIAL_BALANCE: Cycles = Cycles::new(u64::MAX as u128);
        const MEMORY_ALLOCATION: NumBytes = NumBytes::new(1 << 30);
        const HOUR: Duration = Duration::from_secs(3600);

        let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            cost_schedule,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        );
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let canister_id = canister_test_id(1);
        let mut canister = new_canister_state(
            canister_id,
            canister_test_id(11).get(),
            INITIAL_BALANCE,
            NumSeconds::from(0),
        );
        canister.system_state.memory_allocation = MemoryAllocation::from(MEMORY_ALLOCATION);
        canister
            .push_output_request(
                OutputRequestBuilder::default().sender(canister_id).build(),
                UNIX_EPOCH,
            )
            .unwrap();
        canister
            .push_output_request(
                OutputRequestBuilder::default()
                    .sender(canister_id)
                    .deadline(CoarseTime::from_secs_since_unix_epoch(1))
                    .build(),
                UNIX_EPOCH,
            )
            .unwrap();
        let message_memory_usage = canister.message_memory_usage();
        assert_ne!(0, message_memory_usage.guaranteed_response.get());
        assert_ne!(0, message_memory_usage.best_effort.get());

        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                HOUR,
                subnet_cycles_config,
            )
            .unwrap();

        let memory_usage = MEMORY_ALLOCATION + message_memory_usage.total();
        let cycles_burned = INITIAL_BALANCE - canister.system_state.balance();
        assert_eq!(
            cycles_account_manager
                .memory_cost(memory_usage, HOUR, subnet_cycles_config,)
                .real()
                + cycles_account_manager
                    .canister_base_cost(memory_usage, HOUR, subnet_cycles_config)
                    .real(),
            cycles_burned
        )
    })
}

#[test]
fn do_not_charge_canister_for_memory_usage_free_schedule() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    with_test_replica_logger(|log| {
        const INITIAL_BALANCE: Cycles = Cycles::new(u64::MAX as u128);
        const MEMORY_ALLOCATION: NumBytes = NumBytes::new(1 << 30);
        const HOUR: Duration = Duration::from_secs(3600);

        let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            cost_schedule,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        );
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let canister_id = canister_test_id(1);
        let mut canister = new_canister_state(
            canister_id,
            canister_test_id(11).get(),
            INITIAL_BALANCE,
            NumSeconds::from(0),
        );
        canister.system_state.memory_allocation = MemoryAllocation::from(MEMORY_ALLOCATION);
        canister
            .push_output_request(
                OutputRequestBuilder::default().sender(canister_id).build(),
                UNIX_EPOCH,
            )
            .unwrap();
        canister
            .push_output_request(
                OutputRequestBuilder::default()
                    .sender(canister_id)
                    .deadline(CoarseTime::from_secs_since_unix_epoch(1))
                    .build(),
                UNIX_EPOCH,
            )
            .unwrap();
        let message_memory_usage = canister.message_memory_usage();
        assert_ne!(0, message_memory_usage.guaranteed_response.get());
        assert_ne!(0, message_memory_usage.best_effort.get());

        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                HOUR,
                subnet_cycles_config,
            )
            .unwrap();

        let memory_usage = MEMORY_ALLOCATION + message_memory_usage.total();
        let cycles_burned = INITIAL_BALANCE - canister.system_state.balance();
        assert_eq!(cycles_burned, Cycles::new(0));
        assert_eq!(
            cycles_account_manager
                .memory_cost(memory_usage, HOUR, subnet_cycles_config,)
                .real(),
            cycles_burned
        )
    })
}

#[test]
fn do_not_charge_canister_for_compute_allocation_free_schedule() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    with_test_replica_logger(|log| {
        const HOUR: Duration = Duration::from_secs(3600);
        let compute_allocation = ComputeAllocation::try_from(20).unwrap();
        let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
            SMALL_APP_SUBNET_MAX_SIZE,
            cost_schedule,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        );

        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let canister_id = canister_test_id(1);
        let mut canister = new_canister_state(
            canister_id,
            canister_test_id(11).get(),
            Cycles::zero(),
            NumSeconds::from(0),
        );
        canister.system_state.compute_allocation = compute_allocation;
        canister
            .push_output_request(
                OutputRequestBuilder::default().sender(canister_id).build(),
                UNIX_EPOCH,
            )
            .unwrap();
        canister
            .push_output_request(
                OutputRequestBuilder::default()
                    .sender(canister_id)
                    .deadline(CoarseTime::from_secs_since_unix_epoch(1))
                    .build(),
                UNIX_EPOCH,
            )
            .unwrap();
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                &mut canister,
                HOUR,
                subnet_cycles_config,
            )
            .unwrap();

        let expected_fee = cycles_account_manager
            .compute_allocation_cost(compute_allocation, HOUR, subnet_cycles_config)
            .real();
        assert_eq!(expected_fee, Cycles::zero());

        let cycles_burned = canister.system_state.balance();
        assert_eq!(cycles_burned, Cycles::new(0));
    })
}

#[test]
fn cycles_withdraw_no_threshold() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    // Create an account with u128::MAX
    let mut cycles_balance_expected = Cycles::from(u128::MAX);
    let system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let threshold = Cycles::zero();
    let mut balance = system_state.balance();
    assert!(
        cycles_account_manager
            .withdraw_with_threshold(
                system_state.canister_id(),
                &mut balance,
                Cycles::zero(),
                threshold,
                false,
            )
            .is_ok()
    );
    // unchanged cycles
    assert_eq!(balance, cycles_balance_expected);

    // u128::MAX == 2 * i128::MAX + 1
    // withdraw i128::MAX and verify correctness
    let amount = Cycles::from(i128::MAX as u128);
    assert!(
        cycles_account_manager
            .withdraw_with_threshold(
                system_state.canister_id(),
                &mut balance,
                amount,
                threshold,
                false
            )
            .is_ok()
    );
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::from(i128::MAX as u128) + Cycles::new(1));

    assert!(
        cycles_account_manager
            .withdraw_with_threshold(
                system_state.canister_id(),
                &mut balance,
                amount,
                threshold,
                false
            )
            .is_ok()
    );
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::new(1));

    let amount = Cycles::new(1);
    assert!(
        cycles_account_manager
            .withdraw_with_threshold(
                system_state.canister_id(),
                &mut balance,
                amount,
                threshold,
                false
            )
            .is_ok()
    );
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::zero());

    assert!(
        cycles_account_manager
            .withdraw_with_threshold(
                system_state.canister_id(),
                &mut balance,
                amount,
                threshold,
                false
            )
            .is_err()
    );
    cycles_balance_expected -= amount;
    assert_eq!(balance, Cycles::zero());
}

#[test]
fn test_consume_with_threshold() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    // Create an account with u128::MAX
    let mut cycles_balance_expected = Cycles::from(u128::MAX);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    assert_eq!(system_state.balance(), cycles_balance_expected);

    let threshold = Cycles::zero();
    assert!(
        cycles_account_manager
            .consume_with_threshold(
                &mut system_state,
                CompoundCycles::<Memory>::new(Cycles::zero(), cost_schedule),
                threshold,
                false,
            )
            .is_ok()
    );
    // unchanged cycles
    assert_eq!(system_state.balance(), cycles_balance_expected);

    // u128::MAX == 2 * i128::MAX + 1
    // withdraw i128::MAX and verify correctness
    let amount = CompoundCycles::<Memory>::new(Cycles::from(i128::MAX as u128), cost_schedule);
    assert!(
        cycles_account_manager
            .consume_with_threshold(&mut system_state, amount, threshold, false)
            .is_ok()
    );
    cycles_balance_expected -= amount.real();
    assert_eq!(
        system_state.balance(),
        Cycles::from(i128::MAX as u128) + Cycles::new(1)
    );

    assert!(
        cycles_account_manager
            .consume_with_threshold(&mut system_state, amount, threshold, false)
            .is_ok()
    );
    cycles_balance_expected -= amount.real();
    assert_eq!(system_state.balance(), Cycles::new(1));

    let amount = CompoundCycles::<Memory>::new(Cycles::new(1), cost_schedule);
    assert!(
        cycles_account_manager
            .consume_with_threshold(&mut system_state, amount, threshold, false)
            .is_ok()
    );
    cycles_balance_expected -= amount.real();
    assert_eq!(system_state.balance(), Cycles::zero());

    assert!(
        cycles_account_manager
            .consume_with_threshold(&mut system_state, amount, threshold, false)
            .is_err()
    );
    cycles_balance_expected -= amount.real();
    assert_eq!(system_state.balance(), Cycles::zero());
}

#[test]
fn cycles_withdraw_for_execution() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let memory_usage = NumBytes::from(4 << 30);
    let message_memory_usage = MessageMemoryUsage {
        guaranteed_response: NumBytes::new(6 << 20),
        best_effort: NumBytes::new(2 << 20),
    };

    let initial_amount = u128::MAX;
    let initial_cycles = Cycles::from(initial_amount);
    let freeze_threshold = NumSeconds::from(10);
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running_for_testing(
        canister_id,
        canister_test_id(2).get(),
        initial_cycles,
        freeze_threshold,
    );
    system_state.compute_allocation = ComputeAllocation::try_from(90).unwrap();

    let freeze_threshold_cycles = cycles_account_manager.freeze_threshold_cycles(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        memory_usage,
        message_memory_usage,
        system_state.compute_allocation,
        subnet_cycles_config,
        system_state.reserved_balance(),
    );

    let amount =
        CompoundCycles::<Instructions>::new(Cycles::from(initial_amount / 2), cost_schedule);
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                amount,
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
    assert_eq!(system_state.balance(), initial_cycles - amount.real());
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                amount,
                subnet_cycles_config,
                false,
            )
            .is_err()
    );

    let exec_cycles_max = system_state.balance() - freeze_threshold_cycles;
    let compound_exec_cycles_max =
        CompoundCycles::<Instructions>::new(exec_cycles_max, cost_schedule);

    assert!(
        cycles_account_manager
            .can_withdraw_cycles_with_threshold(
                &system_state,
                exec_cycles_max,
                memory_usage,
                message_memory_usage,
                system_state.reserved_balance(),
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                compound_exec_cycles_max,
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
    assert_eq!(system_state.balance(), freeze_threshold_cycles);
    assert_eq!(
        cycles_account_manager.can_withdraw_cycles_with_threshold(
            &system_state,
            Cycles::new(10),
            memory_usage,
            message_memory_usage,
            system_state.reserved_balance(),
            subnet_cycles_config,
            false,
        ),
        Err(CanisterOutOfCyclesError {
            canister_id,
            available: freeze_threshold_cycles,
            requested: Cycles::new(10),
            threshold: freeze_threshold_cycles,
            reveal_top_up: false,
        })
    );

    // no more cycles can be withdrawn, the rest is reserved for storage
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                compound_exec_cycles_max,
                subnet_cycles_config,
                false,
            )
            .is_err()
    );
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                CompoundCycles::<Instructions>::new(Cycles::new(10), cost_schedule),
                subnet_cycles_config,
                false,
            )
            .is_err()
    );
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                CompoundCycles::<Instructions>::new(Cycles::new(1), cost_schedule),
                subnet_cycles_config,
                false,
            )
            .is_err()
    );
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                CompoundCycles::<Instructions>::new(Cycles::zero(), cost_schedule),
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
    assert_eq!(system_state.balance(), freeze_threshold_cycles);
}

#[test]
fn do_not_withdraw_cycles_for_execution_free_schedule() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let memory_usage = NumBytes::from(4 << 30);
    let message_memory_usage = MessageMemoryUsage {
        guaranteed_response: NumBytes::new(6 << 20),
        best_effort: NumBytes::new(2 << 20),
    };

    let initial_amount = u128::MAX;
    let initial_cycles = Cycles::from(initial_amount);
    let freeze_threshold = NumSeconds::from(10);
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running_for_testing(
        canister_id,
        canister_test_id(2).get(),
        initial_cycles,
        freeze_threshold,
    );
    system_state.compute_allocation = ComputeAllocation::try_from(90).unwrap();

    let freeze_threshold_cycles = cycles_account_manager.freeze_threshold_cycles(
        system_state.freeze_threshold,
        system_state.memory_allocation,
        memory_usage,
        message_memory_usage,
        system_state.compute_allocation,
        subnet_cycles_config,
        system_state.reserved_balance(),
    );

    let amount =
        CompoundCycles::<Instructions>::new(Cycles::from(initial_amount / 2), cost_schedule);
    assert!(
        cycles_account_manager
            .consume_cycles_for_final_instructions(
                &mut system_state,
                memory_usage,
                message_memory_usage,
                amount,
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
    assert_eq!(system_state.balance(), initial_cycles);

    let exec_cycles_max = system_state.balance() - freeze_threshold_cycles;

    assert!(
        cycles_account_manager
            .can_withdraw_cycles_with_threshold(
                &system_state,
                exec_cycles_max,
                memory_usage,
                message_memory_usage,
                system_state.reserved_balance(),
                subnet_cycles_config,
                false,
            )
            .is_ok()
    );
}

#[test]
fn withdraw_execution_cycles_consumes_cycles() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state.canister_metrics().consumed_cycles();
    cycles_account_manager
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
                DEFAULT_REFERENCE_SUBNET_SIZE,
            ),
            false,
            WASM_EXECUTION_MODE,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics().consumed_cycles();
    assert!(consumed_cycles_before < consumed_cycles_after);
}

#[test]
fn withdraw_for_transfer_does_not_consume_cycles() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut balance = Cycles::new(5_000_000_000_000);
    let consumed_cycles_before = system_state.canister_metrics().consumed_cycles();
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            system_state.canister_id(),
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            &mut balance,
            Cycles::new(1_000_000),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
                DEFAULT_REFERENCE_SUBNET_SIZE,
            ),
            system_state.reserved_balance(),
            false,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics().consumed_cycles();

    // Cycles are not consumed
    assert_eq!(consumed_cycles_before, consumed_cycles_after);
}

#[test]
fn consume_cycles_updates_consumed_cycles() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let consumed_cycles_before = system_state.canister_metrics().consumed_cycles();
    cycles_account_manager
        .consume_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            CompoundCycles::<Memory>::new(Cycles::new(1_000_000), cost_schedule),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
                DEFAULT_REFERENCE_SUBNET_SIZE,
            ),
            false,
        )
        .unwrap();
    let consumed_cycles_after = system_state.canister_metrics().consumed_cycles();

    assert_eq!(
        consumed_cycles_after - consumed_cycles_before,
        NominalCycles::new(1_000_000)
    );
}

#[test]
fn consume_cycles_for_memory_drains_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000));
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        CompoundCycles::<Memory>::new(Cycles::new(2_000_000), cost_schedule),
        Cycles::new(0),
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_compute_drains_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000));
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        CompoundCycles::<ic_types_cycles::ComputeAllocation>::new(
            Cycles::new(2_000_000),
            cost_schedule,
        ),
        Cycles::new(0),
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_uninstall_drains_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(Cycles::new(4_000_000));
    system_state.reserve_cycles(Cycles::new(1_000_000)).unwrap();
    cam.consume_with_threshold(
        &mut system_state,
        CompoundCycles::<Uninstall>::new(Cycles::new(2_000_000), cost_schedule),
        Cycles::new(0),
        false,
    )
    .unwrap();
    assert_eq!(system_state.reserved_balance(), Cycles::new(0));
    assert_eq!(system_state.balance(), Cycles::new(2_000_000));
}

#[test]
fn consume_cycles_for_execution_does_not_drain_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let reserved = Cycles::new(10_000_000);
    let main = Cycles::new(30_000_000);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(Cycles::zero())
        .build();
    system_state.add_cycles(main + reserved);
    system_state.reserve_cycles(reserved).unwrap();

    let n_max = NumInstructions::from(1_000_000);
    let n_refund = NumInstructions::from(600_000);

    // Prepaying the execution cost only draws from the main balance.
    let prepaid = cam
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            n_max,
            subnet_cycles_config,
            false,
            WASM_EXECUTION_MODE,
        )
        .unwrap();
    assert_ne!(prepaid.real(), Cycles::zero());
    assert_eq!(system_state.reserved_balance(), reserved);
    assert_eq!(system_state.balance(), main - prepaid.real());

    // Refunding the unused instructions returns the cycles to the main balance,
    // again leaving the reserved balance untouched.
    let no_op_counter = IntCounter::new("no_op", "no_op").unwrap();
    cam.refund_unused_execution_cycles(
        &mut system_state,
        n_refund,
        n_max,
        prepaid,
        &no_op_counter,
        subnet_cycles_config,
        WASM_EXECUTION_MODE,
        &no_op_logger(),
    );
    let refund = cam
        .variable_execution_cost(n_refund, subnet_cycles_config, WASM_EXECUTION_MODE)
        .real();
    assert_ne!(refund, Cycles::zero());
    assert_eq!(system_state.reserved_balance(), reserved);
    assert_eq!(system_state.balance(), main - prepaid.real() + refund);
}

#[test]
fn withdraw_cycles_for_transfer_checks_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemState::new_running_for_testing(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::new(21_000_000),
        NumSeconds::from(1_000),
    );
    system_state
        .reserve_cycles(Cycles::new(20_000_000))
        .unwrap();
    let mut new_balance = system_state.balance();
    cycles_account_manager
        .withdraw_cycles_for_transfer(
            system_state.canister_id(),
            system_state.freeze_threshold,
            system_state.memory_allocation,
            NumBytes::from(1_000_000),
            MessageMemoryUsage {
                guaranteed_response: NumBytes::new(1_000),
                best_effort: NumBytes::new(0),
            },
            ComputeAllocation::default(),
            &mut new_balance,
            Cycles::new(1_000_000),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                cost_schedule,
                DEFAULT_REFERENCE_SUBNET_SIZE,
            ),
            system_state.reserved_balance(),
            false,
        )
        .unwrap();
    assert_eq!(Cycles::zero(), new_balance);
}

#[test]
fn freezing_threshold_uses_reserved_balance() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let threshold_without_reserved = cycles_account_manager.freeze_threshold_cycles(
        NumSeconds::from(1_000),
        MemoryAllocation::default(),
        NumBytes::from(1_000_000),
        MessageMemoryUsage {
            guaranteed_response: NumBytes::new(1_000),
            best_effort: NumBytes::new(0),
        },
        ComputeAllocation::default(),
        subnet_cycles_config,
        Cycles::new(0),
    );

    let threshold_with_reserved = cycles_account_manager.freeze_threshold_cycles(
        NumSeconds::from(1_000),
        MemoryAllocation::default(),
        NumBytes::from(1_000_000),
        MessageMemoryUsage {
            guaranteed_response: NumBytes::new(1_000),
            best_effort: NumBytes::new(0),
        },
        ComputeAllocation::default(),
        subnet_cycles_config,
        Cycles::new(1_000),
    );

    assert_eq!(
        threshold_without_reserved,
        threshold_with_reserved + Cycles::new(1_000)
    );
}

#[test]
fn scaling_of_resource_saturation() {
    let rs = ResourceSaturation::default();
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(99, 100, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(100, 100, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(101, 100, 200);
    assert_eq!(10, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(150, 100, 200);
    assert_eq!(500, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(200, 100, 200);
    assert_eq!(1000, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(201, 100, 200);
    assert_eq!(1000, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(0, 200, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(0, 201, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::new(201, 201, 200);
    assert_eq!(0, rs.reservation_factor(1000));

    let rs = ResourceSaturation::default();
    assert_eq!(0, rs.add(1000).reservation_factor(1000));

    let rs = ResourceSaturation::new(100, 100, 200);
    // The usage should be capped at the capacity.
    assert_eq!(1000, rs.add(200).reservation_factor(1000));
}

#[test]
fn test_storage_reservation_cycles() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    const GB: u64 = 1024 * 1024 * 1024;

    let cfg = CyclesAccountManagerConfig::application_subnet();
    let cam = CyclesAccountManagerBuilder::new().build();

    // Allocation of 100GB below the threshold.
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(100 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 101GB at (usage=0GB, threshold=100GB, capacity=200GB).
    // Only 1GB above the threshold participates in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle
                // above the threshold with
                // - base = 1
                // - height = (101 - 100) / (200 - 100).
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(101 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=90GB, threshold=100GB, capacity=200GB).
    // Only 30GB above the threshold participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle
                // above the threshold with
                // - base = 30
                // - height = (130 - 100) / (200 - 100).
                * 30
                * (130 - 100)
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(90 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=100GB, threshold=100GB, capacity=200GB).
    // All 40GB participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                // The remaining computes the area of the triangle above the
                // threshold with
                // - base = 40
                // - height = (140 - 100) / (200 - 100).
                * 40
                * (140 - 100)
                / (200 - 100)
                / 2
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(100 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=160GB, threshold=100GB, capacity=200GB).
    // All 40GB participate in reservation.
    assert_eq!(
        Cycles::new(
            cfg.max_storage_reservation_period.as_secs() as u128
                * cfg.gib_storage_per_second_fee.get()
                * (
                    // This computes the difference of areas of two triangles.
                    // The bigger triangle has base = 100, height = (200 - 100) / (200 - 100).
                    // The smaller triangle has base = 60, height = (160 - 100) / (200 - 100).
                    100 * (200 - 100) / (200 - 100) / 2 - 60 * (160 - 100) / (200 - 100) / 2
                )
        ),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(160 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // The total reserved cycles of small allocations should match that of one
    // large allocation.
    let thirteen_node_config =
        CyclesAccountManagerSubnetConfig::new(13, cost_schedule, DEFAULT_REFERENCE_SUBNET_SIZE);
    let rs0 = ResourceSaturation::new(0, 100 * GB, 1000 * GB);
    let mut total = Cycles::zero();
    let mut rs = rs0.clone();
    for _ in 0..1000 {
        total += cam
            .storage_reservation_cycles(NumBytes::new(GB), &rs, thirteen_node_config)
            .real();
        rs = rs.add(GB);
    }
    assert_eq!(
        total,
        cam.storage_reservation_cycles(NumBytes::new(1000 * GB), &rs0, thirteen_node_config)
            .real()
    )
}

#[test]
fn test_storage_reservation_cycles_free() {
    let cost_schedule = CanisterCyclesCostSchedule::Free;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        SMALL_APP_SUBNET_MAX_SIZE,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    const GB: u64 = 1024 * 1024 * 1024;

    let cam = CyclesAccountManagerBuilder::new().build();

    // Allocation of 100GB below the threshold.
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(100 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 101GB at (usage=0GB, threshold=100GB, capacity=200GB).
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(101 * GB),
            &ResourceSaturation::new(0, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=90GB, threshold=100GB, capacity=200GB).
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(90 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=100GB, threshold=100GB, capacity=200GB).
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(100 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );

    // Allocation of 40GB at (usage=160GB, threshold=100GB, capacity=200GB).
    assert_eq!(
        Cycles::new(0),
        cam.storage_reservation_cycles(
            NumBytes::new(40 * GB),
            &ResourceSaturation::new(160 * GB, 100 * GB, 200 * GB),
            subnet_cycles_config,
        )
        .real()
    );
}

#[test]
fn variable_execution_cost_matches_refund() {
    let cost_schedule = CanisterCyclesCostSchedule::Normal;
    let subnet_size = SMALL_APP_SUBNET_MAX_SIZE;
    let subnet_cycles_config = CyclesAccountManagerSubnetConfig::new(
        subnet_size,
        cost_schedule,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );
    let cam = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let n_max = NumInstructions::from(1_000_000);
    let n_refund = NumInstructions::from(600_000);

    let mut system_state = SystemStateBuilder::new().build();
    let prepaid = cam
        .prepay_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            MessageMemoryUsage::ZERO,
            ComputeAllocation::default(),
            n_max,
            subnet_cycles_config,
            false,
            WASM_EXECUTION_MODE,
        )
        .unwrap();

    let balance_after_prepay = system_state.balance();

    let no_op_counter = IntCounter::new("no_op", "no_op").unwrap();
    cam.refund_unused_execution_cycles(
        &mut system_state,
        n_refund,
        n_max,
        prepaid,
        &no_op_counter,
        subnet_cycles_config,
        WASM_EXECUTION_MODE,
        &no_op_logger(),
    );

    let expected_refund = cam
        .variable_execution_cost(n_refund, subnet_cycles_config, WASM_EXECUTION_MODE)
        .real();
    assert_eq!(
        system_state.balance(),
        balance_after_prepay + expected_refund
    );
}
