//! Tests for resource use charging.

use super::super::test_utilities::{
    SchedulerTest, SchedulerTestBuilder, ingress, on_response, other_side,
};
use super::super::*;
use super::zero_instruction_overhead_config;
use ic_config::subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig};
use ic_management_canister_types_private::{
    Method, Payload as _, TakeCanisterSnapshotArgs, UninstallCodeArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::testing::SystemStateTesting;
use ic_types::messages::{CanisterMessageOrTask, CanisterTask};
use ic_types::time::UNIX_EPOCH;
use ic_types_test_utils::ids::canister_test_id;
use std::time::Duration;

#[test]
fn only_charge_for_allocation_after_specified_duration() {
    let mut test = SchedulerTestBuilder::new().build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    let time_between_batches = test.duration_between_allocation_charges() / 2;

    // Just enough memory to cost us one cycle per second.
    let bytes_per_cycle = (1_u128 << 30)
        .checked_div(
            CyclesAccountManagerConfig::application_subnet()
                .gib_storage_per_second_fee
                .get(),
        )
        .unwrap() as u64
        + 1;

    let initial_cycles = 1_000_000;

    let canister = test.create_canister_with_controller(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(bytes_per_cycle)),
        Some(NumBytes::new(0)), // Don't allocate log memory.
        None,
        Some(initial_time),
        None,
        None,
    );

    // Don't charge because the time since the last charge is too small.
    // Checkpoint round, to force charging for storage.
    test.set_time(initial_time + time_between_batches);
    test.execute_round(ExecutionRoundType::CheckpointRound);

    assert_eq!(
        test.canister_state(canister).system_state.balance().get(),
        initial_cycles
    );

    // The time of the current batch is now long enough that allocation charging
    // should be triggered. Checkpoint round, to force charging for storage.
    test.set_time(initial_time + 2 * time_between_batches);
    test.execute_round(ExecutionRoundType::CheckpointRound);
    assert_eq!(
        test.canister_state(canister).system_state.balance().get(),
        initial_cycles
            - 10
            - test
                .canister_base_cost(NumBytes::from(bytes_per_cycle), time_between_batches * 2,)
                .real()
                .get(),
    );
}

#[test]
fn charging_happens_on_average_once_every_charge_interval_rounds() {
    let mut test = SchedulerTestBuilder::new().build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    // A canister with a memory allocation and plenty of cycles, so that every
    // charge reduces the balance but the canister is never uninstalled.
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(1 << 30)),
        None,
        Some(initial_time),
        None,
    );

    // Advance time by a full charge duration every round, so that a charge is
    // always due whenever charging is attempted (every `CHARGE_INTERVAL_ROUNDS`
    // rounds).
    let charge_duration = test.duration_between_allocation_charges();

    const NUM_ROUNDS: u64 = 1_000;
    let mut num_charges = 0;
    for _ in 0..NUM_ROUNDS {
        test.advance_time(charge_duration);
        let balance_before = test.canister_state(canister).system_state.balance();
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        if test.canister_state(canister).system_state.balance() < balance_before {
            num_charges += 1;
        }
    }

    // Even though enough time has passed to charge in every round, the canister
    // was only charged once every `CHARGE_INTERVAL_ROUNDS` rounds, i.e. on
    // average once every 50 rounds.
    assert_eq!(num_charges, NUM_ROUNDS / CHARGE_INTERVAL_ROUNDS);
}

#[test]
fn charging_for_message_memory_works() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_slice: NumInstructions::new(1),
            max_instructions_per_install_code_slice: NumInstructions::new(1),
            max_instructions_per_round: NumInstructions::from(1),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    let initial_cycles = 1_000_000_000_000;
    let canister = test.create_canister_with_controller(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        Some(NumBytes::new(0)), // Don't allocate log memory.
        None,
        Some(initial_time),
        None,
        None,
    );

    // Send an ingress that triggers an inter-canister call. Because of the scheduler
    // configuration, we can only execute the ingress message but not the
    // inter-canister message so this remains in the canister's input queue.
    test.send_ingress(
        canister,
        ingress(1).call(other_side(canister, 1), on_response(1)),
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let balance_before = test.canister_state(canister).system_state.balance();

    // Set time to at least one interval between charges to trigger a charge
    // because of message memory consumption.
    let charge_duration = test.duration_between_allocation_charges();
    test.set_time(initial_time + charge_duration);
    test.charge_for_resource_allocations();

    // The balance of the canister should have been reduced by the cost of
    // message memory during the charge period.
    let canister_state = test.canister_state(canister);
    assert_eq!(
        canister_state.system_state.balance(),
        balance_before
            - test
                .canister_base_cost(canister_state.memory_usage(), charge_duration)
                .real()
            - test
                .memory_cost(
                    canister_state.message_memory_usage().total(),
                    charge_duration,
                )
                .real(),
    );
}

#[test]
fn charging_for_logging_memory_works() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_slice: NumInstructions::new(1),
            max_instructions_per_install_code_slice: NumInstructions::new(1),
            max_instructions_per_round: NumInstructions::from(1),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    let initial_cycles = 1_000_000_000_000;
    let canister = test.create_canister_with_controller(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        Some(NumBytes::new(4_096)), // Set log_memory_limit to 4KiB.
        None,
        Some(initial_time),
        None,
        None,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let balance_before = test.canister_state(canister).system_state.balance();

    // Set time to at least one interval between charges to trigger a charge
    // because of log memory consumption.
    let charge_duration = test.duration_between_allocation_charges();
    test.set_time(initial_time + charge_duration);
    test.charge_for_resource_allocations();

    // The balance of the canister should have been reduced by the cost of
    // log memory during the charge period.
    let canister_state = test.canister_state(canister);
    assert_eq!(
        canister_state.system_state.balance(),
        balance_before
            - test
                .canister_base_cost(canister_state.memory_usage(), charge_duration)
                .real()
            - test
                .memory_cost(
                    canister_state.log_memory_store_memory_usage(),
                    charge_duration,
                )
                .real(),
    );
}

// Creates an initial state with some canisters that contain very few cycles.
// Ensures that after `execute_round` returns, the canisters have been
// uninstalled.
#[test]
fn canisters_with_insufficient_cycles_are_uninstalled() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    let mut test = SchedulerTestBuilder::new().build();
    for _ in 0..3 {
        test.create_canister_with(
            Cycles::new(100),
            ComputeAllocation::zero(),
            MemoryAllocation::from(NumBytes::from(1 << 30)),
            None,
            Some(initial_time),
            None,
        );
    }
    test.set_time(initial_time + test.duration_between_allocation_charges());

    // Checkpoint round, to force charging for storage.
    test.execute_round(ExecutionRoundType::CheckpointRound);

    for canister in test.state().canisters_iter() {
        assert!(canister.execution_state.is_none());
        assert_eq!(canister.compute_allocation(), ComputeAllocation::zero());
        assert_eq!(
            canister.system_state.memory_allocation,
            MemoryAllocation::default()
        );
        assert_eq!(canister.system_state.canister_version(), 1);
    }
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        3
    );
}

// Uninstalling a canister because it ran out of cycles succeeds even when the
// subnet has no available execution memory: the out-of-cycles path drops the
// canister history (it does not record a `CanisterCodeUninstall` change), so it
// never needs to decrement the subnet available execution memory. This is in
// contrast to `uninstall_code`, which records a canister history change and fails
// if the subnet cannot account for it.
#[test]
fn out_of_cycles_uninstall_succeeds_without_subnet_available_memory() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    // The subnet has no available execution memory. The scheduler test builder
    // also fixes the subnet memory reservation to zero, so the subnet available
    // execution memory is exactly zero.
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_memory_capacity(0)
        .build();
    // A canister with an execution state installed and barely any cycles.
    let canister = test.create_canister_with(
        Cycles::new(100),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(1 << 30)),
        None,
        Some(initial_time),
        None,
    );
    assert!(test.canister_state(canister).execution_state.is_some());
    // The out-of-cycles path drops the canister history without recording a
    // `CanisterCodeUninstall` change, so the total number of changes must not
    // increase across the uninstall.
    let total_num_changes_before = test
        .canister_state(canister)
        .system_state
        .get_canister_history()
        .get_total_num_changes();

    test.set_time(initial_time + test.duration_between_allocation_charges());
    // Checkpoint round, to force charging for storage, which the canister cannot
    // pay for and thus gets uninstalled.
    test.execute_round(ExecutionRoundType::CheckpointRound);

    // The canister was uninstalled out of cycles despite the subnet having no
    // available execution memory, and no `CanisterCodeUninstall` change was
    // recorded (so no subnet available execution memory was needed): the total
    // number of changes is unchanged.
    assert!(test.canister_state(canister).execution_state.is_none());
    assert_eq!(
        test.canister_state(canister)
            .system_state
            .get_canister_history()
            .get_total_num_changes(),
        total_num_changes_before
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        1
    );
}

#[test]
fn open_call_contexts_produce_reject_responses_when_out_of_cycles() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(1 << 30)),
        None,
        Some(initial_time),
        None,
    );

    // Make a XNet call, so the call context stays open, awaiting response from the
    // remote subnet).
    let message_id = test.send_ingress(
        canister,
        ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(test.canister_state(canister).has_output());
    assert!(test.canister_state(canister).execution_state.is_some());

    // Drain all cycles so the next allocation charge triggers uninstall.
    test.canister_state_mut(canister)
        .system_state
        .set_balance(Cycles::zero());

    let duration_between_allocation_charges = test.duration_between_allocation_charges();
    test.set_time(initial_time + duration_between_allocation_charges);

    test.charge_for_resource_allocations();

    // Canister was uninstalled.
    assert!(test.canister_state(canister).execution_state.is_none());
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        1
    );
    // And the ingress was rejected.
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterRejectedMessage,
    );
}

#[test]
fn dont_charge_allocations_for_paused_canisters() {
    const T0: Time = Time::from_nanos_since_unix_epoch(1_000_000_000);
    const INITIAL_CYCLES: Cycles = Cycles::new(10_000_000);
    const MEMORY_ALLOCATION: NumBytes = NumBytes::new(1 << 30);

    let mut test = SchedulerTestBuilder::new().build();

    let mut create_canister_with_memory_allocation = || -> CanisterId {
        test.create_canister_with(
            INITIAL_CYCLES,
            ComputeAllocation::zero(),
            MemoryAllocation::from(MEMORY_ALLOCATION),
            None,
            Some(T0),
            None,
        )
    };
    let canister = create_canister_with_memory_allocation();
    let paused_canister = create_canister_with_memory_allocation();
    let paused_install_canister = create_canister_with_memory_allocation();

    test.canister_state_mut(paused_canister)
        .system_state
        .task_queue
        .enqueue(ExecutionTask::PausedExecution {
            id: PausedExecutionId(0),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });
    test.canister_state_mut(paused_install_canister)
        .system_state
        .task_queue
        .enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));

    let duration_between_allocation_charges = test.duration_between_allocation_charges();
    test.set_time(T0 + duration_between_allocation_charges);

    test.charge_for_resource_allocations();

    fn assert_balance_change(test: &SchedulerTest, canister: CanisterId, duration: Duration) {
        assert_eq!(
            test.canister_state(canister).system_state.balance(),
            INITIAL_CYCLES
                - test.memory_cost(MEMORY_ALLOCATION, duration).real()
                - test.canister_base_cost(MEMORY_ALLOCATION, duration).real()
        );
    }
    // Balance has changed for the canister with no paused execution.
    assert_balance_change(&test, canister, duration_between_allocation_charges);
    // Balance has not changed for the canisters with paused execution/install code.
    assert_balance_change(&test, paused_canister, Duration::from_secs(0));
    assert_balance_change(&test, paused_install_canister, Duration::from_secs(0));

    // One second later, the two long executions complete.
    let duration_plus_one_second = duration_between_allocation_charges + Duration::from_secs(1);
    test.set_time(T0 + duration_plus_one_second);
    test.canister_state_mut(paused_canister)
        .system_state
        .task_queue
        .pop_front();
    test.canister_state_mut(paused_install_canister)
        .system_state
        .task_queue
        .pop_front();

    test.charge_for_resource_allocations();

    // The balance has not changed for the canister that was already charged.
    assert_balance_change(&test, canister, duration_between_allocation_charges);
    // The balance has changed for the canisters with paused execution/install code.
    assert_balance_change(&test, paused_canister, duration_plus_one_second);
    assert_balance_change(&test, paused_install_canister, duration_plus_one_second);
}

#[test]
fn snapshot_is_deleted_when_canister_is_out_of_cycles() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    let mut test = SchedulerTestBuilder::new().build();

    let canister_id = test.create_canister_with_controller(
        Cycles::new(31_750_000),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(1 << 30)),
        None,
        None,
        Some(initial_time),
        None,
        Some(canister_test_id(10).get()),
    );
    assert_eq!(test.state().canister_states().len(), 1);
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        0
    );

    // Taking a snapshot of the canister will decrease the balance.
    // Increase the canister balance to be able to take a new snapshot.
    let subnet_type = SubnetType::Application;
    let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;
    let canister_snapshot_size = test.canister_state(canister_id).snapshot_size_bytes();
    let instructions = scheduler_config.canister_snapshot_baseline_instructions
        + NumInstructions::new(canister_snapshot_size.get());
    let expected_charge = test.execution_cost(instructions);
    test.state_mut()
        .canister_state_make_mut(&canister_id)
        .unwrap()
        .system_state
        .add_cycles(expected_charge);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        args.encode(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);

    // Snapshot was created.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 0);
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        1
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        0
    );
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_some()
    );

    // Uninstall canister due to `out_of_cycles`.
    test.set_time(initial_time + 1000 * test.duration_between_allocation_charges());
    // Checkpoint round, to force charging for storage.
    test.execute_round(ExecutionRoundType::CheckpointRound);

    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        1
    );
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        0
    );
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_none()
    );
}

#[test]
fn snapshot_is_deleted_when_uninstalled_canister_is_out_of_cycles() {
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    let mut test = SchedulerTestBuilder::new().build();

    let canister_id = test.create_canister_with_controller(
        Cycles::new(31_750_000),
        ComputeAllocation::zero(),
        MemoryAllocation::from(NumBytes::from(1 << 30)),
        None,
        None,
        Some(initial_time),
        None,
        Some(canister_test_id(10).get()),
    );
    assert_eq!(test.state().canister_states().len(), 1);
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        0
    );
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_some()
    );

    // Taking a snapshot of the canister will decrease the balance.
    // Increase the canister balance to be able to take a new snapshot.
    let subnet_type = SubnetType::Application;
    let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;
    let canister_snapshot_size = test.canister_state(canister_id).snapshot_size_bytes();
    let instructions = scheduler_config.canister_snapshot_baseline_instructions
        + NumInstructions::new(canister_snapshot_size.get());
    let expected_charge = test.execution_cost(instructions);
    test.state_mut()
        .canister_state_make_mut(&canister_id)
        .unwrap()
        .system_state
        .add_cycles(expected_charge);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        args.encode(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);

    // Snapshot was created.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 0);
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        1
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        0
    );
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_some()
    );

    // Uninstall canister.
    let args: UninstallCodeArgs = UninstallCodeArgs::new(canister_id, None);
    test.inject_call_to_ic00(
        Method::UninstallCode,
        args.encode(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_none()
    );

    // Trigger canister `out_of_cycles`.
    test.set_time(initial_time + 1000 * test.duration_between_allocation_charges());
    // Checkpoint round, to force charging for storage.
    test.execute_round(ExecutionRoundType::CheckpointRound);

    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        1
    );
    assert_eq!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .canister_snapshots
            .len(),
        0
    );
    assert!(
        test.state()
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .is_none()
    );
}
