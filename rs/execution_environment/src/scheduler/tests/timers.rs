//! Tests for heartbeats and global timers.

use super::super::test_utilities::{SchedulerTestBuilder, ingress, instructions};
use super::super::*;
use super::zero_instruction_overhead_config;
use ic_config::subnet_config::SchedulerConfig;
use ic_types::methods::SystemMethod;

#[test]
fn execute_heartbeat_once_per_round_in_system_subnet() {
    // This test sets up a canister on a system subnet with a heartbeat method and
    // three messages. The heartbeat is expected to run once. The messages are
    // expected to run once each.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            ..SchedulerConfig::application_subnet()
        })
        .build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.expect_heartbeat(canister, instructions(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 4.0);
}

#[test]
fn execute_global_timer_once_per_round_in_system_subnet() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterGlobalTimer),
        None,
        None,
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(1));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.expect_global_timer(canister, instructions(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 2.0);
}

#[test]
fn global_timer_is_not_scheduled_if_not_expired() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterGlobalTimer),
        None,
        None,
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(2));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
}

#[test]
fn global_timer_is_not_scheduled_if_global_timer_method_is_not_exported() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        None,
        None,
        None,
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(1));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
}

#[test]
fn heartbeat_is_not_scheduled_if_the_canister_is_stopped() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        Some(CanisterStatusType::Stopped),
    );

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        1
    );
}

#[test]
fn global_timer_is_not_scheduled_if_the_canister_is_stopped() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterGlobalTimer),
        None,
        Some(CanisterStatusType::Stopped),
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(1));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        1
    );
}

#[test]
fn execute_heartbeat_before_messages() {
    // This test sets up a canister on a system subnet with a heartbeat method and
    // three messages. The instruction limit per round allows only a single
    // call. That call should be the heartbeat call.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(1),
            max_instructions_per_message: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::new(1),
            max_instructions_per_install_code_slice: NumInstructions::new(1),
            ..zero_instruction_overhead_config()
        })
        .build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.expect_heartbeat(canister, instructions(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
    assert_eq!(test.ingress_queue_size(canister), 3);
}

#[test]
fn execute_global_timer_before_messages() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(1),
            max_instructions_per_message: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::new(1),
            max_instructions_per_install_code_slice: NumInstructions::new(1),
            ..zero_instruction_overhead_config()
        })
        .build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterGlobalTimer),
        None,
        None,
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(1));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.send_ingress(canister, ingress(1));
    test.expect_global_timer(canister, instructions(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
    assert_eq!(test.ingress_queue_size(canister), 3);
}

#[test]
fn execute_multiple_heartbeats() {
    // This tests multiple canisters with heartbeat methods running over multiple
    // rounds using multiple scheduler cores.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 5,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..zero_instruction_overhead_config()
        })
        .build();
    let number_of_canisters: usize = 3;
    let number_of_messages_per_canister: usize = 4;
    let number_of_rounds: usize = 2;
    for _ in 0..number_of_canisters {
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            None,
            Some(SystemMethod::CanisterHeartbeat),
            None,
            None,
        );
        for _ in 0..number_of_messages_per_canister {
            test.send_ingress(canister, ingress(1));
        }

        for _ in 0..number_of_rounds {
            test.expect_heartbeat(canister, instructions(1));
        }
    }
    for _ in 0..number_of_rounds {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    let metrics = &test.scheduler().metrics;
    let expected_messages =
        number_of_canisters * (number_of_messages_per_canister + number_of_rounds);
    assert_eq!(
        metrics.round_inner.messages.get_sample_sum(),
        expected_messages as f64
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        expected_messages as u64
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        number_of_canisters as u64
    );
}

#[test]
fn heartbeat_metrics_are_recorded() {
    // This test sets up a canister on a system subnet with a heartbeat method.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..zero_instruction_overhead_config()
        })
        .build();
    let canister0 = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    let canister1 = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    test.expect_heartbeat(canister0, instructions(100));
    test.expect_heartbeat(canister1, instructions(101));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(
        2,
        metrics.instructions_consumed_per_message.get_sample_count(),
    );
    assert_eq!(
        200,
        metrics.instructions_consumed_per_message.get_sample_sum() as u64,
    );
    assert_eq!(2, metrics.msg_execution_duration.get_sample_count());
}

/// The scheduler enqueues `Heartbeat` / `GlobalTimer` tasks at the start of
/// each round.  When the instruction budget is too small for all of them to
/// execute, the leftover tasks must be removed from the task queues at the end
/// of `inner_round`.
#[test]
fn unexecuted_heartbeat_and_timer_tasks_are_removed_after_round() {
    const NOW: Time = Time::from_nanos_since_unix_epoch(13);

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(10),
            max_instructions_per_message: NumInstructions::new(10),
            max_instructions_per_slice: NumInstructions::new(10),
            max_instructions_per_install_code_slice: NumInstructions::new(10),
            ..zero_instruction_overhead_config()
        })
        .build();
    test.set_time(NOW);

    // 4 canisters, 2 with heartbeats and 2 with global timers.
    // We can execute 1 task per round per core, so only 2 out of 4 tasks per round.
    for _ in 0..2 {
        let heartbeat = test.create_canister_with(
            Cycles::new(1_000_000_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            None,
            Some(SystemMethod::CanisterHeartbeat),
            None,
            None,
        );
        test.expect_heartbeat(heartbeat, instructions(10));

        let global_timer = test.create_canister_with(
            Cycles::new(1_000_000_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            None,
            Some(SystemMethod::CanisterGlobalTimer),
            None,
            None,
        );
        test.set_canister_global_timer(global_timer, NOW);
        test.expect_global_timer(global_timer, instructions(10));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Two tasks executed.
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 2.0);

    for (i, canister) in test.state().canisters_iter().enumerate() {
        // All tasks removed from all canisters' task queues.
        assert!(canister.system_state.task_queue.is_empty());
        // First two canisters' tasks were executed, the other two not.
        assert_eq!(test.system_task_count(&canister.canister_id()), i / 2);
    }
}
