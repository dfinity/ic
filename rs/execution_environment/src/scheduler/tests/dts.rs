//! Tests for deterministic time slicing..

use super::super::test_utilities::{
    SchedulerTest, SchedulerTestBuilder, TestInstallCode, ingress, instructions,
};
use super::super::*;
use candid::Encode;
use ic_config::subnet_config::SchedulerConfig;
use ic_management_canister_types_private::{CanisterIdRecord, Method};
use ic_registry_subnet_type::SubnetType;
use ic_types::methods::SystemMethod;
use ic_types_test_utils::ids::canister_test_id;
use more_asserts::assert_le;
use proptest::prelude::*;

#[test]
fn dts_long_execution_completes() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    let message_id = test.send_ingress(canister, ingress(1000));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for _ in 1..10 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterDidNotReply,
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        9.0
    );
}

fn can_execute_multiple_messages_per_round_with_dts(mut test: SchedulerTest) {
    let canister = test.create_canister();
    let num_messages = 1000;
    for _ in 0..num_messages {
        test.send_ingress(canister, ingress(1000));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        num_messages
    );
}

// The following two tests check that we can execute multiple messages per round
// with DTS enabled on both app and system subnets. The tests are explicitly
// checking with production configurations to ensure that we don't accidentally
// set incompatible limits and end up reducing throughput a lot (e.g. execute
// only one message per round).
#[test]
fn can_execute_multiple_messages_per_round_on_app_subnets_with_dts() {
    let test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    can_execute_multiple_messages_per_round_with_dts(test);
}

#[test]
fn can_execute_multiple_messages_per_round_on_system_subnets_with_dts() {
    let test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    can_execute_multiple_messages_per_round_with_dts(test);
}

#[test]
fn cannot_execute_management_message_for_targeted_long_execution_canister() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    let message_id = test.send_ingress(canister, ingress(1000));

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for _ in 1..3 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    // Subnet message directed to canister which has a long running message.
    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::CanisterStatus,
        arg,
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);

    // Subnet message will not be picked up because of the long execution.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        4.0
    );

    // Finish the long execution. The subnet message will also be processed.
    for _ in 1..7 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 0);
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterDidNotReply,
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        9.0
    );
}

#[test]
fn dts_long_execution_runs_out_of_instructions() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    let message_id = test.send_ingress(canister, ingress(1001));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for _ in 1..10 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterInstructionLimitExceeded,
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        9.0
    );
}

#[test_strategy::proptest]
fn complete_concurrent_long_executions(
    #[strategy(2..10_usize)] scheduler_cores: usize,
    #[strategy(0..10_usize)] num_canisters: usize,
    #[strategy(1..10_u64)] num_slices: u64,
) {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100 * num_slices),
            max_instructions_per_message: NumInstructions::from(100 * num_slices),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            max_paused_executions: num_canisters,
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let mut message_ids = vec![];
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        let message_id = test.send_ingress(canister_id, ingress(100 * num_slices));
        message_ids.push(message_id);
    }

    // There are no aborts, as `max_paused_executions == num_canisters`
    let number_of_rounds_to_complete =
        num_canisters as u64 * num_slices / scheduler_cores as u64 + num_slices;
    for _ in 0..number_of_rounds_to_complete {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    for message_id in message_ids.iter() {
        let message_error = test.ingress_error(message_id).code();
        assert_eq!(message_error, ErrorCode::CanisterDidNotReply,);
    }
}

#[test_strategy::proptest]
fn respect_max_paused_executions(
    #[strategy(2..10_usize)] scheduler_cores: usize,
    #[strategy(1..10_usize)] num_canisters: usize,
    #[strategy(1..10_u64)] num_slices: u64,
    #[strategy(1..2.max(#num_canisters - 1))] max_paused_executions: usize,
) {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100 * num_slices),
            max_instructions_per_message: NumInstructions::from(100 * num_slices),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            max_paused_executions,
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let mut message_ids = vec![];
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        let message_id = test.send_ingress(canister_id, ingress(100 * num_slices));
        message_ids.push(message_id);
    }

    test.execute_all_with(|test| {
        let paused_executions = test
            .state()
            .canisters_iter()
            .filter(|canister| canister.has_paused_execution())
            .count();
        // Make sure the `max_paused_executions` is respected after each round
        assert_le!(paused_executions, max_paused_executions);
    });

    // Make sure all the messages are complete
    for message_id in message_ids.iter() {
        let message_error = test.ingress_error(message_id).code();
        assert_eq!(message_error, ErrorCode::CanisterDidNotReply,);
    }
}

/// Scenario:
/// 1. One canister with many long messages `slice + 1` instructions each.
/// 2. Many canisters with 4 short messages `slice` instructions each.
///
/// Expectations:
/// 1. As all the canisters have the same compute allocation (0), they all
///    should be scheduled the same number of times.
/// 2. All short executions should be done.
#[test_strategy::proptest(ProptestConfig { cases: 8, ..ProptestConfig::default() })]
fn break_after_long_executions(#[strategy(2..10_usize)] scheduler_cores: usize) {
    let max_instructions_per_slice = SchedulerConfig::application_subnet()
        .max_instructions_per_slice
        .get();
    let num_short_messages = 4;
    let num_long_messages = 10;
    let num_canisters = scheduler_cores * 2;
    let num_rounds = num_canisters * num_short_messages / scheduler_cores;

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: (max_instructions_per_slice * 2).into(),
            max_instructions_per_message: (max_instructions_per_slice * 2).into(),
            max_instructions_per_query_message: max_instructions_per_slice.into(),
            max_paused_executions: num_canisters,
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Create one canister with many long messages
    let long_canister_id = test.create_canister();
    let mut long_message_ids = vec![];
    for _ in 0..num_long_messages {
        let long_message_id =
            test.send_ingress(long_canister_id, ingress(max_instructions_per_slice + 1));
        long_message_ids.push(long_message_id);
    }

    // Create many canisters with 4 short messages each
    let mut short_message_ids = vec![];
    // The minus one long canister
    for _ in 0..num_canisters - 1 {
        let short_canister_id = test.create_canister();
        for _ in 0..num_short_messages {
            let short_message_id =
                test.send_ingress(short_canister_id, ingress(max_instructions_per_slice));
            short_message_ids.push(short_message_id);
        }
    }

    for _round in 0..num_rounds {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    // As all the canisters have the same compute allocation (0), they all
    // should be scheduled the same number of times.
    for canister in test.state().canisters_iter() {
        if canister.canister_id() == long_canister_id {
            continue;
        }
        prop_assert_eq!(
            canister.system_state.canister_metrics().executed(),
            num_short_messages as u64
        );
    }
    // All short executions should be done.
    for message_id in short_message_ids.iter() {
        let message_error = test.ingress_error(message_id).code();
        prop_assert_eq!(message_error, ErrorCode::CanisterDidNotReply);
    }
}

/// Scenario:
/// 1. One canister with two long messages `slice + 1` instructions each.
///
/// Expectations:
/// 1. After the first round the canister should have a paused long execution.
/// 2. After the second round the canister should have no executions, i.e. the
///    finish the paused execution and should not start any new executions.
#[test]
fn filter_after_long_executions() {
    let max_instructions_per_slice = SchedulerConfig::application_subnet()
        .max_instructions_per_slice
        .get();

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            max_instructions_per_round: (max_instructions_per_slice * 2).into(),
            max_instructions_per_message: (max_instructions_per_slice * 2).into(),
            max_instructions_per_query_message: max_instructions_per_slice.into(),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Create a canister with long messages
    let mut long_message_ids = vec![];
    let long_canister_id = test.create_canister();
    for _ in 0..2 {
        let long_message_id =
            test.send_ingress(long_canister_id, ingress(max_instructions_per_slice + 1));
        long_message_ids.push(long_message_id);
    }

    // After the first round the canister should have a paused long execution.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.canister_metrics().executed(), 1);
        assert!(canister.has_paused_execution());
    }

    // After the second round the canister should have no executions, i.e. the
    // finish the paused execution and should not start any new executions.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.canister_metrics().executed(), 2);
        assert!(!canister.has_paused_execution());
    }
}

#[test]
fn dts_allow_only_one_long_install_code_execution_at_any_time() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(160),
            max_instructions_per_message: NumInstructions::from(40),
            max_instructions_per_query_message: NumInstructions::from(10),
            max_instructions_per_slice: NumInstructions::from(10),
            max_instructions_per_install_code: NumInstructions::new(40),
            max_instructions_per_install_code_slice: NumInstructions::new(10),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_1 = test.create_canister();
    let install_code = TestInstallCode::Upgrade {
        post_upgrade: instructions(23),
    };
    test.inject_install_code_call_to_ic00(canister_1, install_code);

    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 0);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .slices
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .messages
            .get_sample_sum(),
        0.0
    );

    // Add a second canister with a long install code message.
    let canister_2 = test.create_canister();
    let install_code = TestInstallCode::Upgrade {
        post_upgrade: instructions(10),
    };
    test.inject_install_code_call_to_ic00(canister_2, install_code);

    // Before second round: install code message in progress.
    // The second canister will not be executed.
    assert!(test.canister_state(canister_1).has_paused_install_code());
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After second round.
    assert!(test.canister_state(canister_1).has_paused_install_code());
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .slices
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_advance_long_install_code
            .slices
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .messages
            .get_sample_sum(),
        0.0
    );

    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        0.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_aborted_execution()
            .get_sample_sum(),
        0.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_install_code()
            .get_sample_sum(),
        2.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_aborted_install_code()
            .get_sample_sum(),
        0.0
    );

    // Third round: execution for first canister is done.
    // The second canister will be executed.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(!test.canister_state(canister_1).has_paused_install_code());
    assert!(!test.canister_state(canister_2).has_paused_install_code());
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 0);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .slices
            .get_sample_sum(),
        2.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_subnet_queue
            .messages
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_advance_long_install_code
            .slices
            .get_sample_sum(),
        2.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .round_advance_long_install_code
            .messages
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_install_code()
            .get_sample_sum(),
        2.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_install_code()
            .get_sample_count(),
        3
    );
}

#[test]
fn dts_resume_install_code_after_abort() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_install_code: NumInstructions::new(1000),
            max_instructions_per_install_code_slice: NumInstructions::new(10),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    let install_code = TestInstallCode::Upgrade {
        post_upgrade: instructions(100),
    };
    test.inject_install_code_call_to_ic00(canister, install_code);

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(test.canister_state(canister).has_paused_install_code());

    test.execute_round(ExecutionRoundType::CheckpointRound);
    assert!(test.canister_state(canister).has_aborted_install_code());

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(test.canister_state(canister).has_paused_install_code());
    for _ in 0..10 {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    assert!(!test.canister_state(canister).has_paused_install_code());
    assert!(!test.canister_state(canister).has_aborted_install_code());

    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_install_code()
            .get_sample_sum(),
        10.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_aborted_install_code()
            .get_sample_sum(),
        1.0
    );
}

#[test]
fn dts_resume_long_execution_after_abort() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_query_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    let message_id = test.send_ingress(canister, ingress(1000));

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert!(test.canister_state(canister).has_paused_execution());
    test.execute_round(ExecutionRoundType::CheckpointRound);
    assert!(!test.canister_state(canister).has_paused_execution());
    assert!(test.canister_state(canister).has_aborted_execution());

    for _ in 0..10 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterDidNotReply,
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_paused_execution()
            .get_sample_sum(),
        10.0
    );
    assert_eq!(
        test.scheduler()
            .state_metrics
            .canister_aborted_execution()
            .get_sample_sum(),
        1.0
    );
}

#[test]
fn dts_update_and_heartbeat() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(300),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_query_message: NumInstructions::from(200),
            max_instructions_per_slice: NumInstructions::from(200),
            max_instructions_per_install_code_slice: NumInstructions::from(200),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    test.expect_heartbeat(canister, instructions(200));
    let message_id = test.send_ingress(canister, ingress(300));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The heartbeat did not give the ingress message a chance to run.
    assert_eq!(test.ingress_status(&message_id), IngressStatus::Unknown);

    test.expect_heartbeat(canister, instructions(100));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Now the ingress message is running.
    assert!(test.canister_state(canister).has_paused_execution());

    test.expect_heartbeat(canister, instructions(200));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Now the ingress message completes.
    assert_eq!(
        test.ingress_error(&message_id).code(),
        ErrorCode::CanisterDidNotReply,
    );
}
