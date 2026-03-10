//! Tests for instruction, memory, callback, heap delta and other limits.

use super::super::test_utilities::{
    SchedulerTestBuilder, TestInstallCode, ingress, instructions, on_response, other_side,
};
use super::super::*;
use super::zero_instruction_messages;
use ic_config::subnet_config::SchedulerConfig;
use ic_replicated_state::testing::CanisterQueuesTesting;
use proptest::prelude::*;

/// This test ensures that inner_loop() breaks out of the loop when the loop
/// consumes max_instructions_per_round.
#[test]
fn inner_loop_stops_when_max_instructions_per_round_consumed() {
    // Create a canister with 3 input messages. 2 of them consume all of
    // max_instructions_per_round. The 2 messages are executed in the first
    // iteration of the loop and then the loop breaks.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            max_instructions_per_query_message: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(50));
    test.send_ingress(canister_id, ingress(50));
    test.send_ingress(canister_id, ingress(50));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(test.ingress_queue_size(canister_id), 1);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.execute_round_called.get(), 1);
    assert_eq!(metrics.inner_round_loop_consumed_max_instructions.get(), 1);
    assert_eq!(
        metrics
            .inner_loop_consumed_non_zero_instructions_count
            .get(),
        1
    );

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        2
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

/// Verifies that the [`SchedulerConfig::instruction_overhead_per_execution`] puts
/// a limit on the number of update messages that will be executed in a single
/// round.
#[test]
fn test_message_limit_from_message_overhead() {
    // Create two canisters on the same subnet. When each one receives a
    // message, it sends a message to the other so that they ping-pong forever.
    let scheduler_config = SchedulerConfig {
        scheduler_cores: 2,
        max_instructions_per_message: NumInstructions::from(5_000_000_000),
        max_instructions_per_query_message: NumInstructions::from(5_000_000_000),
        max_instructions_per_slice: NumInstructions::from(5_000_000_000),
        max_instructions_per_install_code_slice: NumInstructions::from(5_000_000_000),
        max_instructions_per_round: NumInstructions::from(7_000_000_000),
        instruction_overhead_per_execution: NumInstructions::from(2_000_000),
        instruction_overhead_per_canister: NumInstructions::from(0),
        instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
        ..SchedulerConfig::application_subnet()
    };
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(scheduler_config.clone())
        .build();

    let canister0 = test.create_canister();
    let canister1 = test.create_canister();

    // There are 7B instructions allowed per round, but we won't execute a
    // message unless we know there are 5B instructions left since that is the
    // maximum a message could use.  So execution will stop when we've used 2B
    // messages.  There is an overhead of 2M instructions per message so this
    // allows us to execute 1000 messages.  We stop when we've gone over the
    // limit, so one additional message will be handled.
    let expected_number_of_messages = (scheduler_config.max_instructions_per_round
        - scheduler_config.max_instructions_per_message)
        / scheduler_config.instruction_overhead_per_execution
        + 1;

    let mut callee = canister0;
    let mut call = other_side(callee, 0);

    for _ in 0..expected_number_of_messages * 3 {
        callee = if callee == canister1 {
            canister0
        } else {
            canister1
        };
        call = other_side(callee, 0).call(call, on_response(0));
    }

    let message = ingress(0).call(call, on_response(0));
    test.send_ingress(canister0, message);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // All messages are zero instruction messages.
    assert_eq!(
        zero_instruction_messages(test.metrics_registry()),
        expected_number_of_messages
    );

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        0
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
}

/// Tests that given specific subnet callback soft cap and guaranteed canister
/// callback quota values, two canisters trying to call themselves recursively
/// twice will result in the execution of a specific number of messages.
fn test_subnet_callback_soft_cap_impl(
    subnet_callback_soft_cap: usize,
    canister_callback_quota: usize,
    expected_message_executions: u64,
) {
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_callback_soft_limit(subnet_callback_soft_cap)
        .with_canister_guaranteed_callback_quota(canister_callback_quota)
        .build();

    for _ in 0..2 {
        let canister = test.create_canister();
        test.send_ingress(
            canister,
            ingress(1).call(
                other_side(canister, 1).call(other_side(canister, 1), on_response(1)),
                on_response(1),
            ),
        );
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        expected_message_executions
    );
}

#[test]
fn subnet_callback_soft_cap_exceeded() {
    // Given a shared pool size of 2 callbacks, the canisters should be able to
    // execute the first call but not the second one (i.e. 3 messages each).
    let subnet_callback_soft_cap = 2;
    let canister_callback_quota = 0;
    test_subnet_callback_soft_cap_impl(subnet_callback_soft_cap, canister_callback_quota, 6);
}

#[test]
fn subnet_callback_soft_cap_not_exceeded() {
    // Given a shared pool of 3 callbacks, the canisters should each be able to
    // execute both their calls (5 messages each). This is because each of the 2
    // execution threads is allowed full use of the remaining pool (1 callback).
    let subnet_callback_soft_cap = 3;
    let canister_callback_quota = 0;
    test_subnet_callback_soft_cap_impl(subnet_callback_soft_cap, canister_callback_quota, 10);
}

#[test]
fn subnet_callback_soft_cap_ignored() {
    // A shared pool size of 2 callbacks (which would prevent the canisters from
    // making a second call) is ignored if the canisters have available callback
    // quota (with each canister executing 2 calls, i.e. 5 messages).
    let subnet_callback_soft_cap = 2;
    let canister_callback_quota = 10;
    test_subnet_callback_soft_cap_impl(subnet_callback_soft_cap, canister_callback_quota, 10);
}

#[test]
fn dont_execute_any_canisters_if_not_enough_instructions_in_round() {
    let instructions_per_message = NumInstructions::from(5);
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: instructions_per_message - NumInstructions::from(1),
            max_instructions_per_message: instructions_per_message,
            max_instructions_per_query_message: instructions_per_message,
            max_instructions_per_slice: instructions_per_message,
            max_instructions_per_install_code_slice: instructions_per_message,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    for _ in 0..3 {
        let canister = test.create_canister();
        test.send_ingress(canister, ingress(instructions_per_message.get()));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister_state in test.state().canisters_iter() {
        let system_state = &canister_state.system_state;
        assert_eq!(system_state.queues().ingress_queue_size(), 1);
        assert_eq!(
            test.state()
                .canister_priority(&canister_state.canister_id())
                .last_full_execution_round,
            ExecutionRound::from(0)
        );
        assert_eq!(system_state.canister_metrics().rounds_scheduled(), 1);
        assert_eq!(system_state.canister_metrics().executed(), 0);
        assert_eq!(
            system_state
                .canister_metrics()
                .interrupted_during_execution(),
            0
        );
    }
}

#[test]
fn can_execute_messages_with_just_enough_instructions() {
    // In this test we have 3 canisters with 1 message each and the maximum allowed
    // round cycles is 3 times the instructions consumed by each message. Thus, we
    // expect that we have just enough instructions to execute all messages.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(50 * 3),
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_query_message: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::from(50),
            max_instructions_per_install_code_slice: NumInstructions::from(50),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump the round number up to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let num_canisters = 3;
    for _ in 0..num_canisters {
        let canister = test.create_canister();
        test.send_ingress(canister, ingress(50));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister_state in test.state().canisters_iter() {
        let system_state = &canister_state.system_state;
        assert_eq!(system_state.queues().ingress_queue_size(), 0);
        assert_eq!(
            test.state()
                .canister_priority(&canister_state.canister_id())
                .last_full_execution_round,
            ExecutionRound::from(1)
        );
        assert_eq!(system_state.canister_metrics().rounds_scheduled(), 1);
        assert_eq!(system_state.canister_metrics().executed(), 1);
        assert_eq!(
            system_state
                .canister_metrics()
                .interrupted_during_execution(),
            0
        );
    }

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        3
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );
}

#[test]
fn max_canisters_per_round() {
    fn run(canisters_with_no_cycles: usize, canisters_with_cycles: usize) -> usize {
        let mut test = SchedulerTestBuilder::new()
            .with_scheduler_config(SchedulerConfig {
                scheduler_cores: 2,
                max_instructions_per_round: 100.into(),
                max_instructions_per_message: 10.into(),
                max_instructions_per_query_message: 10.into(),
                max_instructions_per_slice: 10.into(),
                max_instructions_per_install_code_slice: 10.into(),
                instruction_overhead_per_execution: 0.into(),
                instruction_overhead_per_canister: 10.into(),
                ..SchedulerConfig::application_subnet()
            })
            .build();

        // Bump up the round number to 1.
        test.execute_round(ExecutionRoundType::OrdinaryRound);

        for _ in 0..canisters_with_no_cycles {
            let canister_id = test.create_canister_with(
                Cycles::new(0),
                ComputeAllocation::zero(),
                MemoryAllocation::default(),
                None,
                None,
                None,
            );
            test.send_ingress(canister_id, ingress(10));
        }
        for _ in 0..canisters_with_cycles {
            let canister_id = test.create_canister();
            test.send_ingress(canister_id, ingress(10));
        }

        test.execute_round(ExecutionRoundType::OrdinaryRound);

        test.state()
            .canisters_iter()
            .filter(|canister| canister.system_state.queues().ingress_queue_size() == 0)
            .count()
    }

    // In this test we have 200 canisters with one input message each. Each
    // message uses 10 instructions. The canister overhead is also 10
    // instructions. The round limit is 100 instructions. We expect 5
    // canisters to execute per scheduler core.
    let executed_canisters = run(0, 200);
    assert_eq!(executed_canisters, 2 * 5);

    // As 200 canisters do not have enough cycles for the actual execution,
    // we expect the scheduler to try to execute them all with no
    // per-canister overhead.
    let executed_canisters = run(200, 0);
    assert_eq!(executed_canisters, 200);

    // As 200 canisters do not have enough cycles for the actual execution,
    // we expect the scheduler to try to execute them all with no
    // per-canister overhead.
    // Plus, we should be able to execute 5 canisters with overhead 10
    // and 10 instructions on each scheduler core.
    let executed_canisters = run(200, 200);
    assert_eq!(executed_canisters, 200 + 2 * 5);
}

#[test]
fn can_fully_execute_canisters_deterministically_until_out_of_instructions() {
    // In this test we have 5 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 51 (per core). Each
    // message consumes 5 instructions, therefore we can execute fully 1
    // canister per core in one round.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_query_message: NumInstructions::from(5),
            max_instructions_per_slice: NumInstructions::from(5),
            max_instructions_per_install_code_slice: NumInstructions::from(5),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let num_canisters = 5;
    for _ in 0..num_canisters {
        let canister = test.create_canister();
        for _ in 0..10 {
            test.send_ingress(canister, ingress(5));
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let mut executed_canisters = 0;
    for canister in test.state().canisters_iter() {
        let priority = test.state().canister_priority(&canister.canister_id());
        if canister.system_state.queues().ingress_queue_size() == 0 {
            assert_eq!(priority.last_full_execution_round, ExecutionRound::from(1));
            executed_canisters += 1;
        } else {
            assert_eq!(canister.system_state.queues().ingress_queue_size(), 10);
            assert_eq!(priority.last_full_execution_round, ExecutionRound::from(0));
        }
    }
    assert_eq!(executed_canisters, 2);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        20
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );
}

#[test]
fn can_execute_messages_from_multiple_canisters_until_out_of_instructions() {
    // In this test we have 2 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 18 (per core). Each core
    // executes 1 canister until we don't have any instructions left anymore. Since
    // each message consumes 5 instructions, we can execute 3 messages from each
    // canister.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_query_message: NumInstructions::from(5),
            max_instructions_per_slice: NumInstructions::from(5),
            max_instructions_per_install_code_slice: NumInstructions::from(5),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let num_canisters = 2;
    for _ in 0..2 {
        let canister = test.create_canister();
        for _ in 0..10 {
            test.send_ingress(canister, ingress(5));
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.queues().ingress_queue_size(), 7);
        assert_ne!(
            canister
                .system_state
                .canister_metrics()
                .interrupted_during_execution(),
            0
        );
        assert_eq!(
            test.state()
                .canister_priority(&canister.canister_id())
                .last_full_execution_round,
            ExecutionRound::from(1)
        );
    }

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        6
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );
}

#[test]
fn subnet_messages_respect_instruction_limit_per_round() {
    // In this test we have a canister with 10 input messages and 20 subnet
    // messages. Each message execution consumes 10 instructions and the round
    // limit is set to 400 instructions.
    // The test expects that subnet messages use about a 1/16 of the round limit
    // and the input messages get the full round limit. More specifically:
    // - 3 subnet messages should run (using 30 out of 400 instructions).
    // - 10 input messages should run (using 100 out of 400 instructions).

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(400),
            max_instructions_per_message: NumInstructions::new(10),
            max_instructions_per_query_message: NumInstructions::new(10),
            max_instructions_per_slice: NumInstructions::new(10),
            max_instructions_per_install_code: NumInstructions::new(10),
            max_instructions_per_install_code_slice: NumInstructions::new(10),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();

    for _ in 0..10 {
        test.send_ingress(canister, ingress(10));
    }

    for _ in 0..20 {
        let install_code = TestInstallCode::Upgrade {
            post_upgrade: instructions(10),
        };
        test.inject_install_code_call_to_ic00(canister, install_code);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_subnet_queue.messages.get_sample_sum(), 3.0);
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 10.0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        13
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

fn scheduled_heap_delta_limit_corner_values() -> BoxedStrategy<u64> {
    prop_oneof!(Just(0), Just(5), Just(10), Just(100), Just(u64::MAX)).boxed()
}

fn scheduled_heap_delta_limit_option_values() -> BoxedStrategy<Option<u64>> {
    prop_oneof!(
        Just(None),
        Just(Some(0)),
        Just(Some(5)),
        Just(Some(10)),
        Just(Some(100)),
        Just(Some(u64::MAX))
    )
    .boxed()
}

#[test_strategy::proptest]
fn scheduled_heap_delta_limit_corner_cases(
    #[strategy(scheduled_heap_delta_limit_corner_values())] current_round: u64,
    #[strategy(scheduled_heap_delta_limit_option_values())] next_checkpoint_round: Option<u64>,
    #[strategy(scheduled_heap_delta_limit_option_values())] current_interval_length: Option<u64>,
    #[strategy(scheduled_heap_delta_limit_corner_values())] subnet_heap_delta_capacity: u64,
    #[strategy(scheduled_heap_delta_limit_corner_values())] heap_delta_initial_reserve: u64,
) {
    let round_summary = if next_checkpoint_round.is_none() || current_interval_length.is_none() {
        None
    } else {
        Some(ExecutionRoundSummary {
            next_checkpoint_round: next_checkpoint_round.unwrap().into(),
            current_interval_length: current_interval_length.unwrap().into(),
        })
    };

    let res = scheduled_heap_delta_limit(
        current_round.into(),
        round_summary.clone(),
        subnet_heap_delta_capacity.into(),
        heap_delta_initial_reserve.into(),
    )
    .get();

    // The result should never exceed the heap delta capacity.
    prop_assert!(res <= subnet_heap_delta_capacity);
    // The result should be at least the initial reserve, provided the reserve is below
    // the heap delta capacity.
    if heap_delta_initial_reserve <= subnet_heap_delta_capacity {
        prop_assert!(res >= heap_delta_initial_reserve);
    }

    // The result should be just the capacity if the round summary is not defined.
    if round_summary.is_none() {
        prop_assert!(res == subnet_heap_delta_capacity);
    }

    // Otherwise, the result should be scaled proportionally to the current round
    // (see the test below).
}

#[test]
fn scheduled_heap_delta_limit_scaling() {
    fn scheduled_limit(
        current_round: u64,
        next_checkpoint_round: u64,
        current_interval_length: u64,
        subnet_heap_delta_capacity: u64,
        heap_delta_initial_reserve: u64,
    ) -> u64 {
        let round_summary = ExecutionRoundSummary {
            next_checkpoint_round: next_checkpoint_round.into(),
            current_interval_length: current_interval_length.into(),
        };

        scheduled_heap_delta_limit(
            current_round.into(),
            Some(round_summary.clone()),
            subnet_heap_delta_capacity.into(),
            heap_delta_initial_reserve.into(),
        )
        .get()
    }

    // Scaling with no initial reserve.
    assert_eq!(0, scheduled_limit(0, 10, 9, 10, 0));
    assert_eq!(5, scheduled_limit(5, 10, 9, 10, 0));
    assert_eq!(10, scheduled_limit(10, 10, 9, 10, 0));
    assert_eq!(10, scheduled_limit(15, 10, 9, 10, 0));

    // Scaling with 50% initial reserve.
    assert_eq!(5, scheduled_limit(0, 10, 9, 10, 5));
    assert_eq!(8, scheduled_limit(5, 10, 9, 10, 5));
    assert_eq!(10, scheduled_limit(10, 10, 9, 10, 5));
    assert_eq!(10, scheduled_limit(15, 10, 9, 10, 5));

    // Scaling across checkpoints.
    assert_eq!(5, scheduled_limit(0, 10, 9, 10, 5));
    assert_eq!(8, scheduled_limit(5, 10, 9, 10, 5));
    assert_eq!(10, scheduled_limit(9, 10, 9, 10, 5));
    assert_eq!(5, scheduled_limit(10, 20, 9, 10, 5));
    assert_eq!(6, scheduled_limit(11, 20, 9, 10, 5));
    assert_eq!(8, scheduled_limit(15, 20, 9, 10, 5));

    // Scaling with invalid round summary (`next_checkpoint_round` is 5).
    assert_eq!(8, scheduled_limit(0, 5, 9, 10, 5));
    assert_eq!(10, scheduled_limit(5, 5, 9, 10, 5));
    assert_eq!(10, scheduled_limit(10, 5, 9, 10, 5));
    assert_eq!(10, scheduled_limit(15, 5, 9, 10, 5));

    // Scaling with invalid round summary (`next_checkpoint_round` is 50).
    assert_eq!(5, scheduled_limit(0, 50, 9, 10, 5));
    assert_eq!(5, scheduled_limit(5, 50, 9, 10, 5));
    assert_eq!(5, scheduled_limit(10, 50, 9, 10, 5));
    assert_eq!(5, scheduled_limit(15, 50, 9, 10, 5));
    // No scaling up until the `next_checkpoint_round` - `current_interval_length`.
    assert_eq!(5, scheduled_limit(40, 50, 9, 10, 5));
    assert_eq!(8, scheduled_limit(45, 50, 9, 10, 5));
    assert_eq!(10, scheduled_limit(50, 50, 9, 10, 5));
    assert_eq!(10, scheduled_limit(55, 50, 9, 10, 5));
}
