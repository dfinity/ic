//! Tests for canister scheduling.

use super::test_utilities::{
    SchedulerTest, SchedulerTestBuilder, ingress, instructions, on_response, other_side,
};
use super::*;
use assert_matches::assert_matches;
use ic_config::subnet_config::{SchedulerConfig, SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::testing::CanisterQueuesTesting;
use ic_types::ingress::IngressStatus;
use ic_types::methods::SystemMethod;
use ic_types::{ComputeAllocation, LongExecutionMode};
use ic_types_cycles::Cycles;
use more_asserts::{assert_ge, assert_le, assert_lt};
use std::cmp::min;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Range;

const M: usize = 1_000_000;
const B: usize = 1_000 * M;

#[test]
fn can_fully_execute_canisters_with_one_input_message_each() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let num_canisters = 3;
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        test.send_ingress(canister_id, ingress(5));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.queues().ingress_queue_size(), 0);
        assert!(test.was_fully_executed(canister.canister_id()));
        let execution_state = canister.execution_state.as_ref().unwrap();
        assert_eq!(execution_state.last_executed_round.get(), 1);
        let canister_metrics = canister.system_state.canister_metrics();
        assert_eq!(canister_metrics.rounds_scheduled(), 1);
        assert_eq!(canister_metrics.executed(), 1);
        assert_eq!(canister_metrics.interrupted_during_execution(), 0);
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

/// This test ensures that inner_loop() breaks out of the loop when the loop did
/// not consume any instructions.
#[test]
fn inner_loop_stops_when_no_instructions_consumed() {
    // Create a canister with 1 input message that consumes half of
    // max_instructions_per_round. This message is executed in the first
    // iteration of the loop and in the second iteration of the loop, no
    // instructions are consumed.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            ..zero_instruction_overhead_config()
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(50));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(test.ingress_queue_size(canister_id), 0);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.execute_round_called.get(), 1);
    assert_eq!(metrics.inner_round_loop_consumed_max_instructions.get(), 0);
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
        1
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

/// A test to ensure that there are multiple iterations of the loop in
/// inner_round().
#[test]
fn test_multiple_iterations_of_inner_loop() {
    // Create two canisters on the same subnet. In the first iteration, the
    // first sends a message to the second. In the second iteration, the second
    // executes the received message.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(200),
            max_instructions_per_message: NumInstructions::new(50),
            max_instructions_per_slice: NumInstructions::from(50),
            max_instructions_per_install_code_slice: NumInstructions::from(50),
            ..zero_instruction_overhead_config()
        })
        .build();

    let canister0 = test.create_canister();
    let canister1 = test.create_canister();

    let message = ingress(50).call(other_side(canister1, 50), on_response(50));
    test.send_ingress(canister0, message);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;

    assert_eq!(metrics.execute_round_called.get(), 1);
    assert_ge!(
        metrics.round_inner_iteration_fin_induct.get_sample_count(),
        3
    );
    assert_eq!(metrics.inner_round_loop_consumed_max_instructions.get(), 0);
    assert_eq!(
        metrics
            .inner_loop_consumed_non_zero_instructions_count
            .get(),
        3
    );

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        3
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
}

#[test]
fn execute_idle_and_canisters_with_messages() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::from(50),
            max_instructions_per_install_code_slice: NumInstructions::from(50),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let idle = test.create_canister();
    let active = test.create_canister();
    test.send_ingress(active, ingress(50));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // We update `last_full_execution_round` for the canister without any
    // input messages.
    assert!(test.was_fully_executed(idle));
    // But not its counts of rounds scheduled or executed.
    let idle = test.canister_state(idle);
    assert_eq!(idle.system_state.canister_metrics().rounds_scheduled(), 0);
    assert_eq!(idle.system_state.canister_metrics().executed(), 0);
    let execution_state = idle.execution_state.as_ref().unwrap();
    assert_eq!(execution_state.last_executed_round.get(), 0);

    assert!(test.was_fully_executed(active));
    let active = test.canister_state(active);
    assert_eq!(active.system_state.canister_metrics().rounds_scheduled(), 1);
    assert_eq!(active.system_state.canister_metrics().executed(), 1);
    assert_eq!(
        active
            .system_state
            .canister_metrics()
            .interrupted_during_execution(),
        0
    );
    let execution_state = active.execution_state.as_ref().unwrap();
    assert_eq!(execution_state.last_executed_round.get(), 1);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        1
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
}

#[test]
fn can_fully_execute_multiple_canisters_with_multiple_messages_each() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let num_canisters = 3;
    for _ in 0..num_canisters {
        let canister = test.create_canister();
        for _ in 0..5 {
            test.send_ingress(canister, ingress(50));
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister_state in test.state().canisters_iter() {
        let system_state = &canister_state.system_state;
        assert_eq!(system_state.queues().ingress_queue_size(), 0);
        assert!(test.was_fully_executed(canister_state.canister_id()));
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
        15
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );
}

#[test]
fn scheduler_long_execution_progress_across_checkpoints() {
    let scheduler_cores = 2;
    let slice_instructions = 2;
    let message_instructions = 40;

    let num_canisters = scheduler_cores;

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: slice_instructions.into(),
            max_instructions_per_message: message_instructions.into(),
            max_instructions_per_slice: slice_instructions.into(),
            max_instructions_per_install_code_slice: slice_instructions.into(),
            ..zero_instruction_overhead_config()
        })
        .build();

    let penalized_long_id = test.create_canister();
    let other_long_id = test.create_canister();
    let mut canister_ids = vec![];
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        canister_ids.push(canister_id);
    }

    // Penalize canister for a long execution.
    let message_id = test.send_ingress(penalized_long_id, ingress(message_instructions));
    assert_eq!(test.ingress_state(&message_id), IngressState::Received);
    for i in 0..message_instructions / slice_instructions {
        // Without short executions, all idle canister will be equally executed.
        if let Some(canister_id) = canister_ids.get(i as usize % num_canisters) {
            test.send_ingress(*canister_id, ingress(slice_instructions));
        }
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    assert_matches!(test.ingress_state(&message_id), IngressState::Failed(_));
    // Assert penalized canister accumulated priority is lower.
    let penalized = test.state().canister_priority(&penalized_long_id);
    let other = test.state().canister_priority(&other_long_id);
    assert_lt!(penalized.accumulated_priority, other.accumulated_priority);

    // Start another long execution on the penalized canister.
    test.send_ingress(penalized_long_id, ingress(message_instructions));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Assert the LEM is prioritized.
    let penalized = test.state().canister_priority(&penalized_long_id);
    assert_eq!(
        penalized.long_execution_mode,
        LongExecutionMode::Prioritized
    );

    // Start a long execution on another non-penalized canister.
    test.send_ingress(other_long_id, ingress(message_instructions));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Assert the LEM is opportunistic.
    let other = test.state().canister_priority(&other_long_id);
    assert_eq!(other.long_execution_mode, LongExecutionMode::Opportunistic);

    // Abort both canisters on checkpoint.
    test.execute_round(ExecutionRoundType::CheckpointRound);

    // Assert penalized canister accumulated priority is still lower.
    let penalized = test.state().canister_priority(&penalized_long_id);
    let other = test.state().canister_priority(&other_long_id);
    assert_lt!(penalized.accumulated_priority, other.accumulated_priority);

    let penalized = test.state().canister_state(&penalized_long_id).unwrap();
    let penalized_executed_before = penalized.system_state.canister_metrics().executed();

    // Send a bunch of messages.
    for canister_id in &canister_ids {
        test.send_ingress(*canister_id, ingress(slice_instructions));
    }

    // Assert that after the checkpoint the penalized canister continues its long execution.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let penalized = test.state().canister_state(&penalized_long_id).unwrap();
    assert_eq!(
        penalized_executed_before + 1,
        penalized.system_state.canister_metrics().executed()
    );
}

#[test]
fn execution_round_does_not_end_too_early() {
    // In this test we have 2 canisters with 10 input messages that execute 10
    // instructions each. There are two scheduler cores, so each canister gets
    // its own thread for running. With the round limit of 150 instructions and
    // each canister executing 100 instructions, we expect two messages to be
    // executed because the canisters are executing in parallel.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(150),
            max_instructions_per_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            ..zero_instruction_overhead_config()
        })
        .build();

    for _ in 0..2 {
        let canister = test.create_canister();
        test.send_ingress(canister, ingress(100));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;

    assert_eq!(
        1,
        metrics
            .round_inner_iteration
            .instructions
            .get_sample_count(),
    );
    assert_eq!(
        200,
        metrics.round_inner_iteration.instructions.get_sample_sum() as u64,
    );
}

// In the following tests we check that the order of the canisters
// inside `inner_round` is the same as the one provided by the scheduling strategy.
#[test]
fn scheduler_maintains_canister_order() {
    let ca = [6, 10, 9, 5, 0];

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            ..zero_instruction_overhead_config()
        })
        .build();

    let mut canisters = vec![];

    for (i, ca) in ca.iter().enumerate() {
        let id = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000_000),
            ComputeAllocation::try_from(*ca).unwrap(),
            MemoryAllocation::default(),
            None,
            None,
            None,
        );
        // The last canister does not have any messages.
        if i != 4 {
            test.send_ingress(id, ingress(1));
        }
        canisters.push(id);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let expected_per_thread = vec![
        vec![canisters[1], canisters[0]],
        vec![canisters[2], canisters[3]],
    ];
    // Build a map of Canister indexes
    let mut canister_indexes = BTreeMap::new();
    for (index, (_round, canister_id, _num_instructions)) in
        test.executed_schedule().into_iter().enumerate()
    {
        assert_eq!(canister_indexes.insert(canister_id, index), None);
    }
    // Assert that Canisters on each thread were scheduled after each other, i.e.
    // have increasing indexes
    for canister_ids in expected_per_thread {
        canister_ids.iter().fold(0, |prev_idx, canister_id| {
            assert_ge!(canister_indexes[canister_id], prev_idx);
            canister_indexes[canister_id]
        });
    }
}

// Returns the sum of messages of the input queues of all canisters.
fn get_available_messages(state: &ReplicatedState) -> u64 {
    state
        .canisters_iter()
        .map(|canister_state| canister_state.system_state.queues().ingress_queue_size() as u64)
        .sum()
}

fn construct_scheduler_for_prop_test(
    scheduler_cores: usize,
    mut canister_params: Vec<ComputeAllocation>,
    messages_per_canister: usize,
    instructions_per_round: usize,
    instructions_per_message: usize,
    heartbeat: bool,
) -> (
    SchedulerTest,
    usize,
    usize,
    NumInstructions,
    NumInstructions,
) {
    // Note: the DTS scheduler requires at least 2 scheduler cores
    assert_ge!(scheduler_cores, 2);
    let scheduler_config = SchedulerConfig {
        scheduler_cores,
        max_instructions_per_round: NumInstructions::from(instructions_per_round as u64),
        max_instructions_per_message: NumInstructions::from(instructions_per_message as u64),
        max_instructions_per_slice: NumInstructions::from(instructions_per_message as u64),
        max_instructions_per_install_code_slice: NumInstructions::from(
            instructions_per_message as u64,
        ),
        ..zero_instruction_overhead_config()
    };
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(scheduler_config)
        .build();

    // Ensure that compute allocation of canisters doesn't exceed the capacity.
    let capacity = RoundSchedule::compute_capacity_percent(scheduler_cores) as u64 - 1;
    let total = canister_params
        .iter()
        .fold(0, |acc, ca| acc + ca.as_percent());
    if total > capacity {
        canister_params = canister_params
            .into_iter()
            .map(|ca| {
                let ca = ((ca.as_percent() * capacity) / total).min(100);
                ComputeAllocation::try_from(ca).unwrap()
            })
            .collect();
    };

    for ca in canister_params.into_iter() {
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000_000),
            ca,
            MemoryAllocation::default(),
            if heartbeat {
                Some(SystemMethod::CanisterHeartbeat)
            } else {
                None
            },
            None,
            None,
        );
        for _ in 0..messages_per_canister {
            test.send_ingress(canister, ingress(instructions_per_message as u64));
        }
    }

    (
        test,
        scheduler_cores,
        messages_per_canister,
        NumInstructions::from(instructions_per_round as u64),
        NumInstructions::from(instructions_per_message as u64),
    )
}

prop_compose! {
    fn arb_scheduler_test(
        scheduler_cores: Range<usize>,
        canisters: Range<usize>,
        messages_per_canister: Range<usize>,
        instructions_per_round: Range<usize>,
        instructions_per_message: Range<usize>,
        heartbeat: bool,
    )
    (
        scheduler_cores in scheduler_cores,
        canister_params in prop::collection::vec(arb_canister_params(), canisters),
        messages_per_canister in messages_per_canister,
        instructions_per_round in instructions_per_round,
        instructions_per_message in instructions_per_message,
    ) -> (SchedulerTest, usize, usize, NumInstructions, NumInstructions) {
        construct_scheduler_for_prop_test(
            scheduler_cores,
            canister_params,
            messages_per_canister,
            instructions_per_round,
            instructions_per_message,
            heartbeat,
        )
    }
}

prop_compose! {
    fn arb_scheduler_test_double(
        scheduler_cores: Range<usize>,
        canisters: Range<usize>,
        messages_per_canister: Range<usize>,
        instructions_per_round: Range<usize>,
        instructions_per_message: Range<usize>,
        heartbeat: bool,
    )
    (
        scheduler_cores in scheduler_cores,
        canister_params in prop::collection::vec(arb_canister_params(), canisters),
        messages_per_canister in messages_per_canister,
        instructions_per_round in instructions_per_round,
        instructions_per_message in instructions_per_message,
    ) -> (SchedulerTest, SchedulerTest, usize, usize, NumInstructions, NumInstructions) {
        let r1 = construct_scheduler_for_prop_test(
            scheduler_cores,
            canister_params.clone(),
            messages_per_canister,
            instructions_per_round,
            instructions_per_message,
            heartbeat,
        );
        let r2 = construct_scheduler_for_prop_test(
            scheduler_cores,
            canister_params,
            messages_per_canister,
            instructions_per_round,
            instructions_per_message,
            heartbeat,
        );
        (r1.0, r2.0, r1.1, r1.2, r1.3, r2.4)
    }
}

prop_compose! {
    fn arb_canister_params()
    (
        a in -100_i16..120_i16,
    ) -> ComputeAllocation {
        // Clamp `a` to [0, 100], but with high probability for 0 and somewhat
        // higher probability for 100.
        let a = a.clamp(0, 100);
        ComputeAllocation::try_from(a as u64).unwrap()
    }
}

// In the following tests we use a notion of `minimum_executed_messages` per
// execution round. The minimum is defined as `min(available_messages,
// floor(`max_instructions_per_round` / `max_instructions_per_message`))`. `available_messages` are the sum of
// messages in the input queues of all canisters.

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
// This test verifies that the scheduler will never consume more than
// `max_instructions_per_round` in a single execution round per core.
fn should_never_consume_more_than_max_instructions_per_round_in_a_single_execution_round(
    #[strategy(arb_scheduler_test(2..10, 1..20, 1..100, M..B, 1..M,  false))] test: (
        SchedulerTest,
        usize,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (
        mut test,
        scheduler_cores,
        _messages_per_canister,
        instructions_per_round,
        instructions_per_message,
    ) = test;
    let available_messages = get_available_messages(test.state());
    let minimum_executed_messages = min(
        available_messages,
        instructions_per_round / instructions_per_message,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let mut executed = HashMap::new();
    for (round, _canister_id, instructions) in test.executed_schedule().into_iter() {
        let entry = executed.entry(round).or_insert(0);
        assert_le!(instructions, instructions_per_message);
        *entry += instructions.get();
    }
    for instructions in executed.values() {
        assert_le!(
            *instructions / scheduler_cores as u64,
            instructions_per_round.get(),
            "Executed more instructions than expected: {} <= {}",
            *instructions,
            instructions_per_round
        );
    }
    let total_executed_instructions: u64 = executed.into_values().sum();
    let total_executed_messages: u64 = total_executed_instructions / instructions_per_message.get();
    assert_le!(
        minimum_executed_messages,
        total_executed_messages,
        "Executed {total_executed_messages} messages but expected at least {minimum_executed_messages}.",
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
// This test verifies that the scheduler is deterministic, i.e. given
// the same input, if we execute a round of computation, we always
// get the same result.
fn scheduler_deterministically_produces_same_output_given_same_input(
    #[strategy(arb_scheduler_test_double(2..10, 1..20, 1..100, M..B, 1..M, false))] test: (
        SchedulerTest,
        SchedulerTest,
        usize,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (
        mut test1,
        mut test2,
        _cores,
        _messages_per_canister,
        _instructions_per_round,
        _instructions_per_message,
    ) = test;
    assert_eq!(test1.state(), test2.state());
    test1.execute_round(ExecutionRoundType::OrdinaryRound);
    test2.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test1.state(), test2.state());
}

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
// This test verifies that the scheduler can successfully deplete the induction
// pool given sufficient consecutive execution rounds.
fn scheduler_can_deplete_induction_pool_given_enough_execution_rounds(
    #[strategy(arb_scheduler_test(2..10, 1..20, 1..100, M..B, 1..M, false))] test: (
        SchedulerTest,
        usize,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (
        mut test,
        _scheduler_cores,
        _messages_per_canister,
        instructions_per_round,
        instructions_per_message,
    ) = test;
    let available_messages = get_available_messages(test.state());
    let minimum_executed_messages = min(
        available_messages,
        instructions_per_round / instructions_per_message,
    );
    let required_rounds = if minimum_executed_messages != 0 {
        available_messages / minimum_executed_messages + 1
    } else {
        1
    };
    for _ in 0..required_rounds {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }
    for canister_state in test.state().canisters_iter() {
        assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
    }
}

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
// This test verifies that the scheduler does not lose any canisters
// after an execution round.
fn scheduler_does_not_lose_canisters(
    #[strategy(arb_scheduler_test(2..3, 1..10, 1..100, M..B, 1..M, false))] test: (
        SchedulerTest,
        usize,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (
        mut test,
        _scheduler_cores,
        _messages_per_canister,
        _instructions_per_round,
        _instructions_per_message,
    ) = test;
    let canisters_before = test.state().canister_states().len();
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let canisters_after = test.state().canister_states().len();
    assert_eq!(canisters_before, canisters_after);
}

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
// Verifies that each canister is scheduled as the first of its thread as
// much as its compute_allocation requires.
fn scheduler_respects_compute_allocation(
    #[strategy(arb_scheduler_test(2..6, 1..10, 1..2, B..B+1, B..B+1, true))] test: (
        SchedulerTest,
        usize,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (
        mut test,
        scheduler_cores,
        _messages_per_canister,
        _instructions_per_round,
        _instructions_per_message,
    ) = test;
    let replicated_state = test.state();
    let number_of_canisters = replicated_state.canister_states().len();
    let total_compute_allocation = replicated_state.total_compute_allocation();
    prop_assert!(total_compute_allocation <= 100 * scheduler_cores as u64);

    // Count, for each canister, how many times it is the first canister
    // to be executed by a thread.
    let mut scheduled_first_counters = HashMap::<CanisterId, usize>::new();

    // Because we may be left with as little free compute capacity as 1, run for
    // enough rounds that every canister gets a chance to be scheduled at least once
    // for free, i.e. `100 * number_of_canisters` rounds.
    let number_of_rounds = 100 * number_of_canisters;

    let canister_ids: Vec<_> = test.state().canister_states().keys().cloned().collect();

    // Add one more round as we update the accumulated priorities at the end of the round now.
    for _ in 0..=number_of_rounds {
        for canister_id in canister_ids.iter() {
            test.expect_heartbeat(*canister_id, instructions(B as u64));
        }
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        for canister in canister_ids.iter() {
            if test.was_fully_executed(*canister) {
                *scheduled_first_counters.entry(*canister).or_insert(0) += 1;
            }
        }
    }

    // Check that the compute allocations of the canisters are respected.
    for (canister_id, canister) in test.state().canister_states().iter() {
        let compute_allocation = canister.compute_allocation().as_percent() as usize;

        let count = scheduled_first_counters.get(canister_id).unwrap_or(&0);

        // Due to `total_compute_allocation < 100 * scheduler_cores`, all canisters
        // except those with an allocation of 100 should have gotten scheduled for free
        // at least once.
        let expected_count = if compute_allocation == 100 {
            number_of_rounds
        } else {
            number_of_rounds / 100 * compute_allocation + 1
        };

        prop_assert!(
            *count >= expected_count,
            "Canister {} (allocation {}) should have been scheduled \
                    {} out of {} rounds, was scheduled only {} rounds instead.",
            canister_id,
            compute_allocation,
            expected_count,
            number_of_rounds,
            *count
        );
    }
}

#[test]
fn scheduler_resets_accumulated_priorities() {
    /// Create `scheduler_cores * 2` canisters with 2 messages each and execute 2 rounds.
    /// Return number of executed second ingress messages.
    fn executed_messages_after_two_rounds(scheduler_cores: usize, reset_interval: u64) -> usize {
        /// Count the number of executed ingress messages.
        fn executed_messages(test: &SchedulerTest, ingress_ids: &[MessageId]) -> usize {
            ingress_ids
                .iter()
                .filter_map(|ingress_id| match test.ingress_status(ingress_id) {
                    IngressStatus::Known {
                        // There is no response, so messages are in the failed state
                        state: IngressState::Failed(_),
                        ..
                    } => Some(()),
                    _ => None,
                })
                .count()
        }

        // There must twice more canisters than the scheduler cores
        let num_canisters = scheduler_cores * 2;

        let subnet_config = SubnetConfig::new(SubnetType::Application);
        let mut test = SchedulerTestBuilder::new()
            .with_scheduler_config(SchedulerConfig {
                scheduler_cores,
                // Increase the overhead to execute just one message per round per core
                instruction_overhead_per_execution: subnet_config
                    .scheduler_config
                    .max_instructions_per_round,
                // Reset accumulated priority every second round
                accumulated_priority_reset_interval: reset_interval.into(),
                ..subnet_config.scheduler_config
            })
            .build();

        // Create canisters with 2 messages each
        let mut canister_ids = Vec::with_capacity(num_canisters);
        let mut first_ingress_ids = Vec::with_capacity(num_canisters);
        let mut second_ingress_ids = Vec::with_capacity(num_canisters);
        for _ in 0..num_canisters {
            let canister_id = test.create_canister();
            canister_ids.push(canister_id);
            first_ingress_ids.push(test.send_ingress(canister_id, ingress(5)));
            second_ingress_ids.push(test.send_ingress(canister_id, ingress(5)));
        }

        // Execute the first round. Only first `scheduler_cores` messages
        // must be executed (marked as `E`):
        // Canister ID:        0 1 2 3 (scheduler_cores * 2)
        // 1st message states: E E . .
        // 2nd message states: . . . .
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        // After the first round, only the first `scheduler_cores` messages will be executed
        assert_eq!(
            scheduler_cores,
            executed_messages(&test, &first_ingress_ids)
        );
        assert_eq!(0, executed_messages(&test, &second_ingress_ids));

        // Execute the second round
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        // Return number of executed second ingress messages
        executed_messages(&test, &second_ingress_ids)
    }

    // Note: the DTS scheduler requires at least 2 scheduler cores
    let scheduler_cores = 2;

    // When there is no reset round, canisters with the same compute allocation
    // get scheduled fairly, one by one:
    //
    // 1. After the first round, some two canisters will be executed.
    // 2. After the second round, the other two canisters will be executed.
    //
    // After two rounds, all canisters will be executed once (marked as `E`):
    //
    //     Canister ID:        0 1 2 3 (scheduler_cores * 2)
    //     1st message states: E E E E
    //     2nd message states: . . . . <-- num_executed_second_messages == 0
    let num_executed_second_messages = executed_messages_after_two_rounds(scheduler_cores, 100);
    assert_eq!(0, num_executed_second_messages);

    // When the accumulated priorities get reset every round, accumulated priority
    // becomes irrelevant. Scheduler will be trying to execute every round
    // the same two canisters:
    //
    // 1. After the first round, some two canister will be executed.
    // 2. After the second round, the same two canisters will be executed.
    //
    // After two rounds, two canisters will be executed twice (marked as `E`):
    //
    //     Canister ID:        0 1 2 3 (scheduler_cores * 2)
    //     1st message states: E E . .
    //     2nd message states: E E . . <-- num_executed_second_messages == scheduler_cores
    let num_executed_second_messages = executed_messages_after_two_rounds(scheduler_cores, 1);
    assert_eq!(scheduler_cores, num_executed_second_messages);
}

#[test]
fn inner_round_first_execution_is_not_a_full_execution() {
    let scheduler_cores = 2;
    let instructions = 20;
    let max_messages_per_round = 3;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: (instructions * max_messages_per_round).into(),
            max_instructions_per_message: instructions.into(),
            max_instructions_per_slice: instructions.into(),
            max_instructions_per_install_code_slice: instructions.into(),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Bump up the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Create `scheduler_cores * 2` canisters, so target canister is not scheduled first.
    let mut canister_ids = vec![];
    for _ in 0..scheduler_cores * 2 {
        canister_ids.push(test.create_canister());
    }
    // Create target canister after.
    let target_id = test.create_canister();
    // Send messages to the target canister.
    for canister_id in &canister_ids {
        let message = ingress(instructions).call(
            other_side(target_id, instructions - 1),
            on_response(instructions - 2),
        );
        test.send_ingress(*canister_id, message);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister in test.state().canisters_iter() {
        let system_state = &canister.system_state;
        // All ingress messages should have been executed in the previous round.
        assert_eq!(system_state.queues().ingress_queue_size(), 0);
        assert_eq!(system_state.canister_metrics().executed(), 1);
        if canister.canister_id() == target_id {
            // The target canister, despite being executed first in the second inner round,
            // should not be marked as fully executed.
            assert_ne!(test.last_round(), 0.into());
            assert!(!test.was_fully_executed(canister.canister_id()));
        } else {
            assert!(test.was_fully_executed(canister.canister_id()));
        }
    }
    let mut total_accumulated_priority = 0;
    let mut total_priority_credit = 0;
    for (_, canister_priority) in test.state().metadata.subnet_schedule.iter() {
        total_accumulated_priority += canister_priority.accumulated_priority.get();
        total_priority_credit += canister_priority.priority_credit.get();
    }
    // The accumulated priority invariant should be respected.
    assert_eq!(total_accumulated_priority - total_priority_credit, 0);
}

#[test]
fn inner_round_long_execution_is_a_full_execution() {
    let scheduler_cores = 2;
    let slice = 20;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: (slice * 2).into(),
            max_instructions_per_message: (slice * 10).into(),
            max_instructions_per_slice: slice.into(),
            max_instructions_per_install_code_slice: slice.into(),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Bump up the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Create `scheduler_cores` canisters, so target canister is not scheduled first.
    let mut canister_ids = vec![];
    for _ in 0..scheduler_cores {
        let canister_id = test.create_canister();
        test.send_ingress(canister_id, ingress(slice));
        canister_ids.push(canister_id);
    }
    // Create a target canister with two long executions.
    let target_id = test.create_canister();
    test.send_ingress(target_id, ingress(slice * 2 + 1));
    test.send_ingress(target_id, ingress(slice * 2 + 1));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister in test.state().canisters_iter() {
        let system_state = &canister.system_state;
        let priority = test.state().canister_priority(&canister.canister_id());
        // All canisters should be executed.
        assert_eq!(system_state.canister_metrics().executed(), 1);
        let execution_state = canister.execution_state.as_ref().unwrap();
        assert_eq!(execution_state.last_executed_round.get(), 1);
        if canister.canister_id() == target_id {
            // The target canister was not executed first, and still have messages.
            assert_eq!(system_state.queues().ingress_queue_size(), 1);
        } else {
            assert_eq!(system_state.queues().ingress_queue_size(), 0);
        }
        // All canisters should be marked as fully executed. The target canister,
        // despite still having messages, executed a full slice of instructions.
        assert_eq!(priority.last_full_execution_round, test.last_round());
    }
    let mut total_accumulated_priority = 0;
    let mut total_priority_credit = 0;
    for (_, canister_priority) in test.state().metadata.subnet_schedule.iter() {
        total_accumulated_priority += canister_priority.accumulated_priority.get();
        total_priority_credit += canister_priority.priority_credit.get();
    }
    // The accumulated priority invariant should be respected.
    assert_eq!(total_accumulated_priority - total_priority_credit, 0);
}

#[test_strategy::proptest(ProptestConfig { cases: 8, ..ProptestConfig::default() })]
fn charge_canisters_for_full_execution(#[strategy(2..10_usize)] scheduler_cores: usize) {
    let instructions = 20;
    let messages_per_round = 2;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: (instructions * messages_per_round).into(),
            max_instructions_per_message: instructions.into(),
            max_instructions_per_slice: instructions.into(),
            max_instructions_per_install_code_slice: instructions.into(),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Bump up the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Create `messages_per_round * 2` canisters for each scheduler core.
    let num_canisters = scheduler_cores as u64 * messages_per_round * 2;
    let mut canister_ids = vec![];
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        // Send one messages per canister. Having `max_messages_per_round * 2` canisters,
        // only half of them will finish in one round.
        test.send_ingress(canister_id, ingress(instructions));
        canister_ids.push(canister_id);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for (i, canister) in test.state().canisters_iter().enumerate() {
        if i < num_canisters as usize / 2 {
            // The first half of the canisters should finish their messages.
            prop_assert_eq!(canister.system_state.queues().ingress_queue_size(), 0);
            prop_assert_eq!(canister.system_state.canister_metrics().executed(), 1);
            prop_assert!(test.was_fully_executed(canister.canister_id()));
        } else {
            // The second half of the canisters should still have their messages.
            prop_assert_eq!(canister.system_state.queues().ingress_queue_size(), 1);
            prop_assert_eq!(canister.system_state.canister_metrics().executed(), 0);
            prop_assert!(!test.was_fully_executed(canister.canister_id()));
        }
    }
    let mut total_accumulated_priority = 0;
    let mut total_priority_credit = 0;
    for (_, canister_priority) in test.state().metadata.subnet_schedule.iter() {
        total_accumulated_priority += canister_priority.accumulated_priority.get();
        total_priority_credit += canister_priority.priority_credit.get();
    }
    prop_assert_eq!(total_accumulated_priority - total_priority_credit, 0);

    // Send one more message for first half of the canisters.
    for (i, canister) in canister_ids.iter().enumerate() {
        if i < num_canisters as usize / 2 {
            test.send_ingress(*canister, ingress(instructions));
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for (i, canister) in test.state().canisters_iter().enumerate() {
        // Now all the canisters should be executed once.
        prop_assert_eq!(canister.system_state.canister_metrics().executed(), 1);
        let priority = test.state().canister_priority(&canister.canister_id());
        let execution_state = canister.execution_state.as_ref().unwrap();
        if i < num_canisters as usize / 2 {
            // The first half of the canisters should have messages.
            prop_assert_eq!(canister.system_state.queues().ingress_queue_size(), 1);
            // The first half of the canisters should be executed two rounds ago.
            prop_assert_eq!(
                priority.last_full_execution_round.get(),
                test.last_round().get() - 1
            );
            prop_assert_eq!(
                execution_state.last_executed_round.get(),
                test.last_round().get() - 1
            );
        } else {
            // The second half of the canisters should finish their messages.
            prop_assert_eq!(canister.system_state.queues().ingress_queue_size(), 0);
            // The second half of the canisters should be executed in the last round.
            prop_assert!(test.was_fully_executed(canister.canister_id()));
            prop_assert_eq!(
                execution_state.last_executed_round.get(),
                test.last_round().get()
            );
        }
    }
    let mut total_accumulated_priority = 0;
    let mut total_priority_credit = 0;
    for (_, canister_priority) in test.state().metadata.subnet_schedule.iter() {
        total_accumulated_priority += canister_priority.accumulated_priority.get();
        total_priority_credit += canister_priority.priority_credit.get();
    }
    prop_assert_eq!(total_accumulated_priority - total_priority_credit, 0);
}

#[test]
fn charge_idle_canisters_for_full_execution_round() {
    let scheduler_cores = 2;
    let num_rounds = 100;
    let slice = 20;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: slice.into(),
            max_instructions_per_message: slice.into(),
            max_instructions_per_slice: slice.into(),
            max_instructions_per_install_code_slice: slice.into(),
            ..zero_instruction_overhead_config()
        })
        .build();

    // Bump up the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Create many idle canisters.
    for _ in 0..scheduler_cores * 2 {
        test.create_canister();
    }

    // Create many busy canisters.
    for _ in 0..scheduler_cores * 2 {
        let canister_id = test.create_canister();
        for _ in 0..num_rounds {
            test.send_ingress(canister_id, ingress(slice));
        }
    }

    for round in 0..num_rounds {
        test.execute_round(ExecutionRoundType::OrdinaryRound);

        for canister in test.state().canisters_iter() {
            // Assert that we punished all idle canisters, not just top `scheduler_cores`.
            if round == 0 && !canister.has_input() {
                assert_ne!(test.last_round(), 0.into());
                assert_eq!(
                    test.state()
                        .canister_priority(&canister.canister_id())
                        .last_full_execution_round,
                    test.last_round()
                );
            }
        }
        let mut total_accumulated_priority = 0;
        let mut total_priority_credit = 0;
        for (_, canister_priority) in test.state().metadata.subnet_schedule.iter() {
            // Assert there is no divergency in accumulated priorities.
            let priority =
                canister_priority.accumulated_priority - canister_priority.priority_credit;
            assert_le!(priority.get(), 100 * MULTIPLIER);
            assert_ge!(priority.get(), -100 * MULTIPLIER);

            total_accumulated_priority += canister_priority.accumulated_priority.get();
            total_priority_credit += canister_priority.priority_credit.get();
        }
        // The accumulated priority invariant should be respected.
        assert_eq!(total_accumulated_priority - total_priority_credit, 0);
    }
}

/// Canisters with inputs but without enough cycles to execute them do get
/// categorized as "fully executed" when their inputs are consumed, even though
/// they didn't actually execute any message.
#[test]
fn frozen_canisters_are_fully_executed() {
    let scheduler_cores = 2;
    let canisters_per_core = 6;
    let slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: (2 * slice).into(),
            max_instructions_per_message: slice.into(),
            max_instructions_per_slice: slice.into(),
            max_instructions_per_install_code_slice: slice.into(),
            // Charge for every message execution enough to execute all but one canister on
            // each core. And to prevent a second iteration.
            instruction_overhead_per_execution: (slice / (canisters_per_core - 1) + 1).into(),
            instruction_overhead_per_canister: 0.into(),
            instruction_overhead_per_canister_for_finalization: 0.into(),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // `2 * canisters_per_core` low cycle balance canisters with inputs.
    let mut canisters = vec![];
    for _ in 0..2 * canisters_per_core {
        // Lots of instructions, as they won't be executed anyway.
        let frozen_canister_id = test.create_canister_with(
            Cycles::new(1),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            None,
            None,
            None,
        );
        test.send_ingress(frozen_canister_id, ingress(slice * 10));
        canisters.push(frozen_canister_id);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // All but 2 canisters were "executed".
    assert_eq!(
        test.scheduler()
            .metrics
            .instructions_consumed_per_message
            .get_sample_count(),
        (canisters_per_core - 1) * 2
    );

    let canister_priority = |canister_id: &CanisterId| -> &ic_replicated_state::CanisterPriority {
        test.state().canister_priority(canister_id)
    };
    for (i, canister) in canisters.iter().enumerate() {
        if (i as u64) < (canisters_per_core - 1) * 2 {
            assert!(
                test.was_fully_executed(*canister),
                "Canister {i} should have been fully executed",
            );
            assert!(
                canister_priority(canister).accumulated_priority.get() < 0,
                "Canister {i} should have been charged"
            );
        } else {
            assert!(
                !test.was_fully_executed(*canister),
                "Canister {i} should not have been executed",
            );
            assert!(
                canister_priority(canister).accumulated_priority.get() > 0,
                "Canister {i} should not have been charged"
            );
        }
    }
}

/// Canisters with heartbeats or timers but without enough cycles to execute them
/// do not get executed, but are charged as idle.
#[test]
fn frozen_canisters_with_heartbeats_or_timers_are_charged_as_idle() {
    let scheduler_cores = 2;
    let canisters_per_core = 2;
    let slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: slice.into(),
            max_instructions_per_message: slice.into(),
            max_instructions_per_slice: slice.into(),
            max_instructions_per_install_code_slice: slice.into(),
            // Set the message execution overhead high enough to ensure that if even one
            // heartbeat/timer were to be executed, it would exceed the round limit.
            instruction_overhead_per_execution: slice.into(),
            instruction_overhead_per_canister: 0.into(),
            instruction_overhead_per_canister_for_finalization: 0.into(),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // `canisters_per_core` pairs (we have 2 cores) of low cycle balance canisters:
    // one with a heartbeat, one with a timer.
    let mut canisters = vec![];
    for _ in 0..canisters_per_core {
        // Low balance canister with heartbeat.
        let heartbeat_canister_id = test.create_canister_with(
            Cycles::new(1_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            Some(SystemMethod::CanisterHeartbeat),
            None,
            None,
        );
        canisters.push(heartbeat_canister_id);

        // Low balance canister with timer.
        let timer_canister_id = test.create_canister_with(
            Cycles::new(1_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            Some(SystemMethod::CanisterGlobalTimer),
            None,
            None,
        );
        canisters.push(timer_canister_id);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // No canisters were executed.
    assert_eq!(
        test.scheduler()
            .metrics
            .instructions_consumed_per_message
            .get_sample_count(),
        0
    );

    // But all canisters were marked as fully executed, because they were idle.
    for (i, canister) in canisters.iter().enumerate() {
        assert!(
            test.was_fully_executed(*canister),
            "Canister {i} should have been charged as idle",
        );
    }
}
