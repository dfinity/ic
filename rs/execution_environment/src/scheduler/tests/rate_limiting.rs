//! Tests for heap delta and install code instruction rate limiting.

use super::super::test_utilities::{
    SchedulerTest, SchedulerTestBuilder, TestInstallCode, ingress, instructions, on_response,
    other_side,
};
use super::super::*;
use candid::Encode;
use ic_config::subnet_config::SchedulerConfig;
use ic_management_canister_types_private::{CanisterIdRecord, EmptyBlob, Method, Payload as _};
use ic_registry_subnet_type::SubnetType;
use ic_types::NumBytes;
use ic_types::messages::Payload;
use more_asserts::assert_ge;

const PAGE_SIZE: NumBytes = NumBytes::new(ic_sys::PAGE_SIZE as u64);

const M: usize = 1_000_000;
const B: usize = 1_000 * M;

#[test]
fn stops_executing_messages_when_heap_delta_capacity_reached() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 1);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
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

#[test]
fn restarts_executing_messages_after_checkpoint_when_heap_delta_capacity_reached() {
    fn rounds_skipped_metric(test: &SchedulerTest) -> u64 {
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get()
    }

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_ne!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);

    // Enqueue a message and execute a round. The round should be skipped due to
    // exceeding the heap delta capacity; and the message should still be enqueued.
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 1);
    assert_eq!(rounds_skipped_metric(&test), 1);
    assert_ne!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);

    // Execute a checkpoint round. The round should still be skipped, but the heap
    // delta estimate should be reset.
    test.execute_round(ExecutionRoundType::CheckpointRound);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(test.ingress_queue_size(canister_id), 1);
    assert_eq!(rounds_skipped_metric(&test), 2);

    // A new round execution should finally execute the message.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(rounds_skipped_metric(&test), 2);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        3
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn smooth_heap_delta_rate_limiting() {
    // Create scheduler test allowing one dirty page per round.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: PAGE_SIZE * 10,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            heap_delta_initial_reserve: NumBytes::from(1),
            ..SchedulerConfig::application_subnet()
        })
        .with_round_summary(ExecutionRoundSummary {
            next_checkpoint_round: 10.into(),
            current_interval_length: 9.into(),
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Both messages should be executed.
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The execution should be rate limited in this round.
    assert_eq!(test.ingress_queue_size(canister_id), 2);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get(),
        1
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The previous messages should be executed in this round.
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        4
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn smooth_heap_delta_rate_limiting_with_initial_burst() {
    fn rounds_skipped_metric(test: &SchedulerTest) -> u64 {
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get()
    }

    // Create scheduler test allowing one dirty page per round with 2 pages burst.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: PAGE_SIZE * 10,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            heap_delta_initial_reserve: PAGE_SIZE * 2,
            ..SchedulerConfig::application_subnet()
        })
        .with_round_summary(ExecutionRoundSummary {
            next_checkpoint_round: 10.into(),
            current_interval_length: 9.into(),
        })
        .build();

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Both messages should be executed.
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Thanks to the burst, the execution should be successful again.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(rounds_skipped_metric(&test), 0);

    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Now it should be rate limited
    assert_eq!(test.ingress_queue_size(canister_id), 2);
    assert_eq!(rounds_skipped_metric(&test), 1);

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The previous messages should be executed in this round.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(rounds_skipped_metric(&test), 1);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        6
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn smooth_heap_delta_rate_limiting_reaches_the_limit() {
    let rounds = 10;
    // Create scheduler test allowing two dirty page per round.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: PAGE_SIZE * rounds * 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_heap_delta_per_iteration: PAGE_SIZE,
            heap_delta_initial_reserve: 1.into(),
            ..SchedulerConfig::application_subnet()
        })
        .with_round_summary(ExecutionRoundSummary {
            next_checkpoint_round: rounds.into(),
            current_interval_length: (rounds - 1).into(),
        })
        .build();
    let canister_id = test.create_canister();

    // Each message dirties 4 pages, so only half of them should be executed
    for i in 0..rounds {
        test.send_ingress(canister_id, ingress(10).dirty_pages(4));
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        // The messages should be executed every second round.
        assert_eq!(
            test.state()
                .metadata
                .subnet_metrics
                .update_transactions_total,
            i / 2 + 1
        );
    }
    // Only half of the messages should be executed.
    assert_eq!(test.ingress_queue_size(canister_id), rounds as usize / 2);
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn smooth_heap_delta_rate_limiting_for_two_canisters() {
    // Create scheduler test allowing one dirty page per round.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: PAGE_SIZE * 10,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            heap_delta_initial_reserve: 1.into(),
            ..SchedulerConfig::application_subnet()
        })
        .with_round_summary(ExecutionRoundSummary {
            next_checkpoint_round: 10.into(),
            current_interval_length: 9.into(),
        })
        .build();

    let a_id = test.create_canister();
    let b_id = test.create_canister();
    test.send_ingress(a_id, ingress(10).dirty_pages(1));
    test.send_ingress(b_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // Both messages should be executed.
    assert_eq!(test.ingress_queue_size(a_id), 0);
    assert_eq!(test.ingress_queue_size(b_id), 0);

    test.send_ingress(a_id, ingress(10).dirty_pages(1));
    test.send_ingress(b_id, ingress(10).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The execution should be rate limited in this round for both canisters.
    assert_eq!(test.ingress_queue_size(a_id), 1);
    assert_eq!(test.ingress_queue_size(b_id), 1);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get(),
        1
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    // The previous messages should be executed in this round.
    assert_eq!(test.ingress_queue_size(a_id), 0);
    assert_eq!(test.ingress_queue_size(b_id), 0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        4
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn no_heap_delta_rate_limiting_for_system_subnet() {
    const GIB: usize = 1024 * 1024 * 1024;
    const PAGE_SIZE: usize = 4_096;
    const SUBNET_HEAP_DELTA_CAPACITY: usize = 140 * GIB;
    const DIRTY_2G_CHUNK: usize = 2 * GIB;

    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_round_summary(ExecutionRoundSummary {
            next_checkpoint_round: 200.into(),
            current_interval_length: 199.into(),
        })
        .build();

    let a_id = test.create_canister();
    // For 140GiB subnet heap delta capacity we should be able to iterate
    // `140 / 2 = 70` times.
    for _ in 0..SUBNET_HEAP_DELTA_CAPACITY / DIRTY_2G_CHUNK {
        test.send_ingress(a_id, ingress(10).dirty_pages(DIRTY_2G_CHUNK / PAGE_SIZE));
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        // Assert the message is executed
        assert_eq!(test.ingress_queue_size(a_id), 0);
        // Assert there is no rate limiting.
        assert_eq!(
            test.scheduler()
                .metrics
                .round_skipped_due_to_current_heap_delta_above_limit
                .get(),
            0
        );
    }
    // Once the subnet capacity is reached, there should be no further executions.
    test.send_ingress(a_id, ingress(10).dirty_pages(DIRTY_2G_CHUNK / PAGE_SIZE));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(a_id), 1);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get(),
        1
    );

    // Assert that we reached the subnet heap delta capacity (140 GiB) in 70 rounds.
    assert_ge!(
        test.scheduler().state_metrics.current_heap_delta(),
        SUBNET_HEAP_DELTA_CAPACITY
    );

    // After a checkpoint round, the message should be executed.
    test.execute_round(ExecutionRoundType::CheckpointRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(a_id), 0);
}

#[test]
fn canister_gets_heap_delta_rate_limited() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .with_rate_limiting_of_heap_delta()
        .build();
    let heap_delta_rate_limit = SchedulerConfig::application_subnet().heap_delta_rate_limit;

    // Execute a message that produces just under 3 rounds worth of heap delta.
    let canister_id = test.create_canister();
    test.send_ingress(
        canister_id,
        ingress(10).dirty_pages(3 * (heap_delta_rate_limit / PAGE_SIZE) as usize - 1),
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    // Current heap delta debit is over the limit, so the canister shouldn't run.
    test.send_ingress(canister_id, ingress(10));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 1);

    // After one more round of credits we should be below the limit and able to run.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        2
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

/// A bug in the first implementation of heap delta rate limiting would prevent
/// a canister which generates heap delta from running after the second
/// iteration, even if it was below the limit. This test verifies that a
/// canister generating small heap deltas can run in many iterations.
#[test]
fn canister_can_run_for_multiple_iterations() {
    // Create a canister which sends a message to itself on each iteration.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            // The number of instructions will limit the canister to running at most 6 times.
            max_instructions_per_round: NumInstructions::new(300),
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

    let canister = test.create_canister();

    let mut call = other_side(canister, 50).dirty_pages(1);
    for _ in 0..10 {
        call = other_side(canister, 50)
            .dirty_pages(1)
            .call(call, on_response(0));
    }

    test.send_ingress(canister, ingress(50).call(call, on_response(0)));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Verify that we actually ran 6 iterations.
    assert_eq!(
        test.scheduler()
            .metrics
            .inner_loop_consumed_non_zero_instructions_count
            .get(),
        6
    );

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        6
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn heap_delta_rate_limiting_metrics_recorded() {
    let scheduler_config = SchedulerConfig {
        scheduler_cores: 2,
        instruction_overhead_per_execution: NumInstructions::from(0),
        instruction_overhead_per_canister: NumInstructions::from(0),
        ..SchedulerConfig::application_subnet()
    };
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(scheduler_config.clone())
        .with_rate_limiting_of_heap_delta()
        .build();

    // One canister starts with a heap delta already above the limit, so it should
    // be rate limited throughout the round.
    let canister0 = test.create_canister();
    test.canister_state_mut(canister0)
        .scheduler_state
        .heap_delta_debit = scheduler_config.heap_delta_rate_limit;
    // Add it to the subnet schedule.
    test.state_mut().canister_priority_mut(canister0);
    test.send_ingress(canister0, ingress(1).dirty_pages(1));

    let canister1 = test.create_canister();
    test.send_ingress(canister1, ingress(1).dirty_pages(1));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.canister_heap_delta_debits.get_sample_count(), 2);
    assert_eq!(
        metrics.canister_heap_delta_debits.get_sample_sum() as u64,
        scheduler_config.heap_delta_rate_limit.get() + 4096
    );
    assert_eq!(
        metrics
            .heap_delta_rate_limited_canisters_per_round
            .get_sample_count(),
        1
    );
    assert_eq!(
        metrics
            .heap_delta_rate_limited_canisters_per_round
            .get_sample_sum() as u64,
        1
    );
}

#[test]
fn heap_delta_rate_limiting_disabled() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister0 = test.create_canister();
    test.send_ingress(canister0, ingress(1).dirty_pages(1));

    let canister1 = test.create_canister();
    test.send_ingress(canister1, ingress(1).dirty_pages(1));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.canister_heap_delta_debits.get_sample_count(), 2);
    assert_eq!(metrics.canister_heap_delta_debits.get_sample_sum(), 0.0);
    assert_eq!(
        metrics
            .heap_delta_rate_limited_canisters_per_round
            .get_sample_count(),
        1
    );
    assert_eq!(
        metrics
            .heap_delta_rate_limited_canisters_per_round
            .get_sample_sum() as u64,
        0
    );
}

#[test]
fn rate_limiting_of_install_code() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(5 * B as u64),
            max_instructions_per_slice: NumInstructions::from(5 * B as u64),
            max_instructions_per_install_code: NumInstructions::from(20 * B as u64),
            max_instructions_per_install_code_slice: NumInstructions::from(5 * B as u64),
            install_code_rate_limit: NumInstructions::from(2 * B as u64),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .with_rate_limiting_of_instructions()
        .build();

    let canister = test.create_canister();

    // First install code after uninstalling the existing code.
    // It consumes 10B instructions and rate limits the subsequent calls.
    let payload = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::UninstallCode,
        payload,
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    let install_code = TestInstallCode::Install {
        init: instructions(10 * B as u64),
    };
    test.inject_install_code_call_to_ic00(canister, install_code);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let responses = test.get_responses_to_injected_calls();
    assert_eq!(
        &responses[0].response_payload,
        &Payload::Data(EmptyBlob.encode())
    );
    assert_eq!(
        &responses[1].response_payload,
        &Payload::Data(EmptyBlob.encode())
    );

    // Try upgrading the canister. It should fail because the canister is rate
    // limited.
    let upgrade = TestInstallCode::Upgrade {
        post_upgrade: instructions(10 * B as u64),
    };
    test.inject_install_code_call_to_ic00(canister, upgrade);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let response = test.get_responses_to_injected_calls().pop().unwrap();
    match response.response_payload {
        Payload::Data(_) => unreachable!("Expected a reject response"),
        Payload::Reject(reject) => {
            assert!(
                reject
                    .message()
                    .contains("is rate limited because it executed too many instructions"),
                "{}",
                reject.message()
            );
        }
    };

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After the previous round the canister is no longer rate limited.
    // Upgrading should succeed now.
    let upgrade = TestInstallCode::Upgrade {
        post_upgrade: instructions(10 * B as u64),
    };
    test.inject_install_code_call_to_ic00(canister, upgrade);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let response = test.get_responses_to_injected_calls().pop().unwrap();
    assert_eq!(response.response_payload, Payload::Data(EmptyBlob.encode()));
}
