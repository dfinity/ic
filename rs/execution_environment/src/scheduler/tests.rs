use super::{
    test_utilities::{ingress, instructions, SchedulerTest, SchedulerTestBuilder, TestInstallCode},
    *,
};
#[cfg(test)]
use crate::scheduler::test_utilities::{on_response, other_side};
use candid::Encode;
use ic00::{
    CanisterHttpRequestArgs, HttpMethod, SignWithECDSAArgs, TransformContext, TransformFunc,
};
use ic_base_types::PrincipalId;
use ic_config::{
    execution_environment::STOP_CANISTER_TIMEOUT_DURATION,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types::{
    self as ic00, BoundedHttpHeaders, CanisterHttpResponsePayload, CanisterIdRecord,
    CanisterStatusType, DerivationPath, EcdsaCurve, EmptyBlob, Method, Payload as _,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::testing::{CanisterQueuesTesting, SystemStateTesting};
use ic_state_machine_tests::{PayloadBuilder, StateMachineBuilder};
use ic_test_utilities_metrics::{
    fetch_counter, fetch_gauge, fetch_gauge_vec, fetch_histogram_stats, fetch_int_gauge,
    fetch_int_gauge_vec, metric_vec, HistogramStats,
};
use ic_test_utilities_state::{get_running_canister, get_stopped_canister, get_stopping_canister};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::{
    batch::ConsensusResponse,
    messages::{
        CallbackId, CanisterMessageOrTask, CanisterTask, Payload, RejectContext,
        StopCanisterCallId, MAX_RESPONSE_COUNT_BYTES,
    },
    methods::SystemMethod,
    time::{expiry_time_from_now, UNIX_EPOCH},
    ComputeAllocation, Cycles, Height, NumBytes,
};
use ic_types_test_utils::ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use proptest::prelude::*;
use std::collections::HashMap;
use std::{cmp::min, ops::Range};
use std::{convert::TryFrom, time::Duration};

const M: usize = 1_000_000;
const B: usize = 1_000 * M;

fn assert_floats_are_equal(val0: f64, val1: f64) {
    if val0 > val1 {
        assert!(val0 - val1 < 0.1);
    } else {
        assert!(val1 - val0 < 0.1);
    }
}

#[test]
fn can_fully_execute_canisters_with_one_input_message_each() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_message_without_dts: NumInstructions::from(5),
            max_instructions_per_slice: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let num_canisters = 3;
    for _ in 0..num_canisters {
        let canister_id = test.create_canister();
        test.send_ingress(canister_id, ingress(5));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.queues().ingress_queue_size(), 0);
        assert_eq!(
            canister.scheduler_state.last_full_execution_round,
            test.last_round()
        );
        let canister_metrics = &canister.system_state.canister_metrics;
        assert_eq!(canister_metrics.skipped_round_due_to_no_messages, 0);
        assert_eq!(canister_metrics.executed, 1);
        assert_eq!(canister_metrics.interrupted_during_execution, 0);
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
fn stops_executing_messages_when_heap_delta_capacity_reached() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
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
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
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
    test.execute_round(ExecutionRoundType::CheckpointRound);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(test.ingress_queue_size(canister_id), 1);
    assert_eq!(
        test.scheduler()
            .metrics
            .round_skipped_due_to_current_heap_delta_above_limit
            .get(),
        1
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);
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
        3
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

#[test]
fn canister_gets_heap_delta_rate_limited() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .with_rate_limiting_of_heap_delta()
        .build();
    let heap_delta_rate_limit = SchedulerConfig::application_subnet().heap_delta_rate_limit;

    let canister_id = test.create_canister();
    test.send_ingress(canister_id, ingress(10).dirty_pages(1));
    test.canister_state_mut(canister_id)
        .scheduler_state
        .heap_delta_debit = heap_delta_rate_limit * 2 - NumBytes::from(1);

    // Current heap delta debit is over the limit, so the canister shouldn't run.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 1);

    // After getting a single round of credits we should be below the limit and able
    // to run.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test.ingress_queue_size(canister_id), 0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        1
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
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
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
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
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
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

#[test]
fn basic_induct_messages_on_same_subnet_works() {
    // Creates two canisters: caller and callee.
    // Sends three ingress messages to the caller, where each message calls the
    // callee and in the response callback makes another call to the callee.
    // Everything should be executed within a single round thanks to the
    // same-subnet message induction.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(1000),
            max_instructions_per_message: NumInstructions::new(55),
            max_instructions_per_message_without_dts: NumInstructions::from(55),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let caller = test.create_canister();
    let callee = test.create_canister();
    let message = ingress(50).call(
        other_side(callee, 50),
        on_response(50).call(other_side(callee, 50), on_response(50)),
    );
    test.send_ingress(caller, message.clone());
    test.send_ingress(caller, message.clone());
    test.send_ingress(caller, message);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // All messages should be executed in a single round.
    assert_eq!(test.ingress_queue_size(caller), 0);
    let number_of_messages = test
        .scheduler()
        .metrics
        .msg_execution_duration
        .get_sample_count();
    // Three ingress messages, six calls, six responses.
    assert_eq!(number_of_messages, 3 + 6 + 6);
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        3 + 6 + 6
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
}

#[test]
fn induct_messages_on_same_subnet_handles_foreign_subnet() {
    // Creates one canister. The canister performs a cross-net call. The
    // cross-net message should remain in the output queue of the caller and
    // should not be inducted.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(1000),
            max_instructions_per_message: NumInstructions::new(50),
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let caller = test.create_canister();
    let callee = test.xnet_canister_id();
    let message = ingress(50).call(other_side(callee, 50), on_response(50));
    test.send_ingress(caller, message);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert!(test.canister_state(caller).has_output());

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        1
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

/// Creates state with one canister. The canister has a message for itself.
/// in its output queue. Ensures that `induct_messages_on_same_subnet()`
/// moves the message.
#[test]
fn induct_messages_to_self_works() {
    // Sends three ingress messages to a canister, where each message calls the
    // same canister and in the response callback makes another self-call.
    // Everything should be executed within a single round thanks to the
    // same-subnet message induction.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::new(1000),
            max_instructions_per_message: NumInstructions::new(55),
            max_instructions_per_message_without_dts: NumInstructions::from(55),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_id = test.create_canister();
    let message = ingress(50).call(
        other_side(canister_id, 50),
        on_response(50).call(other_side(canister_id, 50), on_response(50)),
    );
    test.send_ingress(canister_id, message.clone());
    test.send_ingress(canister_id, message.clone());
    test.send_ingress(canister_id, message);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // All messages should be executed in a single round.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    let number_of_messages = test
        .scheduler()
        .metrics
        .msg_execution_duration
        .get_sample_count();
    // Three ingress messages, six calls, six responses.
    assert_eq!(number_of_messages, 3 + 6 + 6);
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        3 + 6 + 6
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 1);
}

/// Creates state with two canisters. Source canister has two requests for
/// itself and two requests for destination canister in its output queues.
/// Subnet only has enough message memory for two requests.
///
/// Ensures that `induct_messages_on_same_subnet()` respects memory limits
/// on application subnets and ignores them on system subnets.
#[test]
fn induct_messages_on_same_subnet_respects_memory_limits() {
    // Runs a test with the given `available_memory` (expected to be limited to 2
    // requests plus epsilon). Checks that the limit is enforced on application
    // subnets and ignored on system subnets.
    let run_test = |subnet_available_memory: SubnetAvailableMemory, subnet_type| {
        let mut test = SchedulerTestBuilder::new()
            .with_scheduler_config(SchedulerConfig {
                scheduler_cores: 2,
                max_instructions_per_round: NumInstructions::new(1),
                max_instructions_per_message: NumInstructions::new(1),
                max_instructions_per_message_without_dts: NumInstructions::from(1),
                max_instructions_per_slice: NumInstructions::new(1),
                instruction_overhead_per_message: NumInstructions::from(0),
                instruction_overhead_per_canister: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            })
            .with_subnet_message_memory(subnet_available_memory.get_message_memory() as u64)
            .with_subnet_type(subnet_type)
            .build();

        let source = test.create_canister();
        let dest = test.create_canister();

        let source_canister = test.canister_state_mut(source);
        let self_request = RequestBuilder::default()
            .sender(source)
            .receiver(source)
            .build();
        source_canister
            .push_output_request(self_request.clone().into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(self_request.into(), UNIX_EPOCH)
            .unwrap();
        let other_request = RequestBuilder::default()
            .sender(source)
            .receiver(dest)
            .build();
        source_canister
            .push_output_request(other_request.clone().into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(other_request.into(), UNIX_EPOCH)
            .unwrap();
        test.induct_messages_on_same_subnet();

        let source_canister = test.canister_state(source);
        let dest_canister = test.canister_state(dest);
        let source_canister_queues = source_canister.system_state.queues();
        let dest_canister_queues = dest_canister.system_state.queues();
        if subnet_type == SubnetType::Application {
            // Only two messages should have been inducted. After two self-inductions on the
            // source canister, the subnet message memory is exhausted.
            assert_eq!(1, source_canister_queues.output_message_count());
            assert_eq!(2, source_canister_queues.input_queues_message_count());
            assert_eq!(1, dest_canister_queues.input_queues_message_count());
        } else {
            // On a system subnet, with no message memory limits, all messages should have
            // been inducted.
            assert_eq!(0, source_canister_queues.output_message_count());
            assert_eq!(2, source_canister_queues.input_queues_message_count());
            assert_eq!(2, dest_canister_queues.input_queues_message_count());
        }
    };

    // Subnet has memory for 4 initial requests and 2 additional requests (plus
    // epsilon, for small responses).
    run_test(
        SubnetAvailableMemory::new(0, MAX_RESPONSE_COUNT_BYTES as i64 * 75 / 10, 0),
        SubnetType::Application,
    );

    // On system subnets limits will not be enforced for local messages, so running with 0 available
    // memory should also lead to inducting messages on local subnet.
    run_test(SubnetAvailableMemory::new(0, 0, 0), SubnetType::System);
}

/// Verifies that the [`SchedulerConfig::instruction_overhead_per_message`] puts
/// a limit on the number of update messages that will be executed in a single
/// round.
#[test]
fn test_message_limit_from_message_overhead() {
    // Create two canisters on the same subnet. When each one receives a
    // message, it sends a message to the other so that they ping-pong forever.
    let scheduler_config = SchedulerConfig {
        scheduler_cores: 2,
        max_instructions_per_message: NumInstructions::from(5_000_000_000),
        max_instructions_per_message_without_dts: NumInstructions::from(5_000_000_000),
        max_instructions_per_slice: NumInstructions::from(5_000_000_000),
        max_instructions_per_round: NumInstructions::from(7_000_000_000),
        instruction_overhead_per_message: NumInstructions::from(2_000_000),
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
        / scheduler_config.instruction_overhead_per_message
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

    let number_of_messages = test
        .scheduler()
        .metrics
        .msg_execution_duration
        .get_sample_count();
    assert_eq!(number_of_messages, expected_number_of_messages);
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        expected_number_of_messages
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 2);
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
            max_instructions_per_message_without_dts: NumInstructions::new(50),
            max_instructions_per_slice: NumInstructions::from(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister0 = test.create_canister();
    let canister1 = test.create_canister();

    let message = ingress(50).call(other_side(canister1, 50), on_response(50));
    test.send_ingress(canister0, message);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;

    assert_eq!(metrics.execute_round_called.get(), 1);
    assert!(metrics.round_inner_iteration_fin_induct.get_sample_count() >= 3);
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
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
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
fn validate_consumed_instructions_metric() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_round: NumInstructions::from(400),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();
    test.send_ingress(canister, ingress(50).dirty_pages(1));
    test.send_ingress(canister, ingress(50).dirty_pages(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;

    assert_eq!(
        metrics.instructions_consumed_per_round.get_sample_count(),
        2
    );
    assert_floats_are_equal(
        metrics.instructions_consumed_per_round.get_sample_sum(),
        100_f64,
    );
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        2
    );
    assert_floats_are_equal(
        metrics.instructions_consumed_per_message.get_sample_sum(),
        100_f64,
    );
}

#[test]
fn only_charge_for_allocation_after_specified_duration() {
    let mut test = SchedulerTestBuilder::new().build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    let time_between_batches = test
        .scheduler()
        .cycles_account_manager
        .duration_between_allocation_charges()
        / 2;

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

    let canister = test.create_canister_with(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::Reserved(NumBytes::from(bytes_per_cycle)),
        None,
        Some(initial_time),
        None,
    );

    // Don't charge because the time since the last charge is too small.
    test.set_time(initial_time + time_between_batches);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(
        test.canister_state(canister).system_state.balance().get(),
        initial_cycles
    );

    // The time of the current batch is now long enough that allocation charging
    // should be triggered.
    test.set_time(initial_time + 2 * time_between_batches);
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.canister_state(canister).system_state.balance().get(),
        initial_cycles - 10,
    );
}

#[test]
fn charging_for_message_memory_works() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::from(1),
            max_instructions_per_slice: NumInstructions::new(1),
            max_instructions_per_round: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Charging handles time=0 as a special case, so it should be set to some
    // non-zero time.
    let initial_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    test.set_time(initial_time);

    let initial_cycles = 1_000_000_000_000;
    let canister = test.create_canister_with(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        None,
        Some(initial_time),
        None,
    );

    // Send an ingress that triggers an inter-canister call. Because of the scheduler
    // configuration, we can only execute the ingress message but not the
    // inter-canister message so this remain in the canister's input queue.
    test.send_ingress(
        canister,
        ingress(1).call(other_side(canister, 1), on_response(1)),
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let balance_before = test.canister_state(canister).system_state.balance();

    // Set time to at least one interval between charges to trigger a charge
    // because of message memory consumption.
    let charge_duration = test
        .scheduler()
        .cycles_account_manager
        .duration_between_allocation_charges();
    test.set_time(initial_time + charge_duration);
    test.charge_for_resource_allocations();

    // The balance of the canister should have been reduced by the cost of
    // message memory during the charge period.
    assert_eq!(
        test.canister_state(canister).system_state.balance(),
        balance_before
            - test.memory_cost(
                test.canister_state(canister).message_memory_usage(),
                charge_duration,
            ),
    );
}

#[test]
fn dont_execute_any_canisters_if_not_enough_instructions_in_round() {
    let instructions_per_message = NumInstructions::from(5);
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: instructions_per_message - NumInstructions::from(1),
            max_instructions_per_message: instructions_per_message,
            max_instructions_per_message_without_dts: instructions_per_message,
            max_instructions_per_slice: instructions_per_message,
            instruction_overhead_per_message: NumInstructions::from(0),
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
            canister_state.scheduler_state.last_full_execution_round,
            ExecutionRound::from(0)
        );
        assert_eq!(
            system_state
                .canister_metrics
                .skipped_round_due_to_no_messages,
            0
        );
        assert_eq!(system_state.canister_metrics.executed, 0);
        assert_eq!(
            system_state.canister_metrics.interrupted_during_execution,
            0
        );
    }
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
            MemoryAllocation::Reserved(NumBytes::from(1 << 30)),
            None,
            Some(initial_time),
            None,
        );
    }
    test.set_time(
        initial_time
            + test
                .scheduler()
                .cycles_account_manager
                .duration_between_allocation_charges(),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for (_, canister) in test.state().canister_states.iter() {
        assert!(canister.execution_state.is_none());
        assert_eq!(
            canister.scheduler_state.compute_allocation,
            ComputeAllocation::zero()
        );
        assert_eq!(
            canister.system_state.memory_allocation,
            MemoryAllocation::BestEffort
        );
        assert_eq!(canister.system_state.canister_version, 1);
    }
    assert_eq!(
        test.scheduler()
            .metrics
            .num_canisters_uninstalled_out_of_cycles
            .get(),
        3
    );
}

#[test]
fn dont_charge_allocations_for_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new().build();
    let initial_time = UNIX_EPOCH + Duration::from_secs(1);
    let initial_cycles = 10_000_000;

    let canister = test.create_canister_with(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::Reserved(NumBytes::from(1 << 30)),
        None,
        Some(initial_time),
        None,
    );
    let paused_canister = test.create_canister_with(
        Cycles::new(initial_cycles),
        ComputeAllocation::zero(),
        MemoryAllocation::Reserved(NumBytes::from(1 << 30)),
        None,
        Some(initial_time),
        None,
    );
    test.canister_state_mut(paused_canister)
        .system_state
        .task_queue
        .push_front(ExecutionTask::PausedExecution {
            id: PausedExecutionId(0),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });

    assert!(test.canister_state(paused_canister).has_paused_execution());
    assert!(!test.canister_state(canister).has_paused_execution());

    let paused_canister_balance_before =
        test.canister_state(paused_canister).system_state.balance();
    let canister_balance_before = test.canister_state(canister).system_state.balance();

    let duration_between_allocation_charges = test
        .scheduler()
        .cycles_account_manager
        .duration_between_allocation_charges();
    test.set_time(initial_time + duration_between_allocation_charges);

    test.charge_for_resource_allocations();
    // Balance has not changed for canister that has long running execution.
    assert_eq!(
        test.canister_state(paused_canister).system_state.balance(),
        paused_canister_balance_before
    );
    // Balance has changed for this canister.
    assert_eq!(
        test.canister_state(canister).system_state.balance(),
        canister_balance_before
            - test.memory_cost(NumBytes::from(1 << 30), duration_between_allocation_charges)
    );
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
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::from(50),
            instruction_overhead_per_message: NumInstructions::from(0),
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
            canister_state.scheduler_state.last_full_execution_round,
            ExecutionRound::from(1)
        );
        assert_eq!(
            system_state
                .canister_metrics
                .skipped_round_due_to_no_messages,
            0
        );
        assert_eq!(system_state.canister_metrics.executed, 1);
        assert_eq!(
            system_state.canister_metrics.interrupted_during_execution,
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
fn execute_only_canisters_with_messages() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_message_without_dts: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::from(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let idle = test.create_canister();
    let active = test.create_canister();
    test.send_ingress(active, ingress(50));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // We won't update `last_full_execution_round` for the canister without any
    // input messages.
    let idle = test.canister_state(idle);
    assert_eq!(
        idle.scheduler_state.last_full_execution_round,
        ExecutionRound::from(0)
    );
    assert_eq!(
        idle.system_state
            .canister_metrics
            .skipped_round_due_to_no_messages,
        1
    );

    let active = test.canister_state(active);
    let system_state = &active.system_state;
    assert_eq!(
        active.scheduler_state.last_full_execution_round,
        ExecutionRound::from(1)
    );
    assert_eq!(
        system_state
            .canister_metrics
            .skipped_round_due_to_no_messages,
        0
    );
    assert_eq!(active.system_state.canister_metrics.executed, 1);
    assert_eq!(
        system_state.canister_metrics.interrupted_during_execution,
        0
    );

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
        assert_eq!(
            canister_state.scheduler_state.last_full_execution_round,
            ExecutionRound::new(1)
        );
        assert_eq!(
            system_state
                .canister_metrics
                .skipped_round_due_to_no_messages,
            0
        );
        assert_eq!(system_state.canister_metrics.executed, 1);
        assert_eq!(
            system_state.canister_metrics.interrupted_during_execution,
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
fn max_canisters_per_round() {
    // In this test we have 20 canisters with one input messages each. Each
    // message uses 10 instructions. The canister overhead is also 10
    // instructions. The round limit is 100 instructions. We expect that 5
    // canisters to execute per scheduler core.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(10),
            max_instructions_per_message_without_dts: NumInstructions::from(10),
            max_instructions_per_slice: NumInstructions::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(10),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // Bump up the round number to 1.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    for _ in 0..200 {
        let canister = test.create_canister();
        test.send_ingress(canister, ingress(10));
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let mut executed_canisters = 0;
    for canister in test.state().canisters_iter() {
        if canister.system_state.queues().ingress_queue_size() == 0 {
            executed_canisters += 1;
        }
    }
    assert_eq!(executed_canisters, 10);
}

#[test]
fn can_fully_execute_canisters_deterministically_until_out_of_cycles() {
    // In this test we have 5 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 51 (per core). Each
    // message consumes 5 instructions, therefore we can execute fully 1
    // canister per core in one round.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_message_without_dts: NumInstructions::from(5),
            max_instructions_per_slice: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
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
        if canister.system_state.queues().ingress_queue_size() == 0 {
            assert_eq!(
                canister.scheduler_state.last_full_execution_round,
                ExecutionRound::from(1)
            );
            executed_canisters += 1;
        } else {
            assert_eq!(canister.system_state.queues().ingress_queue_size(), 10);
            assert_eq!(
                canister.scheduler_state.last_full_execution_round,
                ExecutionRound::from(0)
            );
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
            max_instructions_per_message_without_dts: NumInstructions::from(5),
            max_instructions_per_slice: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
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
                .canister_metrics
                .interrupted_during_execution,
            0
        );
        assert_eq!(
            canister.scheduler_state.last_full_execution_round,
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
            max_instructions_per_message_without_dts: NumInstructions::new(10),
            max_instructions_per_slice: NumInstructions::new(10),
            max_instructions_per_install_code: NumInstructions::new(10),
            max_instructions_per_install_code_slice: NumInstructions::new(10),
            instruction_overhead_per_message: NumInstructions::from(0),
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
        MemoryAllocation::BestEffort,
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
        MemoryAllocation::BestEffort,
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
        MemoryAllocation::BestEffort,
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
        MemoryAllocation::BestEffort,
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
        MemoryAllocation::BestEffort,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        Some(CanisterStatusType::Stopped),
    );

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
}

#[test]
fn global_timer_is_not_scheduled_if_the_canister_is_stopped() {
    let mut test = SchedulerTestBuilder::new().build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        Some(SystemMethod::CanisterGlobalTimer),
        None,
        Some(CanisterStatusType::Stopped),
    );
    test.set_canister_global_timer(canister, Time::from_nanos_since_unix_epoch(1));
    test.set_time(Time::from_nanos_since_unix_epoch(1));

    test.send_ingress(canister, ingress(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let metrics = &test.scheduler().metrics;
    assert_eq!(metrics.round_inner.messages.get_sample_sum(), 1.0);
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
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::new(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
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
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::new(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();
    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
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
fn test_drain_subnet_messages_with_some_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();

    let mut local_canisters = vec![];
    let mut remote_canisters = vec![];
    let add_messages = |test: &mut SchedulerTest, canisters: &mut Vec<CanisterId>| {
        for _ in 0..2 {
            let canister = test.create_canister_with(
                Cycles::new(1_000_000_000_000),
                ComputeAllocation::zero(),
                MemoryAllocation::BestEffort,
                None,
                None,
                None,
            );
            canisters.push(canister);
        }
    };
    add_messages(&mut test, &mut local_canisters);
    add_messages(&mut test, &mut remote_canisters);

    // Add 3 local subnet input messages.
    // Canister `local_canisters[1]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(local_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StartCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );

    let arg2 = Encode!(&CanisterIdRecord::from(local_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(11),
        InputQueueType::LocalSubnet,
    );

    // Add 2 remote subnet input messages.
    // Canister `remote_canisters[0]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(remote_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(12),
        InputQueueType::RemoteSubnet,
    );
    let arg2 = Encode!(&CanisterIdRecord::from(remote_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(13),
        InputQueueType::RemoteSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 6);

    let long_running_canister_ids: BTreeSet<CanisterId> =
        BTreeSet::from([local_canisters[1], remote_canisters[0]]);
    let new_state = test.drain_subnet_messages(long_running_canister_ids);
    // Left messages that were not able to be executed due to other long running messages
    // belong to `local_canisters[1]` and `remote_canisters[0]` canisters.
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 2);
}

#[test]
fn test_drain_subnet_messages_no_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();

    let add_messages = |test: &mut SchedulerTest, input_type: InputQueueType| {
        for id in 0..2 {
            let local_canister = test.create_canister_with(
                Cycles::new(1_000_000_000_000),
                ComputeAllocation::zero(),
                MemoryAllocation::BestEffort,
                None,
                None,
                None,
            );
            let arg = Encode!(&CanisterIdRecord::from(local_canister)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(id),
                input_type,
            );
        }
    };
    add_messages(&mut test, InputQueueType::LocalSubnet);
    add_messages(&mut test, InputQueueType::RemoteSubnet);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let long_running_canister_ids: BTreeSet<CanisterId> = BTreeSet::new();
    let new_state = test.drain_subnet_messages(long_running_canister_ids);
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
}

#[test]
fn test_drain_subnet_messages_all_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();

    let mut long_running_canister_ids: BTreeSet<CanisterId> = BTreeSet::new();
    let add_messages = |test: &mut SchedulerTest,
                        long_running_canister_ids: &mut BTreeSet<CanisterId>,
                        input_type: InputQueueType| {
        for i in 0..2 {
            let local_canister = test.create_canister_with(
                Cycles::new(1_000_000_000_000),
                ComputeAllocation::zero(),
                MemoryAllocation::BestEffort,
                None,
                None,
                None,
            );
            let arg = Encode!(&CanisterIdRecord::from(local_canister)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(i),
                input_type,
            );
            long_running_canister_ids.insert(local_canister);
        }
    };
    add_messages(
        &mut test,
        &mut long_running_canister_ids,
        InputQueueType::LocalSubnet,
    );
    add_messages(
        &mut test,
        &mut long_running_canister_ids,
        InputQueueType::RemoteSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let new_state = test.drain_subnet_messages(long_running_canister_ids);
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 4);
}

#[test]
fn scheduler_executes_postponed_raw_rand_requests() {
    let canister_id = canister_test_id(2);
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();
    test.advance_to_round(ExecutionRound::new(2));
    let last_round = test.last_round();

    // Inject fake request to be able to create a response.
    let canister = get_running_canister(canister_id);
    test.inject_call_to_ic00(
        Method::RawRand,
        EmptyBlob.encode(),
        Cycles::new(0),
        canister_id,
        InputQueueType::LocalSubnet,
    );
    let state = test.state_mut();
    state.put_canister_state(canister);
    state.pop_subnet_input();
    state
        .metadata
        .subnet_call_context_manager
        .push_raw_rand_request(
            RequestBuilder::new().sender(canister_id).build(),
            last_round,
            UNIX_EPOCH,
        );
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    // Execute the postponed `raw_rand` messages.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );

    assert_eq!(
        fetch_histogram_stats(
            test.metrics_registry(),
            "execution_round_postponed_raw_rand_queue_messages",
        ),
        Some(HistogramStats { sum: 1.0, count: 1 })
    );

    assert_eq!(
        fetch_histogram_stats(
            test.metrics_registry(),
            "execution_round_postponed_raw_rand_queue_instructions",
        ),
        Some(HistogramStats { sum: 0.0, count: 1 })
    );
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
            max_instructions_per_message_without_dts: NumInstructions::new(100),
            max_instructions_per_slice: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();
    let number_of_canisters: usize = 3;
    let number_of_messages_per_canister: usize = 4;
    let number_of_rounds: usize = 2;
    for _ in 0..number_of_canisters {
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000),
            ComputeAllocation::zero(),
            MemoryAllocation::BestEffort,
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
// This test verifies that we can successfully record metrics from a single
// scheduler thread. We feed the `thread` with a single canister which has 3
// ingress messages. The first one runs out of instructions while the other two
// are executed successfully.
fn can_record_metrics_single_scheduler_thread() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_message_without_dts: NumInstructions::new(5),
            max_instructions_per_slice: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister();

    test.send_ingress(canister, ingress(6));
    test.send_ingress(canister, ingress(4));
    test.send_ingress(canister, ingress(4));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        3
    );
    assert_eq!(
        metrics.instructions_consumed_per_round.get_sample_count(),
        1
    );
    assert_eq!(
        metrics.instructions_consumed_per_round.get_sample_sum() as i64,
        5 + 4 + 4
    );
    assert_eq!(metrics.canister_messages_where_cycles_were_charged.get(), 3);
}

#[test]
fn can_record_metrics_for_a_round() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(25),
            max_instructions_per_message: NumInstructions::from(5),
            max_instructions_per_message_without_dts: NumInstructions::new(5),
            max_instructions_per_slice: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let num_canisters = 3;
    // The first two canisters have an `Allocation` of 45% and the last 9%. We'll be
    // forced to execute the first two and then run out of instructions (based on
    // the limits) which will result in a violation of third canister's
    // `Allocation`.
    for i in 0..num_canisters {
        let compute_allocation = if i < 2 { 45 } else { 9 };
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000),
            ComputeAllocation::try_from(compute_allocation).unwrap(),
            MemoryAllocation::BestEffort,
            None,
            None,
            None,
        );
        for _ in 0..5 {
            test.send_ingress(canister, ingress(5));
        }
    }

    // For allocation violation to happen, the canister age should be more than `100/9 = 11 rounds`
    test.advance_to_round(ExecutionRound::from(12));

    for canister in test.state_mut().canister_states.values_mut() {
        canister.scheduler_state.time_of_last_allocation_charge =
            UNIX_EPOCH + Duration::from_secs(1);
    }
    test.state_mut().metadata.batch_time = UNIX_EPOCH
        + Duration::from_secs(1)
        + test
            .scheduler()
            .cycles_account_manager
            .duration_between_allocation_charges();
    test.set_time(
        UNIX_EPOCH
            + Duration::from_secs(1)
            + test
                .scheduler()
                .cycles_account_manager
                .duration_between_allocation_charges(),
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(
        metrics.executable_canisters_per_round.get_sample_sum() as i64,
        3
    );
    assert_eq!(metrics.canister_age.get_sample_sum() as i64, 12);
    assert_eq!(metrics.round_preparation_duration.get_sample_count(), 1);
    assert_eq!(metrics.round_preparation_ingress.get_sample_count(), 1);
    assert_eq!(metrics.round_scheduling_duration.get_sample_count(), 1);
    assert_eq!(metrics.round_scheduling_duration.get_sample_count(), 1);
    assert!(metrics.round_inner_iteration_prep.get_sample_count() >= 1);
    assert!(metrics.round_inner_iteration_exe.get_sample_count() >= 1);
    assert!(metrics.round_inner_iteration_fin.get_sample_count() >= 1);
    assert_eq!(metrics.round_finalization_duration.get_sample_count(), 1);
    assert_eq!(
        metrics.round_finalization_stop_canisters.get_sample_count(),
        1
    );
    assert_eq!(metrics.round_finalization_ingress.get_sample_count(), 1);
    assert_eq!(metrics.round_finalization_charge.get_sample_count(), 1);
    assert_eq!(metrics.canister_compute_allocation_violation.get(), 1);
    assert_eq!(
        metrics.canister_messages_where_cycles_were_charged.get(),
        10
    );

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        10
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );
}

#[test]
fn heap_delta_rate_limiting_metrics_recorded() {
    let scheduler_config = SchedulerConfig {
        scheduler_cores: 2,
        instruction_overhead_per_message: NumInstructions::from(0),
        instruction_overhead_per_canister: NumInstructions::from(0),
        ..SchedulerConfig::application_subnet()
    };
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(scheduler_config.clone())
        .with_rate_limiting_of_heap_delta()
        .build();

    // One canister starts with a heap delta already at the limit, so it should be
    // rate limited.
    let canister0 = test.create_canister();
    test.canister_state_mut(canister0)
        .scheduler_state
        .heap_delta_debit = scheduler_config.heap_delta_rate_limit;
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
    assert_eq!(
        metrics.canister_heap_delta_debits.get_sample_sum() as u64,
        0,
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
        0
    );
}

#[test]
fn stopping_canisters_are_stopped_when_they_are_ready() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister();

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg,
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    assert_eq!(
        test.canister_state(canister).status(),
        CanisterStatusType::Stopped
    );
}

#[test]
fn stopping_canisters_are_not_stopped_if_not_ready() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister();

    // Open a call context by calling a cross-net canister.

    test.send_ingress(
        canister,
        ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg,
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    match system_state.status {
        CanisterStatus::Stopping { .. } => {}
        CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
            unreachable!("Expected the canister to be in stopping mode");
        }
    }
}

#[test]
fn canister_is_stopped_if_timeout_occurs_and_ready_to_stop() {
    let test = StateMachineBuilder::new().build();

    let canister_id = test
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Open a call context, so that the canister doesn't stop immediately.
    {
        let payload = Encode!(&CanisterHttpRequestArgs {
            url: "https://example.com".to_string(),
            headers: BoundedHttpHeaders::new(vec![]),
            method: HttpMethod::GET,
            body: None,
            transform: None,
            max_response_bytes: None,
        })
        .unwrap();

        test.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    "http_request",
                    call_args()
                        .other_side(payload)
                        .on_reject(wasm().reject_message().reject()),
                )
                .into(),
        );
        test.tick();
    }

    // Send request to stop the canister.
    let stop_msg = {
        let arg = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
        let stop_msg = test.send_ingress(
            PrincipalId::new_anonymous(),
            ic00::IC_00,
            "stop_canister",
            arg,
        );
        test.tick();
        stop_msg
    };

    // The canister should now be stopping.
    {
        let status = test.canister_status(canister_id).unwrap().unwrap();
        assert_eq!(status.status(), CanisterStatusType::Stopping);
    }

    // Add the response to the output queue so that the context can be closed.
    {
        let response = CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: vec![],
        };

        let payload = PayloadBuilder::new().http_response(CallbackId::from(0), &response);
        test.execute_payload(payload);
    }

    // Advance the time such that the stop request has, in theory, timed out.
    test.advance_time(STOP_CANISTER_TIMEOUT_DURATION + Duration::from_secs(1));

    // Execute rounds, closing the call context and stopping the canister.
    // Even though the request should've timed out, it doesn't because the canister was ready to
    // stop when we were about to return a timeout, so instead we stop the canister and return
    // a success.
    assert!(test.await_ingress(stop_msg, 2).is_ok());

    // The canister has stopped.
    {
        let status = test.canister_status(canister_id).unwrap().unwrap();
        assert_eq!(status.status(), CanisterStatusType::Stopped);
    }
}

#[test]
fn can_timeout_stop_canister_requests() {
    let batch_time = Time::from_nanos_since_unix_epoch(u64::MAX / 2);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(batch_time)
        .build();

    let canister = test.create_canister();

    // Open a call context by calling a cross-net canister.

    test.send_ingress(
        canister,
        ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    test.set_time(batch_time + Duration::from_secs(60));
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg.clone(),
        Cycles::zero(),
        test.xnet_canister_id(),
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    match &system_state.status {
        CanisterStatus::Stopping { stop_contexts, .. } => {
            // There are 3 associated stop_context due to the stop request that
            // was sent above.
            assert_eq!(stop_contexts.len(), 3);
        }
        CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
            unreachable!("Expected the canister to be in stopping mode");
        }
    }

    // Progress the time so that some stop_contexts will expire.
    test.set_time(batch_time + STOP_CANISTER_TIMEOUT_DURATION + Duration::from_secs(1));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let system_state = &test.canister_state(canister).system_state;

    // Due to the open call context the canister cannot be stopped.
    assert!(!system_state.ready_to_stop());

    match &system_state.status {
        CanisterStatus::Stopping { stop_contexts, .. } => {
            // The first two stop_contexts should have expired, 1 is still active.
            assert_eq!(stop_contexts.len(), 1);
        }
        CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
            unreachable!("Expected the canister to be in stopping mode");
        }
    }
}

#[test]
fn replicated_state_metrics_nothing_exported() {
    let state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    // No canisters in the state. There should be nothing exported.
    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 0),
            (&[("status", "stopping")], 0),
            (&[("status", "stopped")], 0),
        ]),
    );
}

#[test]
fn execution_round_metrics_are_recorded() {
    // In this test we have 2 canisters with 5 input messages each. There are two
    // scheduler cores, so each canister gets its own thread for running.
    // Besides canister messages, there are three subnet messages.
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(400),
            max_instructions_per_message: NumInstructions::from(10),
            max_instructions_per_message_without_dts: NumInstructions::new(10),
            max_instructions_per_slice: NumInstructions::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    for _ in 0..2 {
        let canister = test.create_canister();
        for _ in 0..5 {
            test.send_ingress(canister, ingress(10));
        }
    }

    let canister = test.create_canister();
    for _ in 0..3 {
        let install_code = TestInstallCode::Reinstall {
            init: instructions(10),
        };
        test.inject_install_code_call_to_ic00(canister, install_code);
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    assert_eq!(1, metrics.round.duration.get_sample_count(),);
    assert_eq!(1, metrics.round.instructions.get_sample_count(),);
    assert_eq!(130, metrics.round.instructions.get_sample_sum() as u64);
    assert_eq!(1, metrics.round.messages.get_sample_count());
    assert_eq!(13, metrics.round.messages.get_sample_sum() as u64);
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        13
    );
    assert_eq!(test.state().metadata.subnet_metrics.num_canisters, 3);
    assert_eq!(
        1,
        metrics
            .round_advance_long_install_code
            .duration
            .get_sample_count()
    );
    assert_eq!(
        1,
        metrics
            .round_advance_long_install_code
            .messages
            .get_sample_count()
    );
    assert_eq!(2, metrics.round_subnet_queue.duration.get_sample_count());
    assert_eq!(
        2,
        metrics.round_subnet_queue.instructions.get_sample_count()
    );
    assert_eq!(
        30,
        metrics.round_subnet_queue.instructions.get_sample_sum() as u64,
    );
    assert_eq!(2, metrics.round_subnet_queue.messages.get_sample_count());
    assert_eq!(
        3,
        metrics.round_subnet_queue.messages.get_sample_sum() as u64,
    );
    assert_eq!(1, metrics.round_inner.duration.get_sample_count());
    assert_eq!(1, metrics.round_inner.instructions.get_sample_count());
    assert_eq!(
        100,
        metrics.round_inner.instructions.get_sample_sum() as u64,
    );
    assert_eq!(1, metrics.round_inner.messages.get_sample_count());
    assert_eq!(10, metrics.round_inner.messages.get_sample_sum() as u64,);
    assert_eq!(2, metrics.round_inner_iteration.duration.get_sample_count());
    assert_eq!(
        2,
        metrics
            .round_inner_iteration
            .instructions
            .get_sample_count(),
    );
    assert_eq!(
        100,
        metrics.round_inner_iteration.instructions.get_sample_sum() as u64,
    );
    assert_eq!(2, metrics.round_inner_iteration.messages.get_sample_count(),);
    assert_eq!(
        10,
        metrics.round_inner_iteration.messages.get_sample_sum() as u64,
    );
    assert_eq!(
        2,
        metrics
            .round_inner_iteration_thread
            .duration
            .get_sample_count()
    );
    assert_eq!(
        2,
        metrics
            .round_inner_iteration_thread
            .instructions
            .get_sample_count(),
    );
    assert_eq!(
        100,
        metrics
            .round_inner_iteration_thread
            .instructions
            .get_sample_sum() as u64,
    );
    assert_eq!(
        2,
        metrics
            .round_inner_iteration_thread
            .messages
            .get_sample_count(),
    );
    assert_eq!(
        10,
        metrics
            .round_inner_iteration_thread
            .messages
            .get_sample_sum() as u64,
    );
    assert_eq!(
        10,
        metrics
            .round_inner_iteration_thread_message
            .duration
            .get_sample_count()
    );
    assert_eq!(
        10,
        metrics
            .round_inner_iteration_thread_message
            .instructions
            .get_sample_count(),
    );
    assert_eq!(
        100,
        metrics
            .round_inner_iteration_thread_message
            .instructions
            .get_sample_sum() as u64,
    );
    assert_eq!(
        10,
        metrics
            .round_inner_iteration_thread_message
            .messages
            .get_sample_count(),
    );
    assert_eq!(
        10,
        metrics
            .round_inner_iteration_thread_message
            .messages
            .get_sample_sum() as u64,
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
            max_instructions_per_message_without_dts: NumInstructions::new(100),
            max_instructions_per_slice: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        })
        .build();
    let canister0 = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        Some(SystemMethod::CanisterHeartbeat),
        None,
        None,
    );
    let canister1 = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
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
        metrics
            .round_inner_iteration_thread_message
            .instructions
            .get_sample_count(),
    );
    assert_eq!(
        200,
        metrics
            .round_inner_iteration_thread_message
            .instructions
            .get_sample_sum() as u64,
    );
    assert_eq!(
        2,
        metrics
            .round_inner_iteration_thread_message
            .messages
            .get_sample_count(),
    );
    assert_eq!(
        2,
        metrics
            .round_inner_iteration_thread_message
            .messages
            .get_sample_sum() as u64,
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
            max_instructions_per_message_without_dts: NumInstructions::new(100),
            max_instructions_per_slice: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
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

#[test]
fn replicated_state_metrics_running_canister() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(0)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 1),
            (&[("status", "stopping")], 0),
            (&[("status", "stopped")], 0),
        ]),
    );
}

#[test]
fn replicated_state_metrics_different_canister_statuses() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(0)));
    state.put_canister_state(get_stopped_canister(canister_test_id(2)));
    state.put_canister_state(get_stopping_canister(canister_test_id(1)));
    state.put_canister_state(get_stopped_canister(canister_test_id(3)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 1),
            (&[("status", "stopping")], 1),
            (&[("status", "stopped")], 2),
        ]),
    );
}

#[test]
fn replicated_state_metrics_all_canisters_in_routing_table() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(1)));
    state.put_canister_state(get_running_canister(canister_test_id(2)));

    let routing_table = Arc::make_mut(&mut state.metadata.network_topology.routing_table);
    routing_table
        .insert(
            CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(3),
            },
            subnet_test_id(1),
        )
        .unwrap();

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_int_gauge(&registry, "replicated_state_canisters_not_in_routing_table"),
        Some(0)
    );
}

#[test]
fn replicated_state_metrics_stop_contexts_with_missing_call_ids() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    let mut canister = get_stopping_canister(canister_test_id(2));
    // Add old fake stop canister context with no call ID provided.
    canister
        .system_state
        .add_stop_context(StopCanisterContext::Ingress {
            sender: user_test_id(2),
            message_id: message_test_id(2),
            call_id: None,
        });
    // Add another stop canister context with call ID.
    canister
        .system_state
        .add_stop_context(StopCanisterContext::Ingress {
            sender: user_test_id(2),
            message_id: message_test_id(2),
            call_id: Some(StopCanisterCallId::new(2)),
        });
    state.put_canister_state(canister);

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);
    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        scheduler_metrics.stop_canister_calls_without_call_id.get(),
        1
    );
}

#[test]
fn replicated_state_metrics_some_canisters_not_in_routing_table() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(2)));
    state.put_canister_state(get_running_canister(canister_test_id(100)));

    let routing_table = Arc::make_mut(&mut state.metadata.network_topology.routing_table);
    routing_table
        .insert(
            CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(5),
            },
            subnet_test_id(1),
        )
        .unwrap();

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
        0.into(),
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_int_gauge(&registry, "replicated_state_canisters_not_in_routing_table"),
        Some(1)
    );
}

#[test]
fn long_open_call_context_is_recorded() {
    let mut test = SchedulerTestBuilder::new().build();

    for i in 0..2 {
        let canister = test.create_canister();
        // Open 1 or 2 call contexts by calling a cross-net canister.
        for _ in 0..i + 1 {
            test.send_ingress(
                canister,
                ingress(1).call(other_side(test.xnet_canister_id(), 1), on_response(1)),
            );
        }
    }
    let initial_time = Time::from_nanos_since_unix_epoch(10);
    test.set_time(initial_time);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let current_time = initial_time + Duration::from_secs(60 * 60 * 24);
    test.set_time(current_time);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    let label = HashMap::from([("age", "1d")]);
    let gauge = metrics
        .old_open_call_contexts
        .get_metric_with(&label)
        .unwrap();
    assert_eq!(gauge.get(), 3);

    let gauge = metrics
        .canisters_with_old_open_call_contexts
        .get_metric_with(&label)
        .unwrap();
    assert_eq!(gauge.get(), 2);
}

// In the following tests we check that the order of the canisters
// inside `inner_round` is the same as the one provided by the scheduling strategy.
#[test]
fn scheduler_maintains_canister_order() {
    let ca = [6, 10, 9, 5, 0];

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let mut canisters = vec![];

    for (i, ca) in ca.iter().enumerate() {
        let id = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000_000),
            ComputeAllocation::try_from(*ca).unwrap(),
            MemoryAllocation::BestEffort,
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
            assert!(canister_indexes[canister_id] >= prev_idx);
            canister_indexes[canister_id]
        });
    }
}

#[test]
fn ecdsa_signature_agreements_metric_is_updated() {
    let ecdsa_key = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: String::from("secp256k1"),
    };
    let mut test = SchedulerTestBuilder::new()
        .with_ecdsa_key(ecdsa_key.clone())
        .build();

    let canister_id = test.create_canister();

    let payload = Encode!(&SignWithECDSAArgs {
        message_hash: [0; 32],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: ecdsa_key
    })
    .unwrap();

    // inject two signing request
    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        payload.clone(),
        test.ecdsa_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        payload,
        test.ecdsa_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Check that the SubnetCallContextManager contains both requests.
    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    assert_eq!(sign_with_ecdsa_contexts.len(), 2);

    // reject the first one
    let (callback_id, _) = sign_with_ecdsa_contexts.iter().next().unwrap();
    let response = ConsensusResponse::new(
        *callback_id,
        Payload::Reject(RejectContext::new(RejectCode::SysFatal, "")),
    );

    test.state_mut().consensus_queue.push(response);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        1.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    let ecdsa_signature_agreements_before = test
        .state()
        .metadata
        .subnet_metrics
        .ecdsa_signature_agreements;
    let metric_before = fetch_int_gauge(
        test.metrics_registry(),
        "replicated_state_ecdsa_signature_agreements_total",
    )
    .unwrap();

    // metric and state variable should not have been updated
    assert_eq!(ecdsa_signature_agreements_before, metric_before);
    assert_eq!(0, metric_before);

    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    assert_eq!(sign_with_ecdsa_contexts.len(), 1);

    // send a reply to the second request
    let (callback_id, _) = sign_with_ecdsa_contexts.iter().next().unwrap();
    let response = ConsensusResponse::new(
        *callback_id,
        Payload::Data(
            ic00::SignWithECDSAReply {
                signature: vec![1, 2, 3],
            }
            .encode(),
        ),
    );

    test.state_mut().consensus_queue.push(response);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        2.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    let ecdsa_signature_agreements_after = test
        .state()
        .metadata
        .subnet_metrics
        .ecdsa_signature_agreements;
    let metric_after = fetch_int_gauge(
        test.metrics_registry(),
        "replicated_state_ecdsa_signature_agreements_total",
    )
    .unwrap();

    assert_eq!(
        ecdsa_signature_agreements_before + 1,
        ecdsa_signature_agreements_after
    );
    assert_eq!(ecdsa_signature_agreements_after, metric_after);

    // Check that the request was removed.
    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    assert!(sign_with_ecdsa_contexts.is_empty());
}

#[test]
fn consumed_cycles_ecdsa_outcalls_are_added_to_consumed_cycles_total() {
    let ecdsa_key = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: String::from("secp256k1"),
    };

    let mut test = SchedulerTestBuilder::new()
        .with_ecdsa_key(ecdsa_key.clone())
        .build();

    let fee = test.ecdsa_signature_fee();
    let payment = fee;

    let canister_id = test.create_canister();

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    let consumed_cycles_since_replica_started_before = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        Encode!(&SignWithECDSAArgs {
            message_hash: [0; 32],
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: ecdsa_key
        })
        .unwrap(),
        payment,
        canister_id,
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Check that the SubnetCallContextManager contains the request.
    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    assert_eq!(sign_with_ecdsa_contexts.len(), 1);

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );
    let consumed_cycles_since_replica_started_after = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    assert_eq!(
        consumed_cycles_since_replica_started_before + NominalCycles::from(fee),
        consumed_cycles_since_replica_started_after
    );

    assert_eq!(
        fetch_gauge_vec(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_from_replica_start",
        ),
        metric_vec(&[(&[("use_case", "ECDSAOutcalls")], fee.get() as f64),]),
    );
}

#[test]
fn consumed_cycles_http_outcalls_are_added_to_consumed_cycles_total() {
    let mut test = SchedulerTestBuilder::new().build();
    let caller_canister = test.create_canister();

    test.state_mut().metadata.own_subnet_features.http_requests = true;

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    let consumed_cycles_since_replica_started_before = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    // Create payload of the request.
    let url = "https://".to_string();
    let response_size_limit = 1000u64;
    let transform_method_name = "transform".to_string();
    let transform_context = vec![0, 1, 2];
    let args = CanisterHttpRequestArgs {
        url,
        max_response_bytes: Some(response_size_limit),
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: caller_canister.get().0,
                method: transform_method_name,
            }),
            context: transform_context,
        }),
    };

    // Create request to `HttpRequest` method.
    let payment = Cycles::new(1_000_000_000);
    let payload = args.encode();
    test.inject_call_to_ic00(
        Method::HttpRequest,
        payload,
        payment,
        caller_canister,
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Check that the SubnetCallContextManager contains the request.
    let canister_http_request_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .canister_http_request_contexts;
    assert_eq!(canister_http_request_contexts.len(), 1);

    let http_request_context = canister_http_request_contexts
        .get(&CallbackId::from(0))
        .unwrap();

    let fee = test.http_request_fee(
        http_request_context.variable_parts_size(),
        Some(NumBytes::from(response_size_limit)),
    );

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );
    let consumed_cycles_since_replica_started_after = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    assert_eq!(
        consumed_cycles_since_replica_started_before + NominalCycles::from(fee),
        consumed_cycles_since_replica_started_after
    );

    assert_eq!(
        fetch_gauge_vec(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_from_replica_start",
        ),
        metric_vec(&[(&[("use_case", "HTTPOutcalls")], fee.get() as f64),]),
    );
}

#[test]
fn consumed_cycles_since_replica_started_are_updated_from_valid_canisters() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister_id = test.create_canister_with(
        Cycles::from(5_000_000_000_000u128),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        None,
        None,
        None,
    );

    let removed_cycles = Cycles::from(1000u128);
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(removed_cycles, CyclesUseCase::Instructions);

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_gauge_vec(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_from_replica_start",
        ),
        metric_vec(&[(&[("use_case", "Instructions")], removed_cycles.get() as f64),]),
    );
}

#[test]
fn consumed_cycles_since_replica_started_are_updated_from_deleted_canisters() {
    let mut test = SchedulerTestBuilder::new().build();
    let initial_balance = Cycles::from(5_000_000_000_000u128);
    let canister_id = test.create_canister_with(
        initial_balance,
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        None,
        None,
        Some(CanisterStatusType::Stopped),
    );

    let removed_cycles = Cycles::from(1000u128);
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(removed_cycles, CyclesUseCase::Instructions);

    test.inject_call_to_ic00(
        Method::DeleteCanister,
        CanisterIdRecord::from(canister_id).encode(),
        Cycles::from(1_000_000_000_000u128),
        CanisterId::try_from(user_test_id(1).get()).unwrap(),
        InputQueueType::RemoteSubnet,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    observe_replicated_state_metrics(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &test.scheduler().metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_gauge_vec(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_from_replica_start",
        ),
        metric_vec(&[
            (&[("use_case", "Instructions")], removed_cycles.get() as f64),
            (
                &[("use_case", "DeletedCanisters")],
                (initial_balance.get() - removed_cycles.get()) as f64
            )
        ]),
    );
}

#[test]
fn expired_ingress_messages_are_removed_from_ingress_queues() {
    let batch_time = Time::from_nanos_since_unix_epoch(u64::MAX / 2);
    let mut test = SchedulerTestBuilder::new()
        .with_batch_time(batch_time)
        .build();

    let canister_id = test.create_canister();

    // Add some ingress messages to a canister's queue.
    // Half of them are set with expiry time before the
    // time of the current round while the other half
    // are set to expire after the current round.
    let num_ingress_messages_to_canisters = 10;
    for i in 0..num_ingress_messages_to_canisters {
        if i % 2 == 0 {
            test.send_ingress_with_expiry(
                canister_id,
                ingress(1000),
                batch_time.saturating_sub(Duration::from_secs(1)),
            );
        } else {
            test.send_ingress_with_expiry(
                canister_id,
                ingress(1000),
                batch_time + Duration::from_secs(1),
            );
        }
    }

    // Add some ingress messages to the subnet's queue.
    // Half of them are set with expiry time before the
    // time of the current round while the other half
    // are set to expire after the current round.
    let num_ingress_messages_to_subnet: u64 = 20;
    for i in 0..num_ingress_messages_to_subnet {
        if i % 2 == 0 {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(
                Method::CanisterStatus,
                payload,
                batch_time + Duration::from_secs(1),
            );
        } else {
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_ingress_to_ic00(
                Method::CanisterStatus,
                payload,
                batch_time.saturating_sub(Duration::from_secs(1)),
            );
        }
    }

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // Ingress queues should be empty, messages either expired
    // or were executed in the round.
    assert_eq!(test.ingress_queue_size(canister_id), 0);
    assert_eq!(test.subnet_ingress_queue_size(), 0);

    // Verify that half of the messages expired and the other half got executed.
    assert_eq!(
        fetch_counter(
            test.metrics_registry(),
            "scheduler_expired_ingress_messages_count",
        )
        .unwrap() as u64,
        (num_ingress_messages_to_canisters / 2) + (num_ingress_messages_to_subnet / 2)
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        (num_ingress_messages_to_canisters / 2) + (num_ingress_messages_to_subnet / 2)
    );
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
    last_round: usize,
    mut canister_params: Vec<(ComputeAllocation, ExecutionRound)>,
    messages_per_canister: usize,
    instructions_per_round: usize,
    instructions_per_message: usize,
    heartbeat: bool,
) -> (SchedulerTest, usize, NumInstructions, NumInstructions) {
    // Note: the DTS scheduler requires at least 2 scheduler cores
    assert!(scheduler_cores >= 2);
    let scheduler_config = SchedulerConfig {
        scheduler_cores,
        max_instructions_per_round: NumInstructions::from(instructions_per_round as u64),
        max_instructions_per_message: NumInstructions::from(instructions_per_message as u64),
        max_instructions_per_message_without_dts: NumInstructions::from(
            instructions_per_message as u64,
        ),
        max_instructions_per_slice: NumInstructions::from(instructions_per_message as u64),
        instruction_overhead_per_message: NumInstructions::from(0),
        instruction_overhead_per_canister: NumInstructions::from(0),
        ..SchedulerConfig::application_subnet()
    };
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(scheduler_config)
        .build();

    // Ensure that compute allocation of canisters doesn't exceed the capacity.
    let capacity = SchedulerImpl::compute_capacity_percent(scheduler_cores) as u64 - 1;
    let total = canister_params
        .iter()
        .fold(0, |acc, (ca, _)| acc + ca.as_percent());
    if total > capacity {
        canister_params = canister_params
            .into_iter()
            .map(|(ca, lr)| {
                let ca = ((ca.as_percent() * capacity) / total).min(100);
                (ComputeAllocation::try_from(ca).unwrap(), lr)
            })
            .collect();
    };

    for (ca, last_round) in canister_params.into_iter() {
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000_000),
            ca,
            MemoryAllocation::BestEffort,
            if heartbeat {
                Some(SystemMethod::CanisterHeartbeat)
            } else {
                None
            },
            None,
            None,
        );
        test.canister_state_mut(canister)
            .scheduler_state
            .last_full_execution_round = last_round;
        for _ in 0..messages_per_canister {
            test.send_ingress(canister, ingress(instructions_per_message as u64));
        }
    }
    test.advance_to_round(ExecutionRound::from(last_round as u64 + 1));
    (
        test,
        scheduler_cores,
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
        last_round: usize,
        heartbeat: bool,
    )
    (
        scheduler_cores in scheduler_cores,
        canister_params in prop::collection::vec(arb_canister_params(last_round), canisters),
        messages_per_canister in messages_per_canister,
        instructions_per_round in instructions_per_round,
        instructions_per_message in instructions_per_message,
    ) -> (SchedulerTest, usize, NumInstructions, NumInstructions) {
        construct_scheduler_for_prop_test(
            scheduler_cores,
            last_round,
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
        last_round: usize,
        heartbeat: bool,
    )
    (
        scheduler_cores in scheduler_cores,
        canister_params in prop::collection::vec(arb_canister_params(last_round), canisters),
        messages_per_canister in messages_per_canister,
        instructions_per_round in instructions_per_round,
        instructions_per_message in instructions_per_message,
    ) -> (SchedulerTest, SchedulerTest, usize, NumInstructions, NumInstructions) {
        let r1 = construct_scheduler_for_prop_test(
            scheduler_cores, last_round,
            canister_params.clone(),
            messages_per_canister,
            instructions_per_round,
            instructions_per_message,
            heartbeat,
        );
        let r2 = construct_scheduler_for_prop_test(
            scheduler_cores,
            last_round,
            canister_params,
            messages_per_canister,
            instructions_per_round,
            instructions_per_message,
            heartbeat,
        );
        (r1.0, r2.0, r1.1, r1.2, r1.3)
    }
}

prop_compose! {
    fn arb_canister_params(
        last_round: usize,
    )
    (
        a in -100..120,
        round in 0..=last_round,
    ) -> (ComputeAllocation, ExecutionRound) {
        // Clamp `a` to [0, 100], but with high probability for 0 and somewhat
        // higher probability for 100.
        let a = if a < 0 {
            0
        } else if a > 100 {
            100
        } else {
            a
        };

        (
            ComputeAllocation::try_from(a as u64).unwrap(),
            ExecutionRound::from(round as u64),
        )
    }
}

// In the following tests we use a notion of `minimum_executed_messages` per
// execution round. The minimum is defined as `min(available_messages,
// floor(`max_instructions_per_round` / `max_instructions_per_message`))`. `available_messages` are the sum of
// messages in the input queues of all canisters.

#[test_strategy::proptest]
// This test verifies that the scheduler will never consume more than
// `max_instructions_per_round` in a single execution round per core.
fn should_never_consume_more_than_max_instructions_per_round_in_a_single_execution_round(
    #[strategy(arb_scheduler_test(2..10, 1..20, 1..100, M..B, 1..M, 100, false))] test: (
        SchedulerTest,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (mut test, scheduler_cores, instructions_per_round, instructions_per_message) = test;
    let available_messages = get_available_messages(test.state());
    let minimum_executed_messages = min(
        available_messages,
        instructions_per_round / instructions_per_message,
    );
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let mut executed = HashMap::new();
    for (round, _canister_id, instructions) in test.executed_schedule().into_iter() {
        let entry = executed.entry(round).or_insert(0);
        assert!(instructions <= instructions_per_message);
        *entry += instructions.get();
    }
    for instructions in executed.values() {
        assert!(
            *instructions / scheduler_cores as u64 <= instructions_per_round.get(),
            "Executed more instructions than expected: {} <= {}",
            *instructions,
            instructions_per_round
        );
    }
    let total_executed_instructions: u64 = executed.into_values().sum();
    let total_executed_messages: u64 = total_executed_instructions / instructions_per_message.get();
    assert!(
        minimum_executed_messages <= total_executed_messages,
        "Executed {} messages but expected at least {}.",
        total_executed_messages,
        minimum_executed_messages,
    );
}

#[test_strategy::proptest]
// This test verifies that the scheduler is deterministic, i.e. given
// the same input, if we execute a round of computation, we always
// get the same result.
fn scheduler_deterministically_produces_same_output_given_same_input(
    #[strategy(arb_scheduler_test_double(2..10, 1..20, 1..100, M..B, 1..M, 100, false))] test: (
        SchedulerTest,
        SchedulerTest,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (mut test1, mut test2, _cores, _instructions_per_round, _instructions_per_message) = test;
    assert_eq!(test1.state(), test2.state());
    test1.execute_round(ExecutionRoundType::OrdinaryRound);
    test2.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(test1.state(), test2.state());
}

#[test_strategy::proptest]
// This test verifies that the scheduler can successfully deplete the induction
// pool given sufficient consecutive execution rounds.
fn scheduler_can_deplete_induction_pool_given_enough_execution_rounds(
    #[strategy(arb_scheduler_test(2..10, 1..20, 1..100, M..B, 1..M, 100, false))] test: (
        SchedulerTest,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (mut test, _scheduler_cores, instructions_per_round, instructions_per_message) = test;
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

#[test_strategy::proptest]
// This test verifies that the scheduler does not lose any canisters
// after an execution round.
fn scheduler_does_not_lose_canisters(
    #[strategy(arb_scheduler_test(2..3, 1..10, 1..100, M..B, 1..M, 100, false))] test: (
        SchedulerTest,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (mut test, _scheduler_cores, _instructions_per_round, _instructions_per_message) = test;
    let canisters_before = test.state().canisters_iter().count();
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let canisters_after = test.state().canisters_iter().count();
    assert_eq!(canisters_before, canisters_after);
}

#[test_strategy::proptest(ProptestConfig { cases: 20, ..ProptestConfig::default() })]
// Verifies that each canister is scheduled as the first of its thread as
// much as its compute_allocation requires.
fn scheduler_respects_compute_allocation(
    #[strategy(arb_scheduler_test(2..10, 1..20, 0..1, B..B+1, B..B+1, 0, true))] test: (
        SchedulerTest,
        usize,
        NumInstructions,
        NumInstructions,
    ),
) {
    let (mut test, scheduler_cores, _instructions_per_round, _instructions_per_message) = test;
    let replicated_state = test.state();
    let number_of_canisters = replicated_state.canister_states.len();
    let total_compute_allocation = replicated_state.total_compute_allocation();
    assert!(total_compute_allocation <= 100 * scheduler_cores as u64);

    // Count, for each canister, how many times it is the first canister
    // to be executed by a thread.
    let mut scheduled_first_counters = HashMap::<CanisterId, usize>::new();

    // Because we may be left with as little free compute capacity as 1, run for
    // enough rounds that every canister gets a chance to be scheduled at least once
    // for free, i.e. `100 * number_of_canisters` rounds.
    let number_of_rounds = 100 * number_of_canisters;

    let canister_ids: Vec<_> = test.state().canister_states.iter().map(|x| *x.0).collect();

    for _ in 0..number_of_rounds {
        for canister_id in canister_ids.iter() {
            test.expect_heartbeat(*canister_id, instructions(B as u64));
        }
        test.execute_round(ExecutionRoundType::OrdinaryRound);
        for (canister_id, canister) in test.state().canister_states.iter() {
            if canister.scheduler_state.last_full_execution_round == test.last_round() {
                let count = scheduled_first_counters.entry(*canister_id).or_insert(0);
                *count += 1;
            }
        }
    }

    // Check that the compute allocations of the canisters are respected.
    for (canister_id, canister) in test.state().canister_states.iter() {
        let compute_allocation = canister.scheduler_state.compute_allocation.as_percent() as usize;

        let count = scheduled_first_counters.get(canister_id).unwrap_or(&0);

        // Due to `total_compute_allocation < 100 * scheduler_cores`, all canisters
        // except those with an allocation of 100 should have gotten scheduled for free
        // at least once.
        let expected_count = if compute_allocation == 100 {
            number_of_rounds
        } else {
            number_of_rounds / 100 * compute_allocation + 1
        };

        assert!(
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
fn rate_limiting_of_install_code() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(5 * B as u64),
            max_instructions_per_slice: NumInstructions::from(5 * B as u64),
            max_instructions_per_install_code: NumInstructions::from(20 * B as u64),
            max_instructions_per_install_code_slice: NumInstructions::from(5 * B as u64),
            install_code_rate_limit: NumInstructions::from(2 * B as u64),
            instruction_overhead_per_message: NumInstructions::from(0),
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

#[test]
fn dts_long_execution_completes() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
            .metrics
            .canister_paused_execution
            .get_sample_sum(),
        9.0
    );
}

#[test]
fn cannot_execute_management_message_for_targeted_long_execution_canister() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
            .metrics
            .canister_paused_execution
            .get_sample_sum(),
        3.0
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
            .metrics
            .canister_paused_execution
            .get_sample_sum(),
        9.0
    );
}

#[test]
fn dts_long_execution_runs_out_of_instructions() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
            .metrics
            .canister_paused_execution
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
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100 * num_slices),
            max_instructions_per_message: NumInstructions::from(100 * num_slices),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100 * num_slices),
            max_instructions_per_message: NumInstructions::from(100 * num_slices),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
        assert!(paused_executions <= max_paused_executions);
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
            max_instructions_per_message_without_dts: max_instructions_per_slice.into(),
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
            canister.system_state.canister_metrics.executed,
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
            max_instructions_per_message_without_dts: max_instructions_per_slice.into(),
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
        assert_eq!(canister.system_state.canister_metrics.executed, 1);
        assert!(canister.has_paused_execution());
    }

    // After the second round the canister should have no executions, i.e. the
    // finish the paused execution and should not start any new executions.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    for canister in test.state().canisters_iter() {
        assert_eq!(canister.system_state.canister_metrics.executed, 2);
        assert!(!canister.has_paused_execution());
    }
}

#[test]
fn dts_allow_only_one_long_install_code_execution_at_any_time() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(160),
            max_instructions_per_message: NumInstructions::from(40),
            max_instructions_per_message_without_dts: NumInstructions::from(10),
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
            .metrics
            .canister_paused_execution
            .get_sample_sum(),
        0.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_aborted_execution
            .get_sample_sum(),
        0.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_paused_install_code
            .get_sample_sum(),
        1.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_aborted_install_code
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

    // Execute another round to refresh the metrics
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_paused_install_code
            .get_sample_sum(),
        2.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_paused_install_code
            .get_sample_count(),
        4
    );
}

#[test]
fn dts_resume_install_code_after_abort() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
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
            .metrics
            .canister_paused_install_code
            .get_sample_sum(),
        10.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_aborted_install_code
            .get_sample_sum(),
        1.0
    );
}

#[test]
fn dts_resume_long_execution_after_abort() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_message_without_dts: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(100),
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
            .metrics
            .canister_paused_execution
            .get_sample_sum(),
        10.0
    );
    assert_eq!(
        test.scheduler()
            .metrics
            .canister_aborted_execution
            .get_sample_sum(),
        1.0
    );
}

#[test]
fn dts_update_and_heartbeat() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            max_instructions_per_round: NumInstructions::from(300),
            max_instructions_per_message: NumInstructions::from(1000),
            max_instructions_per_message_without_dts: NumInstructions::from(200),
            max_instructions_per_slice: NumInstructions::from(100),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
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
                instruction_overhead_per_message: subnet_config
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
fn test_is_next_method_added_to_task_queue() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister = test.create_canister_with(
        Cycles::new(1_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::BestEffort,
        None,
        None,
        None,
    );
    let may_schedule_heartbeat = false;
    let may_schedule_global_timer = false;

    let mut heartbeat_and_timer_canister_ids = BTreeSet::new();
    assert!(!test
        .canister_state_mut(canister)
        .system_state
        .queues_mut()
        .has_input());

    for _ in 0..3 {
        // The timer did not reach the deadline and the canister does not have
        // input, hence no method will be chosen.
        assert!(!is_next_method_chosen(
            test.canister_state_mut(canister),
            &mut heartbeat_and_timer_canister_ids,
            may_schedule_heartbeat,
            may_schedule_global_timer,
        ));
        assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::new());
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    // Make canister able to schedule both heartbeat and global timer.
    let may_schedule_heartbeat = true;
    let may_schedule_global_timer = true;

    // Set input.
    test.canister_state_mut(canister)
        .system_state
        .queues_mut()
        .push_ingress(Ingress {
            source: user_test_id(77),
            receiver: canister,
            effective_canister_id: None,
            method_name: String::from("test"),
            method_payload: vec![1_u8],
            message_id: message_test_id(555),
            expiry_time: expiry_time_from_now(),
        });

    assert!(test
        .canister_state_mut(canister)
        .system_state
        .queues_mut()
        .has_input());

    while test
        .canister_state_mut(canister)
        .get_next_scheduled_method()
        != NextScheduledMethod::Message
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        &mut heartbeat_and_timer_canister_ids,
        may_schedule_heartbeat,
        may_schedule_global_timer,
    ));

    // Since NextScheduledMethod is Message it is not expected that Heartbeat
    // and GlobalTimer are added to the queue.
    assert!(test
        .canister_state_mut(canister)
        .system_state
        .task_queue
        .is_empty());

    assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::new());

    // Add a mock task, to know if new tasks are added
    // at the front or back of the queue.
    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .push_front(ExecutionTask::PausedExecution {
            id: PausedExecutionId(1),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });

    while test
        .canister_state_mut(canister)
        .get_next_scheduled_method()
        != NextScheduledMethod::Heartbeat
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }

    // Since NextScheduledMethod is Heartbeat it is expected that Heartbeat
    // and GlobalTimer are added at the front of the queue.
    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        &mut heartbeat_and_timer_canister_ids,
        may_schedule_heartbeat,
        may_schedule_global_timer,
    ));

    assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::from([canister]));
    assert_eq!(
        test.canister_state_mut(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::Heartbeat)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(
        test.canister_state_mut(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::GlobalTimer)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::from([canister]));

    heartbeat_and_timer_canister_ids = BTreeSet::new();

    while test
        .canister_state_mut(canister)
        .get_next_scheduled_method()
        != NextScheduledMethod::GlobalTimer
    {
        test.canister_state_mut(canister)
            .inc_next_scheduled_method();
    }
    // Since NextScheduledMethod is GlobalTimer it is expected that GlobalTimer
    // and Heartbeat are added at the front of the queue.
    assert!(is_next_method_chosen(
        test.canister_state_mut(canister),
        &mut heartbeat_and_timer_canister_ids,
        may_schedule_heartbeat,
        may_schedule_global_timer,
    ));

    assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::from([canister]));
    assert_eq!(
        test.canister_state_mut(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::GlobalTimer)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(
        test.canister_state_mut(canister)
            .system_state
            .task_queue
            .front(),
        Some(&ExecutionTask::Heartbeat)
    );

    test.canister_state_mut(canister)
        .system_state
        .task_queue
        .pop_front();

    assert_eq!(heartbeat_and_timer_canister_ids, BTreeSet::from([canister]));
}

pub(crate) fn make_key_id(id: u64) -> EcdsaKeyId {
    EcdsaKeyId::from_str(&format!("Secp256k1:key_{:?}", id)).unwrap()
}

fn inject_ecdsa_signing_request(test: &mut SchedulerTest, key_id: &EcdsaKeyId) {
    let canister_id = test.create_canister();

    let payload = Encode!(&SignWithECDSAArgs {
        message_hash: [0; 32],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: key_id.clone()
    })
    .unwrap();

    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        payload.clone(),
        test.ecdsa_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
fn test_sign_with_ecdsa_contexts_are_not_updated_without_quadruples() {
    let key_id = make_key_id(0);
    let mut test = SchedulerTestBuilder::new()
        .with_ecdsa_key(key_id.clone())
        .build();

    inject_ecdsa_signing_request(&mut test, &key_id);

    // Check that nonce isn't set in the following round
    for _ in 0..2 {
        test.execute_round(ExecutionRoundType::OrdinaryRound);

        let sign_with_ecdsa_context = &test
            .state()
            .sign_with_ecdsa_contexts()
            .values()
            .next()
            .expect("Context should exist");

        // Check that quadruple and nonce are none
        assert!(sign_with_ecdsa_context.nonce.is_none());
        assert!(sign_with_ecdsa_context.matched_quadruple.is_none());
    }
}

#[test]
fn test_sign_with_ecdsa_contexts_are_updated_with_quadruples() {
    let key_id = make_key_id(0);
    let mut test = SchedulerTestBuilder::new()
        .with_ecdsa_key(key_id.clone())
        .build();
    let pre_sig_id = PreSigId(0);
    let pre_sig_ids = BTreeSet::from_iter([pre_sig_id]);

    inject_ecdsa_signing_request(&mut test, &key_id);
    test.deliver_pre_signature_ids(BTreeMap::from_iter([(key_id, pre_sig_ids)]));

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let sign_with_ecdsa_context = &test
        .state()
        .sign_with_ecdsa_contexts()
        .values()
        .next()
        .expect("Context should exist");

    let expected_height = Height::from(test.last_round().get());

    // Check that quadruple was matched
    assert_eq!(
        sign_with_ecdsa_context.matched_quadruple,
        Some((pre_sig_id, expected_height))
    );
    // Check that nonce is still none
    assert!(sign_with_ecdsa_context.nonce.is_none());

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let sign_with_ecdsa_context = &test
        .state()
        .sign_with_ecdsa_contexts()
        .values()
        .next()
        .expect("Context should exist");

    // Check that quadruple is still matched
    assert_eq!(
        sign_with_ecdsa_context.matched_quadruple,
        Some((pre_sig_id, expected_height))
    );
    // Check that nonce is set
    let nonce = sign_with_ecdsa_context.nonce;
    assert!(nonce.is_some());

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let sign_with_ecdsa_context = &test
        .state()
        .sign_with_ecdsa_contexts()
        .values()
        .next()
        .expect("Context should exist");

    // Check that nonce wasn't changed
    let nonce = sign_with_ecdsa_context.nonce;
    assert_eq!(sign_with_ecdsa_context.nonce, nonce);
}

#[test]
fn test_sign_with_ecdsa_contexts_are_matched_under_multiple_keys() {
    let key_ids: Vec<_> = (0..3).map(make_key_id).collect();
    let mut test = SchedulerTestBuilder::new()
        .with_ecdsa_keys(key_ids.clone())
        .build();

    // Deliver 2 quadruples for the first key, 1 for the second, 0 for the third
    let pre_sig_ids0 = BTreeSet::from_iter([PreSigId(0), PreSigId(1)]);
    let pre_sig_ids1 = BTreeSet::from_iter([PreSigId(2)]);
    let pre_sig_id_map = BTreeMap::from_iter([
        (key_ids[0].clone(), pre_sig_ids0.clone()),
        (key_ids[1].clone(), pre_sig_ids1.clone()),
    ]);
    test.deliver_pre_signature_ids(pre_sig_id_map);

    // Inject 3 contexts requesting the third, second and first key in order
    for i in (0..3).rev() {
        inject_ecdsa_signing_request(&mut test, &key_ids[i])
    }

    // Execute two rounds
    for _ in 0..2 {
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    let sign_with_ecdsa_contexts = &test.state().sign_with_ecdsa_contexts();

    // First context (requesting key 3) should be unmatched
    let context0 = sign_with_ecdsa_contexts.get(&CallbackId::from(0)).unwrap();
    assert!(context0.nonce.is_none());
    assert!(context0.matched_quadruple.is_none());

    // Remaining contexts should have been matched
    let expected_height = Height::from(test.last_round().get() - 1);
    let context1 = sign_with_ecdsa_contexts.get(&CallbackId::from(1)).unwrap();
    assert!(context1.nonce.is_some());
    assert_eq!(
        context1.matched_quadruple,
        Some((*pre_sig_ids1.first().unwrap(), expected_height))
    );

    let context2 = sign_with_ecdsa_contexts.get(&CallbackId::from(2)).unwrap();
    assert!(context2.nonce.is_some());
    assert_eq!(
        context2.matched_quadruple,
        Some((*pre_sig_ids0.first().unwrap(), expected_height))
    );
}

#[test]
fn clean_in_progress_raw_rand_request_from_subnet_call_context_manager() {
    let canister_id = canister_test_id(2);
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(100),
            max_instructions_per_message: NumInstructions::from(1),
            max_instructions_per_message_without_dts: NumInstructions::new(1),
            max_instructions_per_slice: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();
    test.advance_to_round(ExecutionRound::new(2));
    let last_round = test.last_round();

    // Inject fake request to be able to create a response.
    let canister = get_running_canister(canister_id);
    test.inject_call_to_ic00(
        Method::RawRand,
        EmptyBlob.encode(),
        Cycles::new(0),
        canister_id,
        InputQueueType::LocalSubnet,
    );
    let state = test.state_mut();
    state.put_canister_state(canister);
    state.pop_subnet_input();
    state
        .metadata
        .subnet_call_context_manager
        .push_raw_rand_request(
            RequestBuilder::new().sender(canister_id).build(),
            last_round,
            UNIX_EPOCH,
        );
    // `SubnetCallContextManager` contains one `RawRandContext`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    // Helper function for invoking `after_split()`.
    fn after_split(state: &mut ReplicatedState) {
        state.metadata.split_from = Some(state.metadata.own_subnet_id);
        state.after_split();
    }

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `RawRandContext` and does not produce a response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );
    assert!(!test.state().subnet_queues().has_output());

    // Simulate a subnet split that migrates the canister to another subnet.
    test.state_mut().take_canister_state(&canister_id);
    after_split(test.state_mut());

    // Should have removed the `RawRandContext` and produced a reject response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );
    assert!(test.state().subnet_queues().has_output());
}
