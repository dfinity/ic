//! Tests for `induct_messages_on_same_subnet()`.

use super::super::test_utilities::{SchedulerTestBuilder, ingress, on_response, other_side};
use super::super::*;
use ic_config::subnet_config::SchedulerConfig;
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::MAX_RESPONSE_COUNT_BYTES;
use ic_types::time::{CoarseTime, UNIX_EPOCH};

const SOME_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(1);

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
            max_instructions_per_query_message: NumInstructions::from(55),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            instruction_overhead_per_execution: NumInstructions::from(0),
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
            max_instructions_per_query_message: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            instruction_overhead_per_execution: NumInstructions::from(0),
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
            max_instructions_per_query_message: NumInstructions::from(55),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            instruction_overhead_per_execution: NumInstructions::from(0),
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

/// Creates state with two canisters. Source canister has two guaranteed response
/// requests for itself and two requests for destination canister in its output
/// queues (as well as a couple of best-effort requests). Subnet only has enough
/// guaranteed response message memory for two requests.
///
/// Ensures that `induct_messages_on_same_subnet()` respects guaranteed response
/// memory limits on application subnets and ignores them on system subnets.
#[test]
fn induct_messages_on_same_subnet_respects_memory_limits() {
    // Runs a test with the given `available_memory` (expected to be limited to 2
    // requests plus epsilon). Checks that the limit is enforced on application
    // subnets and ignored on system subnets.
    let run_test = |guaranteed_response_message_memory, subnet_type| {
        let mut test = SchedulerTestBuilder::new()
            .with_scheduler_config(SchedulerConfig {
                scheduler_cores: 2,
                max_instructions_per_round: NumInstructions::new(1),
                max_instructions_per_message: NumInstructions::new(1),
                max_instructions_per_query_message: NumInstructions::from(1),
                max_instructions_per_slice: NumInstructions::new(1),
                max_instructions_per_install_code_slice: NumInstructions::new(1),
                instruction_overhead_per_execution: NumInstructions::from(0),
                instruction_overhead_per_canister: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            })
            .with_subnet_guaranteed_response_message_memory(
                guaranteed_response_message_memory as u64,
            )
            .with_subnet_type(subnet_type)
            .build();

        let source = test.create_canister();
        let dest = test.create_canister();
        let request_to = |canister: CanisterId, deadline: CoarseTime| {
            RequestBuilder::default()
                .sender(source)
                .receiver(canister)
                .deadline(deadline)
                .build()
        };

        let source_canister = test.canister_state_mut(source);
        // First, best-effort messages to `source` and `dest`.
        source_canister
            .push_output_request(request_to(source, SOME_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(request_to(dest, SOME_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        // Then a couple of guaranteed response messages to each of `source` and `dest`.
        source_canister
            .push_output_request(request_to(source, NO_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(request_to(source, NO_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(request_to(dest, NO_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        source_canister
            .push_output_request(request_to(dest, NO_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        test.induct_messages_on_same_subnet();

        let source_canister = test.canister_state(source);
        let dest_canister = test.canister_state(dest);
        let source_canister_queues = source_canister.system_state.queues();
        let dest_canister_queues = dest_canister.system_state.queues();
        if subnet_type == SubnetType::Application {
            // Only the two best-effort messages and the first two guaranteed response
            // messages should have been inducted. After two self-inductions on the source
            // canister, the subnet message memory is exhausted.
            assert_eq!(2, source_canister_queues.output_queues_message_count());
            assert_eq!(3, source_canister_queues.input_queues_message_count());
            assert_eq!(1, dest_canister_queues.input_queues_message_count());
        } else {
            // On a system subnet, with no message memory limits, all messages should have
            // been inducted.
            assert_eq!(0, source_canister_queues.output_queues_message_count());
            assert_eq!(3, source_canister_queues.input_queues_message_count());
            assert_eq!(3, dest_canister_queues.input_queues_message_count());
        }
    };

    // Subnet has memory for 4 outbound requests and 2 inbound requests (plus
    // epsilon, for small responses).
    run_test(
        MAX_RESPONSE_COUNT_BYTES as i64 * 65 / 10,
        SubnetType::Application,
    );

    // On system subnets limits will not be enforced for local messages, so running with 0 available
    // memory should also lead to inducting messages on local subnet.
    run_test(0, SubnetType::System);
}
