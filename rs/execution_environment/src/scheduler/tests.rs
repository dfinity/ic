use super::*;
#[cfg(test)]
use crate::execution_environment::{CanisterHeartbeatError, MockExecutionEnvironment};
use candid::Encode;
use ic_base_types::NumSeconds;
use ic_config::subnet_config::{CyclesAccountManagerConfig, SchedulerConfig};
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{CanisterIdRecord, Method};
use ic_interfaces::execution_environment::{ExecuteMessageResult, HypervisorError};
use ic_interfaces::messages::CanisterInputMessage;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::SubnetTopology;
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
    CallOrigin, ExportedFunctions,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    history::MockIngressHistory,
    metrics::{
        fetch_histogram_stats, fetch_int_counter, fetch_int_gauge, fetch_int_gauge_vec, metric_vec,
    },
    mock_time,
    state::{
        arb_replicated_state, get_initial_state, get_initial_system_subnet_state,
        get_running_canister, get_stopped_canister, get_stopping_canister, initial_execution_state,
        new_canister_state, CallContextBuilder, CanisterStateBuilder, ReplicatedStateBuilder,
    },
    types::{
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::{RequestBuilder, SignedIngressBuilder},
    },
    with_test_replica_logger,
};
use ic_types::messages::CallContextId;
use ic_types::methods::{Callback, SystemMethod, WasmClosure};
use ic_types::{
    ingress::WasmResult, methods::WasmMethod, time::UNIX_EPOCH, ComputeAllocation, Cycles, NumBytes,
};
use ic_types::{
    messages::{CallbackId, RequestOrResponse, MAX_RESPONSE_COUNT_BYTES},
    MAX_MEMORY_ALLOCATION,
};
use ic_wasm_types::WasmEngineError;
use lazy_static::lazy_static;
use maplit::btreemap;
use mockall::predicate::always;
use proptest::prelude::*;
use std::cmp::min;
use std::collections::{BTreeSet, HashMap};
use std::{convert::TryFrom, path::PathBuf, time::Duration};

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(1 << 30);
const LAST_ROUND_MAX: u64 = 100;
const MAX_CANISTER_MEMORY_SIZE: NumBytes = MAX_MEMORY_ALLOCATION;
const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(u64::MAX);
const MAX_NUMBER_OF_CANISTERS: u64 = 0;

lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
    static ref SUBNET_AVAILABLE_MEMORY: AvailableMemory = AvailableMemory::new(
        MAX_MEMORY_ALLOCATION.get() as i64,
        MAX_MEMORY_ALLOCATION.get() as i64
    );
}

fn assert_floats_are_equal(val0: f64, val1: f64) {
    if val0 > val1 {
        assert!(val0 - val1 < 0.1);
    } else {
        assert!(val1 - val0 < 0.1);
    }
}

#[test]
fn can_fully_execute_canisters_with_one_input_message_each() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg
                + NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stops_executing_messages_when_heap_delta_capacity_reached() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            subnet_heap_delta_capacity: NumBytes::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 2,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        NumInstructions::from(10),
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
            }

            for canister_state in state.canisters_iter_mut() {
                canister_state.push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_state.canister_id())
                        .build()
                        .into(),
                );
            }
            let round = ExecutionRound::from(2);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );

            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 1);
            }

            assert_eq!(
                scheduler
                    .metrics
                    .round_skipped_due_to_current_heap_delta_above_limit
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn canister_gets_heap_delta_rate_limited() {
    let heap_delta_rate_limit = SchedulerConfig::application_subnet().heap_delta_rate_limit;
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 1,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        1,
        NumInstructions::from(10),
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let canister = state.canisters_iter_mut().next().unwrap();
            canister.scheduler_state.heap_delta_debit =
                heap_delta_rate_limit * 2 - NumBytes::from(1);

            // Current heap delta debit is over the limit, so the canister shouldn't run.
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(
                state
                    .canisters_iter_mut()
                    .next()
                    .unwrap()
                    .system_state
                    .queues()
                    .ingress_queue_size(),
                1
            );

            // After getting a single round of credits we should be below the limit and able
            // to run.
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(2),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(
                state
                    .canisters_iter_mut()
                    .next()
                    .unwrap()
                    .system_state
                    .queues()
                    .ingress_queue_size(),
                0
            );
        },
        ingress_history_writer,
        exec_env,
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
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 1,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        1,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                0
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

/// This test ensures that inner_loop() breaks out of the loop when the loop
/// consumes max_instructions_per_round.
#[test]
fn inner_loop_stops_when_max_instructions_per_round_consumed() {
    // Create a canister with 3 input messages. 2 of them consume all of
    // max_instructions_per_round. The 2 messages are executed in the first
    // iteration of the loop and then the loop breaks.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 3,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 1);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                1
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

fn setup_routing_table() -> (SubnetId, RoutingTable) {
    let subnet_id = subnet_test_id(1);
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    })
    .unwrap();
    (subnet_id, routing_table)
}

/// Creates state with two canisters. Source canister has a message for
/// destination canister in its output queue. Ensures that
/// `induct_messages_on_same_subnet()` moves the message from source to
/// destination canister.
#[test]
fn basic_induct_messages_on_same_subnet_works() {
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1),
            max_instructions_per_message: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        NumInstructions::from(1),
        NumBytes::new(0),
    ));
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(2, 0);
            let mut canisters = state.take_canister_states();
            let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
            let source_canister_id = canister_ids.pop().unwrap();
            let dest_canister_id = canister_ids.pop().unwrap();

            let source_canister = canisters.get_mut(&source_canister_id).unwrap();
            source_canister
                .push_output_request(
                    RequestBuilder::default()
                        .sender(source_canister_id)
                        .receiver(dest_canister_id)
                        .build(),
                )
                .unwrap();
            state.put_canister_states(canisters);

            let (own_subnet_id, routing_table) = setup_routing_table();
            state.metadata.network_topology.routing_table = Arc::new(routing_table);
            state.metadata.own_subnet_id = own_subnet_id;
            scheduler.induct_messages_on_same_subnet(&mut state);
            let mut canisters = state.take_canister_states();
            let source_canister = canisters.remove(&source_canister_id).unwrap();
            let dest_canister = canisters.remove(&dest_canister_id).unwrap();
            assert!(!source_canister.has_output());
            assert!(dest_canister.has_input());
        },
        ingress_history_writer,
        exec_env,
    )
}

/// Creates state with one canister. The canister has a message for a
/// canister on another subnet in its output queue. Ensures that
/// `induct_messages_on_same_subnet()` does not move the message.
#[test]
fn induct_messages_on_same_subnet_handles_foreign_subnet() {
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1),
            max_instructions_per_message: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        NumInstructions::from(1),
        NumBytes::new(0),
    ));
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(1, 0);
            let mut canisters = state.take_canister_states();
            let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
            let source_canister_id = canister_ids.pop().unwrap();
            let source_canister = canisters.get_mut(&source_canister_id).unwrap();
            source_canister
                .push_output_request(
                    RequestBuilder::default()
                        .sender(source_canister_id)
                        .receiver(canister_test_id(0xffff))
                        .build(),
                )
                .unwrap();
            state.put_canister_states(canisters);

            let (own_subnet_id, routing_table) = setup_routing_table();
            state.metadata.network_topology.routing_table = Arc::new(routing_table);
            state.metadata.own_subnet_id = own_subnet_id;

            scheduler.induct_messages_on_same_subnet(&mut state);

            let mut canisters = state.take_canister_states();
            let source_canister = canisters.remove(&source_canister_id).unwrap();
            assert!(source_canister.has_output());
        },
        ingress_history_writer,
        exec_env,
    )
}

/// Creates state with one canister. The canister has a message for itself.
/// in its output queue. Ensures that `induct_messages_on_same_subnet()`
/// moves the message.
#[test]
fn induct_messages_to_self_works() {
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1),
            max_instructions_per_message: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        NumInstructions::from(1),
        NumBytes::new(0),
    ));
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(1, 0);
            let mut canisters = state.take_canister_states();
            let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
            let source_canister_id = canister_ids.pop().unwrap();
            let source_canister = canisters.get_mut(&source_canister_id).unwrap();
            source_canister
                .push_output_request(
                    RequestBuilder::default()
                        .sender(source_canister_id)
                        .receiver(source_canister_id)
                        .build(),
                )
                .unwrap();
            state.put_canister_states(canisters);

            let (own_subnet_id, routing_table) = setup_routing_table();
            state.metadata.network_topology.routing_table = Arc::new(routing_table);
            state.metadata.own_subnet_id = own_subnet_id;

            scheduler.induct_messages_on_same_subnet(&mut state);

            let mut canisters = state.take_canister_states();
            let source_canister = canisters.remove(&source_canister_id).unwrap();
            assert!(!source_canister.has_output());
            assert!(source_canister.has_input());
        },
        ingress_history_writer,
        exec_env,
    )
}

/// Creates state with two canisters. Source canister has two requests for
/// itself and two requests for destination canister in its output queues.
/// Source canister only has enough memory for one request, subnet only has
/// enough memory for 2 requests.
///
/// Ensures that `induct_messages_on_same_subnet()` moves one message from each
/// output queue into the corresponding input queue.
#[test]
fn induct_messages_on_same_subnet_respects_memory_limits() {
    // Runs a test with the given `available_memory` (expected to be limited to 2
    // requests plus epsilon). Checks that the limit is enforced on application
    // subnets and ignored on system subnets.
    let run_test = |subnet_available_memory, subnet_type| {
        let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round: NumInstructions::from(1),
                max_instructions_per_message: NumInstructions::from(1),
                instruction_overhead_per_message: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 0,
        };

        let mut exec_env = MockExecutionEnvironment::new();
        exec_env
            .expect_subnet_available_memory()
            .times(..)
            .return_const(subnet_available_memory);
        // Canisters can have up to 5 outstanding requests (plus epsilon). I.e. for
        // source canister, 4 outgoing + 1 incoming request plus small responses.
        exec_env
            .expect_max_canister_memory_size()
            .times(..)
            .return_const(NumBytes::from(MAX_RESPONSE_COUNT_BYTES as u64 * 55 / 10));
        let exec_env = Arc::new(exec_env);

        scheduler_test(
            &scheduler_test_fixture,
            |scheduler| {
                let mut state = match subnet_type {
                    SubnetType::Application => get_initial_state(2, 0),
                    SubnetType::System => get_initial_system_subnet_state(2, 0),
                    _ => unreachable!(),
                };
                let mut canisters = state.take_canister_states();
                let mut canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
                let source_canister_id = canister_ids.pop().unwrap();
                let dest_canister_id = canister_ids.pop().unwrap();

                let source_canister = canisters.get_mut(&source_canister_id).unwrap();
                let self_request = RequestBuilder::default()
                    .sender(source_canister_id)
                    .receiver(source_canister_id)
                    .build();
                source_canister
                    .push_output_request(self_request.clone())
                    .unwrap();
                source_canister.push_output_request(self_request).unwrap();
                let other_request = RequestBuilder::default()
                    .sender(source_canister_id)
                    .receiver(dest_canister_id)
                    .build();
                source_canister
                    .push_output_request(other_request.clone())
                    .unwrap();
                source_canister.push_output_request(other_request).unwrap();
                state.put_canister_states(canisters);

                let (own_subnet_id, routing_table) = setup_routing_table();
                state.metadata.network_topology.routing_table = Arc::new(routing_table);
                state.metadata.own_subnet_id = own_subnet_id;

                scheduler.induct_messages_on_same_subnet(&mut state);

                let mut canisters = state.take_canister_states();
                let source_canister = canisters.remove(&source_canister_id).unwrap();
                let dest_canister = canisters.remove(&dest_canister_id).unwrap();
                let source_canister_queues = source_canister.system_state.queues();
                let dest_canister_queues = dest_canister.system_state.queues();
                if ENFORCE_MESSAGE_MEMORY_USAGE && subnet_type == SubnetType::Application {
                    // Only one message should have been inducted from each queue: we first induct
                    // messages to self and hit the canister memory limit (1 more reserved slot);
                    // then induct messages for `dest_canister` and hit the subnet memory limit (2
                    // more reserved slots, minus the 1 before).
                    assert_eq!(2, source_canister_queues.output_message_count());
                    assert_eq!(1, source_canister_queues.input_queues_message_count());
                    assert_eq!(1, dest_canister_queues.input_queues_message_count());
                } else {
                    // Without memory limits all messages should have been inducted.
                    assert_eq!(0, source_canister_queues.output_message_count());
                    assert_eq!(2, source_canister_queues.input_queues_message_count());
                    assert_eq!(2, dest_canister_queues.input_queues_message_count());
                }
            },
            ingress_history_writer,
            exec_env,
        )
    };

    // Subnet has memory for 2 more requests (plus epsilon, for small responses).
    run_test(
        AvailableMemory::new(MAX_RESPONSE_COUNT_BYTES as i64 * 25 / 10, 1 << 30),
        SubnetType::Application,
    );
    // Subnet has message memory for 2 more requests (plus epsilon, for small responses).
    run_test(
        AvailableMemory::new(1 << 30, MAX_RESPONSE_COUNT_BYTES as i64 * 25 / 10),
        SubnetType::Application,
    );

    // On system subnets limits will not be enforced for local messages, so running with 0 available
    // memory should also lead to inducting messages on local subnet.
    run_test(AvailableMemory::new(0, 0), SubnetType::System);
}

/// Verifies that the [`SchedulerConfig::instruction_overhead_per_message`] puts
/// a limit on the number of update messages that will be executed in a single
/// round.
#[test]
fn test_message_limit_from_message_overhead() {
    // Create two canisters on the same subnet. When each one receives a
    // message, it sends a message to the other so that they ping-pong forever.
    let canister0 = canister_test_id(0);
    let canister1 = canister_test_id(1);
    let mut exec_env = MockExecutionEnvironment::new();
    // Return sufficiently large subnet and canister memory limits.
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_max_canister_memory_size()
        .times(..)
        .return_const(MAX_CANISTER_MEMORY_SIZE);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    exec_env
        .expect_execute_canister_message()
        .times(..)
        .returning(move |mut canister, instruction_limit, msg, _, _, _| {
            if let CanisterInputMessage::Request(ic_types::messages::Request {
                receiver,
                sender,
                sender_reply_callback,
                ..
            }) = msg
            {
                canister.push_output_response(Response {
                    originator: sender,
                    respondent: receiver,
                    originator_reply_callback: sender_reply_callback,
                    refund: Cycles::from(0u64),
                    response_payload: Payload::Data(vec![]),
                })
            }
            match msg {
                CanisterInputMessage::Response(msg) => {
                    canister
                        .system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .unregister_callback(msg.originator_reply_callback)
                        .unwrap();
                }
                CanisterInputMessage::Request(_) | CanisterInputMessage::Ingress(_) => {
                    let canister_id = canister.canister_id();
                    let other_canister = if canister_id == canister0 {
                        canister1
                    } else {
                        canister0
                    };
                    let callback_id = canister
                        .system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .register_callback(Callback {
                            call_context_id: CallContextId::new(0),
                            originator: None,
                            respondent: None,
                            cycles_sent: Cycles::from(0u64),
                            on_reply: WasmClosure::new(0, 0),
                            on_reject: WasmClosure::new(0, 0),
                            on_cleanup: None,
                        });
                    canister
                        .push_output_request(
                            RequestBuilder::new()
                                .sender(canister_id)
                                .receiver(other_canister)
                                .sender_reply_callback(callback_id)
                                .build(),
                        )
                        .unwrap();
                }
            }
            ExecuteMessageResult {
                canister: canister.clone(),
                num_instructions_left: instruction_limit,
                ingress_status: None,
                heap_delta: NumBytes::from(0),
            }
        });
    let exec_env = Arc::new(exec_env);
    let scheduler_config = SchedulerConfig {
        scheduler_cores: 1,
        instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
        max_instructions_per_message: NumInstructions::from(5_000_000_000),
        max_instructions_per_round: NumInstructions::from(7_000_000_000),
        instruction_overhead_per_message: NumInstructions::from(2_000_000),
        ..SchedulerConfig::application_subnet()
    };

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

    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config,
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedStateBuilder::new()
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_canister_id(canister_test_id(0))
                        .with_ingress(
                            SignedIngressBuilder::new()
                                .canister_id(canister0)
                                .build()
                                .into(),
                        )
                        .build(),
                )
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_canister_id(canister_test_id(1))
                        .build(),
                )
                .build();
            let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => scheduler.own_subnet_id,
            }).unwrap());
            state.metadata.network_topology.routing_table = routing_table;

            let round = ExecutionRound::from(1);
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            let number_of_messages = scheduler.metrics.msg_execution_duration.get_sample_count();
            assert_eq!(number_of_messages, expected_number_of_messages);
        },
        Arc::new(MockIngressHistory::new()),
        exec_env,
    );
}

/// A test to ensure that there are multiple iterations of the loop in
/// inner_round().
#[test]
fn test_multiple_iterations_of_inner_loop() {
    // Create two canisters on the same subnet. In the first iteration, the
    // first sends a message to the second. In the second iteration, the second
    // executes the received message.
    let mut exec_env = MockExecutionEnvironment::new();
    // Return sufficiently large subnet and canister memory limits.
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_max_canister_memory_size()
        .times(..)
        .return_const(MAX_CANISTER_MEMORY_SIZE);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    exec_env
        .expect_execute_canister_message()
        .times(2)
        .returning(move |mut canister, _, msg, _, _, _| {
            let canister0 = canister_test_id(0);
            let canister1 = canister_test_id(1);
            let canister_id = canister.canister_id();
            if canister_id == canister0 {
                canister
                    .push_output_request(
                        RequestBuilder::new()
                            .sender(canister0)
                            .receiver(canister1)
                            .build(),
                    )
                    .unwrap();
                if let CanisterInputMessage::Ingress(msg) = msg {
                    ExecuteMessageResult {
                        canister: canister.clone(),
                        num_instructions_left: NumInstructions::new(0),
                        ingress_status: Some((
                            msg.message_id,
                            IngressStatus::Processing {
                                receiver: canister.canister_id().get(),
                                user_id: user_test_id(0),
                                time: mock_time(),
                            },
                        )),
                        heap_delta: NumBytes::from(1),
                    }
                } else {
                    unreachable!("Only ingress messages are expected.")
                }
            } else if canister_id == canister1 {
                ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    ingress_status: None,
                    heap_delta: NumBytes::from(1),
                }
            } else {
                unreachable!(
                    "message should be directed to {} or {}",
                    canister0, canister1
                );
            }
        });
    let exec_env = Arc::new(exec_env);
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(200),
            max_instructions_per_message: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => scheduler.own_subnet_id,
            }).unwrap());
            state.metadata.network_topology.routing_table = routing_table;

            let canister_id = canister_test_id(0);
            state
                .canister_state_mut(&canister_id)
                .unwrap()
                .push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .build()
                        .into(),
                );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                0
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                2
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

/// A bug in the first implementation of heap delta rate limiting would prevent
/// a canister which generates heap delta from running after the second
/// iteration, even if it was below the limit. This test verifies that a
/// canister generating small heap deltas can run in many iterations.
#[test]
fn canister_can_run_for_multiple_iterations() {
    // Create a canister which sends a message to itself on each iteration.
    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_max_canister_memory_size()
        .times(..)
        .return_const(MAX_CANISTER_MEMORY_SIZE);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    exec_env
        .expect_execute_canister_message()
        .times(..)
        .returning(move |mut canister, _, _, _, _, _| {
            let canister_id = canister.canister_id();
            canister
                .push_output_request(
                    RequestBuilder::new()
                        .sender(canister_id)
                        .receiver(canister_id)
                        .build(),
                )
                .unwrap();
            ExecuteMessageResult {
                canister,
                num_instructions_left: NumInstructions::from(0),
                ingress_status: None,
                heap_delta: NumBytes::from(1),
            }
        });
    let exec_env = Arc::new(exec_env);
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            // The number of instructions will limit the canister to running at most 6 times.
            max_instructions_per_round: NumInstructions::new(300),
            max_instructions_per_message: NumInstructions::new(50),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 0,
    };

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let canister_id = canister_test_id(0);
            state
                .canister_state_mut(&canister_id)
                .unwrap()
                .push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .build()
                        .into(),
                );

            let round = ExecutionRound::from(1);
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            // Verify that we actually ran 6 iterations.
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                6
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn validate_consumed_instructions_metric() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_round: NumInstructions::from(400),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 2,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
            }
            assert_eq!(
                scheduler
                    .metrics
                    .instructions_consumed_per_round
                    .get_sample_count(),
                2
            );
            assert_floats_are_equal(
                scheduler
                    .metrics
                    .instructions_consumed_per_round
                    .get_sample_sum(),
                100_f64,
            );
            assert_eq!(
                scheduler
                    .metrics
                    .instructions_consumed_per_message
                    .get_sample_count(),
                2
            );
            assert_floats_are_equal(
                scheduler
                    .metrics
                    .instructions_consumed_per_message
                    .get_sample_sum(),
                100_f64,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn only_charge_for_allocation_after_specified_duration() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig::application_subnet(),
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    let prev_time = Time::from_nanos_since_unix_epoch(1_000_000_000_000);
    let initial_cycles = 1_000_000;
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let time_between_batches = scheduler
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
            let mut state = ReplicatedStateBuilder::new()
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_memory_allocation(NumBytes::from(bytes_per_cycle))
                        .with_cycles(initial_cycles)
                        .build(),
                )
                .with_time(prev_time + time_between_batches)
                .with_time_of_last_allocation(prev_time)
                .build();

            // Don't charge because the time since the last charge is too small.
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            let canister_state = state.canisters_iter().next().unwrap();
            assert_eq!(canister_state.system_state.balance().get(), initial_cycles);

            // The time of the current batch is now long enough that allocation charging
            // should be triggered.
            state.metadata.batch_time += time_between_batches;
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            let canister_state = state.canisters_iter().next().unwrap();
            assert_eq!(
                canister_state.system_state.balance().get(),
                initial_cycles - 10
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn dont_execute_any_canisters_if_not_enough_cycles() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg
                - NumInstructions::from(1),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 1);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    ExecutionRound::from(0)
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 0);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

// Creates an initial state with some canisters that contain very few cycles.
// Ensures that after `execute_round` returns, the canisters have been
// uninstalled.
#[test]
fn canisters_with_insufficient_cycles_are_uninstalled() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let num_canisters = 3;
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg
                - NumInstructions::from(1),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: num_canisters,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(0, 0);
            // Set the cycles balance of all canisters to small enough amount so
            // that they cannot pay for their resource usage but also do not set
            // it to 0 as that is a simpler test.
            for i in 0..num_canisters {
                let canister_state = CanisterStateBuilder::new()
                    .with_canister_id(canister_test_id(i))
                    .with_cycles(Cycles::from(100))
                    .with_wasm(vec![1; 1 << 30])
                    .build();
                state.put_canister_state(canister_state);
            }
            state.metadata.time_of_last_allocation_charge = UNIX_EPOCH + Duration::from_secs(1);
            state.metadata.batch_time = state.metadata.time_of_last_allocation_charge
                + scheduler
                    .cycles_account_manager
                    .duration_between_allocation_charges();

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );

            for (_, canister) in state.canister_states.iter() {
                assert!(canister.execution_state.is_none());
                assert_eq!(
                    canister.scheduler_state.compute_allocation,
                    ComputeAllocation::zero()
                );
                assert_eq!(
                    canister.system_state.memory_allocation,
                    MemoryAllocation::BestEffort
                );
            }
            assert_eq!(
                scheduler
                    .metrics
                    .num_canisters_uninstalled_out_of_cycles
                    .get() as u64,
                num_canisters
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_execute_messages_with_just_enough_cycles() {
    // In this test we have 3 canisters with 1 message each and the maximum allowed
    // round cycles is 3 times the instructions consumed by each message. Thus, we
    // expect that we have just enough instructions to execute all messages.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg * 3,
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    ExecutionRound::from(1)
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execute_only_canisters_with_messages() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg
                + NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state.put_canister_state(new_canister_state(
                canister_test_id(3),
                user_test_id(24).get(),
                *INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                // We won't update `last_full_execution_round` for the canister without any
                // input messages.
                if canister_state.canister_id() == canister_test_id(3) {
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(0)
                    );
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .skipped_round_due_to_no_messages,
                        1
                    );
                } else {
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(1)
                    );
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .skipped_round_due_to_no_messages,
                        0
                    );
                    assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .interruped_during_execution,
                        0
                    );
                }
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_fully_execute_multiple_canisters_with_multiple_messages_each() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 5,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        15,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(15);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(4);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_fully_execute_canisters_deterministically_until_out_of_cycles() {
    // In this test we have 5 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 51 (per core). Each
    // message consumes 5 instructions, therefore we can execute fully 1
    // canister per core in one round.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 5,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        20,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(20);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                let id = &canister_state.canister_id();
                if id == &canister_test_id(0) || id == &canister_test_id(1) {
                    assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        round
                    );
                } else {
                    assert_eq!(
                        canister_state.system_state.queues().ingress_queue_size(),
                        10
                    );
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(0)
                    );
                }
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_execute_messages_from_multiple_canisters_until_out_of_instructions() {
    // In this test we have 2 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 18 (per core). Each core
    // executes 1 canister until we don't have any instructions left anymore. Since
    // each message consumes 5 instructions, we can execute 3 messages from each
    // canister.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        6,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(6);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 7);
                assert_ne!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn subnet_messages_respect_instruction_limit_per_round() {
    // In this test we have a canister with 10 input messages and 20 subnet
    // messages. Each message execution consumes 10 instructions and the round
    // limit is set to 400 instructions.
    // The test expects that subnet messages use about a 1/16 of the round limit
    // and the input messages get the full round limit. More specifically:
    // - 3 subnet messages should run (using 30 out of 100 instructions).
    // - 10 input messages should run (using 100 out of 100 instructions).

    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(400),
            max_instructions_per_message: NumInstructions::new(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 10,
    };

    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        10,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    );

    exec_env
        .expect_execute_subnet_message()
        .times(3)
        .returning(move |_, state, _, _, _, _, _, _| (state, NumInstructions::from(0)));

    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(10));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let canister = state.canisters_iter().next().unwrap();
            let controller_id = canister.system_state.controllers.iter().next().unwrap();
            let controller = CanisterId::new(*controller_id).unwrap();
            let canister_id = canister.canister_id();
            let subnet_id = state.metadata.own_subnet_id;
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            let cycles = 1000000;

            for _ in 0..20 {
                state
                    .subnet_queues_mut()
                    .push_input(
                        QUEUE_INDEX_NONE,
                        RequestOrResponse::Request(
                            RequestBuilder::new()
                                .sender(controller)
                                .receiver(CanisterId::from(subnet_id))
                                .method_name(Method::CanisterStatus)
                                .method_payload(payload.clone())
                                .payment(Cycles::from(cycles))
                                .build(),
                        ),
                        InputQueueType::RemoteSubnet,
                    )
                    .unwrap();
            }

            let round = ExecutionRound::from(1);
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execute_heartbeat_once_per_round_in_system_subnet() {
    // This test sets up a canister on a system subnet with a heartbeat method and
    // three messages. The heartbeat is expected to run once. The messages are
    // expected to run once each.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 3,
    };
    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        NumInstructions::from(1),
        NumBytes::new(0),
    );
    exec_env
        .expect_execute_canister_heartbeat()
        .times(1)
        .returning(move |canister, instruction_limit, _, _, _| {
            (
                canister,
                instruction_limit - NumInstructions::from(1),
                Ok(NumBytes::new(1)),
            )
        });
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            for canister in state.canisters_iter_mut() {
                if let Some(ref mut execution_state) = canister.execution_state {
                    execution_state.exports = ExportedFunctions::new(
                        [WasmMethod::System(SystemMethod::CanisterHeartbeat)]
                            .iter()
                            .cloned()
                            .collect(),
                    );
                }
            }
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execute_heartbeat_before_messages() {
    // This test sets up a canister on a system subnet with a heartbeat method and
    // three messages. The instruction limit per round allows only a single
    // call. That call should be the heartbeat call.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1),
            max_instructions_per_message: NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 3,
    };
    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        NumInstructions::from(1),
        NumBytes::new(0),
    );
    exec_env
        .expect_execute_canister_heartbeat()
        .times(1)
        .returning(move |canister, instruction_limit, _, _, _| {
            (
                canister,
                instruction_limit - NumInstructions::from(1),
                Ok(NumBytes::new(1)),
            )
        });
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            for canister in state.canisters_iter_mut() {
                if let Some(ref mut execution_state) = canister.execution_state {
                    execution_state.exports = ExportedFunctions::new(
                        [WasmMethod::System(SystemMethod::CanisterHeartbeat)]
                            .iter()
                            .cloned()
                            .collect(),
                    );
                }
            }
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execute_multiple_heartbeats() {
    // This tests multiple canisters with heartbeat methods running over multiple
    // rounds using multiple scheduler cores.
    let number_of_canisters: usize = 3;
    let number_of_messages_per_canister: usize = 4;
    let number_of_rounds: usize = 2;
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 5,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: number_of_canisters as u64,
        message_num_per_canister: number_of_messages_per_canister as u64,
    };
    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        number_of_canisters * number_of_messages_per_canister,
        NumInstructions::from(1),
        NumBytes::new(0),
    );
    exec_env
        .expect_execute_canister_heartbeat()
        .times(number_of_canisters * number_of_rounds)
        .returning(move |canister, instruction_limit, _, _, _| {
            (
                canister,
                instruction_limit - NumInstructions::from(1),
                Ok(NumBytes::new(1)),
            )
        });
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer =
        default_ingress_history_writer_mock(number_of_canisters * number_of_messages_per_canister);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            for canister in state.canisters_iter_mut() {
                if let Some(ref mut execution_state) = canister.execution_state {
                    execution_state.exports = ExportedFunctions::new(
                        [WasmMethod::System(SystemMethod::CanisterHeartbeat)]
                            .iter()
                            .cloned()
                            .collect(),
                    );
                }
            }
            for _ in 0..number_of_rounds {
                state = scheduler.execute_round(
                    state,
                    Randomness::from([0; 32]),
                    None,
                    ExecutionRound::from(1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_NUMBER_OF_CANISTERS,
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
// This test verifies that we can successfully record metrics from a single
// scheduler thread. We feed the `thread` with a single canister which has 3
// ingress messages. The first one runs out of instructions while the other two
// are executed successfully.
fn can_record_metrics_single_scheduler_thread() {
    ic_test_utilities::with_test_replica_logger(|log| {
        let max_instructions_per_message = NumInstructions::from(5);
        let scheduler_config = SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        };

        let mut exec_env = MockExecutionEnvironment::new();
        let canister_id = canister_test_id(0);

        exec_env
            .expect_execute_canister_message()
            .times(1)
            .returning(move |canister, _, _, _, _, _| ExecuteMessageResult {
                canister,
                num_instructions_left: NumInstructions::from(0),
                ingress_status: Some((
                    message_test_id(0),
                    IngressStatus::Failed {
                        receiver: canister_id.get(),
                        user_id: user_test_id(0),
                        error: UserError::new(ErrorCode::CanisterOutOfCycles, "".to_string()),
                        time: mock_time(),
                    },
                )),
                heap_delta: NumBytes::from(0),
            });

        for message_id in 1..3 {
            exec_env
                .expect_execute_canister_message()
                .times(1)
                .returning(move |canister, _, _, _, _, _| ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(1),
                    ingress_status: Some((
                        message_test_id(message_id),
                        IngressStatus::Completed {
                            receiver: canister_id.get(),
                            user_id: user_test_id(0),
                            result: WasmResult::Reply(vec![]),
                            time: mock_time(),
                        },
                    )),
                    heap_delta: NumBytes::from(0),
                });
        }

        let mut canister_state = new_canister_state(
            canister_id,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let mut exports = BTreeSet::new();
        exports.insert(WasmMethod::Update("write".to_string()));
        exports.insert(WasmMethod::Query("read".to_string()));
        let mut execution_state = initial_execution_state();
        execution_state.exports = ExportedFunctions::new(exports);
        canister_state.execution_state = Some(execution_state);

        for nonce in 0..3 {
            canister_state.push_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_id)
                    .method_name("write".to_string())
                    .nonce(nonce)
                    .build()
                    .into(),
            );
        }

        let metrics_registry = MetricsRegistry::new();

        // This is needed for constructing an instance of `SchedulerImpl`, but its
        // methods are not called. That's why the expected number of calls is 0.
        let ingress_history_writer = default_ingress_history_writer_mock(0);
        let ingress_history_writer = Arc::new(ingress_history_writer);

        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_max_num_instructions(MAX_INSTRUCTIONS_PER_MESSAGE)
                .build(),
        );

        let network_topology = Arc::new(NetworkTopology {
            subnets: [(
                subnet_test_id(1),
                SubnetTopology {
                    subnet_type: SubnetType::Application,
                    ..SubnetTopology::default()
                },
            )]
            .iter()
            .cloned()
            .collect(),
            ..NetworkTopology::default()
        });

        let scheduler = SchedulerImpl::new(
            scheduler_config.clone(),
            subnet_test_id(1),
            ingress_history_writer,
            Arc::new(exec_env),
            cycles_account_manager,
            &metrics_registry,
            log,
            FlagStatus::Enabled,
            FlagStatus::Enabled,
        );

        let measurement_scope = MeasurementScope::root(&scheduler.metrics.round_inner_iteration);

        scheduler.execute_canisters_in_inner_round(
            vec![vec![canister_state]],
            scheduler_config,
            ExecutionRound::from(0),
            mock_time(),
            *SUBNET_AVAILABLE_MEMORY,
            network_topology,
            HeartbeatHandling::Execute {
                only_track_system_errors: true,
            },
            &measurement_scope,
        );

        let cycles_consumed_per_message_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_instructions_consumed_per_message",
        )
        .unwrap();
        let cycles_consumed_per_round_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_instructions_consumed_per_round",
        )
        .unwrap();
        let msg_execution_duration_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_message_execution_duration_seconds",
        )
        .unwrap();
        let canister_messages_where_cycles_were_charged = fetch_int_counter(
            &metrics_registry,
            "scheduler_canister_messages_where_cycles_were_charged",
        )
        .unwrap();

        assert_eq!(msg_execution_duration_stats.count, 3);
        assert_eq!(cycles_consumed_per_message_stats.count, 3);
        assert_eq!(cycles_consumed_per_round_stats.sum as i64, 13);
        assert_eq!(canister_messages_where_cycles_were_charged, 3);
    });
}

#[test]
fn can_record_metrics_for_a_round() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 5,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        10,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(10);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    fn update_canister_allocation(
        mut state: ReplicatedState,
        canister_id: CanisterId,
        allocation: ComputeAllocation,
    ) -> ReplicatedState {
        let mut canister_state = state.canister_state(&canister_id).unwrap().clone();
        canister_state.scheduler_state.compute_allocation = allocation;
        state.put_canister_state(canister_state);
        state
    }

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            // The first two canisters have an `Allocation` of 1 and the last 1/3. We'll be
            // forced to execute the first two and then run out of instructions (based on
            // the limits) which will result in a violation of third canister's
            // `Allocation`.
            for id in 0..2u64 {
                state = update_canister_allocation(
                    state,
                    canister_test_id(id),
                    ComputeAllocation::try_from(100).unwrap(),
                );
            }
            state = update_canister_allocation(
                state,
                canister_test_id(2),
                ComputeAllocation::try_from(33).unwrap(),
            );

            let round = ExecutionRound::from(4);
            state.metadata.time_of_last_allocation_charge = UNIX_EPOCH + Duration::from_secs(1);
            state.metadata.batch_time = state.metadata.time_of_last_allocation_charge
                + scheduler
                    .cycles_account_manager
                    .duration_between_allocation_charges();
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );

            let registry = &scheduler_test_fixture.metrics_registry;
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_executable_canisters_per_round")
                    .unwrap()
                    .sum as i64,
                3
            );
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_canister_age_rounds")
                    .unwrap()
                    .sum as i64,
                4
            );
            assert_eq!(
                fetch_histogram_stats(registry, "execution_round_preparation_duration_seconds")
                    .unwrap()
                    .count,
                1
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_preparation_ingress_pruning_duration_seconds"
                )
                .unwrap()
                .count,
                1
            );
            assert_eq!(
                fetch_histogram_stats(registry, "execution_round_scheduling_duration_seconds")
                    .unwrap()
                    .count,
                1
            );
            assert!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_inner_preparation_duration_seconds"
                )
                .unwrap()
                .count
                    >= 1
            );
            assert!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_inner_finalization_duration_seconds"
                )
                .unwrap()
                .count
                    >= 1
            );
            assert!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_inner_finalization_message_induction_duration_seconds"
                )
                .unwrap()
                .count
                    >= 1
            );
            assert_eq!(
                fetch_histogram_stats(registry, "execution_round_finalization_duration_seconds")
                    .unwrap()
                    .count,
                1
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_finalization_stop_canisters_duration_seconds"
                )
                .unwrap()
                .count,
                1
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_finalization_ingress_history_prune_duration_seconds"
                )
                .unwrap()
                .count,
                1
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "execution_round_finalization_charge_resources_duration_seconds"
                )
                .unwrap()
                .count,
                1
            );
            assert_eq!(
                fetch_int_counter(registry, "scheduler_compute_allocation_violations"),
                Some(1)
            );
            assert_eq!(
                fetch_int_counter(
                    registry,
                    "scheduler_canister_messages_where_cycles_were_charged"
                ),
                Some(10)
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn heap_delta_rate_limiting_metrics_recorded() {
    let heap_delta_per_message = 1024;
    // Two canisters each get one message.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 1,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        1,
        NumInstructions::from(10),
        NumBytes::new(heap_delta_per_message),
    ));

    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            // One canister starts with a heap delta already at the limit, so it should be
            // rate limited.
            let canister0 = state.canisters_iter_mut().next().unwrap();
            canister0.scheduler_state.heap_delta_debit = scheduler.config.heap_delta_rate_limit;

            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(2),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );

            let registry = &scheduler_test_fixture.metrics_registry;
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_canister_heap_delta_debits")
                    .unwrap()
                    .count as u64,
                2
            );
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_canister_heap_delta_debits")
                    .unwrap()
                    .sum as u64,
                scheduler.config.heap_delta_rate_limit.get() + 1024
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "scheduler_heap_delta_rate_limited_canisters_per_round"
                )
                .unwrap()
                .count as u64,
                1
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "scheduler_heap_delta_rate_limited_canisters_per_round"
                )
                .unwrap()
                .sum as u64,
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn heap_delta_rate_limiting_disabled() {
    let heap_delta_per_message = 1024;
    // Two canisters each get one message.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 1,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        NumInstructions::from(10),
        NumBytes::new(heap_delta_per_message),
    ));

    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));
    with_test_replica_logger(|log| {
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_max_num_instructions(MAX_INSTRUCTIONS_PER_MESSAGE)
                .build(),
        );
        let scheduler = SchedulerImpl::new(
            scheduler_test_fixture.scheduler_config.clone(),
            subnet_test_id(1),
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            &scheduler_test_fixture.metrics_registry,
            log,
            FlagStatus::Disabled,
            FlagStatus::Enabled,
        );
        let state = get_initial_state(
            scheduler_test_fixture.canister_num,
            scheduler_test_fixture.message_num_per_canister,
        );

        scheduler.execute_round(
            state,
            Randomness::from([0; 32]),
            None,
            ExecutionRound::from(2),
            ProvisionalWhitelist::Set(BTreeSet::new()),
            MAX_NUMBER_OF_CANISTERS,
        );

        let registry = &scheduler_test_fixture.metrics_registry;
        assert_eq!(
            fetch_histogram_stats(registry, "scheduler_canister_heap_delta_debits")
                .unwrap()
                .count as u64,
            2
        );
        assert_eq!(
            fetch_histogram_stats(registry, "scheduler_canister_heap_delta_debits")
                .unwrap()
                .sum as u64,
            0
        );
        assert_eq!(
            fetch_histogram_stats(
                registry,
                "scheduler_heap_delta_rate_limited_canisters_per_round"
            )
            .unwrap()
            .count as u64,
            1
        );
        assert_eq!(
            fetch_histogram_stats(
                registry,
                "scheduler_heap_delta_rate_limited_canisters_per_round"
            )
            .unwrap()
            .sum as u64,
            0
        );
    });
}

#[test]
fn requested_method_does_not_exist() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 0,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        4,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(4);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedStateBuilder::new().build();

            let canister_id = canister_test_id(0);
            let mut canister_state = new_canister_state(
                canister_id,
                user_test_id(24).get(),
                *INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let mut exports = BTreeSet::new();
            exports.insert(WasmMethod::Update("write".to_string()));
            exports.insert(WasmMethod::Query("read".to_string()));
            let mut execution_state = initial_execution_state();
            execution_state.exports = ExportedFunctions::new(exports);
            canister_state.execution_state = Some(execution_state);

            for nonce in 0..3 {
                canister_state.push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .method_name("write".to_string())
                        .nonce(nonce)
                        .build()
                        .into(),
                );
            }
            canister_state.push_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_id)
                    .method_name("unknown".to_string())
                    .nonce(4)
                    .build()
                    .into(),
            );
            state.put_canister_state(canister_state);

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stopping_canisters_are_stopped_when_they_are_ready() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };

    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    let exec_env = Arc::new(exec_env);

    // Expect ingress history writer to be called twice to respond to
    // the two stop messages defined below.
    let ingress_history_writer = default_ingress_history_writer_mock(2);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedStateBuilder::new().build();
            // Create a canister in the stopping state and assume that the
            // controller sent two stop messages at the same time.
            let mut canister = get_stopping_canister(canister_test_id(0));

            canister
                .system_state
                .add_stop_context(StopCanisterContext::Ingress {
                    sender: user_test_id(0),
                    message_id: message_test_id(0),
                });

            canister
                .system_state
                .add_stop_context(StopCanisterContext::Ingress {
                    sender: user_test_id(0),
                    message_id: message_test_id(1),
                });

            state.put_canister_state(canister);

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(state.canister_states.len(), 1);
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.status(), CanisterStatusType::Stopped);
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stopping_canisters_are_not_stopped_if_not_ready() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: NumInstructions::from(5),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };

    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);

    // Expect ingress history writer to never be called since the canister
    // isn't ready to be stopped.
    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedStateBuilder::new().build();
            // Create a canister in the stopping state and assume that the
            // controller sent two stop messages at the same time.
            let mut canister = get_stopping_canister(canister_test_id(0));

            let stop_context_1 = StopCanisterContext::Ingress {
                sender: user_test_id(0),
                message_id: message_test_id(0),
            };

            let stop_context_2 = StopCanisterContext::Ingress {
                sender: user_test_id(0),
                message_id: message_test_id(1),
            };

            canister
                .system_state
                .add_stop_context(stop_context_1.clone());
            canister
                .system_state
                .add_stop_context(stop_context_2.clone());

            // Create a call context. Because there's a call context the
            // canister should _not_ be ready to be stopped, and therefore
            // the scheduler will keep it as-is in its stopping state.
            canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .new_call_context(
                    CallOrigin::Ingress(user_test_id(13), message_test_id(14)),
                    Cycles::from(10),
                    Time::from_nanos_since_unix_epoch(0),
                );

            let expected_ccm = canister
                .system_state
                .call_context_manager()
                .unwrap()
                .clone();

            state.put_canister_state(canister);

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(state.canister_states.len(), 1);
            assert_eq!(
                state
                    .canister_state_mut(&canister_test_id(0))
                    .unwrap()
                    .system_state
                    .status,
                CanisterStatus::Stopping {
                    stop_contexts: vec![stop_context_1, stop_context_2],
                    call_context_manager: expected_ccm
                }
            );
            assert!(!state
                .canister_state_mut(&canister_test_id(0))
                .unwrap()
                .system_state
                .ready_to_stop());
        },
        ingress_history_writer,
        Arc::new(exec_env),
    );
}

#[test]
fn replicated_state_metrics_nothing_exported() {
    let state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
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
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(400),
            max_instructions_per_message: NumInstructions::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 5,
    };
    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        10,
        NumInstructions::from(10),
        NumBytes::new(0),
    );

    exec_env
        .expect_execute_subnet_message()
        .times(3)
        .returning(move |_, state, _, _, _, _, _, _| (state, NumInstructions::from(0)));

    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(10);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let canister = state.canisters_iter().next().unwrap();
            let controller_id = canister.system_state.controllers.iter().next().unwrap();
            let controller = CanisterId::new(*controller_id).unwrap();
            let canister_id = canister.canister_id();
            let subnet_id = state.metadata.own_subnet_id;
            let payload = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            let cycles = 1000000;
            for _ in 0..3 {
                state
                    .subnet_queues_mut()
                    .push_input(
                        QUEUE_INDEX_NONE,
                        RequestOrResponse::Request(
                            RequestBuilder::new()
                                .sender(controller)
                                .receiver(CanisterId::from(subnet_id))
                                .method_name(Method::CanisterStatus)
                                .method_payload(payload.clone())
                                .payment(Cycles::from(cycles))
                                .build(),
                        ),
                        InputQueueType::RemoteSubnet,
                    )
                    .unwrap();
            }
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(1, scheduler.metrics.round.duration.get_sample_count(),);
            assert_eq!(1, scheduler.metrics.round.instructions.get_sample_count(),);
            assert_eq!(
                130,
                scheduler.metrics.round.instructions.get_sample_sum() as u64
            );
            assert_eq!(1, scheduler.metrics.round.messages.get_sample_count());
            assert_eq!(13, scheduler.metrics.round.messages.get_sample_sum() as u64);
            assert_eq!(
                1,
                scheduler
                    .metrics
                    .round_subnet_queue
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                1,
                scheduler
                    .metrics
                    .round_subnet_queue
                    .instructions
                    .get_sample_count()
            );
            assert_eq!(
                30,
                scheduler
                    .metrics
                    .round_subnet_queue
                    .instructions
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                1,
                scheduler
                    .metrics
                    .round_subnet_queue
                    .messages
                    .get_sample_count()
            );
            assert_eq!(
                3,
                scheduler
                    .metrics
                    .round_subnet_queue
                    .messages
                    .get_sample_sum() as u64,
            );
            assert_eq!(1, scheduler.metrics.round_inner.duration.get_sample_count());
            assert_eq!(
                1,
                scheduler
                    .metrics
                    .round_inner
                    .instructions
                    .get_sample_count()
            );
            assert_eq!(
                100,
                scheduler.metrics.round_inner.instructions.get_sample_sum() as u64,
            );
            assert_eq!(1, scheduler.metrics.round_inner.messages.get_sample_count());
            assert_eq!(
                10,
                scheduler.metrics.round_inner.messages.get_sample_sum() as u64,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .instructions
                    .get_sample_count(),
            );
            assert_eq!(
                100,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .instructions
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .messages
                    .get_sample_count(),
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .messages
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread
                    .instructions
                    .get_sample_count(),
            );
            assert_eq!(
                100,
                scheduler
                    .metrics
                    .round_inner_iteration_thread
                    .instructions
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread
                    .messages
                    .get_sample_count(),
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration_thread
                    .messages
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_message
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_message
                    .instructions
                    .get_sample_count(),
            );
            assert_eq!(
                100,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_message
                    .instructions
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_message
                    .messages
                    .get_sample_count(),
            );
            assert_eq!(
                10,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_message
                    .messages
                    .get_sample_sum() as u64,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn heartbeat_metrics_are_recorded() {
    // This test sets up a canister on a system subnet with a heartbeat method.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::system_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 1,
    };
    let mut exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        NumInstructions::from(1),
        NumBytes::new(0),
    );
    exec_env
        .expect_execute_canister_heartbeat()
        .times(2)
        .returning(move |canister, _, _, _, _| {
            let canister0 = canister_test_id(0);
            let canister1 = canister_test_id(1);
            if canister.canister_id() == canister0 {
                (canister, NumInstructions::from(0), Ok(NumBytes::new(1)))
            } else if canister.canister_id() == canister1 {
                (
                    canister,
                    NumInstructions::from(0),
                    Err(CanisterHeartbeatError::CanisterExecutionFailed(
                        HypervisorError::WasmEngineError(WasmEngineError::FailedToInitializeEngine),
                    )),
                )
            } else {
                unreachable!("Should only be executing canisters 0 and 1")
            }
        });
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(2);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            for canister in state.canisters_iter_mut() {
                if let Some(ref mut execution_state) = canister.execution_state {
                    execution_state.exports = ExportedFunctions::new(
                        [WasmMethod::System(SystemMethod::CanisterHeartbeat)]
                            .iter()
                            .cloned()
                            .collect(),
                    );
                }
            }
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_heartbeat
                    .instructions
                    .get_sample_count(),
            );
            assert_eq!(
                200,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_heartbeat
                    .instructions
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_heartbeat
                    .messages
                    .get_sample_count(),
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration_thread_heartbeat
                    .messages
                    .get_sample_sum() as u64,
            );
            assert_eq!(
                1,
                scheduler
                    .metrics
                    .execution_round_failed_heartbeat_executions
                    .get()
            )
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execution_round_does_not_too_early() {
    // In this test we have 2 canisters with 10 input messages that execute 10
    // instructions each. There are two scheduler cores, so each canister gets
    // its own thread for running. With the round limit of 150 instructions and
    // each canister executing 100 instructions, we expect two iterations
    // because the canisters are executing in parallel.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(150),
            max_instructions_per_message: NumInstructions::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        20,
        NumInstructions::from(10),
        NumBytes::new(0),
    );

    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(20);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );
            assert_eq!(
                2,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .instructions
                    .get_sample_count(),
            );
            assert_eq!(
                200,
                scheduler
                    .metrics
                    .round_inner_iteration
                    .instructions
                    .get_sample_sum() as u64,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn canisters_reject_open_call_contexts_when_forcibly_uninstalled() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(150),
            max_instructions_per_message: NumInstructions::from(10),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        NumInstructions::from(10),
        NumBytes::new(0),
    );

    let exec_env = Arc::new(exec_env);

    // A canister gets charged based on the duration of time between two blocks,
    // which is the difference between the following two times.
    let time_in_future = Time::from_nanos_since_unix_epoch(100000000000000);
    let time_now = Time::from_nanos_since_unix_epoch(1);

    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(0));
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedStateBuilder::new()
                .with_time(time_in_future)
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_canister_id(canister_test_id(0))
                        .build(),
                )
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_canister_id(canister_test_id(1))
                        // No cycles, so that it gets uninstalled.
                        .with_cycles(0)
                        // Add an allocation so that a canister needs to pay > 0 cycles.
                        .with_compute_allocation(ComputeAllocation::try_from(10).unwrap())
                        // Create a request from canister 0 so that there's an output queue
                        // from canister 1 to canister 0.
                        .with_canister_request(
                            RequestBuilder::new()
                                .sender(canister_test_id(0))
                                .receiver(canister_test_id(1))
                                .build(),
                        )
                        // Create a call context that should result in a response back to canister
                        // 0.
                        .with_call_context(
                            CallContextBuilder::new()
                                .with_call_origin(CallOrigin::CanisterUpdate(
                                    canister_test_id(0),
                                    CallbackId::from(0),
                                ))
                                .with_responded(false)
                                .build(),
                        )
                        .build(),
                )
                .build();

            state.metadata.time_of_last_allocation_charge = time_now;
            scheduler.charge_canisters_for_resource_allocation_and_usage(&mut state);

            // Verify that the response is in the output queue.
            assert!(
                state
                    .canister_state(&canister_test_id(1))
                    .unwrap()
                    .has_output(),
                "Expected response to canister 0 in canister 1's output queue."
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn replicated_state_metrics_running_canister() {
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    state.put_canister_state(get_running_canister(canister_test_id(0)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
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
fn test_uninstall_canister() {
    let mut canister = CanisterStateBuilder::new()
        .with_canister_id(canister_test_id(0))
        .with_cycles(0)
        .with_wasm(vec![4, 5, 6])
        .with_stable_memory(vec![1, 2, 3])
        .with_memory_allocation(1000)
        .with_compute_allocation(ComputeAllocation::try_from(99).unwrap())
        .build();
    uninstall_canister(
        &no_op_logger(),
        &mut canister,
        &PathBuf::from("NOT_USED"),
        mock_time(),
    );

    assert_eq!(canister.execution_state, None);
}

#[test]
fn replicated_state_metrics_different_canister_statuses() {
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    state.put_canister_state(get_running_canister(canister_test_id(0)));
    state.put_canister_state(get_stopped_canister(canister_test_id(2)));
    state.put_canister_state(get_stopping_canister(canister_test_id(1)));
    state.put_canister_state(get_stopped_canister(canister_test_id(3)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(
        subnet_test_id(1),
        &state,
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
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

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
        &scheduler_metrics,
        &no_op_logger(),
    );

    assert_eq!(
        fetch_int_gauge(&registry, "replicated_state_canisters_not_in_routing_table"),
        Some(0)
    );
}

#[test]
fn replicated_state_metrics_some_canisters_not_in_routing_table() {
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

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
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    let context_creation_time = Time::from_nanos_since_unix_epoch(10);
    // The round occurs one day after the call context was created so it should
    // be recorded.
    let round_time = context_creation_time + Duration::from_secs(60 * 60 * 24);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let state = ReplicatedStateBuilder::new()
                .with_time(round_time)
                .with_canister(
                    CanisterStateBuilder::new()
                        .with_canister_id(canister_test_id(1))
                        .with_cycles(1_000_000_000_000_000u64)
                        .with_call_context(
                            CallContextBuilder::new()
                                .with_call_origin(CallOrigin::CanisterUpdate(
                                    canister_test_id(0),
                                    CallbackId::from(0),
                                ))
                                .with_responded(false)
                                .with_time(context_creation_time)
                                .build(),
                        )
                        .build(),
                )
                .build();

            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                None,
                ExecutionRound::from(4),
                ProvisionalWhitelist::Set(BTreeSet::new()),
                MAX_NUMBER_OF_CANISTERS,
            );

            let registry = &scheduler_test_fixture.metrics_registry;
            assert_eq!(
                fetch_int_gauge_vec(registry, "scheduler_old_open_call_contexts")[&btreemap! {
                    "age".to_string() => "1d".to_string()
                }],
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

// In the following tests we check that the order of the canisters
// inside `inner_round` is the same as the one provided by the scheduling strategy.
#[test]
fn scheduler_maintains_canister_order() {
    // A list of canisters with different computation allocation values set.
    let canisters = vec![
        CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(0))
            .with_compute_allocation(ComputeAllocation::try_from(60).unwrap())
            .build(),
        CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(1))
            .with_compute_allocation(ComputeAllocation::try_from(100).unwrap())
            .build(),
        CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(2))
            .with_compute_allocation(ComputeAllocation::try_from(90).unwrap())
            .build(),
        CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(4))
            .with_compute_allocation(ComputeAllocation::try_from(60).unwrap())
            .build(),
    ];
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );
    for mut canister in canisters {
        canister.push_ingress(
            SignedIngressBuilder::new()
                .canister_id(canister.canister_id())
                .build()
                .into(),
        );
        state.put_canister_state(canister);
    }
    // This canister has no messages.
    state.put_canister_state(
        CanisterStateBuilder::new()
            .with_canister_id(canister_test_id(100))
            .with_compute_allocation(ComputeAllocation::try_from(0).unwrap())
            .build(),
    );

    let num_messages = 4;
    let scheduler_cores = 1;
    let current_round = ExecutionRound::from(1);
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg
                + NumInstructions::from(1),
            instruction_overhead_per_message: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: state.canister_states.len() as u64,
        message_num_per_canister: 1,
    };

    let mut exec_env = MockExecutionEnvironment::new();
    let num_instructions_left = scheduler_test_fixture
        .scheduler_config
        .max_instructions_per_message
        - num_instructions_consumed_per_msg;

    // The expected order which will be used to execute canisters.
    let expected_ordered_canisters = apply_scheduling_strategy(
        scheduler_cores,
        current_round,
        &mut state.canister_states.clone(),
    );
    let ordered_canisters = expected_ordered_canisters.clone();

    // Return sufficiently large subnet and canister memory limits.
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_max_canister_memory_size()
        .times(..)
        .return_const(MAX_CANISTER_MEMORY_SIZE);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    let mut index = 0;
    exec_env
        .expect_execute_canister_message()
        .times(num_messages)
        .returning(move |canister, _, msg, _, _, _| {
            if let CanisterInputMessage::Ingress(msg) = msg {
                let canister_id = canister.canister_id();
                // Canister 5 does not have any messages.
                assert!(canister_id != canister_test_id(5));
                assert_eq!(expected_ordered_canisters[index], canister_id);
                index += 1;

                ExecuteMessageResult {
                    canister: canister.clone(),
                    num_instructions_left,
                    ingress_status: Some((
                        msg.message_id,
                        IngressStatus::Completed {
                            receiver: canister.canister_id().get(),
                            user_id: user_test_id(0),
                            result: WasmResult::Reply(vec![]),
                            time: mock_time(),
                        },
                    )),
                    heap_delta: NumBytes::new(0),
                }
            } else {
                unreachable!("Only ingress messages are expected.");
            }
        });
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(num_messages);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let measurement_scope = MeasurementScope::root(&scheduler.metrics.round);
            scheduler.inner_round(state, &ordered_canisters, current_round, &measurement_scope);
        },
        ingress_history_writer,
        exec_env,
    );
}

proptest! {
    // In the following tests we use a notion of `minimum_executed_messages` per
    // execution round. The minimum is defined as `min(available_messages,
    // floor(`max_instructions_per_round` / `max_instructions_per_message`))`. `available_messages` are the sum of
    // messages in the input queues of all canisters.

    #[test]
    // This test verifies that the scheduler will never consume more than
    // `max_instructions_per_round` in a single execution round.
    fn should_never_consume_more_than_max_instructions_per_round_in_a_single_execution_round(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg,
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let ingress_history_writer = default_ingress_history_writer_mock(
            minimum_executed_messages as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
                scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    None,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_NUMBER_OF_CANISTERS,
                );
            },
            ingress_history_writer,
            Arc::new(exec_env),
        );
    }

    #[test]
    // This test verifies that the scheduler is deterministic, i.e. given
    // the same input, if we execute a round of computation, we always
    // get the same result.
    fn scheduler_deterministically_produces_same_output_given_same_input(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            2 * minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let ingress_history_writer = default_ingress_history_writer_mock(
            (minimum_executed_messages * 2) as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
                let new_state1 = scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    None,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_NUMBER_OF_CANISTERS,
                );
                let new_state2 = scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    None,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_NUMBER_OF_CANISTERS,
                );
                assert_eq!(new_state1, new_state2);
            },
            ingress_history_writer,
            Arc::new(exec_env),
        );
    }

    #[test]
    // This test verifies that the scheduler can successfully deplete the induction
    // pool given sufficient consecutive execution rounds.
    fn scheduler_can_deplete_induction_pool_given_enough_execution_rounds(
        scheduler_cores in scheduler_cores(),
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        mut state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg
        );
        let required_rounds = if minimum_executed_messages != 0 {
            available_messages / minimum_executed_messages + 1
        } else {
            1
        };
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 0, // Not used in this test
            message_num_per_canister: 0, // Not used in this test
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            available_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let exec_env = Arc::new(exec_env);

        let start_round = LAST_ROUND_MAX + 1;
        let end_round = required_rounds + start_round;
        let ingress_history_writer = default_ingress_history_writer_mock(available_messages as usize);
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
                for round in start_round..end_round {
                    state =
                        scheduler.execute_round(
                            state,
                            Randomness::from([0; 32]),
                            None,
                            ExecutionRound::from(round),
                            ProvisionalWhitelist::Set(BTreeSet::new()),
                            MAX_NUMBER_OF_CANISTERS,
                        );
                }
                for canister_state in state.canisters_iter() {
                    assert_eq!(canister_state.system_state.queues().ingress_queue_size(), 0);
                }
            },
            ingress_history_writer,
            exec_env,
        );
    }

    #[test]
    // This test verifies that the scheduler does not lose any canisters
    // after an execution round.
    fn scheduler_does_not_lose_canisters(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg,
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
            instruction_overhead_per_message: NumInstructions::from(0),
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let exec_env = Arc::new(exec_env);

        let ingress_history_writer = default_ingress_history_writer_mock(
            minimum_executed_messages as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
                let original_canister_count = state.canisters_iter().count();
                let state = scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    None,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                    MAX_NUMBER_OF_CANISTERS,
                );
                assert_eq!(state.canisters_iter().count(), original_canister_count);
            },
            ingress_history_writer,
            exec_env,
        );
    }

    #[test]
    // Verifies that each canister is scheduled as the first of its thread as
    // much as its compute_allocation requires.
    fn scheduler_respects_compute_allocation(
        mut replicated_state in arb_replicated_state(24, 2, 1),
        mut scheduler_cores in 1..16_usize
    ) {
        let number_of_canisters = replicated_state.canister_states.len();
        let total_compute_allocation = replicated_state.total_compute_allocation() as usize;

        // Ensure that the capacity is greater than the total_compute_allocation.
        if total_compute_allocation >= 100 * scheduler_cores {
            scheduler_cores = total_compute_allocation / 100 + 1;
        }

        // Count, for each canister, how many times it is the first canister
        // to be executed by a thread.
        let mut scheduled_first_counters = HashMap::<CanisterId, usize>::new();

        // Because we may be left with as little free compute capacity as 1, run for
        // enough rounds that every canister gets a chance to be scheduled at least once
        // for free, i.e. `100 * number_of_canisters` rounds.
        let number_of_rounds = 100 * number_of_canisters;

        for i in 0..number_of_rounds {
            // Ask for partitioning.
            let ordered_canister_ids = apply_scheduling_strategy(
                scheduler_cores,
                ExecutionRound::new(i as u64),
                &mut replicated_state.canister_states,
            );

            // "Schedule" the first `scheduler_cores` canisters.
            for canister_id in ordered_canister_ids
                .iter()
                .take(min(scheduler_cores, ordered_canister_ids.len()))
            {
                let count = scheduled_first_counters.entry(*canister_id).or_insert(0);
                *count += 1;
            }
        }

        // Check that the compute allocations of the canisters are respected.
        for (canister_id, canister) in replicated_state.canister_states.iter() {
            let compute_allocation =
                canister.scheduler_state.compute_allocation.as_percent() as usize;

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
}

struct SchedulerTestFixture {
    pub scheduler_config: SchedulerConfig,
    pub metrics_registry: MetricsRegistry,
    pub canister_num: u64,
    pub message_num_per_canister: u64,
}

fn default_exec_env_mock(
    f: &SchedulerTestFixture,
    calls: usize,
    cycles_per_message: NumInstructions,
    heap_delta_per_message: NumBytes,
) -> MockExecutionEnvironment {
    let mut exec_env = MockExecutionEnvironment::new();
    let num_instructions_left =
        f.scheduler_config.max_instructions_per_message - cycles_per_message;

    // Return sufficiently large subnet and canister memory limits.
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .return_const(*SUBNET_AVAILABLE_MEMORY);
    exec_env
        .expect_max_canister_memory_size()
        .times(..)
        .return_const(MAX_CANISTER_MEMORY_SIZE);
    exec_env
        .expect_subnet_memory_capacity()
        .times(..)
        .return_const(SUBNET_MEMORY_CAPACITY);
    exec_env
        .expect_execute_canister_message()
        .times(calls)
        .returning(move |canister, _, msg, _, _, _| {
            if let CanisterInputMessage::Ingress(msg) = msg {
                ExecuteMessageResult {
                    canister: canister.clone(),
                    num_instructions_left,
                    ingress_status: Some((
                        msg.message_id,
                        IngressStatus::Completed {
                            receiver: canister.canister_id().get(),
                            user_id: user_test_id(0),
                            result: WasmResult::Reply(vec![]),
                            time: mock_time(),
                        },
                    )),
                    heap_delta: heap_delta_per_message,
                }
            } else {
                unreachable!("Only ingress messages are expected.");
            }
        });
    exec_env
}

fn default_ingress_history_writer_mock(calls: usize) -> MockIngressHistory {
    let mut ingress_history_writer = MockIngressHistory::new();
    ingress_history_writer
        .expect_set_status()
        .with(always(), always(), always())
        .times(calls)
        .returning(|_, _, _| {});
    ingress_history_writer
}

fn scheduler_test(
    test_fixture: &SchedulerTestFixture,
    run_test: impl FnOnce(SchedulerImpl),
    ingress_history_writer: Arc<MockIngressHistory>,
    exec_env: Arc<MockExecutionEnvironment>,
) {
    with_test_replica_logger(|log| {
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_max_num_instructions(MAX_INSTRUCTIONS_PER_MESSAGE)
                .build(),
        );
        let scheduler = SchedulerImpl::new(
            test_fixture.scheduler_config.clone(),
            subnet_test_id(1),
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            &test_fixture.metrics_registry,
            log,
            FlagStatus::Enabled,
            FlagStatus::Enabled,
        );
        run_test(scheduler);
    });
}

// Returns the sum of messages of the input queues of all canisters.
fn get_available_messages(state: &ReplicatedState) -> u64 {
    state
        .canisters_iter()
        .map(|canister_state| canister_state.system_state.queues().ingress_queue_size() as u64)
        .sum()
}

prop_compose! {
    fn scheduler_cores() (scheduler_cores in 1..32usize) -> usize {
        scheduler_cores
    }
}

prop_compose! {
    fn instructions_limits()
    (
        num_instructions_consumed_per_msg in 1..1_000_000u64, max_instructions_per_round in 1_000_000..1_000_000_000u64
    ) -> (NumInstructions, NumInstructions) {
        (NumInstructions::from(num_instructions_consumed_per_msg), NumInstructions::from(max_instructions_per_round))
    }
}
