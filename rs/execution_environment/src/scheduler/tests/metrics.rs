//! Tests for scheduler metrics.

use super::super::test_utilities::{
    SchedulerTestBuilder, TestInstallCode, ingress, instructions, on_response, other_side,
};
use super::super::*;
use super::{make_ecdsa_key_id, make_schnorr_key_id, zero_instruction_messages};
use candid::Encode;
use ic_config::subnet_config::SchedulerConfig;
use ic_error_types::RejectCode;
use ic_logger::no_op_logger;
use ic_management_canister_types_private::{
    self as ic00, BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterIdRecord, DerivationPath,
    HttpMethod, MasterPublicKeyId, Method, Payload as _, SignWithECDSAArgs, SignWithSchnorrArgs,
    TransformContext, TransformFunc,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_replicated_state::metadata_state::testing::NetworkTopologyTesting;
use ic_replicated_state::testing::SystemStateTesting;
use ic_test_utilities_metrics::{
    HistogramStats, fetch_gauge, fetch_gauge_vec, fetch_histogram_vec_stats, fetch_int_gauge,
    fetch_int_gauge_vec, metric_vec,
};
use ic_test_utilities_state::{get_running_canister, get_stopped_canister, get_stopping_canister};
use ic_types::batch::ConsensusResponse;
use ic_types::messages::{
    CallbackId, Payload, RejectContext, StopCanisterCallId, StopCanisterContext,
};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::time::UNIX_EPOCH;
use ic_types_test_utils::ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id};
use more_asserts::assert_ge;
use std::time::Duration;

#[test]
fn validate_consumed_instructions_metric() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_query_message: NumInstructions::from(50),
            max_instructions_per_slice: NumInstructions::new(50),
            max_instructions_per_install_code_slice: NumInstructions::new(50),
            max_instructions_per_round: NumInstructions::from(400),
            instruction_overhead_per_execution: NumInstructions::from(0),
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

    // 1 round, 2 inner iterations, 2 messages. Each 100 instructions.
    assert_eq!(metrics.round.instructions.get_sample_count(), 1);
    assert_eq!(metrics.round.instructions.get_sample_sum(), 100_f64);
    assert_eq!(
        metrics
            .round_inner_iteration
            .instructions
            .get_sample_count(),
        2
    );
    assert_eq!(
        metrics.round_inner_iteration.instructions.get_sample_sum(),
        100_f64,
    );
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        2
    );
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_sum(),
        100_f64,
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
            max_instructions_per_query_message: NumInstructions::new(5),
            max_instructions_per_slice: NumInstructions::from(5),
            max_instructions_per_install_code_slice: NumInstructions::from(5),
            instruction_overhead_per_execution: NumInstructions::from(0),
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
    assert_eq!(metrics.round.instructions.get_sample_count(), 1);
    assert_eq!(
        metrics.round.instructions.get_sample_sum() as i64,
        5 + 4 + 4
    );

    // No messages consumed zero instructions.
    assert_eq!(zero_instruction_messages(test.metrics_registry()), 0);
}

#[test]
fn can_record_metrics_for_a_round() {
    let num_canisters = 3;
    let scheduler_cores = num_canisters as usize - 1;
    let instructions = 5;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores,
            max_instructions_per_round: NumInstructions::from(instructions * 2),
            max_instructions_per_message: NumInstructions::from(instructions),
            max_instructions_per_query_message: NumInstructions::new(instructions),
            max_instructions_per_slice: NumInstructions::from(instructions),
            max_instructions_per_install_code_slice: NumInstructions::from(instructions),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    // The first two canisters have an `Allocation` of 45% and the last 9%. We'll be
    // forced to execute the first two and then run out of instructions (based on
    // the limits) which will result in a violation of third canister's
    // `Allocation`.
    for i in 0..num_canisters {
        let compute_allocation = if i < 2 { 45 } else { 9 };
        let canister = test.create_canister_with(
            Cycles::new(1_000_000_000_000_000),
            ComputeAllocation::try_from(compute_allocation).unwrap(),
            MemoryAllocation::default(),
            None,
            None,
            None,
        );
        for _ in 0..5 {
            test.send_ingress(canister, ingress(instructions));
        }
    }

    for canister in test.state_mut().canisters_iter_mut() {
        Arc::make_mut(canister)
            .system_state
            .time_of_last_allocation_charge = UNIX_EPOCH + Duration::from_secs(1);
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
        metrics.executable_canisters_per_round.get_sample_sum() as u64,
        num_canisters
    );
    // The canister age metric is not observed for newly created canisters.
    assert_eq!(metrics.canister_age.get_sample_sum() as i64, 0);
    assert_eq!(metrics.round_preparation_duration.get_sample_count(), 1);
    assert_eq!(metrics.round_preparation_ingress.get_sample_count(), 1);
    // Once for `apply_scheduling_strategy()`, once for `finish_round()`.
    assert_eq!(metrics.round_scheduling_duration.get_sample_count(), 2);
    assert_ge!(metrics.round_inner_iteration_prep.get_sample_count(), 1);
    assert_ge!(metrics.round_inner_iteration_exe.get_sample_count(), 1);
    assert_ge!(metrics.round_inner_iteration_fin.get_sample_count(), 1);
    assert_eq!(metrics.round_finalization_duration.get_sample_count(), 1);
    assert_eq!(
        metrics.round_finalization_stop_canisters.get_sample_count(),
        1
    );
    assert_eq!(metrics.round_finalization_ingress.get_sample_count(), 1);
    assert_eq!(metrics.round_finalization_charge.get_sample_count(), 1);
    // Compute allocation violation is not observed for newly created canisters.
    assert_eq!(metrics.canister_compute_allocation_violation.get(), 0);

    // `2 * scheduler_cores` messages were executed.
    assert_eq!(
        metrics.instructions_consumed_per_message.get_sample_count(),
        scheduler_cores as u64 * 2
    );
    // All of them consumed some instructions.
    assert_eq!(zero_instruction_messages(test.metrics_registry()), 0);

    assert_eq!(
        test.state()
            .metadata
            .subnet_metrics
            .update_transactions_total,
        scheduler_cores as u64 * 2
    );
    assert_eq!(
        test.state().metadata.subnet_metrics.num_canisters,
        num_canisters
    );

    // Bump up the round number.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // For allocation violation to happen, the canister age should be more than `100/9 = 11 rounds`
    // plus 2 rounds already executed.
    test.advance_to_round(ExecutionRound::from(11 + 2));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    // The canister age metric should be observed now.
    assert_eq!(metrics.canister_age.get_sample_sum() as i64, 12);
    // Compute allocation violation should also be observed now.
    assert_eq!(metrics.canister_compute_allocation_violation.get(), 1);
}

/// Check that when a canister is scheduled and can't prepay for execution, the
/// message time isn't recorded, but the metric for zero instruction messages is
/// incremented.
#[test]
fn prepay_failures_counted() {
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(1000),
            max_instructions_per_message: NumInstructions::from(100),
            max_instructions_per_query_message: NumInstructions::new(100),
            max_instructions_per_slice: NumInstructions::from(100),
            max_instructions_per_install_code_slice: NumInstructions::from(100),
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            instruction_overhead_per_canister_for_finalization: NumInstructions::from(0),
            ..SchedulerConfig::application_subnet()
        })
        .build();

    let canister_with_cycles = test.create_canister_with(
        Cycles::new(1_000_000_000_000_000),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        None,
        None,
    );
    let canister_without_cycles = test.create_canister_with(
        Cycles::new(10),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        None,
        None,
    );
    test.send_ingress(canister_with_cycles, ingress(5));
    test.send_ingress(canister_without_cycles, ingress(5));

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let metrics = &test.scheduler().metrics;
    // We should have one entry for the canister with cycles that ran.
    assert_eq!(metrics.msg_execution_duration.get_sample_count(), 1);
    // We should have one count for the canister that couldn't prepay.
    assert_eq!(zero_instruction_messages(test.metrics_registry()), 1);
}

#[test]
fn replicated_state_metrics_nothing_exported() {
    let state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let registry = MetricsRegistry::new();
    let state_metrics = ReplicatedStateMetrics::new(&registry);

    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

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
            max_instructions_per_query_message: NumInstructions::new(10),
            max_instructions_per_slice: NumInstructions::from(10),
            max_instructions_per_install_code_slice: NumInstructions::from(10),
            instruction_overhead_per_execution: NumInstructions::from(0),
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
        metrics.instructions_consumed_per_message.get_sample_count(),
    );
    assert_eq!(
        100,
        metrics.instructions_consumed_per_message.get_sample_sum() as u64,
    );
    assert_eq!(10, metrics.msg_execution_duration.get_sample_count());
}

#[test]
fn replicated_state_metrics_running_canister() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(0)));

    let registry = MetricsRegistry::new();
    let state_metrics = ReplicatedStateMetrics::new(&registry);

    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

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
    let state_metrics = ReplicatedStateMetrics::new(&registry);

    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

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

    state
        .metadata
        .network_topology
        .routing_table_mut()
        .insert(
            CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(3),
            },
            subnet_test_id(1),
        )
        .unwrap();

    let registry = MetricsRegistry::new();
    let state_metrics = ReplicatedStateMetrics::new(&registry);

    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

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
    let state_metrics = ReplicatedStateMetrics::new(&registry);
    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

    assert_eq!(state_metrics.stop_canister_calls_without_call_id(), 1);
}

#[test]
fn replicated_state_metrics_some_canisters_not_in_routing_table() {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    state.put_canister_state(get_running_canister(canister_test_id(2)));
    state.put_canister_state(get_running_canister(canister_test_id(100)));

    state
        .metadata
        .network_topology
        .routing_table_mut()
        .insert(
            CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(5),
            },
            subnet_test_id(1),
        )
        .unwrap();

    let registry = MetricsRegistry::new();
    let state_metrics = ReplicatedStateMetrics::new(&registry);

    state_metrics.observe(subnet_test_id(1), &state, 0.into(), &no_op_logger());

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

    let state_metrics = &test.scheduler().state_metrics;
    let gauge = state_metrics
        .old_open_call_contexts()
        .get_metric_with_label_values(&["1d"])
        .unwrap();
    assert_eq!(gauge.get(), 3);

    let gauge = state_metrics
        .canisters_with_old_open_call_contexts()
        .get_metric_with_label_values(&["1d"])
        .unwrap();
    assert_eq!(gauge.get(), 2);
}

#[test]
fn threshold_signature_agreements_metric_is_updated() {
    let ecdsa_key_id = make_ecdsa_key_id(0);
    let master_ecdsa_key_id = MasterPublicKeyId::Ecdsa(ecdsa_key_id.clone());
    let schnorr_key_id = make_schnorr_key_id(0);
    let master_schnorr_key_id = MasterPublicKeyId::Schnorr(schnorr_key_id.clone());
    let mut test = SchedulerTestBuilder::new()
        .with_replica_version(ReplicaVersion::default())
        .with_chain_keys(vec![
            master_ecdsa_key_id.clone(),
            master_schnorr_key_id.clone(),
        ])
        .build();

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        1.into(),
        &no_op_logger(),
    );

    let canister_id = test.create_canister();

    let ecdsa_payload = Encode!(&SignWithECDSAArgs {
        message_hash: [1; 32],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: ecdsa_key_id,
    })
    .unwrap();
    let schnorr_payload = Encode!(&SignWithSchnorrArgs {
        message: vec![1; 128],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: schnorr_key_id,
        aux: None,
    })
    .unwrap();

    // inject three signing request
    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        ecdsa_payload.clone(),
        test.ecdsa_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        ecdsa_payload,
        test.ecdsa_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
    test.inject_call_to_ic00(
        Method::SignWithSchnorr,
        schnorr_payload,
        test.schnorr_signature_fee(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );

    // There should be no in flight contexts yet
    let in_flight_contexts_metric = fetch_histogram_vec_stats(
        test.metrics_registry(),
        "execution_in_flight_signature_request_contexts",
    );
    assert!(in_flight_contexts_metric.is_empty());

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // At the end of the round, the in flight contexts should have been observed.
    let in_flight_contexts_metric = fetch_histogram_vec_stats(
        test.metrics_registry(),
        "execution_in_flight_signature_request_contexts",
    );
    assert_eq!(
        metric_vec(&[
            (
                &[("key_id", &master_ecdsa_key_id.to_string())],
                HistogramStats { count: 1, sum: 2.0 }
            ),
            (
                &[("key_id", &master_schnorr_key_id.to_string())],
                HistogramStats { count: 1, sum: 1.0 }
            ),
        ]),
        in_flight_contexts_metric,
    );

    // Check that the SubnetCallContextManager contains all requests.
    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();
    assert_eq!(sign_with_ecdsa_contexts.len(), 2);
    let sign_with_schnorr_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_schnorr_contexts();
    assert_eq!(sign_with_schnorr_contexts.len(), 1);

    // reject the first ecdsa context
    let (callback_id, _) = sign_with_ecdsa_contexts.iter().next().unwrap();
    let response = ConsensusResponse::new(
        *callback_id,
        Payload::Reject(RejectContext::new(RejectCode::SysFatal, "")),
    );

    test.state_mut().consensus_queue.push(response);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // After the round, the rejected context should be observed
    let in_flight_contexts_metric = fetch_histogram_vec_stats(
        test.metrics_registry(),
        "execution_in_flight_signature_request_contexts",
    );
    assert_eq!(
        metric_vec(&[
            (
                &[("key_id", &master_ecdsa_key_id.to_string())],
                HistogramStats { count: 2, sum: 3.0 }
            ),
            (
                &[("key_id", &master_schnorr_key_id.to_string())],
                HistogramStats { count: 2, sum: 2.0 }
            ),
        ]),
        in_flight_contexts_metric,
    );

    let threshold_signature_agreements_before = &test
        .state()
        .metadata
        .subnet_metrics
        .threshold_signature_agreements;
    let metric_before = fetch_int_gauge_vec(
        test.metrics_registry(),
        "replicated_state_threshold_signature_agreements_total",
    );

    // metric and state variable should not have been updated
    assert!(threshold_signature_agreements_before.is_empty());
    assert!(metric_before.is_empty());

    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();
    assert_eq!(sign_with_ecdsa_contexts.len(), 1);

    // send a reply to the remaining requests
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
    let (callback_id, _) = sign_with_schnorr_contexts.iter().next().unwrap();
    let response = ConsensusResponse::new(
        *callback_id,
        Payload::Data(
            ic00::SignWithSchnorrReply {
                signature: vec![1, 2, 3],
            }
            .encode(),
        ),
    );
    test.state_mut().consensus_queue.push(response);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        2.into(),
        &no_op_logger(),
    );

    let threshold_signature_agreements_after = &test
        .state()
        .metadata
        .subnet_metrics
        .threshold_signature_agreements;
    assert_eq!(threshold_signature_agreements_after.len(), 2);

    // Value of the new ecdsa metric should be set to 1
    let ecdsa_count = threshold_signature_agreements_after
        .get(&master_ecdsa_key_id)
        .unwrap();
    assert_eq!(1, *ecdsa_count);

    // Value of the new schnorr metric should be set to 1
    let schnorr_count = threshold_signature_agreements_after
        .get(&master_schnorr_key_id)
        .unwrap();
    assert_eq!(1, *schnorr_count);

    let metrics_after = fetch_int_gauge_vec(
        test.metrics_registry(),
        "replicated_state_threshold_signature_agreements_total",
    );
    assert_eq!(
        metrics_after,
        metric_vec(&[
            (&[("key_id", &master_ecdsa_key_id.to_string())], 1),
            (&[("key_id", &master_schnorr_key_id.to_string())], 1),
        ]),
    );

    // Check that the requests were removed.
    let sign_with_threshold_contexts = &test.state().signature_request_contexts();
    assert!(sign_with_threshold_contexts.is_empty());
}

#[test]
fn consumed_cycles_ecdsa_outcalls_are_added_to_consumed_cycles_total() {
    let key_id = make_ecdsa_key_id(0);
    let mut test = SchedulerTestBuilder::new()
        .with_chain_key(MasterPublicKeyId::Ecdsa(key_id.clone()))
        .build();

    let fee = test.ecdsa_signature_fee();
    let payment = fee;

    let canister_id = test.create_canister();

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &no_op_logger(),
    );

    let consumed_cycles_before = NominalCycles::from(
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
            key_id,
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
        .sign_with_ecdsa_contexts();
    assert_eq!(sign_with_ecdsa_contexts.len(), 1);

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &no_op_logger(),
    );
    let consumed_cycles_after = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    assert_eq!(
        consumed_cycles_before + NominalCycles::from(fee),
        consumed_cycles_after
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

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &no_op_logger(),
    );

    let consumed_cycles_before = NominalCycles::from(
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
        is_replicated: None,
        pricing_version: None,
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

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
        &no_op_logger(),
    );
    let consumed_cycles_after = NominalCycles::from(
        fetch_gauge(
            test.metrics_registry(),
            "replicated_state_consumed_cycles_since_replica_started",
        )
        .unwrap() as u128,
    );

    assert_eq!(
        consumed_cycles_before + NominalCycles::from(fee),
        consumed_cycles_after
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
fn http_outcalls_free() {
    let mut test = SchedulerTestBuilder::new()
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .build();
    let caller_canister = test.create_canister();

    test.state_mut().metadata.own_subnet_features.http_requests = true;

    let cycles_before = test.canister_state(caller_canister).system_state.balance();

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
        is_replicated: None,
        pricing_version: None,
    };

    // Create request to `HttpRequest` method.
    let payment = Cycles::new(0);
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
    assert_eq!(fee, Cycles::new(0));
    let cycles_after = test.canister_state(caller_canister).system_state.balance();
    assert_eq!(cycles_before, cycles_after);
}

#[test]
fn consumed_cycles_are_updated_from_valid_canisters() {
    let mut test = SchedulerTestBuilder::new().build();

    let canister_id = test.create_canister_with(
        Cycles::from(5_000_000_000_000u128),
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
        None,
        None,
        None,
    );

    let removed_cycles = Cycles::from(1000u128);
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(removed_cycles, CyclesUseCase::Instructions);

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
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
fn consumed_cycles_are_updated_from_deleted_canisters() {
    let mut test = SchedulerTestBuilder::new().build();
    let initial_balance = Cycles::from(5_000_000_000_000u128);
    let canister_id = test.create_canister_with(
        initial_balance,
        ComputeAllocation::zero(),
        MemoryAllocation::default(),
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

    test.scheduler().state_metrics.observe(
        test.scheduler().own_subnet_id,
        test.state(),
        0.into(),
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
