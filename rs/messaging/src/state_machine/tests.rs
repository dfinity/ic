use super::*;
use crate::message_routing::CRITICAL_ERROR_NON_INCREASING_BATCH_TIME;
use crate::{
    routing::demux::MockDemux, routing::stream_builder::MockStreamBuilder,
    state_machine::StateMachineImpl,
};
use ic_interfaces::execution_environment::Scheduler;
use ic_interfaces_state_manager::StateManager;
use ic_management_canister_types::MasterPublicKeyId;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{ReplicatedState, SubnetTopology};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_execution_environment::test_registry_settings;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_test_utilities_types::{
    batch::BatchBuilder, ids::subnet_test_id, messages::SignedIngressBuilder,
};
use ic_types::consensus::idkg::PreSigId;
use ic_types::messages::SignedIngress;
use ic_types::{batch::BatchMessages, crypto::canister_threshold_sig::MasterPublicKey};
use ic_types::{Height, PrincipalId, SubnetId, Time};
use maplit::btreemap;
use mockall::{mock, predicate::*, Sequence};
use std::collections::{BTreeMap, BTreeSet};

mock! {
    pub Scheduler {}
    impl Scheduler for Scheduler {
        type State = ReplicatedState;
        fn execute_round(
            &self,
            state: ic_replicated_state::ReplicatedState,
            randomness: ic_types::Randomness,
            idkg_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
            idkg_pre_signature_ids: BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>>,
            current_round: ExecutionRound,
            round_summary: Option<ExecutionRoundSummary>,
            current_round_type: ExecutionRoundType,
            registry_settings: &RegistryExecutionSettings,
        ) -> ReplicatedState;
    }
}

struct StateMachineTestFixture {
    scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
    demux: Box<dyn Demux>,
    stream_builder: Box<dyn StreamBuilder>,
    initial_state: ReplicatedState,
    network_topology: NetworkTopology,
    metrics: MessageRoutingMetrics,
    metrics_registry: MetricsRegistry,
}

/// Returns a test fixture for state machine tests with Mocks for Demux,
/// Scheduler, and StreamBuilder. The Mocks will ensure that a panic
/// occurs if they are called in the wrong order.
fn test_fixture(provided_batch: &Batch) -> StateMachineTestFixture {
    // Initial state provided by the state manager.
    let initial_height = Height::from(provided_batch.batch_number.get() - 1);
    let state_manager = FakeStateManager::new();
    let (_height, initial_state) = state_manager.take_tip();
    let metrics_registry = MetricsRegistry::new();
    let metrics = MessageRoutingMetrics::new(&metrics_registry);

    let round = ExecutionRound::from(initial_height.get() + 1);
    let round_type = if provided_batch.requires_full_state_hash {
        ExecutionRoundType::CheckpointRound
    } else {
        ExecutionRoundType::OrdinaryRound
    };

    let mut seq = Sequence::new();

    let mut demux = Box::new(MockDemux::new());
    demux
        .expect_process_payload()
        .times(1)
        .in_sequence(&mut seq)
        .with(always(), eq(provided_batch.messages.clone()))
        .returning(|state, _| state);

    let mut scheduler = Box::new(MockScheduler::new());
    scheduler
        .expect_execute_round()
        .times(1)
        .in_sequence(&mut seq)
        .with(
            always(),
            eq(provided_batch.randomness),
            eq(provided_batch.idkg_subnet_public_keys.clone()),
            eq(provided_batch.idkg_pre_signature_ids.clone()),
            eq(round),
            eq(None),
            eq(round_type),
            eq(test_registry_settings()),
        )
        .returning(|state, _, _, _, _, _, _, _| state);

    let mut stream_builder = Box::new(MockStreamBuilder::new());
    stream_builder
        .expect_build_streams()
        .times(1)
        .in_sequence(&mut seq)
        .with(always())
        .returning(|state| state);

    let mut subnets = BTreeMap::new();
    subnets.insert(
        subnet_test_id(0),
        SubnetTopology {
            public_key: vec![0, 1, 2, 3],
            nodes: BTreeSet::new(),
            subnet_type: SubnetType::Application,
            subnet_features: SubnetFeatures::default(),
            idkg_keys_held: BTreeSet::new(),
        },
    );

    let network_topology = NetworkTopology {
        subnets,
        routing_table: Default::default(),
        nns_subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(0)),
        canister_migrations: Default::default(),
        ..Default::default()
    };

    StateMachineTestFixture {
        scheduler,
        demux,
        stream_builder,
        initial_state,
        network_topology,
        metrics,
        metrics_registry,
    }
}

// Utility to build an Ingress message.
fn signed_ingress() -> SignedIngress {
    SignedIngressBuilder::new()
        .sign_for_randomly_generated_sender()
        .build()
}

#[test]
fn state_machine_populates_network_topology() {
    let provided_batch = BatchBuilder::new().batch_number(Height::new(1)).build();
    let fixture = test_fixture(&provided_batch);

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        ));

        assert_ne!(
            fixture.initial_state.metadata.network_topology,
            fixture.network_topology.clone()
        );

        let state = state_machine.execute_round(
            fixture.initial_state,
            fixture.network_topology.clone(),
            provided_batch,
            Default::default(),
            &test_registry_settings(),
            Default::default(),
            Default::default(),
        );

        assert_eq!(state.metadata.network_topology, fixture.network_topology);
    });
}

// Tests the processing of a batch. Ensures that the Demux, Scheduler, and
// StreamBuilder are invoked in order and that all of them are called.
fn test_delivered_batch(provided_batch: Batch) -> ReplicatedState {
    let fixture = test_fixture(&provided_batch);

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        ));

        state_machine.execute_round(
            fixture.initial_state,
            NetworkTopology::default(),
            provided_batch,
            Default::default(),
            &test_registry_settings(),
            Default::default(),
            Default::default(),
        )
    })
}

// Parameterized test engine for changing the number of ingress messages
// included in the provided batch.
fn param_batch_test(batch_num: Height, in_count: u64) {
    let mut ingress_messages = Vec::<SignedIngress>::new();
    for _ in 0..in_count {
        let in_msg = signed_ingress();
        ingress_messages.push(in_msg);
    }

    let batch_builder = BatchBuilder::new();
    let provided_batch = batch_builder
        .messages(BatchMessages {
            signed_ingress_msgs: ingress_messages,
            ..BatchMessages::default()
        })
        .batch_number(batch_num)
        .build();

    test_delivered_batch(provided_batch);
}

#[test]
fn test_delivered_batch_interface() {
    for i in 0..2 {
        param_batch_test(Height::from(27), i);
    }
}

#[test]
fn test_batch_time_regression() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(1),
        Time::from_nanos_since_unix_epoch(2),
        1,
    );
}

#[test]
fn test_batch_time_same() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(2),
        1,
    );
}

#[test]
fn test_batch_time_advance() {
    test_batch_time_impl(
        Time::from_nanos_since_unix_epoch(2),
        Time::from_nanos_since_unix_epoch(3),
        Time::from_nanos_since_unix_epoch(3),
        0,
    );
}

/// Executes a batch with the given `batch_time` on a state with the given
/// `state_batch_time`. Tests the resulting state's `batch_time` against
/// `expected_batch_time`, as well as the `mr_non_increasing_batch_time`
/// critical error counter.
fn test_batch_time_impl(
    state_batch_time: Time,
    batch_time: Time,
    expected_batch_time: Time,
    expected_regression_count: u64,
) {
    // Batch with the provided `batch_time`.
    let provided_batch = BatchBuilder::new()
        .batch_number(Height::new(1))
        .time(batch_time)
        .build();

    // Fixture wrapping a state with the given `state_time` as `batch_time`.
    let mut fixture = test_fixture(&provided_batch);
    fixture.initial_state.metadata.batch_time = state_batch_time;

    with_test_replica_logger(|log| {
        let _ = &fixture;
        let state_machine = StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            log,
            fixture.metrics,
        );

        assert_eq!(
            Some(0),
            fetch_critical_error_non_increasing_batch_time_count(&fixture.metrics_registry)
        );
        assert_eq!(state_batch_time, fixture.initial_state.metadata.batch_time,);

        let state = state_machine.execute_round(
            fixture.initial_state,
            fixture.network_topology.clone(),
            provided_batch,
            Default::default(),
            &test_registry_settings(),
            Default::default(),
            Default::default(),
        );

        assert_eq!(
            Some(expected_regression_count),
            fetch_critical_error_non_increasing_batch_time_count(&fixture.metrics_registry)
        );
        assert_eq!(expected_batch_time, state.metadata.batch_time,);
    });
}

fn fetch_critical_error_non_increasing_batch_time_count(
    metrics_registry: &MetricsRegistry,
) -> Option<u64> {
    fetch_int_counter_vec(metrics_registry, "critical_errors")
        .get(&btreemap! { "error".to_string() => CRITICAL_ERROR_NON_INCREASING_BATCH_TIME.to_string() })
        .cloned()
}
