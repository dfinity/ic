use super::*;
use crate::message_routing::CRITICAL_ERROR_NON_INCREASING_BATCH_TIME;
use crate::routing::demux::MockDemux;
use crate::routing::stream_builder::MockStreamBuilder;
use crate::state_machine::StateMachineImpl;
use ic_interfaces::execution_environment::Scheduler;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{ReplicatedState, SubnetTopology};
use ic_test_utilities_execution_environment::test_registry_settings;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, nonzero_values};
use ic_test_utilities_state::new_canister_state;
use ic_test_utilities_types::batch::BatchBuilder;
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1, SUBNET_2};
use ic_test_utilities_types::messages::SignedIngressBuilder;
use ic_types::batch::{BatchMessages, BlockmakerMetrics, CanisterCyclesCostSchedule, ChainKeyData};
use ic_types::messages::SignedIngress;
use ic_types::{
    CanisterId, Height, PrincipalId, Randomness, RegistryVersion, ReplicaVersion, Time,
};
use maplit::btreemap;
use mockall::{Sequence, mock, predicate::*};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

mock! {
    pub Scheduler {}

    impl Scheduler for Scheduler {
        type State = ReplicatedState;
        fn execute_round(
            &self,
            state: ReplicatedState,
            randomness: Randomness,
            chain_key_data: ChainKeyData,
            replica_version: &ReplicaVersion,
            current_round: ExecutionRound,
            round_summary: Option<ExecutionRoundSummary>,
            current_round_type: ExecutionRoundType,
            registry_settings: &RegistryExecutionSettings,
        ) -> ReplicatedState;

        fn checkpoint_round_with_no_execution(&self, state: &mut ReplicatedState);
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
    let initial_state = ReplicatedState::new(SUBNET_1, SubnetType::Application);
    let metrics_registry = MetricsRegistry::new();
    let metrics = MessageRoutingMetrics::new(&metrics_registry);

    let round = ExecutionRound::from(provided_batch.batch_number.get());
    let round_type = if provided_batch.requires_full_state_hash {
        ExecutionRoundType::CheckpointRound
    } else {
        ExecutionRoundType::OrdinaryRound
    };

    let mut seq = Sequence::new();

    let (messages, chain_key_data) = match &provided_batch.content {
        BatchContent::Data {
            batch_messages,
            chain_key_data,
            ..
        } => (batch_messages.clone(), chain_key_data.clone()),
        BatchContent::Splitting { .. } => unimplemented!(),
    };

    let mut demux = Box::new(MockDemux::new());
    demux
        .expect_process_payload()
        .times(1)
        .in_sequence(&mut seq)
        .with(always(), eq(messages))
        .returning(|state, _| state);

    let mut scheduler = Box::new(MockScheduler::new());
    scheduler
        .expect_execute_round()
        .times(1)
        .in_sequence(&mut seq)
        .with(
            always(),
            eq(provided_batch.randomness),
            eq(chain_key_data.clone()),
            eq(provided_batch.replica_version.clone()),
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
        SUBNET_0,
        SubnetTopology {
            public_key: vec![0, 1, 2, 3],
            nodes: BTreeSet::new(),
            subnet_type: SubnetType::Application,
            subnet_features: SubnetFeatures::default(),
            chain_keys_held: BTreeSet::new(),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        },
    );

    let network_topology = NetworkTopology {
        subnets,
        nns_subnet_id: SUBNET_0,
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
            Default::default(),
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
            Default::default(),
            log,
            fixture.metrics,
        ));

        state_machine.execute_round(
            fixture.initial_state,
            fixture.network_topology.clone(),
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

const NNS_SUBNET_ID: SubnetId = SUBNET_0;
const SUBNET_A: SubnetId = SUBNET_1;
const SUBNET_B: SubnetId = SUBNET_2;
const CANISTER_RANGE_NNS: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(0),
    end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
};
const CANISTER_RANGE_A: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET),
    end: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET - 1),
};
const CANISTER_RANGE_B: CanisterIdRange = CanisterIdRange {
    start: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET),
    end: CanisterId::from_u64(3 * CANISTER_IDS_PER_SUBNET - 1),
};

/// Returns a test fixture for subnet splitting tests with mocks for Demux,
/// Scheduler, and StreamBuilder. The mocks ensure that only expected calls are
/// made, and they are made in the expected order.
fn split_fixture() -> StateMachineTestFixture {
    // Initial state, with 2 canisters.
    let mut initial_state = ReplicatedState::new(SUBNET_A, SubnetType::Application);
    initial_state.canister_states.insert(
        CANISTER_RANGE_A.start,
        new_canister_state(
            CANISTER_RANGE_A.start,
            PrincipalId::new_anonymous(),
            Cycles::new(1_000_000_000_000),
            3600.into(),
        ),
    );
    initial_state.canister_states.insert(
        CANISTER_RANGE_B.start,
        new_canister_state(
            CANISTER_RANGE_B.start,
            PrincipalId::new_anonymous(),
            Cycles::new(1_000_000_000_000),
            3600.into(),
        ),
    );

    let mut scheduler = Box::new(MockScheduler::new());
    let demux = Box::new(MockDemux::new());
    let stream_builder = Box::new(MockStreamBuilder::new());
    let mut seq = Sequence::new();
    scheduler
        .expect_checkpoint_round_with_no_execution()
        .times(1)
        .in_sequence(&mut seq)
        .with(always())
        .return_const(());

    let subnets = btreemap! {
        SUBNET_A => SubnetTopology::default(),
        SUBNET_B => SubnetTopology::default(),
    };
    let network_topology = NetworkTopology {
        subnets,
        nns_subnet_id: NNS_SUBNET_ID,
        routing_table: Arc::new(
            RoutingTable::try_from(btreemap! {
                CANISTER_RANGE_NNS => NNS_SUBNET_ID,
                CANISTER_RANGE_A => SUBNET_A,
                CANISTER_RANGE_B => SUBNET_B,
            })
            .unwrap(),
        ),
        ..Default::default()
    };

    let metrics_registry = MetricsRegistry::new();
    let metrics = MessageRoutingMetrics::new(&metrics_registry);

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

fn test_online_split(new_subnet_id: SubnetId, other_subnet_id: SubnetId) -> ReplicatedState {
    let fixture = split_fixture();
    let split_batch = Batch {
        batch_number: Height::from(0),
        batch_summary: None,
        requires_full_state_hash: false,
        content: BatchContent::Splitting {
            new_subnet_id,
            other_subnet_id,
        },
        randomness: Randomness::from([0; 32]),
        registry_version: RegistryVersion::from(1),
        time: fixture
            .initial_state
            .metadata
            .batch_time
            .checked_add(Duration::from_secs(1))
            .unwrap(),
        blockmaker_metrics: BlockmakerMetrics::new_for_test(),
        replica_version: ReplicaVersion::default(),
    };

    let state_after_split = with_test_replica_logger(|log| {
        let state_machine = Box::new(StateMachineImpl::new(
            fixture.scheduler,
            fixture.demux,
            fixture.stream_builder,
            Default::default(),
            log,
            fixture.metrics,
        ));

        state_machine.execute_round(
            fixture.initial_state,
            fixture.network_topology.clone(),
            split_batch,
            Default::default(),
            &test_registry_settings(),
            Default::default(),
            Default::default(),
        )
    });

    assert_eq!(
        BTreeMap::new(),
        nonzero_values(fetch_int_counter_vec(
            &fixture.metrics_registry,
            "critical_errors"
        ))
    );

    state_after_split
}

/// Tests a *subnet A* -> *subnet A'* online split.
#[test]
fn test_online_split_subnet_a() {
    let state_after_split = test_online_split(SUBNET_A, SUBNET_B);
    // Only hosting canister `CANISTER_RANGE_0.start`.
    assert_eq!(
        vec![&CANISTER_RANGE_A.start],
        state_after_split.canister_states.keys().collect::<Vec<_>>()
    );
}

/// Tests a *subnet A* -> *subnet B* online split.
#[test]
fn test_online_split_subnet_b() {
    let state_after_split = test_online_split(SUBNET_B, SUBNET_A);
    // Only hosting canister `CANISTER_RANGE_1.start`.
    assert_eq!(
        vec![&CANISTER_RANGE_B.start],
        state_after_split.canister_states.keys().collect::<Vec<_>>()
    );
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
            Default::default(),
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
        assert_eq!(expected_batch_time, state.metadata.batch_time);
    });
}

fn fetch_critical_error_non_increasing_batch_time_count(
    metrics_registry: &MetricsRegistry,
) -> Option<u64> {
    fetch_int_counter_vec(metrics_registry, "critical_errors")
        .get(&btreemap! { "error".to_string() => CRITICAL_ERROR_NON_INCREASING_BATCH_TIME.to_string() })
        .cloned()
}
