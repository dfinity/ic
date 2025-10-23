//! This tests the speed of get_ingress_payload under the following conditions:
//!
//! - The ingress pool is populated with a given number of ingress messages.
//! - Each message is about 1KB in size.
//! - About only 10% of the messages are suitable for payload selection
//!   (non-expired and not too far in the future).
//!
//! We vary the pool size count between 15,000 and 105,000, with 10,000
//! increments.

use criterion::{Criterion, criterion_group, criterion_main};
use ic_artifact_pool::ingress_pool::IngressPoolImpl;
use ic_crypto_temp_crypto::temp_crypto_component_with_fake_registry;
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::{
    ingress_manager::IngressSelector,
    ingress_pool::{ChangeAction, IngressPool, Mutations},
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
    time_source::TimeSource,
};
use ic_interfaces_mocks::consensus_pool::MockConsensusTime;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_limits::{
    MAX_BLOCK_PAYLOAD_SIZE, MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET,
    MAX_INGRESS_MESSAGES_PER_BLOCK, MAX_INGRESS_TTL,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::{
    artifact_pool_config::with_test_pool_config,
    cycles_account_manager::CyclesAccountManagerBuilder,
};
use ic_test_utilities_registry::test_subnet_record;
use ic_test_utilities_state::{CanisterStateBuilder, MockIngressHistory, ReplicatedStateBuilder};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    CanisterId, Cycles, Height, NumBytes, PrincipalId, RegistryVersion, SubnetId, Time,
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    ingress::IngressStatus,
    malicious_flags::MaliciousFlags,
};
use pprof::criterion::{Output, PProfProfiler};
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::Duration,
};

const MEASUREMENT_TIME: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct TestCase {
    canisters_count: usize,
    ingress_pool_size: usize,
    ingress_message_size: usize,
}

/// Helper to run a single test with dependency setup.
fn set_up_dependencies_and_run_test<T>(test_case: TestCase, test: T)
where
    T: FnOnce(&mut IngressManager, Time),
{
    // build replicated state with enough cycles per canister id
    let mut replicated_state = ReplicatedStateBuilder::new().with_subnet_id(subnet_test_id(0));
    let canisters: Vec<CanisterId> = (0..test_case.canisters_count)
        .map(|i| CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(i as u64)))
        .collect();
    for canister_id in &canisters {
        replicated_state = replicated_state.with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(*canister_id)
                .with_cycles(Cycles::new(500_000_000_000)) /* 500 billion cycles */
                .build(),
        );
    }
    let replicated_state = replicated_state.build();

    let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
    ingress_hist_reader
        .expect_get_status_at_height()
        .returning(|_| Ok(Box::new(|_| IngressStatus::Unknown)));
    let subnet_id = subnet_test_id(0);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let registry = setup_registry(subnet_id, runtime.handle().clone());
    let consensus_time = Arc::new(MockConsensusTime::new());
    let mut state_manager = MockStateManager::new();
    state_manager.expect_get_state_at().return_const(Ok(
        ic_interfaces_state_manager::Labeled::new(Height::new(0), Arc::new(replicated_state)),
    ));

    with_test_pool_config(|pool_config| {
        let metrics_registry = MetricsRegistry::new();
        const VALIDATOR_NODE_ID: u64 = 42;
        let ingress_signature_crypto = Arc::new(temp_crypto_component_with_fake_registry(
            node_test_id(VALIDATOR_NODE_ID),
        ));
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
            node_test_id(VALIDATOR_NODE_ID),
            pool_config,
            metrics_registry.clone(),
            no_op_logger(),
        )));
        let time_source = FastForwardTimeSource::new();
        let mut ingress_manager = IngressManager::new(
            time_source.clone(),
            consensus_time,
            ingress_hist_reader,
            ingress_pool.clone(),
            registry.clone(),
            ingress_signature_crypto,
            metrics_registry,
            subnet_id,
            no_op_logger(),
            Arc::new(state_manager),
            cycles_account_manager,
            MaliciousFlags::default(),
            RandomStateKind::Random,
        );
        let now = time_source.get_relative_time();
        let then = prepare(
            time_source.as_ref(),
            ingress_pool,
            now,
            test_case.ingress_pool_size,
            test_case.ingress_message_size,
            &canisters,
        );
        time_source.set_time(then).unwrap();

        test(&mut ingress_manager, then)
    })
}

/// Sets up a registry client.
fn setup_registry(subnet_id: SubnetId, runtime: tokio::runtime::Handle) -> Arc<dyn RegistryClient> {
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let subnet_record = test_subnet_record();
    registry_data_provider
        .add(
            &make_subnet_record_key(subnet_id),
            RegistryVersion::from(1),
            Some(subnet_record),
        )
        .expect("Failed to add subnet record.");
    let registry = Arc::new(RegistryClientImpl::new(
        Arc::clone(&registry_data_provider) as Arc<_>,
        None,
    ));
    runtime.block_on(async { registry.as_ref().fetch_and_start_polling().unwrap() });
    registry
}

/// Prepare pool with a set of ingress messages, only about 10% of them will
/// be considered as valid according to expiry restrictions (not expired & not
/// too far in the future).
///
/// Also, the number of canisters is roughly `num * 0.1`. So there's 1 canister
/// for every 10 ingress messages.
///
/// Return the mean of all expiry time.
fn prepare(
    time_source: &dyn TimeSource,
    pool: Arc<RwLock<IngressPoolImpl>>,
    now: Time,
    number_of_ingress_messages: usize,
    ingress_message_size: usize,
    canisters: &[CanisterId],
) -> Time {
    let mut changeset = Mutations::new();
    let mut pool = pool.write().unwrap();

    let mut canisters = canisters.iter().cycle();

    for i in 0..number_of_ingress_messages {
        let expiry = 5 * MAX_INGRESS_TTL;
        let ingress = SignedIngressBuilder::new()
            .method_name("provisional_create_canister_with_cycles")
            .method_payload(vec![0; ingress_message_size - 200])
            .nonce(i as u64)
            .expiry_time(now + expiry)
            .canister_id(*canisters.next().unwrap())
            .build();

        let message_id = IngressMessageId::from(&ingress);
        pool.insert(UnvalidatedArtifact {
            message: ingress,
            peer_id: node_test_id((i % 10) as u64),
            timestamp: time_source.get_relative_time(),
        });
        changeset.push(ChangeAction::MoveToValidated(message_id));
    }
    pool.apply(changeset);
    assert_eq!(pool.unvalidated().size(), 0);
    assert_eq!(pool.validated().size(), number_of_ingress_messages);
    now + 5 * MAX_INGRESS_TTL
}

/// Build the actual ingress payload.
fn get_ingress_payload(
    now: Time,
    manager: &IngressManager,
    byte_limit: NumBytes,
) -> IngressPayload {
    let validation_context = ValidationContext {
        time: now,
        registry_version: RegistryVersion::from(1),
        certified_height: Height::from(0),
    };
    let past_payload = HashSet::new();
    manager.get_ingress_payload(&past_payload, &validation_context, byte_limit)
}

/// Validate payload
fn validate_ingress_payload(now: Time, manager: &IngressManager, payload: &IngressPayload) -> bool {
    let validation_context = ValidationContext {
        time: now,
        registry_version: RegistryVersion::from(1),
        certified_height: Height::from(0),
    };
    let past_payload = HashSet::new();
    manager
        .validate_ingress_payload(payload, &past_payload, &validation_context)
        .is_ok()
}

/// Speed test for building ingress payloads.
fn build_payload(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("get_ingress_payload");
    group.measurement_time(MEASUREMENT_TIME);

    let test_cases = [
        TestCase {
            canisters_count: 100_000,
            ingress_pool_size: 100 * MAX_INGRESS_MESSAGES_PER_BLOCK as usize,
            ingress_message_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_MESSAGES_PER_BLOCK)
                as usize,
        },
        TestCase {
            canisters_count: 1,
            ingress_pool_size: 100 * MAX_INGRESS_MESSAGES_PER_BLOCK as usize,
            ingress_message_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_MESSAGES_PER_BLOCK)
                as usize,
        },
        TestCase {
            canisters_count: 1_000,
            ingress_pool_size: MAX_INGRESS_MESSAGES_PER_BLOCK as usize,
            ingress_message_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_MESSAGES_PER_BLOCK)
                as usize,
        },
        TestCase {
            canisters_count: 1,
            ingress_pool_size: MAX_INGRESS_MESSAGES_PER_BLOCK as usize,
            ingress_message_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_MESSAGES_PER_BLOCK)
                as usize,
        },
        TestCase {
            canisters_count: 1,
            ingress_pool_size: 2,
            ingress_message_size: MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET as usize,
        },
        TestCase {
            canisters_count: 1,
            ingress_pool_size: 100,
            ingress_message_size: MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET as usize,
        },
    ];

    for test_case in test_cases {
        set_up_dependencies_and_run_test(
            test_case,
            |manager: &mut IngressManager, current_time: Time| {
                let name = format!(
                    "canisters: {}, ingress pool size: {}, ingress message size: {}",
                    test_case.canisters_count,
                    test_case.ingress_pool_size,
                    test_case.ingress_message_size
                );

                group.bench_function(&name, |bench| {
                    bench.iter(|| {
                        get_ingress_payload(
                            current_time,
                            manager,
                            NumBytes::new(MAX_BLOCK_PAYLOAD_SIZE),
                        );
                    })
                });
            },
        );
    }

    group.finish()
}

/// Speed test for validating ingress payloads.
fn validate_payload(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("validate_ingress_payload");
    group.measurement_time(MEASUREMENT_TIME);

    let test_cases = [
        TestCase {
            canisters_count: 1,
            ingress_pool_size: MAX_INGRESS_MESSAGES_PER_BLOCK as usize,
            ingress_message_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_MESSAGES_PER_BLOCK)
                as usize,
        },
        TestCase {
            canisters_count: 1,
            ingress_pool_size: (MAX_BLOCK_PAYLOAD_SIZE / MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET)
                as usize,
            ingress_message_size: MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET as usize,
        },
    ];

    for test_case in test_cases {
        set_up_dependencies_and_run_test(
            test_case,
            |manager: &mut IngressManager, current_time| {
                let payload = get_ingress_payload(
                    current_time,
                    manager,
                    NumBytes::new(MAX_BLOCK_PAYLOAD_SIZE),
                );

                let name = format!(
                    "ingress message count: {}, ingress message size: {}",
                    payload.message_count(),
                    test_case.ingress_message_size
                );

                group.bench_function(&name, |bench| {
                    bench.iter(|| {
                        validate_ingress_payload(current_time, manager, &payload);
                    })
                });
            },
        );
    }

    group.finish()
}

criterion_group! {
    name = benches;
    // Flamegraphs can be generated by passing the `--profile-time SECONDS` argument
    // to the benchmark. The SVG files can be found in the bazel output directory.
    config = Criterion::default().with_profiler(PProfProfiler::new(499, Output::Flamegraph(None)));
    targets = build_payload, validate_payload
}

criterion_main!(benches);
