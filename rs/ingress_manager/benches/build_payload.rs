//! This tests the speed of get_ingress_payload under the following conditions:
//!
//! - The ingress pool is populated with a given number of ingress messages.
//! - Each message is about 1KB in size.
//! - About only 10% of the messages are suitable for payload selection
//!   (non-expired and not too far in the future).
//!
//! We vary the pool size count between 15,000 and 105,000, with 10,000
//! increments.

use criterion::{criterion_group, criterion_main, Criterion};
use ic_artifact_pool::ingress_pool::IngressPoolImpl;
use ic_constants::MAX_INGRESS_TTL;
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::{
    ingress_manager::IngressSelector,
    ingress_pool::{ChangeAction, ChangeSet, IngressPool},
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
    time_source::TimeSource,
};
use ic_interfaces_mocks::consensus_pool::MockConsensusTime;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::{
    crypto::temp_crypto_component_with_fake_registry,
    cycles_account_manager::CyclesAccountManagerBuilder,
};
use ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config;
use ic_test_utilities_registry::test_subnet_record;
use ic_test_utilities_state::{CanisterStateBuilder, MockIngressHistory, ReplicatedStateBuilder};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    artifact::IngressMessageId, batch::ValidationContext, ingress::IngressStatus,
    malicious_flags::MaliciousFlags, CanisterId, Cycles, Height, NumBytes, PrincipalId,
    RegistryVersion, SubnetId, Time,
};
use rand::{Rng, RngCore};
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

/// Helper to run a single test with dependency setup.
fn run_test<T>(_test_name: &str, canisters: &[CanisterId], test: T)
where
    T: FnOnce(
        Arc<FastForwardTimeSource>,
        Arc<RwLock<IngressPoolImpl>>,
        &mut IngressManager,
        Arc<dyn RegistryClient>,
        &[CanisterId],
    ),
{
    // build replicated state with enough cycles per canister id
    let mut replicated_state = ReplicatedStateBuilder::new().with_subnet_id(subnet_test_id(0));
    for canister_id in canisters {
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
        test(
            time_source.clone(),
            ingress_pool.clone(),
            &mut IngressManager::new(
                time_source,
                consensus_time,
                ingress_hist_reader,
                ingress_pool,
                registry.clone(),
                ingress_signature_crypto,
                metrics_registry,
                subnet_id,
                no_op_logger(),
                Arc::new(state_manager),
                cycles_account_manager,
                MaliciousFlags::default(),
                RandomStateKind::Random,
            ),
            registry,
            canisters,
        )
    })
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
    num: usize,
    canisters: &[CanisterId],
) -> Time {
    let mut changeset = ChangeSet::new();
    let ingress_size = 1024;
    let mut rng = rand::thread_rng();
    let mut pool = pool.write().unwrap();

    let mut canisters = canisters.iter().cycle();

    for i in 0..num {
        // Only 10% of them will be considered valid
        let expiry = std::time::Duration::from_millis(
            rng.gen::<u64>() % (10 * (MAX_INGRESS_TTL.as_millis() as u64)),
        );
        let ingress = SignedIngressBuilder::new()
            .method_name("provisional_create_canister_with_cycles")
            .method_payload(vec![0; ingress_size])
            .nonce(i as u64)
            .expiry_time(now + expiry)
            .canister_id(*canisters.next().unwrap())
            .build();
        let message_id = IngressMessageId::from(&ingress);
        let peer_id = (i % 10) as u64;
        pool.insert(UnvalidatedArtifact {
            message: ingress,
            peer_id: node_test_id(peer_id),
            timestamp: time_source.get_relative_time(),
        });
        changeset.push(ChangeAction::MoveToValidated(message_id));
    }
    pool.apply_changes(changeset);
    assert_eq!(pool.unvalidated().size(), 0);
    assert_eq!(pool.validated().size(), num);
    now + 5 * MAX_INGRESS_TTL
}

/// Build the actual ingress payload.
fn get_ingress_payload(now: Time, manager: &IngressManager, byte_limit: NumBytes) -> usize {
    let validation_context = ValidationContext {
        time: now,
        registry_version: RegistryVersion::from(1),
        certified_height: Height::from(0),
    };
    let past_payload = HashSet::new();
    let payload = manager.get_ingress_payload(&past_payload, &validation_context, byte_limit);
    payload.message_count()
}

/// Speed test for building ingress payloads.
fn build_payload(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("build_payload");
    group.sample_size(30);
    group.measurement_time(std::time::Duration::from_secs(10));
    for i in 1..=10 {
        let size = 5000 + 10000 * i;
        // canister ids iterator
        let mut rng = rand::thread_rng();
        let canisters: Vec<CanisterId> = (0..(size / 10))
            .map(|_| {
                CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(rng.next_u64()))
            })
            .collect();

        run_test(
            "get_ingress_payload",
            &canisters,
            |time_source: Arc<FastForwardTimeSource>,
             pool,
             manager: &mut IngressManager,
             registry,
             canisters| {
                let now = time_source.get_relative_time();
                let then = prepare(time_source.as_ref(), pool, now, size, canisters);
                time_source.set_time(then).unwrap();
                let name = format!("get_ingress_payload({})", size);
                let byte_limit = registry
                    .get_subnet_record(subnet_test_id(0), RegistryVersion::new(1))
                    .unwrap()
                    .unwrap()
                    .max_block_payload_size;

                group.bench_function(&name, |bench| {
                    bench.iter(|| {
                        let n = get_ingress_payload(then, manager, NumBytes::new(byte_limit));
                        assert!(n > 800, "Insufficient number of ingress in payload: {}", n);
                        assert!(n < 1020, "Too many ingress in payload: {}", n);
                    })
                });
            },
        );
    }
    group.finish()
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

criterion_group!(benches, build_payload);

criterion_main!(benches);
