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
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    ingress_manager::IngressSelector,
    ingress_pool::{ChangeAction, ChangeSet, IngressPool, MutableIngressPool},
    registry::RegistryClient,
    time_source::TimeSource,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::make_subnet_record_key;
use ic_test_utilities::{
    artifact_pool_config::with_test_pool_config,
    consensus::MockConsensusCache,
    crypto::temp_crypto_component_with_fake_registry,
    cycles_account_manager::CyclesAccountManagerBuilder,
    history::MockIngressHistory,
    registry::test_subnet_record,
    state::ReplicatedStateBuilder,
    state_manager::MockStateManager,
    types::ids::{node_test_id, subnet_test_id},
    types::messages::SignedIngressBuilder,
    FastForwardTimeSource,
};
use ic_types::{
    artifact::{IngressMessageAttribute, IngressMessageId},
    batch::ValidationContext,
    ic00::IC_00,
    ingress::{IngressStatus, MAX_INGRESS_TTL},
    malicious_flags::MaliciousFlags,
    Height, RegistryVersion, SubnetId, Time,
};
use rand::Rng;
use std::collections::HashSet;
use std::sync::Arc;

/// Helper to run a single test with dependency setup.
fn run_test<T>(_test_name: &str, test: T)
where
    T: FnOnce(Arc<FastForwardTimeSource>, &mut IngressPoolImpl, &mut IngressManager),
{
    let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
    ingress_hist_reader
        .expect_get_status_at_height()
        .returning(|_| Ok(Box::new(|_| IngressStatus::Unknown)));
    let subnet_id = subnet_test_id(0);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let registry = setup_registry(subnet_id, runtime.handle().clone());
    let consensus_pool_cache = Arc::new(MockConsensusCache::new());
    let mut state_manager = MockStateManager::new();
    state_manager.expect_get_state_at().return_const(Ok(
        ic_interfaces::state_manager::Labeled::new(
            Height::new(0),
            Arc::new(ReplicatedStateBuilder::default().build()),
        ),
    ));

    with_test_pool_config(|pool_config| {
        let metrics_registry = MetricsRegistry::new();
        const VALIDATOR_NODE_ID: u64 = 42;
        let ingress_signature_crypto = Arc::new(temp_crypto_component_with_fake_registry(
            node_test_id(VALIDATOR_NODE_ID),
        ));
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        test(
            FastForwardTimeSource::new(),
            &mut IngressPoolImpl::new(pool_config, metrics_registry.clone(), no_op_logger()),
            &mut IngressManager::new(
                consensus_pool_cache,
                ingress_hist_reader,
                registry,
                ingress_signature_crypto,
                metrics_registry,
                subnet_id,
                no_op_logger(),
                Arc::new(state_manager),
                cycles_account_manager,
                MaliciousFlags::default(),
            ),
        )
    })
}

/// Prepare pool with a set of ingress messages, only about 10% of them will
/// be considered as valid according to expiry restrictions (not expired & not
/// too far in the future).
///
/// Return the mean of all expiry time.
fn prepare(
    time_source: &dyn TimeSource,
    pool: &mut IngressPoolImpl,
    now: Time,
    num: usize,
) -> Time {
    let mut changeset = ChangeSet::new();
    let ingress_size = 1024;
    let mut rng = rand::thread_rng();
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
            .canister_id(IC_00)
            .build();
        let message_id = IngressMessageId::from(&ingress);
        let attribute = IngressMessageAttribute::new(&ingress);
        let peer_id = (i % 10) as u64;
        let integrity_hash = ic_crypto::crypto_hash(ingress.binary()).get();
        pool.insert(UnvalidatedArtifact {
            message: ingress,
            peer_id: node_test_id(peer_id),
            timestamp: time_source.get_relative_time(),
        });
        changeset.push(ChangeAction::MoveToValidated((
            message_id,
            0,
            attribute,
            integrity_hash,
        )));
    }
    pool.apply_changeset(changeset);
    assert_eq!(pool.unvalidated().size(), 0);
    assert_eq!(pool.validated().size(), num);
    now + 5 * MAX_INGRESS_TTL
}

/// Build the actual ingress payload.
fn get_ingress_payload(now: Time, pool: &IngressPoolImpl, manager: &IngressManager) -> usize {
    let validation_context = ValidationContext {
        time: now,
        registry_version: RegistryVersion::from(1),
        certified_height: Height::from(0),
    };
    let past_payload = HashSet::new();
    let payload = manager.get_ingress_payload(pool, &past_payload, &validation_context);
    payload.message_count()
}

/// Speed test for building ingress payloads.
fn build_payload(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("build_payload");
    group.sample_size(30);
    group.measurement_time(std::time::Duration::from_secs(10));
    for i in 1..=10 {
        let size = 5000 + 10000 * i;
        run_test(
            "get_ingress_payload",
            |time_source: Arc<FastForwardTimeSource>,
             pool: &mut IngressPoolImpl,
             manager: &mut IngressManager| {
                let now = time_source.get_relative_time();
                let then = prepare(time_source.as_ref(), pool, now, size);
                time_source.set_time(then).unwrap();
                let name = format!("get_ingress_payload({})", size);
                group.bench_function(&name, |bench| {
                    bench.iter(|| {
                        let n = get_ingress_payload(then, pool, manager);
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
