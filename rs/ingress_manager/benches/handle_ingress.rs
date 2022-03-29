//! This tests the speed of on_state_change of IngressHandler under the
//! following conditions:
//!
//! - The ingress pool is populated with a given number of ingress messages,
//!   both unvalidated and validated.
//! - Some of the validated messages are about to be purged due to expiration.
//! - Some of the validated messages are about to be purged due to execution or
//!   finalization.
//! - We use real (or almost real) for dependencies like crypto and
//!   IngressHistoryReader.
//! - The changeset is also realistically applied.
//!
//! We vary the rate of unvalidated ingress coming into the unvalidated pool
//! between 100/s and 1000/s, and each message has a 100 bytes payload.

use criterion::{criterion_group, criterion_main, Criterion};
use ic_artifact_pool::ingress_pool::IngressPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_constants::MAX_INGRESS_TTL;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact, ingress_manager::IngressHandler,
    ingress_pool::MutableIngressPool, registry::RegistryClient, time_source::TimeSource,
};
use ic_interfaces_state_manager::Labeled;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{BitcoinState, CanisterQueues, ReplicatedState, SystemMetadata};
use ic_test_utilities::{
    consensus::MockConsensusCache,
    crypto::temp_crypto_component_with_fake_registry,
    cycles_account_manager::CyclesAccountManagerBuilder,
    history::MockIngressHistory,
    mock_time,
    registry::test_subnet_record,
    state::ReplicatedStateBuilder,
    state_manager::MockStateManager,
    types::ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id},
    types::messages::SignedIngressBuilder,
    FastForwardTimeSource,
};
use ic_types::{
    ingress::IngressStatus,
    malicious_flags::MaliciousFlags,
    messages::{MessageId, SignedIngress},
    Height, RegistryVersion, SubnetId, Time,
};
use rand::{seq::SliceRandom, Rng};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default payload size is 100 bytes.
const PAYLOAD_SIZE: usize = 100;

/// Max ingress message per payload.
const MAX_INGRESS_COUNT_PER_PAYLOAD: usize = 1000;

/// Block time
const BLOCK_TIME: Duration = Duration::from_secs(2);

type Histories = Arc<RwLock<Vec<Arc<(Time, HashSet<MessageId>)>>>>;

struct SimulatedIngressHistory {
    time_source: Arc<dyn TimeSource>,
    histories: Histories,
}

impl SimulatedIngressHistory {
    fn new(time_source: Arc<dyn TimeSource>) -> (Self, MockIngressHistory) {
        let mut ingress_hist_reader = MockIngressHistory::new();
        let histories: Histories = Arc::new(RwLock::new(Vec::new()));
        let hist = histories.clone();
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(move || {
                let set = hist.read().unwrap()[0].clone();
                Box::new(move |ingress_id| {
                    if set.1.contains(ingress_id) {
                        IngressStatus::Unknown
                    } else {
                        IngressStatus::Completed {
                            receiver: canister_test_id(0).get(),
                            user_id: user_test_id(0),
                            result: ic_types::ingress::WasmResult::Reply(vec![]),
                            time: mock_time(),
                        }
                    }
                })
            });
        (
            SimulatedIngressHistory {
                time_source,
                histories,
            },
            ingress_hist_reader,
        )
    }

    /// Return the simulated batch time, As time_source increases by BLOCK_TIME,
    /// next batch is retrieved from the pre-computed ingress histories.
    fn batch_time(&self) -> Time {
        let mut histories = self.histories.write().unwrap();
        let mut t = histories[0].0;
        while self.time_source.get_relative_time() > t + BLOCK_TIME {
            histories.remove(0);
            t = histories[0].0;
        }
        t
    }

    /// Build out the entire ingress history, with one set every 2 seconds.
    /// For each set:
    ///
    /// 1. We assign a non-decreasing timestamp `t` that is 2s greater than
    ///    previous one.
    ///
    /// 2. It contains up to MAX_INGRESS_COUNT_PER_PAYLAD * MAX_INGRES_TTL / 2
    ///    messages.
    ///
    /// 3. All messages are within expiry between `t - 2s - MAX_INGRESS_TTL` and
    ///    `t - 2s`.
    fn set_history(&self, messages: BTreeMap<Time, MessageId>) {
        let mut rng = rand::thread_rng();
        let start_time = self.time_source.get_relative_time();
        let end_time = *messages.keys().rev().next().unwrap();
        let mut histories = vec![];
        let mut time = start_time + Duration::from_secs(2);
        let set_limit = MAX_INGRESS_COUNT_PER_PAYLOAD * (MAX_INGRESS_TTL.as_secs() as usize) / 2;
        while time < end_time {
            let min_time = if start_time + MAX_INGRESS_TTL < time {
                time - MAX_INGRESS_TTL
            } else {
                start_time
            };
            let mut messages: Vec<MessageId> = messages
                .range(min_time..time)
                .map(|(_, v)| v.clone())
                .collect();
            messages.shuffle(&mut rng);
            let set = messages.into_iter().take(set_limit).collect::<HashSet<_>>();
            histories.push(Arc::new((time, set)));
            time += Duration::from_secs(2);
        }
        *self.histories.write().unwrap() = histories;
    }
}

/// Helper to run a single test with dependency setup.
fn run_test<T>(_test_name: &str, test: T)
where
    T: FnOnce(
        Arc<FastForwardTimeSource>,
        ArtifactPoolConfig,
        ReplicaLogger,
        &SimulatedIngressHistory,
        &mut IngressManager,
    ),
{
    ic_test_utilities::with_test_replica_logger(|log| {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            // Set initial time to non-zero
            time_source
                .set_time(mock_time() + Duration::from_secs(1))
                .unwrap();
            let (history, ingress_hist_reader) = SimulatedIngressHistory::new(time_source.clone());
            let history = Arc::new(history);
            let history_cl = history.clone();
            let subnet_id = subnet_test_id(1);
            let mut state_manager = MockStateManager::new();
            state_manager
                .expect_latest_state_height()
                .return_const(Height::from(1));
            state_manager.expect_get_latest_state().returning(move || {
                let mut metadata = SystemMetadata::new(subnet_id, SubnetType::Application);
                metadata.batch_time = history_cl.batch_time();
                Labeled::new(
                    Height::from(1),
                    Arc::new(ReplicatedState::new_from_checkpoint(
                        BTreeMap::new(),
                        metadata,
                        CanisterQueues::default(),
                        Vec::new(),
                        BitcoinState::default(),
                        std::path::PathBuf::new(),
                    )),
                )
            });

            let mut consensus_pool_cache = MockConsensusCache::new();
            let time_source_cl = time_source.clone();
            consensus_pool_cache
                .expect_consensus_time()
                .returning(move || Some(time_source_cl.get_relative_time()));

            let subnet_id = subnet_test_id(0);
            const VALIDATOR_NODE_ID: u64 = 42;
            let ingress_signature_crypto = Arc::new(temp_crypto_component_with_fake_registry(
                node_test_id(VALIDATOR_NODE_ID),
            ));
            let mut state_manager = MockStateManager::new();
            state_manager.expect_get_state_at().return_const(Ok(
                ic_interfaces_state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(ReplicatedStateBuilder::default().build()),
                ),
            ));

            let metrics_registry = MetricsRegistry::new();
            let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
                pool_config.clone(),
                metrics_registry.clone(),
                no_op_logger(),
            )));

            let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let mut ingress_manager = IngressManager::new(
                Arc::new(consensus_pool_cache),
                Box::new(ingress_hist_reader),
                ingress_pool,
                setup_registry(subnet_id, runtime.handle().clone()),
                ingress_signature_crypto,
                metrics_registry,
                subnet_id,
                log.clone(),
                Arc::new(state_manager),
                cycles_account_manager,
                MaliciousFlags::default(),
            );
            test(
                time_source,
                pool_config,
                log,
                &history,
                &mut ingress_manager,
            );
        })
    })
}

/// Prepare a set of unvalidated ingress messages, with expiry
/// randomly distributed over the given expiry time period.
fn prepare(time_source: &dyn TimeSource, duration: Duration, num: usize) -> Vec<SignedIngress> {
    let now = time_source.get_relative_time();
    let max_expiry = now + duration;
    let mut rng = rand::thread_rng();
    (0..num)
        .map(|i| {
            let expiry = std::time::Duration::from_millis(
                rng.gen::<u64>() % ((max_expiry - now).as_millis() as u64),
            );
            SignedIngressBuilder::new()
                .method_payload(vec![0; PAYLOAD_SIZE])
                .nonce(i as u64)
                .expiry_time(now + expiry)
                .build()
        })
        .collect::<Vec<_>>()
}

/// Setup ingress pool with the given set of messages.
fn setup(
    time_source: &FastForwardTimeSource,
    pool_config: ArtifactPoolConfig,
    log: ReplicaLogger,
    messages: Vec<SignedIngress>,
) -> (IngressPoolImpl, BTreeMap<Time, MessageId>) {
    let mut pool = IngressPoolImpl::new(pool_config, MetricsRegistry::new(), log);
    let mut message_ids = BTreeMap::new();
    let timestamp = time_source.get_relative_time();
    for (i, ingress) in messages.into_iter().enumerate() {
        message_ids.insert(ingress.expiry_time(), ingress.id());
        pool.insert(UnvalidatedArtifact {
            message: ingress,
            peer_id: node_test_id((i % 10) as u64),
            timestamp,
        });
    }
    (pool, message_ids)
}

/// Call ingress manager on_state_change, and apply changeset to the ingress
/// pool. Return number of change actions.
fn on_state_change(pool: &mut IngressPoolImpl, manager: &IngressManager) -> usize {
    let changeset = manager.on_state_change(pool);
    let n = changeset.len();
    pool.apply_changeset(changeset);
    n
}

/// Speed test for ingress handling.
fn handle_ingress(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("handle_ingress");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for i in 1..=10 {
        // num messages per second
        let ingress_rate = i * 100;
        // We don't have to run the benchmark for the full TTL interval. Ending in 30
        // simulated seconds is good enough.
        let time_span = Duration::from_secs(30);
        // range of ingress expiry
        let expiry_range = MAX_INGRESS_TTL + time_span;
        let total_messages = ingress_rate * expiry_range.as_secs();
        run_test(
            "get_ingress_payload",
            |time_source: Arc<FastForwardTimeSource>,
             pool_config: ArtifactPoolConfig,
             log: ReplicaLogger,
             history: &SimulatedIngressHistory,
             manager: &mut IngressManager| {
                let name = format!("handle_ingress({})", ingress_rate);
                let messages = prepare(time_source.as_ref(), expiry_range, total_messages as usize);
                let (pool, message_ids) = setup(time_source.as_ref(), pool_config, log, messages);
                group.bench_function(&name, |bench| {
                    bench.iter_custom(|iters| {
                        let mut elapsed = Duration::from_secs(0);
                        for _ in 0..iters {
                            let bench_start = Instant::now();
                            let mut ingress_pool = pool.clone();
                            time_source.reset();
                            // We skip the first MAX_INGRESS_TTL duration in order to save
                            // overall benchmark time. Also by this time, the ingress
                            // history has become fully populated.
                            let start = time_source.get_relative_time() + MAX_INGRESS_TTL;
                            time_source.set_time(start).unwrap();
                            history.set_history(message_ids.clone());
                            // Increment time every 200ms until it is over.
                            loop {
                                on_state_change(&mut ingress_pool, manager);
                                let now = time_source.get_relative_time();
                                if now >= start + time_span {
                                    break;
                                }
                                time_source
                                    .set_time(now + Duration::from_millis(200))
                                    .unwrap();
                            }
                            elapsed += bench_start.elapsed();
                        }
                        elapsed
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

criterion_group!(benches, handle_ingress);

criterion_main!(benches);
