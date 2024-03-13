#[rustfmt::skip]
mod unformatted {
//! <h1>Overview</h1>
//!
//! The *Artifact Manager* stores artifacts in the artifact pool. These
//! artifacts are used by the node it is running on and other nodes in the same
//! subnet. The *Artifact Manager* interacts with *Gossip* and its application
//! components:
//!
//!   * *Consensus*
//!   * *Distributed Key Generation*
//!   * *Certification*
//!   * *Ingress Manager*
//!   * *State Sync*
//!
//! It acts as a dispatcher for *Gossip* and ensures that the artifacts are
//! processed by the correct application components. It (de)multiplexes
//! artifacts to and from the different application components on behalf of
//! *Gossip* and bundles filters and priority functions.
//!
//! In order to let the *Consensus* components be stateless, the artifact
//! manager notifies the application components of artifacts received from
//! peers. The application components can then check if they are valid and
//! change their artifact pools (with a write lock to prevent conflicts and to
//! allow concurrent reads to the artifact pools).
//!
//! <h1>Properties</h1>
//!
//!   * All artifacts in the validated part of the artifact pool have been
//!     checked to be valid by the corresponding application component.
//!   * When new artifacts have been added to the artifact pool or when
//!     triggered by *Gossip*, the *Artifact Manager* asks the application
//!     components to check if they want to add new artifacts or move artifacts
//!     from the unvalidated part to the validated part of the pool.
//!   * When artifacts are added to the validated part of the artifact pool, the
//!     *Artifact Manager* notifies *Gossip* of adverts to send to peers.
//!     checked to be valid by the corresponding application component
//!   * When new artifacts have been added to the artifact pool or when
//!     triggered by Gossip the Artifact Manager asks the application components
//!     to check if they want to add new artifacts or move artifacts from the
//!     unvalidated part to the validated part of the pool
//!   * When artifacts are added to the validated part of the artifact pool, the
//!     Artifact Manager notifies Gossip of adverts to send to peers.
//!
//! <h1>High Level View</h1>
//!
//!
//!#                                                                 --------------------------
//!#                                                                 | ArtifactManagerBackend |
//!#                                                           |->   |     (Consensus)        |
//!#                                                           |     -------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |       (Dkg)            |
//!#                                                           |     -------------------------
//!#     --------------          ------------------------      |     --------------------------
//!#     |   P2P      | <------> |  ArtifactManagerImpl |  ----|->   | ArtifactManagerBackend |
//!#     --------------          ------------------------      |     |     (Certification)    |
//!#                                                           |     --------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |     (Ingress)          |
//!#                                                           |     -------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |     (State Sync)       |
//!#                                                                 -------------------------
//!
//!  The main components are:
//!   * Front end
//!     manager::ArtifactManagerImpl implements the ArtifactManager trait and talks
//!     to P2P. It maintains the map of backends, one for each client: consensus, DKG,
//!     certification, ingress, state sync. It is just a light weight layer that routes the
//!     requests to the appropriate backend
//!
//!   * Back ends
//!     clients::ArtifactManagerBackend is a per-client wrapper that has two parts:
//!     1. Sync: Requests that can be served in the caller's context are processed by the
//!        sync part (e.g) has_artifact(), get_validated_by_identifier() that only need to
//!        look up the artifact pool
//!
//!        clients::ConsensusClient, etc implement the per-client sync part
//!
//!     2. Async: Processes the received artifacts via on_artifact(). The new artifacts are
//!        queued to a background worker thread. The thread runs a loop that calls into the
//!        per-client ArtifactProcessor implementation with the newly received artifacts
//!
//!        a. processors::ArtifactProcessorJoinGuard manages the life cycle of these back ground
//!           threads, and queues the requests to the background thread via a crossbeam channel
//!        b. processors::ConsensusProcessor, etc implement the per-client ArtifactProcessor
//!           logic called by the threads. These roughly perform the sequence: add the new
//!           artifacts to the unvalidated pool, call the client.on_state_change(), apply the
//!           returned changes(mutations) to the artifact pools
//!
}

pub mod manager;
mod pool_readers;
pub mod processors;

use ic_interfaces::{
    p2p::{
        artifact_manager::{ArtifactClient, ArtifactProcessor, ArtifactProcessorEvent, JoinGuard},
        consensus::{
            ChangeResult, ChangeSetProducer, MutablePool, PriorityFnAndFilterProducer,
            ValidatedPoolReader,
        },
    },
    time_source::TimeSource,
};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{artifact::*, artifact_kind::*, malicious_flags::MaliciousFlags};
use prometheus::{histogram_opts, labels, Histogram};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, RwLock,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::timeout,
};

type ArtifactEventSender<Artifact> = UnboundedSender<UnvalidatedArtifactMutation<Artifact>>;

/// Metrics for a client artifact processor.
struct ArtifactProcessorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
    outbound_artifact_bytes: Histogram,
    /// The last update time.
    last_update: std::time::Instant,
}

impl ArtifactProcessorMetrics {
    /// The constructor creates a `ArtifactProcessorMetrics` instance.
    fn new(metrics_registry: MetricsRegistry, client: String) -> Self {
        let const_labels = labels! {"client".to_string() => client.to_string()};
        let processing_time = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_time_seconds",
                "Artifact manager client processing time, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                const_labels.clone()
            ))
            .unwrap(),
        );
        let processing_interval = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_interval_seconds",
                "Duration between Artifact manager client processing, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                const_labels.clone()
            ))
            .unwrap(),
        );

        let outbound_artifact_bytes = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_outbound_artifact_bytes",
                "Distribution of bytes from artifacts that should be delivered to all peers.",
                decimal_buckets(0, 6),
                const_labels.clone()
            ))
            .unwrap(),
        );

        Self {
            processing_time,
            processing_interval,
            outbound_artifact_bytes,
            last_update: std::time::Instant::now(),
        }
    }

    fn with_metrics<T, F: FnOnce() -> T>(&mut self, run: F) -> T {
        self.processing_interval
            .observe((std::time::Instant::now() - self.last_update).as_secs_f64());
        let _timer = self.processing_time.start_timer();
        let result = run();
        self.last_update = std::time::Instant::now();
        result
    }
}

/// Manages the life cycle of the client specific artifact processor thread.
pub struct ArtifactProcessorJoinGuard {
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl JoinGuard for ArtifactProcessorJoinGuard {}

impl ArtifactProcessorJoinGuard {
    pub fn new(handle: JoinHandle<()>, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            handle: Some(handle),
            shutdown,
        }
    }
}

impl Drop for ArtifactProcessorJoinGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, SeqCst);
            handle.join().unwrap();
        }
    }
}

pub fn run_artifact_processor<
    Artifact: ArtifactKind + 'static,
    S: Fn(ArtifactProcessorEvent<Artifact>) + Send + 'static,
>(
    time_source: Arc<dyn TimeSource>,
    metrics_registry: MetricsRegistry,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    send_advert: S,
) -> (Box<dyn JoinGuard>, ArtifactEventSender<Artifact>)
where
    <Artifact as ic_types::artifact::ArtifactKind>::Message: Send,
    <Artifact as ic_types::artifact::ArtifactKind>::Id: Send,
{
    // Making this channel bounded can be problematic since we don't have true multiplexing
    // of P2P messages.
    // Possible scenario is - adverts+chunks arrive on the same channel, slow consensus
    // will result on slow consuption of chunks. Slow consumption of chunks will in turn
    // result in slower consumptions of adverts. Ideally adverts are consumed at rate
    // independent of consensus.
    #[allow(clippy::disallowed_methods)]
    let (sender, receiver) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn the processor thread
    let shutdown_cl = shutdown.clone();
    let handle = ThreadBuilder::new()
        .name(format!("{}_Processor", Artifact::TAG))
        .spawn(move || {
            process_messages(
                time_source,
                client,
                Box::new(send_advert),
                receiver,
                ArtifactProcessorMetrics::new(metrics_registry, Artifact::TAG.to_string()),
                shutdown_cl,
            );
        })
        .unwrap();

    (
        Box::new(ArtifactProcessorJoinGuard::new(handle, shutdown)),
        sender,
    )
}

// The artifact processor thread loop
#[allow(clippy::too_many_arguments)]
fn process_messages<
    Artifact: ArtifactKind + 'static,
    S: Fn(ArtifactProcessorEvent<Artifact>) + Send + 'static,
>(
    time_source: Arc<dyn TimeSource>,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    send_advert: Box<S>,
    mut receiver: UnboundedReceiver<UnvalidatedArtifactMutation<Artifact>>,
    mut metrics: ArtifactProcessorMetrics,
    shutdown: Arc<AtomicBool>,
) {
    let current_thread_rt = tokio::runtime::Builder::new_current_thread()
        .thread_name("ArtifactProcessor_Thread".to_string())
        .enable_time()
        .build()
        .unwrap();
    let mut last_on_state_change_result = false;
    while !shutdown.load(SeqCst) {
        // TODO: assess impact of continued processing in same
        // iteration if StateChanged
        let recv_timeout = if last_on_state_change_result {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(ARTIFACT_MANAGER_TIMER_DURATION_MSEC)
        };

        let batched_artifact_events = current_thread_rt.block_on(async {
            match timeout(recv_timeout, receiver.recv()).await {
                Ok(Some(artifact_event)) => {
                    let mut artifacts = vec![artifact_event];
                    while let Ok(artifact) = receiver.try_recv() {
                        artifacts.push(artifact);
                    }
                    Some(artifacts)
                }
                Ok(None) => {
                    // p2p is stopped
                    None
                }
                Err(_) => Some(vec![]),
            }
        });
        let batched_artifact_events = match batched_artifact_events {
            Some(v) => v,
            None => {
                return;
            }
        };
        let ChangeResult {
            artifacts_with_opt,
            purged,
            poll_immediately,
        } = metrics
            .with_metrics(|| client.process_changes(time_source.as_ref(), batched_artifact_events));
        for artifact_with_opt in artifacts_with_opt {
            metrics
                .outbound_artifact_bytes
                .observe(artifact_with_opt.advert.size as f64);
            send_advert(ArtifactProcessorEvent::Artifact(artifact_with_opt));
        }

        for advert in purged {
            send_advert(ArtifactProcessorEvent::Purge(advert));
        }
        last_on_state_change_result = poll_immediately;
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

/// The struct contains all relevant interfaces for P2P to operate.
pub struct ArtifactClientHandle<Artifact: ArtifactKind + 'static> {
    /// To send the process requests
    pub sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    /// Reference to the artifact client.
    /// TODO: long term we can remove the 'ArtifactClient' and directly use
    /// 'ValidatedPoolReader' and ' PriorityFnAndFilterProducer' traits.
    pub pool_reader: Box<dyn ArtifactClient<Artifact>>,
}

pub fn create_ingress_handlers<
    PoolIngress: MutablePool<IngressArtifact> + Send + Sync + ValidatedPoolReader<IngressArtifact> + 'static,
    G: PriorityFnAndFilterProducer<IngressArtifact, PoolIngress> + 'static,
    S: Fn(ArtifactProcessorEvent<IngressArtifact>) + Send + 'static,
>(
    send_advert: S,
    time_source: Arc<dyn TimeSource>,
    ingress_pool: Arc<RwLock<PoolIngress>>,
    priority_fn_and_filter_producer: Arc<G>,
    ingress_handler: Arc<
        dyn ChangeSetProducer<
                PoolIngress,
                ChangeSet = <PoolIngress as MutablePool<IngressArtifact>>::ChangeSet,
            > + Send
            + Sync,
    >,
    metrics_registry: MetricsRegistry,
    malicious_flags: MaliciousFlags,
) -> (ArtifactClientHandle<IngressArtifact>, Box<dyn JoinGuard>) {
    let client = processors::IngressProcessor::new(ingress_pool.clone(), ingress_handler);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle {
            sender,
            pool_reader: Box::new(pool_readers::IngressClient::new(
                ingress_pool,
                priority_fn_and_filter_producer,
                malicious_flags,
            )),
        },
        jh,
    )
}

pub fn create_consensus_handlers<
    PoolConsensus: MutablePool<ConsensusArtifact> + Send + Sync + ValidatedPoolReader<ConsensusArtifact> + 'static,
    C: ChangeSetProducer<
            PoolConsensus,
            ChangeSet = <PoolConsensus as MutablePool<ConsensusArtifact>>::ChangeSet,
        > + 'static,
    G: PriorityFnAndFilterProducer<ConsensusArtifact, PoolConsensus> + 'static,
    S: Fn(ArtifactProcessorEvent<ConsensusArtifact>) + Send + 'static,
>(
    send_advert: S,
    consensus: C,
    consensus_gossip: Arc<G>,
    time_source: Arc<dyn TimeSource>,
    consensus_pool: Arc<RwLock<PoolConsensus>>,
    metrics_registry: MetricsRegistry,
) -> (ArtifactClientHandle<ConsensusArtifact>, Box<dyn JoinGuard>) {
    let client = processors::Processor::new(consensus_pool.clone(), consensus);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle {
            sender,
            pool_reader: Box::new(pool_readers::ConsensusClient::new(
                consensus_pool,
                consensus_gossip,
            )),
        },
        jh,
    )
}

pub fn create_certification_handlers<
    PoolCertification: MutablePool<CertificationArtifact>
        + ValidatedPoolReader<CertificationArtifact>
        + Send
        + Sync
        + 'static,
    C: ChangeSetProducer<
            PoolCertification,
            ChangeSet = <PoolCertification as MutablePool<CertificationArtifact>>::ChangeSet,
        > + 'static,
    G: PriorityFnAndFilterProducer<CertificationArtifact, PoolCertification> + 'static,
    S: Fn(ArtifactProcessorEvent<CertificationArtifact>) + Send + 'static,
>(
    send_advert: S,
    certifier: C,
    certifier_gossip: Arc<G>,
    time_source: Arc<dyn TimeSource>,
    certification_pool: Arc<RwLock<PoolCertification>>,
    metrics_registry: MetricsRegistry,
) -> (
    ArtifactClientHandle<CertificationArtifact>,
    Box<dyn JoinGuard>,
) {
    let client = processors::Processor::new(certification_pool.clone(), certifier);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle {
            sender,
            pool_reader: Box::new(pool_readers::CertificationClient::new(
                certification_pool,
                certifier_gossip,
            )),
        },
        jh,
    )
}

pub fn create_dkg_handlers<
    PoolDkg: MutablePool<DkgArtifact> + Send + Sync + ValidatedPoolReader<DkgArtifact> + 'static,
    C: ChangeSetProducer<PoolDkg, ChangeSet = <PoolDkg as MutablePool<DkgArtifact>>::ChangeSet>
        + 'static,
    G: PriorityFnAndFilterProducer<DkgArtifact, PoolDkg> + 'static,
    S: Fn(ArtifactProcessorEvent<DkgArtifact>) + Send + 'static,
>(
    send_advert: S,
    dkg: C,
    dkg_gossip: Arc<G>,
    time_source: Arc<dyn TimeSource>,
    dkg_pool: Arc<RwLock<PoolDkg>>,
    metrics_registry: MetricsRegistry,
) -> (ArtifactClientHandle<DkgArtifact>, Box<dyn JoinGuard>) {
    let client = processors::Processor::new(dkg_pool.clone(), dkg);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle::<DkgArtifact> {
            sender,
            pool_reader: Box::new(pool_readers::DkgClient::new(dkg_pool, dkg_gossip)),
        },
        jh,
    )
}

pub fn create_ecdsa_handlers<
    PoolEcdsa: MutablePool<EcdsaArtifact> + Send + Sync + ValidatedPoolReader<EcdsaArtifact> + 'static,
    C: ChangeSetProducer<
            PoolEcdsa,
            ChangeSet = <PoolEcdsa as MutablePool<EcdsaArtifact>>::ChangeSet,
        > + 'static,
    G: PriorityFnAndFilterProducer<EcdsaArtifact, PoolEcdsa> + 'static,
    S: Fn(ArtifactProcessorEvent<EcdsaArtifact>) + Send + 'static,
>(
    send_advert: S,
    ecdsa: C,
    ecdsa_gossip: Arc<G>,
    time_source: Arc<dyn TimeSource>,
    ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
    metrics_registry: MetricsRegistry,
) -> (ArtifactClientHandle<EcdsaArtifact>, Box<dyn JoinGuard>) {
    let client = processors::Processor::new(ecdsa_pool.clone(), ecdsa);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle::<EcdsaArtifact> {
            sender,
            pool_reader: Box::new(pool_readers::EcdsaClient::new(ecdsa_pool, ecdsa_gossip)),
        },
        jh,
    )
}

pub fn create_https_outcalls_handlers<
    PoolCanisterHttp: MutablePool<CanisterHttpArtifact>
        + ValidatedPoolReader<CanisterHttpArtifact>
        + Send
        + Sync
        + 'static,
    C: ChangeSetProducer<
            PoolCanisterHttp,
            ChangeSet = <PoolCanisterHttp as MutablePool<CanisterHttpArtifact>>::ChangeSet,
        > + 'static,
    G: PriorityFnAndFilterProducer<CanisterHttpArtifact, PoolCanisterHttp> + Send + Sync + 'static,
    S: Fn(ArtifactProcessorEvent<CanisterHttpArtifact>) + Send + 'static,
>(
    send_advert: S,
    pool_manager: C,
    canister_http_gossip: Arc<G>,
    time_source: Arc<dyn TimeSource>,
    canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
    metrics_registry: MetricsRegistry,
) -> (
    ArtifactClientHandle<CanisterHttpArtifact>,
    Box<dyn JoinGuard>,
) {
    let client = processors::Processor::new(canister_http_pool.clone(), pool_manager);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (
        ArtifactClientHandle::<CanisterHttpArtifact> {
            sender,
            pool_reader: Box::new(pool_readers::CanisterHttpClient::new(
                canister_http_pool,
                canister_http_gossip,
            )),
        },
        jh,
    )
}
