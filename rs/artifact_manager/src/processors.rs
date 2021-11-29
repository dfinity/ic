//! The tokio thread based implementation of `ArtifactProcessor`

use crate::{artifact::*, clients};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::UnvalidatedArtifact,
    certification,
    certification::{Certifier, CertifierGossip, MutableCertificationPool},
    consensus::{Consensus, ConsensusGossip},
    consensus_pool::{ChangeAction as ConsensusAction, ConsensusPoolCache, MutableConsensusPool},
    dkg::{ChangeAction as DkgChangeAction, Dkg, DkgGossip, MutableDkgPool},
    ecdsa::{Ecdsa, EcdsaChangeAction, EcdsaGossip, MutableEcdsaPool},
    ingress_manager::IngressHandler,
    ingress_pool::{
        ChangeAction as IngressAction, IngressPoolObject, IngressPoolSelect, MutableIngressPool,
        SelectResult,
    },
    time_source::{SysTimeSource, TimeSource},
};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::consensus::HasRank;
use ic_types::{
    artifact::*,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    NodeId, Time,
};
use prometheus::{histogram_opts, labels, Histogram, IntCounter};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{Builder as ThreadBuilder, JoinHandle};

#[derive(Debug, PartialEq, Eq)]
enum AdvertSource {
    /// The artifact was produced by this peer
    Produced,

    /// Artifact was downloaded from another peer and being relayed
    Relayed,
}

/// A client may be either wrapped in `Box` or `Arc`.
pub enum BoxOrArcClient<Artifact: ArtifactKind> {
    /// The client wrapped in `Box`.
    BoxClient(Box<dyn ArtifactProcessor<Artifact>>),
    /// The client wrapped in `Arc`.
    ArcClient(Arc<dyn ArtifactProcessor<Artifact> + Sync + 'static>),
}

impl<Artifact: ArtifactKind> BoxOrArcClient<Artifact> {
    /// The method calls the corresponding client's `process_changes` with the
    /// given time source and artifacts.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<Artifact::Message>>,
    ) -> (Vec<AdvertSendRequest<Artifact>>, ProcessingResult) {
        match self {
            BoxOrArcClient::BoxClient(client) => client.process_changes(time_source, artifacts),
            BoxOrArcClient::ArcClient(client) => client.process_changes(time_source, artifacts),
        }
    }
}

/// Metrics for a client artifact processor.
struct ArtifactProcessorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
    /// The last update time.
    last_update: std::time::Instant,
}

impl ArtifactProcessorMetrics {
    /// The constructor creates a `ArtifactProcessorMetrics` instance.
    fn new(metrics_registry: MetricsRegistry, client: String) -> Self {
        let processing_time = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_time_seconds",
                "Artifact manager client processing time, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                labels! {"client".to_string() => client.clone()}
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
                labels! {"client".to_string() => client}
            ))
            .unwrap(),
        );

        Self {
            processing_time,
            processing_interval,
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

/// Pokes the thread to run on_state_change()
struct ProcessRequest;

/// Manages the life cycle of the client specific artifact processor thread.
/// Also serves as the front end to enqueue requests to the processor thread.
pub struct ArtifactProcessorManager<Artifact: ArtifactKind + 'static> {
    /// The list of unvalidated artifacts.
    pending_artifacts: Arc<Mutex<Vec<UnvalidatedArtifact<Artifact::Message>>>>,
    /// To send the process requests
    sender: Sender<ProcessRequest>,
    /// Handle for the processing thread
    handle: Option<JoinHandle<()>>,
    /// To signal processing thread to exit.
    /// TODO: handle.abort() does not seem to work as expected
    shutdown: Arc<AtomicBool>,
}

impl<Artifact: ArtifactKind + 'static> ArtifactProcessorManager<Artifact> {
    pub fn new<S: Fn(AdvertSendRequest<Artifact>) + Send + 'static>(
        time_source: Arc<SysTimeSource>,
        metrics_registry: MetricsRegistry,
        client: BoxOrArcClient<Artifact>,
        send_advert: S,
    ) -> Self
    where
        <Artifact as ic_types::artifact::ArtifactKind>::Message: Send,
    {
        let pending_artifacts = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));

        // Spawn the processor thread
        let sender_cl = sender.clone();
        let pending_artifacts_cl = pending_artifacts.clone();
        let shutdown_cl = shutdown.clone();
        let handle = ThreadBuilder::new()
            .name("ArtifactProcessorThread".to_string())
            .spawn(move || {
                Self::process_messages(
                    pending_artifacts_cl,
                    time_source,
                    client,
                    Box::new(send_advert),
                    sender_cl,
                    receiver,
                    ArtifactProcessorMetrics::new(metrics_registry, Artifact::TAG.to_string()),
                    shutdown_cl,
                );
            })
            .unwrap();

        Self {
            pending_artifacts,
            sender,
            handle: Some(handle),
            shutdown,
        }
    }

    pub fn on_artifact(&self, artifact: UnvalidatedArtifact<Artifact::Message>) {
        let mut pending_artifacts = self.pending_artifacts.lock().unwrap();
        pending_artifacts.push(artifact);
        self.sender
            .send(ProcessRequest)
            .unwrap_or_else(|err| panic!("Failed to send request: {:?}", err));
    }

    // The artifact processor thread loop
    #[allow(clippy::too_many_arguments)]
    fn process_messages<S: Fn(AdvertSendRequest<Artifact>) + Send + 'static>(
        pending_artifacts: Arc<Mutex<Vec<UnvalidatedArtifact<Artifact::Message>>>>,
        time_source: Arc<SysTimeSource>,
        client: BoxOrArcClient<Artifact>,
        send_advert: Box<S>,
        sender: Sender<ProcessRequest>,
        receiver: Receiver<ProcessRequest>,
        mut metrics: ArtifactProcessorMetrics,
        shutdown: Arc<AtomicBool>,
    ) {
        let recv_timeout = std::time::Duration::from_millis(ARTIFACT_MANAGER_TIMER_DURATION_MSEC);
        loop {
            let ret = receiver.recv_timeout(recv_timeout);
            if shutdown.load(SeqCst) {
                return;
            }

            match ret {
                Ok(_) | Err(RecvTimeoutError::Timeout) => {
                    time_source.update_time().ok();

                    let artifacts = {
                        let mut artifacts = Vec::new();
                        let mut received_artifacts = pending_artifacts.lock().unwrap();
                        std::mem::swap(&mut artifacts, &mut received_artifacts);
                        artifacts
                    };

                    let (adverts, result) = metrics
                        .with_metrics(|| client.process_changes(time_source.as_ref(), artifacts));

                    if let ProcessingResult::StateChanged = result {
                        // TODO: assess impact of continued processing in same
                        // iteration if StateChanged, get rid of sending self messages
                        sender
                            .send(ProcessRequest)
                            .unwrap_or_else(|err| panic!("Failed to send request: {:?}", err));
                    }
                    adverts.into_iter().for_each(&send_advert);
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

impl<Artifact: ArtifactKind + 'static> Drop for ArtifactProcessorManager<Artifact> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, SeqCst);
            handle.join().unwrap();
        }
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

/// *Consensus* `OnStateChange` client.
pub struct ConsensusProcessor<PoolConsensus, PoolIngress> {
    /// The *Consensus* pool.
    consensus_pool: Arc<RwLock<PoolConsensus>>,
    /// The ingress pool.
    ingress_pool: Arc<RwLock<PoolIngress>>,
    /// The *Consensus* client.
    client: Box<dyn Consensus>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<
        PoolConsensus: MutableConsensusPool + Send + Sync + 'static,
        PoolIngress: IngressPoolSelect + Send + Sync + 'static,
    > ConsensusProcessor<PoolConsensus, PoolIngress>
{
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Consensus + 'static,
        G: ConsensusGossip + 'static,
        S: Fn(AdvertSendRequest<ConsensusArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        ingress_pool: Arc<RwLock<PoolIngress>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::ConsensusClient<PoolConsensus>,
        ArtifactProcessorManager<ConsensusArtifact>,
    ) {
        let (consensus, consensus_gossip) = setup();
        let client = Self {
            consensus_pool: consensus_pool.clone(),
            ingress_pool,
            client: Box::new(consensus),
            invalidated_artifacts: metrics_registry.int_counter(
                "consensus_invalidated_artifacts",
                "The number of invalidated consensus artifacts",
            ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (
            clients::ConsensusClient::new(consensus_pool, consensus_gossip),
            manager,
        )
    }

    fn advert_class(&self, msg: &ConsensusMessage, source: AdvertSource) -> AdvertClass {
        // Notify all peers for artifacts produced by us
        if source == AdvertSource::Produced {
            return AdvertClass::Critical;
        }

        // For relayed artifacts: use best effort for shares,
        // notify all peers for the rest (actual objects like block
        // proposals, notary/finalization)
        match msg {
            ConsensusMessage::RandomBeacon(_) => AdvertClass::Critical,
            ConsensusMessage::Notarization(_) => AdvertClass::Critical,
            ConsensusMessage::Finalization(_) => AdvertClass::Critical,
            ConsensusMessage::RandomTape(_) => AdvertClass::Critical,
            ConsensusMessage::CatchUpPackage(_) => AdvertClass::Critical,
            ConsensusMessage::BlockProposal(_) => AdvertClass::Critical,
            ConsensusMessage::RandomBeaconShare(_) => AdvertClass::BestEffort,
            ConsensusMessage::NotarizationShare(_) => AdvertClass::BestEffort,
            ConsensusMessage::FinalizationShare(_) => AdvertClass::BestEffort,
            ConsensusMessage::RandomTapeShare(_) => AdvertClass::BestEffort,
            ConsensusMessage::CatchUpPackageShare(_) => AdvertClass::BestEffort,
        }
    }
}

impl<
        PoolConsensus: MutableConsensusPool + Send + Sync + 'static,
        PoolIngress: IngressPoolSelect + Send + Sync + 'static,
    > ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<PoolConsensus, PoolIngress>
{
    /// The method processes changes in the *Consensus* pool and ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<ConsensusMessage>>,
    ) -> (Vec<AdvertSendRequest<ConsensusArtifact>>, ProcessingResult) {
        {
            let mut consensus_pool = self.consensus_pool.write().unwrap();
            for artifact in artifacts {
                debug!(
                    tag => "consensus_trace",
                    self.log,
                    "process_change::artifact {}",
                    serde_json::to_string(&artifact).unwrap()
                );
                consensus_pool.insert(artifact)
            }
        }
        let mut adverts = Vec::new();
        let change_set = {
            let consensus_pool = self.consensus_pool.read().unwrap();
            let ingress_pool = Arc::clone(&self.ingress_pool) as Arc<_>;
            let ingress_pool = IngressPoolSelectWrapper::new(&ingress_pool);
            self.client.on_state_change(&*consensus_pool, &ingress_pool)
        };
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for change_action in change_set.iter() {
            debug!(
                tag => "consensus_trace",
                self.log,
                "process_change::change_action {}",
                serde_json::to_string(&change_action).unwrap()
            );
            match change_action {
                ConsensusAction::AddToValidated(to_add) => {
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_add,
                        self.advert_class(to_add, AdvertSource::Produced),
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_add {
                        let rank = p.clone().content.decompose().1.rank();
                        info!(
                            self.log,
                            "Added proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_move,
                        self.advert_class(to_move, AdvertSource::Relayed),
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_move {
                        let rank = p.clone().content.decompose().1.rank();
                        info!(
                            self.log,
                            "Moved proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::RemoveFromValidated(_) => {}
                ConsensusAction::RemoveFromUnvalidated(_) => {}
                ConsensusAction::PurgeValidatedBelow(_) => {}
                ConsensusAction::PurgeUnvalidatedBelow(_) => {}
                ConsensusAction::HandleInvalid(artifact, s) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid artifact {} {:?}", s, artifact);
                }
            }
        }
        debug!(
            tag => "consensus_trace",
            self.log,
            "process_change::apply_changes {}",
            serde_json::to_string(&time_source.get_relative_time()).unwrap()
        );

        self.consensus_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);

        (adverts, changed)
    }
}

/// A wrapper for the ingress pool that delays locking until the member function
/// of `IngressPoolSelect` is actually called.
struct IngressPoolSelectWrapper {
    pool: std::sync::Arc<std::sync::RwLock<dyn IngressPoolSelect>>,
}

impl IngressPoolSelectWrapper {
    /// The constructor creates a `IngressPoolSelectWrapper` instance.
    pub fn new(pool: &std::sync::Arc<std::sync::RwLock<dyn IngressPoolSelect>>) -> Self {
        IngressPoolSelectWrapper { pool: pool.clone() }
    }
}

/// `IngressPoolSelectWrapper` implements the `IngressPoolSelect` trait.
impl IngressPoolSelect for IngressPoolSelectWrapper {
    fn select_validated<'a>(
        &self,
        range: std::ops::RangeInclusive<Time>,
        f: Box<dyn FnMut(&IngressPoolObject) -> SelectResult<SignedIngress> + 'a>,
    ) -> Vec<SignedIngress> {
        let pool = self.pool.read().unwrap();
        pool.select_validated(range, f)
    }
}

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<Pool> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<Pool>>,
    /// The ingress handler.
    client: Arc<dyn IngressHandler + Send + Sync>,
    /// Our node id
    node_id: NodeId,
}

impl<Pool: MutableIngressPool + Send + Sync + 'static> IngressProcessor<Pool> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<S: Fn(AdvertSendRequest<IngressArtifact>) + Send + 'static>(
        send_advert: S,
        time_source: Arc<SysTimeSource>,
        ingress_pool: Arc<RwLock<Pool>>,
        ingress_handler: Arc<dyn IngressHandler + Send + Sync>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        node_id: NodeId,
        malicious_flags: MaliciousFlags,
    ) -> (
        clients::IngressClient<Pool>,
        ArtifactProcessorManager<IngressArtifact>,
    ) {
        let client = Self {
            ingress_pool: ingress_pool.clone(),
            client: ingress_handler,
            node_id,
        };
        let manager = ArtifactProcessorManager::new(
            time_source.clone(),
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (
            clients::IngressClient::new(time_source, ingress_pool, log, malicious_flags),
            manager,
        )
    }

    fn advert_class(&self, source: AdvertSource) -> AdvertClass {
        // 1. Notify all peers for ingress messages received directly by us
        // 2. For relayed ingress messages: don't notify any peers
        match source {
            AdvertSource::Produced => AdvertClass::Critical,
            AdvertSource::Relayed => AdvertClass::None,
        }
    }
}

impl<Pool: MutableIngressPool + Send + Sync + 'static> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<Pool>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<SignedIngress>>,
    ) -> (Vec<AdvertSendRequest<IngressArtifact>>, ProcessingResult) {
        {
            let mut ingress_pool = self.ingress_pool.write().unwrap();
            for artifact in artifacts {
                ingress_pool.insert(artifact)
            }
        }
        let change_set = {
            let pool = self.ingress_pool.read().unwrap();
            self.client.on_state_change(&*pool)
        };

        let mut adverts = Vec::new();
        for change_action in change_set.iter() {
            match change_action {
                IngressAction::MoveToValidated((
                    message_id,
                    source_node_id,
                    size,
                    attribute,
                    integrity_hash,
                )) => {
                    let advert_source = if *source_node_id == self.node_id {
                        AdvertSource::Produced
                    } else {
                        AdvertSource::Relayed
                    };
                    adverts.push(AdvertSendRequest {
                        advert: Advert {
                            size: *size,
                            id: message_id.clone(),
                            attribute: attribute.clone(),
                            integrity_hash: integrity_hash.clone(),
                        },
                        advert_class: self.advert_class(advert_source),
                    });
                }
                IngressAction::RemoveFromUnvalidated(_)
                | IngressAction::RemoveFromValidated(_)
                | IngressAction::PurgeBelowExpiry(_) => {}
            }
        }
        self.ingress_pool
            .write()
            .unwrap()
            .apply_changeset(change_set);
        (adverts, ProcessingResult::StateUnchanged)
    }
}

/// Certification `OnStateChange` client.
pub struct CertificationProcessor<PoolCertification> {
    /// The *Consensus* pool cache.
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The certification pool.
    certification_pool: Arc<RwLock<PoolCertification>>,
    /// The certifier.
    client: Box<dyn Certifier>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    CertificationProcessor<PoolCertification>
{
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Certifier + 'static,
        G: CertifierGossip + 'static,
        S: Fn(AdvertSendRequest<CertificationArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::CertificationClient<PoolCertification>,
        ArtifactProcessorManager<CertificationArtifact>,
    ) {
        let (certifier, certifier_gossip) = setup();
        let client = Self {
            consensus_pool_cache: consensus_pool_cache.clone(),
            certification_pool: certification_pool.clone(),
            client: Box::new(certifier),
            invalidated_artifacts: metrics_registry.int_counter(
                "certification_invalidated_artifacts",
                "The number of invalidated certification artifacts",
            ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (
            clients::CertificationClient::new(
                consensus_pool_cache,
                certification_pool,
                certifier_gossip,
            ),
            manager,
        )
    }
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    ArtifactProcessor<CertificationArtifact> for CertificationProcessor<PoolCertification>
{
    /// The method processes changes in the certification pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CertificationMessage>>,
    ) -> (
        Vec<AdvertSendRequest<CertificationArtifact>>,
        ProcessingResult,
    ) {
        {
            let mut certification_pool = self.certification_pool.write().unwrap();
            for artifact in artifacts {
                certification_pool.insert(artifact.message)
            }
        }
        let mut adverts = Vec::new();
        let change_set = self.client.on_state_change(
            self.consensus_pool_cache.as_ref(),
            self.certification_pool.clone(),
        );
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for action in change_set.iter() {
            match action {
                certification::ChangeAction::AddToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert_send_request(
                        msg,
                        AdvertClass::Critical,
                    ))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert_send_request(
                        msg,
                        AdvertClass::Critical,
                    ))
                }
                certification::ChangeAction::HandleInvalid(msg, reason) => {
                    self.invalidated_artifacts.inc();
                    warn!(
                        self.log,
                        "Invalid certification message ({:?}): {:?}", reason, msg
                    );
                }
                _ => {}
            }
        }
        self.certification_pool
            .write()
            .unwrap()
            .apply_changes(change_set);
        (adverts, changed)
    }
}

/// Distributed key generation (DKG) `OnStateChange` client.
pub struct DkgProcessor<PoolDkg> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    dkg_pool: Arc<RwLock<PoolDkg>>,
    /// The DKG client.
    client: Box<dyn Dkg>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> DkgProcessor<PoolDkg> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Dkg + 'static,
        G: DkgGossip + 'static,
        S: Fn(AdvertSendRequest<DkgArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        dkg_pool: Arc<RwLock<PoolDkg>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::DkgClient<PoolDkg>,
        ArtifactProcessorManager<DkgArtifact>,
    ) {
        let (dkg, dkg_gossip) = setup();
        let client = Self {
            dkg_pool: dkg_pool.clone(),
            client: Box::new(dkg),
            invalidated_artifacts: metrics_registry.int_counter(
                "dkg_invalidated_artifacts",
                "The number of invalidated DKG artifacts",
            ),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (clients::DkgClient::new(dkg_pool, dkg_gossip), manager)
    }
}

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> ArtifactProcessor<DkgArtifact>
    for DkgProcessor<PoolDkg>
{
    /// The method processes changes in the DKG pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<dkg::Message>>,
    ) -> (Vec<AdvertSendRequest<DkgArtifact>>, ProcessingResult) {
        {
            let mut dkg_pool = self.dkg_pool.write().unwrap();
            for artifact in artifacts {
                dkg_pool.insert(artifact)
            }
        }
        let mut adverts = Vec::new();
        let change_set = {
            let dkg_pool = self.dkg_pool.read().unwrap();
            let change_set = self.client.on_state_change(&*dkg_pool);
            for change_action in change_set.iter() {
                match change_action {
                    DkgChangeAction::AddToValidated(to_add) => adverts.push(
                        DkgArtifact::message_to_advert_send_request(to_add, AdvertClass::Critical),
                    ),
                    DkgChangeAction::MoveToValidated(message) => adverts.push(
                        DkgArtifact::message_to_advert_send_request(message, AdvertClass::Critical),
                    ),
                    DkgChangeAction::HandleInvalid(msg, reason) => {
                        self.invalidated_artifacts.inc();
                        warn!(self.log, "Invalid DKG message ({:?}): {:?}", reason, msg);
                    }
                    _ => (),
                }
            }
            change_set
        };
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        self.dkg_pool.write().unwrap().apply_changes(change_set);
        (adverts, changed)
    }
}

/// ECDSA `OnStateChange` client.
pub struct EcdsaProcessor<PoolEcdsa> {
    ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
    client: Box<dyn Ecdsa>,
    log: ReplicaLogger,
}

impl<PoolEcdsa: MutableEcdsaPool + Send + Sync + 'static> EcdsaProcessor<PoolEcdsa> {
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Ecdsa + 'static,
        G: EcdsaGossip + 'static,
        S: Fn(AdvertSendRequest<EcdsaArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> (
        clients::EcdsaClient<PoolEcdsa>,
        ArtifactProcessorManager<EcdsaArtifact>,
    ) {
        let (ecdsa, ecdsa_gossip) = setup();
        let client = Self {
            ecdsa_pool: ecdsa_pool.clone(),
            client: Box::new(ecdsa),
            log,
        };
        let manager = ArtifactProcessorManager::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (clients::EcdsaClient::new(ecdsa_pool, ecdsa_gossip), manager)
    }
}

impl<PoolEcdsa: MutableEcdsaPool + Send + Sync + 'static> ArtifactProcessor<EcdsaArtifact>
    for EcdsaProcessor<PoolEcdsa>
{
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<EcdsaMessage>>,
    ) -> (Vec<AdvertSendRequest<EcdsaArtifact>>, ProcessingResult) {
        {
            let mut ecdsa_pool = self.ecdsa_pool.write().unwrap();
            for artifact in artifacts {
                ecdsa_pool.insert(artifact)
            }
        }

        let mut adverts = Vec::new();
        let change_set = {
            let ecdsa_pool = self.ecdsa_pool.read().unwrap();
            let change_set = self.client.on_state_change(&*ecdsa_pool);

            for change_action in change_set.iter() {
                match change_action {
                    EcdsaChangeAction::AddToValidated(msg) => adverts.push(
                        EcdsaArtifact::message_to_advert_send_request(msg, AdvertClass::Critical),
                    ),
                    EcdsaChangeAction::MoveToValidated(msg_id) => {
                        if let Some(msg) = ecdsa_pool.unvalidated().get(msg_id) {
                            adverts.push(EcdsaArtifact::message_to_advert_send_request(
                                &msg,
                                AdvertClass::Critical,
                            ))
                        } else {
                            warn!(
                                self.log,
                                "EcdsaProcessor::MoveToValidated(): artifact not found: {:?}",
                                msg_id
                            );
                        }
                    }
                    EcdsaChangeAction::RemoveValidated(_) => {}
                    EcdsaChangeAction::RemoveUnvalidated(_) => {}
                    EcdsaChangeAction::HandleInvalid(_, _) => {}
                }
            }
            change_set
        };

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        self.ecdsa_pool.write().unwrap().apply_changes(change_set);
        (adverts, changed)
    }
}
