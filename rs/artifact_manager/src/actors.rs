//! The module runs `ArtifactProcessor` as actors.

use crate::{artifact::*, clients};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use ic_base_thread::async_safe_block_on_await;
use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::UnvalidatedArtifact,
    certification,
    certification::{Certifier, CertifierGossip, MutableCertificationPool},
    consensus::{Consensus, ConsensusGossip},
    consensus_pool::{ChangeAction as ConsensusAction, ConsensusPoolCache, MutableConsensusPool},
    dkg::{ChangeAction as DkgChangeAction, Dkg, DkgGossip, MutableDkgPool},
    ingress_manager::IngressHandler,
    ingress_pool::{
        ChangeAction as IngressAction, IngressPoolObject, IngressPoolSelect, MutableIngressPool,
        SelectResult,
    },
    time_source::{SysTimeSource, TimeSource},
};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::*,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    Time,
};
use prometheus::{histogram_opts, labels, Histogram, IntCounter};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex, RwLock};

use tokio::task::JoinHandle;

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
    ) -> (Vec<Advert<Artifact>>, ProcessingResult) {
        match self {
            BoxOrArcClient::BoxClient(client) => client.process_changes(time_source, artifacts),
            BoxOrArcClient::ArcClient(client) => client.process_changes(time_source, artifacts),
        }
    }
}

/// Metrics for a client actor.
struct ClientActorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
    /// The last update time.
    last_update: std::time::Instant,
}

impl ClientActorMetrics {
    /// The constructor creates a `ClientActorMetrics` instance.
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

/// Pokes the actor to run on_state_change()
struct ProcessRequest;

pub struct ClientActor<Artifact: ArtifactKind + 'static> {
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

impl<Artifact: ArtifactKind + 'static> ClientActor<Artifact> {
    pub fn new<S: Fn(Advert<Artifact>) + Send + 'static>(
        time_source: Arc<SysTimeSource>,
        metrics_registry: MetricsRegistry,
        client: BoxOrArcClient<Artifact>,
        send_advert: S,
        rt_handle: tokio::runtime::Handle,
    ) -> Self
    where
        <Artifact as ic_types::artifact::ArtifactKind>::Message: Send,
    {
        let pending_artifacts = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));

        let sender_cl = sender.clone();
        let pending_artifacts_cl = pending_artifacts.clone();
        let shutdown_cl = shutdown.clone();
        let handle = rt_handle.spawn_blocking(move || {
            Self::process_messages(
                pending_artifacts_cl,
                time_source,
                client,
                Box::new(send_advert),
                sender_cl,
                receiver,
                ClientActorMetrics::new(metrics_registry, Artifact::TAG.to_string()),
                shutdown_cl,
            );
        });

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

    #[allow(clippy::too_many_arguments)]
    fn process_messages<S: Fn(Advert<Artifact>) + Send + 'static>(
        pending_artifacts: Arc<Mutex<Vec<UnvalidatedArtifact<Artifact::Message>>>>,
        time_source: Arc<SysTimeSource>,
        client: BoxOrArcClient<Artifact>,
        send_advert: Box<S>,
        sender: Sender<ProcessRequest>,
        receiver: Receiver<ProcessRequest>,
        mut metrics: ClientActorMetrics,
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

impl<Artifact: ArtifactKind + 'static> Drop for ClientActor<Artifact> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, SeqCst);
            async_safe_block_on_await(handle).unwrap();
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
    /// The functions runs *Consensus* `on_state_change` as an actor in the
    /// given arbiter.
    ///
    /// It returns both a `client::ConsensusClient` and an actor address, which
    /// are to be managed by the `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Consensus + 'static,
        G: ConsensusGossip + 'static,
        S: Fn(Advert<ConsensusArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        ingress_pool: Arc<RwLock<PoolIngress>>,
        rt_handle: tokio::runtime::Handle,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::ConsensusClient<PoolConsensus>,
        ClientActor<ConsensusArtifact>,
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
        let actor = ClientActor::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
            rt_handle,
        );
        (
            clients::ConsensusClient::new(consensus_pool, consensus_gossip),
            actor,
        )
    }
}

impl<
        PoolConsensus: MutableConsensusPool + Send + Sync,
        PoolIngress: IngressPoolSelect + Send + Sync + 'static,
    > ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<PoolConsensus, PoolIngress>
{
    /// The method processes changes in the *Consensus* pool and ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<ConsensusMessage>>,
    ) -> (Vec<Advert<ConsensusArtifact>>, ProcessingResult) {
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
                    adverts.push(ConsensusArtifact::message_to_advert(to_add))
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    adverts.push(ConsensusArtifact::message_to_advert(to_move))
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
}

impl<Pool: MutableIngressPool + Send + Sync + 'static> IngressProcessor<Pool> {
    /// The function runs ingress `on_state_change` as an actor in the given
    /// arbiter. It returns both a `client::IngressClient` and an actor
    /// address, both of which are to be managed by the 'ArtifactManager'.
    #[allow(clippy::too_many_arguments)]
    pub fn build<S: Fn(Advert<IngressArtifact>) + Send + 'static>(
        send_advert: S,
        time_source: Arc<SysTimeSource>,
        ingress_pool: Arc<RwLock<Pool>>,
        ingress_handler: Arc<dyn IngressHandler + Send + Sync>,
        rt_handle: tokio::runtime::Handle,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        malicious_flags: MaliciousFlags,
    ) -> (clients::IngressClient<Pool>, ClientActor<IngressArtifact>) {
        let client = Self {
            ingress_pool: ingress_pool.clone(),
            client: ingress_handler,
        };
        let actor = ClientActor::new(
            time_source.clone(),
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
            rt_handle,
        );
        (
            clients::IngressClient::new(time_source, ingress_pool, log, malicious_flags),
            actor,
        )
    }
}

impl<Pool: MutableIngressPool + Send + Sync> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<Pool>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<SignedIngress>>,
    ) -> (Vec<Advert<IngressArtifact>>, ProcessingResult) {
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

        let adverts = change_set
            .iter()
            .filter_map(|change_action| match change_action {
                IngressAction::MoveToValidated((message_id, size, attribute, integrity_hash)) => {
                    Some(Advert {
                        size: *size,
                        id: message_id.clone(),
                        attribute: attribute.clone(),
                        integrity_hash: integrity_hash.clone(),
                    })
                }
                IngressAction::RemoveFromUnvalidated(_)
                | IngressAction::RemoveFromValidated(_)
                | IngressAction::PurgeBelowExpiry(_) => None,
            })
            .collect();
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
    /// The function runs certification `on_state_change` as an actor in the
    /// given arbiter. It returns both a `client::CertificationClient` and
    /// an actor address, both of which are to be managed by the
    /// `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Certifier + 'static,
        G: CertifierGossip + 'static,
        S: Fn(Advert<CertificationArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        rt_handle: tokio::runtime::Handle,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::CertificationClient<PoolCertification>,
        ClientActor<CertificationArtifact>,
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
        let actor = ClientActor::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
            rt_handle,
        );
        (
            clients::CertificationClient::new(
                consensus_pool_cache,
                certification_pool,
                certifier_gossip,
            ),
            actor,
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
    ) -> (Vec<Advert<CertificationArtifact>>, ProcessingResult) {
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
                    adverts.push(CertificationArtifact::message_to_advert(msg))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert(msg))
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
    /// The functino runs DKG `on_state_change` as an actor in the given
    /// arbiter. It returns both `client::DkgClient` and an actor address,
    /// both of which are to be managed by the `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn build<
        C: Dkg + 'static,
        G: DkgGossip + 'static,
        S: Fn(Advert<DkgArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        dkg_pool: Arc<RwLock<PoolDkg>>,
        rt_handle: tokio::runtime::Handle,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (clients::DkgClient<PoolDkg>, ClientActor<DkgArtifact>) {
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
        let actor = ClientActor::new(
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
            rt_handle,
        );
        (clients::DkgClient::new(dkg_pool, dkg_gossip), actor)
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
    ) -> (Vec<Advert<DkgArtifact>>, ProcessingResult) {
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
                    DkgChangeAction::AddToValidated(to_add) => {
                        adverts.push(DkgArtifact::message_to_advert(to_add))
                    }
                    DkgChangeAction::MoveToValidated(message) => {
                        adverts.push(DkgArtifact::message_to_advert(message))
                    }
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
