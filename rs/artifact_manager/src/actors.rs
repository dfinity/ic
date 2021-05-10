//! The module runs `ArtifactProcessor` as actors.

use crate::{artifact::*, clients};
use actix::prelude::*;
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
    messages::SignedIngress,
    Time,
};
use prometheus::{histogram_opts, labels, Histogram, IntCounter};
use std::sync::{Arc, RwLock};

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

/// Each `ArtifactProcessor` runs as an actor.
///
/// It receives `PollEvent`s from external interface, and will run
/// `on_state_change` in response to `PollEvent`s. The result of
/// `on_state_change` is a list of `GossipAdvert`s to send to P2P. At the
/// moment, a `send_advert` callback is used to deliver adverts. The future plan
/// is to use actor messages for this purpose.
pub struct ClientActor<Artifact: ArtifactKind> {
    /// The time source, using automatic reference counting.
    time_source: Arc<SysTimeSource>,
    /// The client, wrapped in either `Box` or `Arc`.
    client: BoxOrArcClient<Artifact>,
    /// The send advert function.
    send_advert: Box<dyn Fn(Advert<Artifact>) + Send>,
    /// Flag indicating if 'OnStateChange' is scheduled.
    pending_on_state_change: bool,
    /// The list of unvalidated artifacts.
    pending_artifacts: Vec<UnvalidatedArtifact<Artifact::Message>>,
    /// The client actor metrics.
    metrics: Option<ClientActorMetrics>,
}

impl<Artifact: ArtifactKind + 'static> ClientActor<Artifact> {
    /// The function creates an actor and starts it in the given `arbiter`.
    ///
    /// It also sets up a regular timer to send `PollEvent`s to this actor
    /// every `AM_TIMER_DURATION_MSEC` milliseconds.
    pub fn new<S: Fn(Advert<Artifact>) + Send + 'static>(
        arbiter: &Arbiter,
        time_source: Arc<SysTimeSource>,
        metrics_registry: MetricsRegistry,
        client: BoxOrArcClient<Artifact>,
        send_advert: S,
    ) -> Addr<ClientActor<Artifact>> {
        let address = ClientActor::start_in_arbiter(arbiter, move |_| ClientActor {
            time_source,
            client,
            send_advert: Box::new(send_advert),
            pending_on_state_change: false,
            pending_artifacts: Vec::new(),
            metrics: Some(ClientActorMetrics::new(
                metrics_registry,
                Artifact::TAG.to_string(),
            )),
        });
        let address_clone = address.clone();
        let timer = Box::pin(async move {
            let mut interval = actix::clock::interval_at(
                actix::clock::Instant::now(),
                std::time::Duration::from_millis(ARTIFACT_MANAGER_TIMER_DURATION_MSEC),
            );
            loop {
                interval.tick().await;
                address_clone.do_send(PollEvent);
            }
        });
        arbiter.send(timer);
        address
    }
}

impl<Artifact: ArtifactKind + 'static> Actor for ClientActor<Artifact> {
    type Context = Context<Self>;
}

/// The `ClientActor` responds to `PollEvent`s by running `on_state_change`.
///
/// Since external `PollEvent`s may come at any time, and `on_state_change`
/// must be run sequentially, an internal `pending_on_state_change` flag
/// and an internal event type `OnStateChange` is used to make sure that
/// `on_state_change` is not run more frequently than necessary.
//
// Each `OnStateChange` event corresponds to an `on_state_change` invocation. The code behaves
// as follows:
// - If a `PollEvent` comes in while there is no `OnStateChange` being scheduled (i.e.
//   'pending_on_state_change' is false), we'll schedule one.
// - If we have already scheduled an `OnStateChange` event (i.e. 'pending_on_state_change' is true),
//   we will ignore the `PollEvent`.
//
// Effectively this rule makes sure there is at most one 'OneStateChange' event in the mailbox.
//
// It may also happen that each `on_state_change` takes longer than the poll interval. In this case,
// we will still schedule the next 'OnStageChange' so that we run next `on_state_change` as soon as
// possible. This is different than enforcing a fixed interval between two `on_state_change` calls.
#[derive(Message)]
#[rtype(result = "Result<(), ()>")]
struct PollEvent;

impl<Artifact: ArtifactKind + 'static> Handler<PollEvent> for ClientActor<Artifact> {
    type Result = Result<(), ()>;

    /// The method handles the given `PollEvent`.
    ///
    /// If the the `changed` flag is not set, the method triggers an
    /// `OnStateChange` event and sets the `changed` flag in the process.
    fn handle(&mut self, _poll_event: PollEvent, ctx: &mut Self::Context) -> Self::Result {
        if !self.pending_on_state_change {
            self.pending_on_state_change = true;
            ctx.address().do_send(OnStateChangeEvent)
        }
        Ok(())
    }
}

/// The struct holds an unvalidated artifact message.
#[derive(Message)]
#[rtype(result = "Result<(), ()>")]
pub(crate) struct NewArtifact<Artifact: ArtifactKind>(
    pub(crate) UnvalidatedArtifact<Artifact::Message>,
);

impl<Artifact: ArtifactKind + 'static> Handler<NewArtifact<Artifact>> for ClientActor<Artifact> {
    type Result = Result<(), ()>;

    /// The method handles the given `NewArtifact`.
    ///
    /// The `NewArtifact` is cached in a batch, which will be processed once
    /// `on_state_change` is called.
    /// Other than that, it behaves just like the
    /// handling of `PollEvent`, i.e., If the the `changed` flag is not set, the
    /// method  triggers an `OnStateChange` event and sets the `changed` flag in
    /// the process.
    fn handle(&mut self, event: NewArtifact<Artifact>, ctx: &mut Self::Context) -> Self::Result {
        self.pending_artifacts.push(event.0);
        if !self.pending_on_state_change {
            self.pending_on_state_change = true;
            ctx.address().do_send(OnStateChangeEvent)
        }
        Ok(())
    }
}

/// An internal event that triggers `on_state_change` to start running.
#[derive(Message)]
#[rtype(result = "Result<(), ()>")]
struct OnStateChangeEvent;

impl<Artifact: ArtifactKind + 'static> Handler<OnStateChangeEvent> for ClientActor<Artifact> {
    type Result = Result<(), ()>;

    /// The method disregards the given `OnStateChangeEvent`.
    ///
    /// Instead of running `on_state_change` in a while loop until there are no
    /// more changes, another `OnStateChangeEvent` is sent to the same actor
    /// at the end if there are more changes, giving other asynchronous jobs
    /// a chance to run.
    fn handle(&mut self, _poll_event: OnStateChangeEvent, ctx: &mut Self::Context) -> Self::Result {
        // First, reset the `pending_on_state_change` flag.
        self.pending_on_state_change = false;
        self.time_source.update_time().ok();
        let mut artifacts = Vec::new();
        std::mem::swap(&mut artifacts, &mut self.pending_artifacts);
        let time_source = self.time_source.as_ref();
        let mut metrics = self.metrics.take().unwrap();
        let (adverts, result) =
            metrics.with_metrics(|| self.client.process_changes(time_source, artifacts));
        self.metrics = Some(metrics);
        if let ProcessingResult::StateChanged = result {
            self.pending_on_state_change = true;
            ctx.address().do_send(OnStateChangeEvent);
        }
        adverts.into_iter().for_each(&self.send_advert);
        Ok(())
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

/// *Consensus* `OnStateChange` client.
pub struct ConsensusClient<PoolConsensus, PoolIngress> {
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
    > ConsensusClient<PoolConsensus, PoolIngress>
{
    /// The functions runs *Consensus* `on_state_change` as an actor in the
    /// given arbiter.
    ///
    /// It returns both a `client::ConsensusClient` and an actor address, which
    /// are to be managed by the `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn run<
        C: Consensus + 'static,
        G: ConsensusGossip + 'static,
        S: Fn(Advert<ConsensusArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        arbiter: &Arbiter,
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        ingress_pool: Arc<RwLock<PoolIngress>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::ConsensusClient<PoolConsensus>,
        Addr<ClientActor<ConsensusArtifact>>,
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
        let addr = ClientActor::new(
            arbiter,
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (
            clients::ConsensusClient::new(consensus_pool, consensus_gossip),
            addr,
        )
    }
}

impl<
        PoolConsensus: MutableConsensusPool + Send + Sync,
        PoolIngress: IngressPoolSelect + Send + Sync + 'static,
    > ArtifactProcessor<ConsensusArtifact> for ConsensusClient<PoolConsensus, PoolIngress>
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
                    adverts.push(ConsensusArtifact::to_advert(to_add))
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    adverts.push(ConsensusArtifact::to_advert(to_move))
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
pub struct IngressClient<Pool> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<Pool>>,
    /// The ingress handler.
    client: Arc<dyn IngressHandler + Send + Sync>,
}

impl<Pool: MutableIngressPool + Send + Sync + 'static> IngressClient<Pool> {
    /// The function runs ingress `on_state_change` as an actor in the given
    /// arbiter. It returns both a `client::IngressClient` and an actor
    /// address, both of which are to be managed by the 'ArtifactManager'.
    #[allow(clippy::too_many_arguments)]
    pub fn run<S: Fn(Advert<IngressArtifact>) + Send + 'static>(
        arbiter: &Arbiter,
        send_advert: S,
        time_source: Arc<SysTimeSource>,
        ingress_pool: Arc<RwLock<Pool>>,
        ingress_handler: Arc<dyn IngressHandler + Send + Sync>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::IngressClient<Pool>,
        Addr<ClientActor<IngressArtifact>>,
    ) {
        let client = Self {
            ingress_pool: ingress_pool.clone(),
            client: ingress_handler,
        };
        let addr = ClientActor::new(
            arbiter,
            time_source.clone(),
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (
            clients::IngressClient::new(time_source, ingress_pool, log),
            addr,
        )
    }
}

impl<Pool: MutableIngressPool + Send + Sync> ArtifactProcessor<IngressArtifact>
    for IngressClient<Pool>
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
pub struct CertificationClient<PoolCertification> {
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
    CertificationClient<PoolCertification>
{
    /// The function runs certification `on_state_change` as an actor in the
    /// given arbiter. It returns both a `client::CertificationClient` and
    /// an actor address, both of which are to be managed by the
    /// `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn run<
        C: Certifier + 'static,
        G: CertifierGossip + 'static,
        S: Fn(Advert<CertificationArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        arbiter: &Arbiter,
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (
        clients::CertificationClient<PoolCertification>,
        Addr<ClientActor<CertificationArtifact>>,
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
        let addr = ClientActor::new(
            arbiter,
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
            addr,
        )
    }
}

impl<PoolCertification: MutableCertificationPool + Send + Sync + 'static>
    ArtifactProcessor<CertificationArtifact> for CertificationClient<PoolCertification>
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
                    adverts.push(CertificationArtifact::to_advert(msg))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(CertificationArtifact::to_advert(msg))
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
pub struct DkgClient<PoolDkg> {
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

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> DkgClient<PoolDkg> {
    /// The functino runs DKG `on_state_change` as an actor in the given
    /// arbiter. It returns both `client::DkgClient` and an actor address,
    /// both of which are to be managed by the `ArtifactManager`.
    #[allow(clippy::too_many_arguments)]
    pub fn run<
        C: Dkg + 'static,
        G: DkgGossip + 'static,
        S: Fn(Advert<DkgArtifact>) + Send + 'static,
        F: FnOnce() -> (C, G),
    >(
        arbiter: &Arbiter,
        send_advert: S,
        setup: F,
        time_source: Arc<SysTimeSource>,
        dkg_pool: Arc<RwLock<PoolDkg>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> (clients::DkgClient<PoolDkg>, Addr<ClientActor<DkgArtifact>>) {
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
        let addr = ClientActor::new(
            arbiter,
            time_source,
            metrics_registry,
            BoxOrArcClient::BoxClient(Box::new(client)),
            send_advert,
        );
        (clients::DkgClient::new(dkg_pool, dkg_gossip), addr)
    }
}

impl<PoolDkg: MutableDkgPool + Send + Sync + 'static> ArtifactProcessor<DkgArtifact>
    for DkgClient<PoolDkg>
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
                        adverts.push(DkgArtifact::to_advert(to_add))
                    }
                    DkgChangeAction::MoveToValidated(message) => {
                        adverts.push(DkgArtifact::to_advert(message))
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
