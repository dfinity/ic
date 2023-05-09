//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::{ChangeResult, ChangeSetProducer, MutablePool, UnvalidatedArtifact},
    canister_http::CanisterHttpChangeSet,
    certification::{
        ChangeAction as CertificationChangeAction, ChangeSet as CertificationChangeSet,
    },
    consensus_pool::{ChangeAction as ConsensusAction, ChangeSet as CoonsensusChangeSet},
    dkg::{ChangeAction as DkgChangeAction, ChangeSet as DkgChangeSet},
    ecdsa::EcdsaChangeSet,
    ingress_pool::ChangeSet as IngressChangeSet,
    time_source::TimeSource,
};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::*,
    artifact_kind::*,
    canister_http::CanisterHttpResponseShare,
    consensus::HasRank,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    messages::SignedIngress,
};
use prometheus::{histogram_opts, Histogram, IntCounter};
use std::sync::{Arc, RwLock};

/// *Consensus* `OnStateChange` client.
pub struct ConsensusProcessor<PoolConsensus> {
    /// The *Consensus* pool.
    consensus_pool: Arc<RwLock<PoolConsensus>>,
    /// The *Consensus* client.
    client: Box<dyn ChangeSetProducer<PoolConsensus, ChangeSet = CoonsensusChangeSet>>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolConsensus> ConsensusProcessor<PoolConsensus> {
    pub fn new(
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        client: Box<dyn ChangeSetProducer<PoolConsensus, ChangeSet = CoonsensusChangeSet>>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            consensus_pool,
            client,
            log,
            invalidated_artifacts: metrics_registry.int_counter(
                "consensus_invalidated_artifacts",
                "The number of invalidated consensus artifacts",
            ),
        }
    }
}

impl<
        PoolConsensus: MutablePool<ConsensusArtifact, CoonsensusChangeSet> + Send + Sync + 'static,
    > ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<PoolConsensus>
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
        let change_set = {
            let consensus_pool = self.consensus_pool.read().unwrap();
            self.client.on_state_change(&*consensus_pool)
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
                    if let ConsensusMessage::BlockProposal(p) = to_add {
                        let rank = p.content.as_ref().rank();
                        debug!(
                            self.log,
                            "Added proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    if let ConsensusMessage::BlockProposal(p) = to_move {
                        let rank = p.content.as_ref().rank();
                        debug!(
                            self.log,
                            "Moved proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::RemoveFromValidated(_) => {}
                ConsensusAction::RemoveFromUnvalidated(_) => {}
                ConsensusAction::PurgeValidatedBelow(_) => {}
                ConsensusAction::PurgeValidatedSharesBelow(_) => {}
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

        let ChangeResult(_purged, adverts) = self
            .consensus_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);

        (adverts, changed)
    }
}

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<PoolIngress> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<PoolIngress>>,
    /// The ingress handler.
    client: Arc<dyn ChangeSetProducer<PoolIngress, ChangeSet = IngressChangeSet> + Send + Sync>,
}

impl<PoolIngress> IngressProcessor<PoolIngress> {
    pub fn new(
        ingress_pool: Arc<RwLock<PoolIngress>>,
        client: Arc<dyn ChangeSetProducer<PoolIngress, ChangeSet = IngressChangeSet> + Send + Sync>,
    ) -> Self {
        Self {
            ingress_pool,
            client,
        }
    }
}

impl<PoolIngress: MutablePool<IngressArtifact, IngressChangeSet> + Send + Sync + 'static>
    ArtifactProcessor<IngressArtifact> for IngressProcessor<PoolIngress>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
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
        let ChangeResult(_purged, adverts) = self
            .ingress_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (adverts, ProcessingResult::StateUnchanged)
    }
}

/// Certification `OnStateChange` client.
pub struct CertificationProcessor<PoolCertification> {
    /// The certification pool.
    certification_pool: Arc<RwLock<PoolCertification>>,
    /// The certifier.
    client: Box<dyn ChangeSetProducer<PoolCertification, ChangeSet = CertificationChangeSet>>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolCertification> CertificationProcessor<PoolCertification> {
    pub fn new(
        certification_pool: Arc<RwLock<PoolCertification>>,
        client: Box<dyn ChangeSetProducer<PoolCertification, ChangeSet = CertificationChangeSet>>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            certification_pool,
            client,
            log,
            invalidated_artifacts: metrics_registry.int_counter(
                "certification_invalidated_artifacts",
                "The number of invalidated certification artifacts",
            ),
        }
    }
}

impl<
        PoolCertification: MutablePool<CertificationArtifact, CertificationChangeSet> + Send + Sync + 'static,
    > ArtifactProcessor<CertificationArtifact> for CertificationProcessor<PoolCertification>
{
    /// The method processes changes in the certification pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CertificationMessage>>,
    ) -> (Vec<Advert<CertificationArtifact>>, ProcessingResult) {
        {
            let mut certification_pool = self.certification_pool.write().unwrap();
            for artifact in artifacts {
                certification_pool.insert(artifact)
            }
        }
        let change_set = self
            .client
            .on_state_change(&*self.certification_pool.read().unwrap());
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        for action in change_set.iter() {
            if let CertificationChangeAction::HandleInvalid(msg, reason) = action {
                self.invalidated_artifacts.inc();
                warn!(
                    self.log,
                    "Invalid certification message ({:?}): {:?}", reason, msg
                );
            }
        }
        let ChangeResult(_purged, adverts) = self
            .certification_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (adverts, changed)
    }
}

/// Distributed key generation (DKG) `OnStateChange` client.
pub struct DkgProcessor<PoolDkg> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    dkg_pool: Arc<RwLock<PoolDkg>>,
    /// The DKG client.
    client: Box<dyn ChangeSetProducer<PoolDkg, ChangeSet = DkgChangeSet>>,
    /// The invalidated artifacts counter.
    invalidated_artifacts: IntCounter,
    /// The logger.
    log: ReplicaLogger,
}

impl<PoolDkg> DkgProcessor<PoolDkg> {
    pub fn new(
        dkg_pool: Arc<RwLock<PoolDkg>>,
        client: Box<dyn ChangeSetProducer<PoolDkg, ChangeSet = DkgChangeSet>>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            dkg_pool,
            client,
            log,
            invalidated_artifacts: metrics_registry.int_counter(
                "dkg_invalidated_artifacts",
                "The number of invalidated DKG artifacts",
            ),
        }
    }
}

impl<PoolDkg: MutablePool<DkgArtifact, DkgChangeSet> + Send + Sync + 'static>
    ArtifactProcessor<DkgArtifact> for DkgProcessor<PoolDkg>
{
    /// The method processes changes in the DKG pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<dkg::Message>>,
    ) -> (Vec<Advert<DkgArtifact>>, ProcessingResult) {
        {
            let mut dkg_pool = self.dkg_pool.write().unwrap();
            for artifact in artifacts {
                dkg_pool.insert(artifact)
            }
        }
        let change_set = {
            let dkg_pool = self.dkg_pool.read().unwrap();
            let change_set = self.client.on_state_change(&*dkg_pool);
            for change_action in change_set.iter() {
                if let DkgChangeAction::HandleInvalid(msg, reason) = change_action {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid DKG message ({:?}): {:?}", reason, msg);
                }
            }
            change_set
        };
        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        let ChangeResult(_purged, adverts) = self
            .dkg_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (adverts, changed)
    }
}

/// ECDSA `OnStateChange` client.
pub struct EcdsaProcessor<PoolEcdsa> {
    ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
    client: Box<dyn ChangeSetProducer<PoolEcdsa, ChangeSet = EcdsaChangeSet>>,
    ecdsa_pool_update_duration: Histogram,
}

impl<PoolEcdsa> EcdsaProcessor<PoolEcdsa> {
    pub fn new(
        ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
        client: Box<dyn ChangeSetProducer<PoolEcdsa, ChangeSet = EcdsaChangeSet>>,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            ecdsa_pool,
            client,
            ecdsa_pool_update_duration: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ecdsa_pool_update_duration_seconds",
                    "Time to apply changes to ECDSA artifact pool, in seconds",
                    vec![
                        0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0,
                        8.0, 10.0, 15.0, 20.0, 50.0,
                    ]
                ))
                .unwrap(),
            ),
        }
    }
}

impl<PoolEcdsa: MutablePool<EcdsaArtifact, EcdsaChangeSet> + Send + Sync + 'static>
    ArtifactProcessor<EcdsaArtifact> for EcdsaProcessor<PoolEcdsa>
{
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<EcdsaMessage>>,
    ) -> (Vec<Advert<EcdsaArtifact>>, ProcessingResult) {
        {
            let mut ecdsa_pool = self.ecdsa_pool.write().unwrap();
            for artifact in artifacts {
                ecdsa_pool.insert(artifact)
            }
        }

        let change_set = {
            let ecdsa_pool = self.ecdsa_pool.read().unwrap();
            self.client.on_state_change(&*ecdsa_pool)
        };

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        let _timer = self.ecdsa_pool_update_duration.start_timer();
        let ChangeResult(_purged, adverts) = self
            .ecdsa_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (adverts, changed)
    }
}

pub struct CanisterHttpProcessor<PoolCanisterHttp> {
    canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
    client: Box<dyn ChangeSetProducer<PoolCanisterHttp, ChangeSet = CanisterHttpChangeSet>>,
}

impl<PoolCanisterHttp> CanisterHttpProcessor<PoolCanisterHttp> {
    pub fn new(
        canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
        client: Box<dyn ChangeSetProducer<PoolCanisterHttp, ChangeSet = CanisterHttpChangeSet>>,
    ) -> Self {
        Self {
            canister_http_pool,
            client,
        }
    }
}

impl<
        PoolCanisterHttp: MutablePool<CanisterHttpArtifact, CanisterHttpChangeSet> + Send + Sync + 'static,
    > ArtifactProcessor<CanisterHttpArtifact> for CanisterHttpProcessor<PoolCanisterHttp>
{
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CanisterHttpResponseShare>>,
    ) -> (Vec<Advert<CanisterHttpArtifact>>, ProcessingResult) {
        {
            let mut pool = self.canister_http_pool.write().unwrap();
            for artifact in artifacts {
                pool.insert(artifact);
            }
        }
        let change_set = self
            .client
            .on_state_change(&*self.canister_http_pool.read().unwrap());

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        let ChangeResult(_purged, adverts) = self
            .canister_http_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (adverts, changed)
    }
}
