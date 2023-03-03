//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::UnvalidatedArtifact,
    canister_http::*,
    certification,
    certification::{Certifier, MutableCertificationPool},
    consensus::Consensus,
    consensus_pool::{ChangeAction as ConsensusAction, ConsensusPoolCache, MutableConsensusPool},
    dkg::{ChangeAction as DkgChangeAction, Dkg, MutableDkgPool},
    ecdsa::{Ecdsa, EcdsaChangeAction, MutableEcdsaPool},
    ingress_manager::IngressHandler,
    ingress_pool::{ChangeAction as IngressAction, MutableIngressPool},
    time_source::TimeSource,
};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_types::{
    artifact::*,
    artifact_kind::*,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    messages::SignedIngress,
    NodeId,
};
use ic_types::{canister_http::CanisterHttpResponseShare, consensus::HasRank};
use prometheus::{Histogram, IntCounter};
use std::sync::{Arc, RwLock};

/// *Consensus* `OnStateChange` client.
pub struct ConsensusProcessor<PoolConsensus> {
    /// The *Consensus* pool.
    pub(crate) consensus_pool: Arc<RwLock<PoolConsensus>>,
    /// The *Consensus* client.
    pub(crate) client: Box<dyn Consensus>,
    /// The invalidated artifacts counter.
    pub(crate) invalidated_artifacts: IntCounter,
    /// The logger.
    pub(crate) log: ReplicaLogger,
}

impl<PoolConsensus: MutableConsensusPool + Send + Sync + 'static>
    ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<PoolConsensus>
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
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_add,
                        ArtifactDestination::AllPeersInSubnet,
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_add {
                        let rank = p.clone().content.decompose().1.rank();
                        debug!(
                            self.log,
                            "Added proposal {:?} of rank {:?} to artifact pool", p, rank
                        );
                    }
                }
                ConsensusAction::MoveToValidated(to_move) => {
                    adverts.push(ConsensusArtifact::message_to_advert_send_request(
                        to_move,
                        ArtifactDestination::AllPeersInSubnet,
                    ));
                    if let ConsensusMessage::BlockProposal(p) = to_move {
                        let rank = p.clone().content.decompose().1.rank();
                        debug!(
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

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<PoolIngress> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    pub(crate) ingress_pool: Arc<RwLock<PoolIngress>>,
    /// The ingress handler.
    pub(crate) client: Arc<dyn IngressHandler + Send + Sync>,
    /// Our node id
    pub(crate) node_id: NodeId,
}

impl<PoolIngress: MutableIngressPool + Send + Sync + 'static> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<PoolIngress>
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
                    if *source_node_id == self.node_id {
                        adverts.push(AdvertSendRequest {
                            advert: Advert {
                                size: *size,
                                id: message_id.clone(),
                                attribute: attribute.clone(),
                                integrity_hash: integrity_hash.clone(),
                            },
                            dest: ArtifactDestination::AllPeersInSubnet,
                        });
                    }
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
    pub(crate) consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The certification pool.
    pub(crate) certification_pool: Arc<RwLock<PoolCertification>>,
    /// The certifier.
    pub(crate) client: Box<dyn Certifier>,
    /// The invalidated artifacts counter.
    pub(crate) invalidated_artifacts: IntCounter,
    /// The logger.
    pub(crate) log: ReplicaLogger,
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
                        ArtifactDestination::AllPeersInSubnet,
                    ))
                }
                certification::ChangeAction::MoveToValidated(msg) => {
                    adverts.push(CertificationArtifact::message_to_advert_send_request(
                        msg,
                        ArtifactDestination::AllPeersInSubnet,
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
    pub(crate) dkg_pool: Arc<RwLock<PoolDkg>>,
    /// The DKG client.
    pub(crate) client: Box<dyn Dkg>,
    /// The invalidated artifacts counter.
    pub(crate) invalidated_artifacts: IntCounter,
    /// The logger.
    pub(crate) log: ReplicaLogger,
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
                    DkgChangeAction::AddToValidated(to_add) => {
                        adverts.push(DkgArtifact::message_to_advert_send_request(
                            to_add,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    DkgChangeAction::MoveToValidated(message) => {
                        adverts.push(DkgArtifact::message_to_advert_send_request(
                            message,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
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

/// ECDSA `OnStateChange` client.
pub struct EcdsaProcessor<PoolEcdsa> {
    pub(crate) ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
    pub(crate) client: Box<dyn Ecdsa>,
    pub(crate) ecdsa_pool_update_duration: Histogram,
    pub(crate) log: ReplicaLogger,
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
                    // 1. Notify all peers for ecdsa messages received directly by us
                    // 2. For relayed ecdsa support messages: don't notify any peers.
                    // 3. For other relayed messages: still notify peers.
                    EcdsaChangeAction::AddToValidated(msg) => {
                        adverts.push(EcdsaArtifact::message_to_advert_send_request(
                            msg,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    EcdsaChangeAction::MoveToValidated(msg_id) => {
                        if let Some(msg) = ecdsa_pool.unvalidated().get(msg_id) {
                            match msg {
                                EcdsaMessage::EcdsaDealingSupport(_) => (),
                                _ => adverts.push(EcdsaArtifact::message_to_advert_send_request(
                                    &msg,
                                    ArtifactDestination::AllPeersInSubnet,
                                )),
                            }
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

        let _timer = self.ecdsa_pool_update_duration.start_timer();
        self.ecdsa_pool.write().unwrap().apply_changes(change_set);
        (adverts, changed)
    }
}

pub struct CanisterHttpProcessor<PoolCanisterHttp> {
    pub(crate) consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    pub(crate) canister_http_pool: Arc<RwLock<PoolCanisterHttp>>,
    pub(crate) client: Arc<RwLock<dyn CanisterHttpPoolManager + Sync + 'static>>,
    pub(crate) log: ReplicaLogger,
}

impl<PoolCanisterHttp: MutableCanisterHttpPool + Send + Sync + 'static>
    ArtifactProcessor<CanisterHttpArtifact> for CanisterHttpProcessor<PoolCanisterHttp>
{
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<CanisterHttpResponseShare>>,
    ) -> (
        Vec<AdvertSendRequest<CanisterHttpArtifact>>,
        ProcessingResult,
    ) {
        {
            let mut pool = self.canister_http_pool.write().unwrap();
            for artifact in artifacts {
                pool.insert(artifact);
            }
        }

        let mut adverts = Vec::new();
        let change_set = {
            let canister_http_pool = self.canister_http_pool.read().unwrap();
            let change_set = self
                .client
                .write()
                .unwrap()
                .on_state_change(self.consensus_pool_cache.as_ref(), &*canister_http_pool);

            for change_action in change_set.iter() {
                match change_action {
                    CanisterHttpChangeAction::AddToValidated(share, _) => {
                        adverts.push(CanisterHttpArtifact::message_to_advert_send_request(
                            share,
                            ArtifactDestination::AllPeersInSubnet,
                        ))
                    }
                    CanisterHttpChangeAction::MoveToValidated(msg_id) => {
                        if let Some(msg) = canister_http_pool.lookup_unvalidated(msg_id) {
                            adverts.push(CanisterHttpArtifact::message_to_advert_send_request(
                                &msg,
                                ArtifactDestination::AllPeersInSubnet,
                            ))
                        } else {
                            warn!(
                                self.log,
                                "CanisterHttpProcessor::MoveToValidated(): artifact not found: {:?}",
                                msg_id
                            );
                        }
                    }
                    CanisterHttpChangeAction::RemoveContent(_) => {}
                    CanisterHttpChangeAction::RemoveValidated(_) => {}
                    CanisterHttpChangeAction::RemoveUnvalidated(_) => {}
                    CanisterHttpChangeAction::HandleInvalid(_, _) => {}
                }
            }
            change_set
        };

        let changed = if !change_set.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };

        self.canister_http_pool
            .write()
            .unwrap()
            .apply_changes(change_set);
        (adverts, changed)
    }
}
