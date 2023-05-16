//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::{ChangeResult, ChangeSetProducer, MutablePool, UnvalidatedArtifact},
    canister_http::CanisterHttpChangeSet,
    certification::ChangeSet as CertificationChangeSet,
    consensus_pool::ChangeSet as CoonsensusChangeSet,
    dkg::ChangeSet as DkgChangeSet,
    ecdsa::EcdsaChangeSet,
    ingress_pool::ChangeSet as IngressChangeSet,
    time_source::TimeSource,
};
use ic_types::{
    artifact::*,
    artifact_kind::*,
    canister_http::CanisterHttpResponseShare,
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    messages::SignedIngress,
};
use std::sync::{Arc, RwLock};

/// *Consensus* `OnStateChange` client.
pub struct ConsensusProcessor<PoolConsensus> {
    /// The *Consensus* pool.
    consensus_pool: Arc<RwLock<PoolConsensus>>,
    /// The *Consensus* client.
    client: Box<dyn ChangeSetProducer<PoolConsensus, ChangeSet = CoonsensusChangeSet>>,
}

impl<PoolConsensus> ConsensusProcessor<PoolConsensus> {
    pub fn new(
        consensus_pool: Arc<RwLock<PoolConsensus>>,
        client: Box<dyn ChangeSetProducer<PoolConsensus, ChangeSet = CoonsensusChangeSet>>,
    ) -> Self {
        Self {
            consensus_pool,
            client,
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
}

impl<PoolCertification> CertificationProcessor<PoolCertification> {
    pub fn new(
        certification_pool: Arc<RwLock<PoolCertification>>,
        client: Box<dyn ChangeSetProducer<PoolCertification, ChangeSet = CertificationChangeSet>>,
    ) -> Self {
        Self {
            certification_pool,
            client,
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
}

impl<PoolDkg> DkgProcessor<PoolDkg> {
    pub fn new(
        dkg_pool: Arc<RwLock<PoolDkg>>,
        client: Box<dyn ChangeSetProducer<PoolDkg, ChangeSet = DkgChangeSet>>,
    ) -> Self {
        Self { dkg_pool, client }
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
            self.client.on_state_change(&*dkg_pool)
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
}

impl<PoolEcdsa> EcdsaProcessor<PoolEcdsa> {
    pub fn new(
        ecdsa_pool: Arc<RwLock<PoolEcdsa>>,
        client: Box<dyn ChangeSetProducer<PoolEcdsa, ChangeSet = EcdsaChangeSet>>,
    ) -> Self {
        Self { ecdsa_pool, client }
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
