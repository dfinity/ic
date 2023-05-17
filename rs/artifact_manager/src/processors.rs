//! The module contains implementations of the 'ArtifactProcessor' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::{
    artifact_manager::{ArtifactProcessor, ProcessingResult},
    artifact_pool::{ChangeSetProducer, MutablePool, UnvalidatedArtifact},
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
pub struct ConsensusProcessor<P, C> {
    /// The *Consensus* pool.
    consensus_pool: Arc<RwLock<P>>,
    /// The *Consensus* client.
    client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> ConsensusProcessor<P, C> {
    pub fn new(
        consensus_pool: Arc<RwLock<P>>,
        client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self {
            consensus_pool,
            client,
        }
    }
}

impl<C, P: MutablePool<ConsensusArtifact, C> + Send + Sync + 'static>
    ArtifactProcessor<ConsensusArtifact> for ConsensusProcessor<P, C>
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
        let result = self
            .consensus_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);

        (result.adverts, result.changed)
    }
}

/// The ingress `OnStateChange` client.
pub struct IngressProcessor<P, C> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<P>>,
    /// The ingress handler.
    client: Arc<dyn ChangeSetProducer<P, ChangeSet = C> + Send + Sync>,
}

impl<P, C> IngressProcessor<P, C> {
    pub fn new(
        ingress_pool: Arc<RwLock<P>>,
        client: Arc<dyn ChangeSetProducer<P, ChangeSet = C> + Send + Sync>,
    ) -> Self {
        Self {
            ingress_pool,
            client,
        }
    }
}

impl<C, P: MutablePool<IngressArtifact, C> + Send + Sync + 'static>
    ArtifactProcessor<IngressArtifact> for IngressProcessor<P, C>
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
        let result = self
            .ingress_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        // We ignore the ingress pool's "changed" result and return StateUnchanged,
        // in order to not trigger an immediate re-processing.
        (result.adverts, ProcessingResult::StateUnchanged)
    }
}

/// Certification `OnStateChange` client.
pub struct CertificationProcessor<P, C> {
    /// The certification pool.
    certification_pool: Arc<RwLock<P>>,
    /// The certifier.
    client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> CertificationProcessor<P, C> {
    pub fn new(
        certification_pool: Arc<RwLock<P>>,
        client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self {
            certification_pool,
            client,
        }
    }
}

impl<C, P: MutablePool<CertificationArtifact, C> + Send + Sync + 'static>
    ArtifactProcessor<CertificationArtifact> for CertificationProcessor<P, C>
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
        let result = self
            .certification_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (result.adverts, result.changed)
    }
}

/// Distributed key generation (DKG) `OnStateChange` client.
pub struct DkgProcessor<P, C> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    dkg_pool: Arc<RwLock<P>>,
    /// The DKG client.
    client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> DkgProcessor<P, C> {
    pub fn new(
        dkg_pool: Arc<RwLock<P>>,
        client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self { dkg_pool, client }
    }
}

impl<C, P: MutablePool<DkgArtifact, C> + Send + Sync + 'static> ArtifactProcessor<DkgArtifact>
    for DkgProcessor<P, C>
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
        let result = self
            .dkg_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (result.adverts, result.changed)
    }
}

/// ECDSA `OnStateChange` client.
pub struct EcdsaProcessor<P, C> {
    ecdsa_pool: Arc<RwLock<P>>,
    client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> EcdsaProcessor<P, C> {
    pub fn new(
        ecdsa_pool: Arc<RwLock<P>>,
        client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self { ecdsa_pool, client }
    }
}

impl<C, P: MutablePool<EcdsaArtifact, C> + Send + Sync + 'static> ArtifactProcessor<EcdsaArtifact>
    for EcdsaProcessor<P, C>
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
        let result = self
            .ecdsa_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (result.adverts, result.changed)
    }
}

/// CanisterHttp `OnStateChange` client.
pub struct CanisterHttpProcessor<P, C> {
    canister_http_pool: Arc<RwLock<P>>,
    client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
}

impl<P, C> CanisterHttpProcessor<P, C> {
    pub fn new(
        canister_http_pool: Arc<RwLock<P>>,
        client: Box<dyn ChangeSetProducer<P, ChangeSet = C>>,
    ) -> Self {
        Self {
            canister_http_pool,
            client,
        }
    }
}

impl<C, P: MutablePool<CanisterHttpArtifact, C> + Send + Sync + 'static>
    ArtifactProcessor<CanisterHttpArtifact> for CanisterHttpProcessor<P, C>
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
        let result = self
            .canister_http_pool
            .write()
            .unwrap()
            .apply_changes(time_source, change_set);
        (result.adverts, result.changed)
    }
}
