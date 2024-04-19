//! The module contains implementations of the 'ArtifactClient' trait for all
//! P2P clients that require consensus over their artifacts.

use ic_interfaces::p2p::{
    artifact_manager::ArtifactClient,
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
};
use ic_types::{
    artifact::*,
    artifact_kind::*,
    canister_http::*,
    consensus::{
        certification::CertificationMessage,
        dkg::DkgMessageId,
        dkg::Message as DkgMessage,
        idkg::{EcdsaMessage, EcdsaMessageAttribute},
        ConsensusMessage,
    },
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
};
use std::sync::{Arc, RwLock};

/// The *Consensus* `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct ConsensusClient<Pool, T> {
    /// The *Consensus* pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `ConsensusGossip` client.
    priority_fn_and_filter: Arc<T>,
}

impl<Pool, T> ConsensusClient<Pool, T> {
    /// The constructor creates a `ConsensusClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: Arc<T>) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<ConsensusArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<ConsensusArtifact, Pool> + 'static,
    > ArtifactClient<ConsensusArtifact> for ConsensusClient<Pool, T>
{
    /// The method returns `true` if and only if the *Consensus* pool contains
    /// the given *Consensus* message ID.
    fn has_artifact(&self, msg_id: &ConsensusMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the *Consensus* message with the given ID from the
    /// *Consensus* pool if available.
    fn get_validated_by_identifier(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the *Consensus* message filter.
    fn get_filter(&self) -> ConsensusMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated *Consensus* artifacts.
    fn get_all_validated_by_filter(
        &self,
        filter: &ConsensusMessageFilter,
    ) -> Vec<Advert<ConsensusArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| ConsensusArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<ConsensusMessageId, ()> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }
}

/// The ingress `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct IngressClient<Pool, T> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: Arc<T>,
    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
}

impl<Pool, T> IngressClient<Pool, T> {
    /// The constructor creates an `IngressClient` instance.
    pub fn new(
        pool: Arc<RwLock<Pool>>,
        priority_fn_and_filter: Arc<T>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
            malicious_flags,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<IngressArtifact> + Send + Sync + 'static,
        T: PriorityFnAndFilterProducer<IngressArtifact, Pool> + 'static,
    > ArtifactClient<IngressArtifact> for IngressClient<Pool, T>
{
    /// The method checks if the ingress pool contains an ingress message with
    /// the given ID.
    fn has_artifact(&self, msg_id: &IngressMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `SignedIngress` message with the given ingress
    /// message ID from the ingress pool (if available).
    fn get_validated_by_identifier(&self, msg_id: &IngressMessageId) -> Option<SignedIngress> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<IngressMessageId, ()> {
        let pool = self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(&pool)
    }
}

/// The certification `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct CertificationClient<Pool, T> {
    /// The certification pool, protected by a read-write lock and automatic
    /// reference counting.
    pool: Arc<RwLock<Pool>>,
    /// The `PriorityFnAndFilterProducer` client.
    priority_fn_and_filter: Arc<T>,
}

impl<Pool, T> CertificationClient<Pool, T> {
    /// The constructor creates a `CertificationClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: Arc<T>) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<CertificationArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<CertificationArtifact, Pool> + 'static,
    > ArtifactClient<CertificationArtifact> for CertificationClient<Pool, T>
{
    /// The method checks if the certification pool contains a certification
    /// message with the given ID.
    fn has_artifact(&self, msg_id: &CertificationMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `CertificationMessage` for the given
    /// certification message ID if available.
    fn get_validated_by_identifier(
        &self,
        msg_id: &CertificationMessageId,
    ) -> Option<CertificationMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the certification message filter.
    fn get_filter(&self) -> CertificationMessageFilter {
        self.priority_fn_and_filter.get_filter()
    }

    /// The method returns all adverts for validated certification messages.
    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<CertificationArtifact>> {
        self.pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter)
            .map(|msg| CertificationArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<CertificationMessageId, ()> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }
}

/// The DKG client.
pub struct DkgClient<Pool, T> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    pool: Arc<RwLock<Pool>>,
    /// The `DkgGossip` client.
    priority_fn_and_filter: Arc<T>,
}

impl<Pool, T> DkgClient<Pool, T> {
    /// The constructor creates a `DkgClient` instance.
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: Arc<T>) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<DkgArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<DkgArtifact, Pool> + 'static,
    > ArtifactClient<DkgArtifact> for DkgClient<Pool, T>
{
    /// The method checks if the DKG pool contains a DKG message with the given
    /// ID.
    fn has_artifact(&self, msg_id: &DkgMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the validated DKG message for the given DKG message
    /// if available.
    fn get_validated_by_identifier(&self, msg_id: &DkgMessageId) -> Option<DkgMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> PriorityFn<DkgMessageId, ()> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }
}

/// The ECDSA client.
pub struct EcdsaClient<Pool, T> {
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: Arc<T>,
}

impl<Pool, T> EcdsaClient<Pool, T> {
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: Arc<T>) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<EcdsaArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<EcdsaArtifact, Pool> + 'static,
    > ArtifactClient<EcdsaArtifact> for EcdsaClient<Pool, T>
{
    fn has_artifact(&self, msg_id: &EcdsaMessageId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(&self) -> PriorityFn<EcdsaMessageId, EcdsaMessageAttribute> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }
}

/// The CanisterHttp Client
pub struct CanisterHttpClient<Pool, T> {
    pool: Arc<RwLock<Pool>>,
    priority_fn_and_filter: Arc<T>,
}

impl<Pool, T> CanisterHttpClient<Pool, T> {
    pub fn new(pool: Arc<RwLock<Pool>>, priority_fn_and_filter: Arc<T>) -> Self {
        Self {
            pool,
            priority_fn_and_filter,
        }
    }
}

impl<
        Pool: ValidatedPoolReader<CanisterHttpArtifact> + Send + Sync,
        T: PriorityFnAndFilterProducer<CanisterHttpArtifact, Pool> + 'static,
    > ArtifactClient<CanisterHttpArtifact> for CanisterHttpClient<Pool, T>
{
    fn has_artifact(&self, msg_id: &CanisterHttpResponseId) -> bool {
        self.pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(&self) -> PriorityFn<CanisterHttpResponseId, ()> {
        let pool = &*self.pool.read().unwrap();
        self.priority_fn_and_filter.get_priority_function(pool)
    }
}
