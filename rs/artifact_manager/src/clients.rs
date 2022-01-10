//! The module contains implementations of the artifact client trait.

use crate::artifact::*;
use crate::processors::ArtifactProcessorManager;
use ic_interfaces::{
    artifact_manager::{AdvertMismatchError, ArtifactAcceptance, ArtifactClient, OnArtifactError},
    artifact_pool::{ArtifactPoolError, ReplicaVersionMismatch, UnvalidatedArtifact},
    certification::{CertificationPool, CertifierGossip},
    consensus::ConsensusGossip,
    consensus_pool::{ConsensusPool, ConsensusPoolCache},
    dkg::{DkgGossip, DkgPool},
    ecdsa::{EcdsaGossip, EcdsaPool},
    gossip_pool::{
        CertificationGossipPool, ConsensusGossipPool, DkgGossipPool, EcdsaGossipPool,
        IngressGossipPool,
    },
    ingress_pool::IngressPool,
    time_source::TimeSource,
};
use ic_logger::{debug, ReplicaLogger};
use ic_types::{
    artifact,
    artifact::*,
    chunkable::*,
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
        HasVersion,
    },
    ingress::{MAX_INGRESS_TTL, PERMITTED_DRIFT_AT_ARTIFACT_MANAGER},
    malicious_flags::MaliciousFlags,
    messages::{SignedIngress, SignedRequestBytes},
    p2p, NodeId, ReplicaVersion,
};
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, RwLock};

/// In order to let the artifact manager manage artifact clients, which can be
/// parameterized by different artifact types, it has to use trait objects.
/// Consequently, there has to be a translation between various artifact
/// sub-types to the top-level enum types. The trait `ArtifactManagerBackend`
/// achieves both goals by acting as a middleman.
///
/// The trick of this translation is to erase the type parameter from all
/// interface functions. As a result, member functions of this trait mostly
/// resemble those of `ArtifactClient`, but use top-level artifact types. The
/// translation is mostly handled via `From/Into`, `TryFrom/Into`, `AsMut` and
/// `AsRef` traits that are automatically derived between artifact subtypes and
/// the top-level types.
pub(crate) trait ArtifactManagerBackend: Send + Sync {
    /// The method is called when an artifact is received.
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        msg: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>>;

    /// The method indicates whether an artifact exists.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()>;

    /// The method returns a validated artifact with the given ID, or an error.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()>;

    /// The method adds the client's filter to the given artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter);

    /// The method returns all validated artifacts that match the given filter.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert>;

    /// The method returns the remaining quota for a given peer and artifact
    /// tag.
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize>;

    /// The method returns a priority function for a given artifact tag.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn>;

    /// The method returns a chunk tracker for a given artifact ID.
    fn get_chunk_tracker(
        &self,
        id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>>;
}

/// Implementation struct for `ArtifactManagerBackend`.
pub(crate) struct ArtifactManagerBackendImpl<Artifact: ArtifactKind + 'static> {
    /// Reference to the artifact client.
    pub client: Arc<dyn ArtifactClient<Artifact>>,
    /// The artifact processor front end.
    pub processor: ArtifactProcessorManager<Artifact>,
}

/// Trait implementation for `ArtifactManagerBackend`.
impl<Artifact: ArtifactKind> ArtifactManagerBackend for ArtifactManagerBackendImpl<Artifact>
where
    Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
    Artifact::Message: ChunkableArtifact + Send + 'static,
    Advert<Artifact>:
        Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
    for<'a> &'a Artifact::Id: TryFrom<&'a artifact::ArtifactId, Error = &'a artifact::ArtifactId>,
    artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
    for<'a> &'a Artifact::Attribute:
        TryFrom<&'a artifact::ArtifactAttribute, Error = &'a artifact::ArtifactAttribute>,
    Artifact::Attribute: 'static,
    Artifact::Id: 'static,
{
    /// The method is called when the given artifact is received.
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        artifact: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>> {
        match (artifact.try_into(), advert.try_into()) {
            (Ok(msg), Ok(advert)) => {
                let result = self
                    .client
                    .as_ref()
                    .check_artifact_acceptance(msg, &peer_id)?;
                match result {
                    ArtifactAcceptance::Processed => (),
                    ArtifactAcceptance::AcceptedForProcessing(message) => {
                        Artifact::check_advert(&message, &advert).map_err(|expected| {
                            AdvertMismatchError {
                                received: advert.into(),
                                expected: expected.into(),
                            }
                        })?;
                        // this sends to an unbounded channel, which is what we want here
                        self.processor.on_artifact(UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        })
                    }
                };
                Ok(())
            }
            (Err(artifact), _) => Err(OnArtifactError::NotProcessed(Box::new(artifact))),
            (_, Err(advert)) => Err(OnArtifactError::MessageConversionfailed(advert)),
        }
    }

    /// The method checks if the artifact with the given ID is available.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self.client.as_ref().has_artifact(id)),
            Err(_) => Err(()),
        }
    }

    /// The method returns the validated artifact for the given ID.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self
                .client
                .as_ref()
                .get_validated_by_identifier(id)
                .map(|x| Box::new(x) as Box<dyn ChunkableArtifact>)),
            Err(_) => Err(()),
        }
    }

    /// The method gets the client's filter and adds it to the artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter) {
        *filter.as_mut() = self.client.as_ref().get_filter()
    }

    /// The method returns all validated adverts.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        self.client
            .as_ref()
            .get_all_validated_by_filter(filter.as_ref())
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>()
    }

    /// The method returns the remaining quota for the peer with the given ID.s
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize> {
        if tag == Artifact::TAG {
            Some(self.client.as_ref().get_remaining_quota(peer_id))
        } else {
            None
        }
    }

    /// The method returns the priority function.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
        if tag == Artifact::TAG {
            let func = self.client.as_ref().get_priority_function()?;
            Some(Box::new(
                move |id: &'_ artifact::ArtifactId, attribute: &'_ artifact::ArtifactAttribute| {
                    match (id.try_into(), attribute.try_into()) {
                        (Ok(idd), Ok(attr)) => func(idd, attr),
                        _ => panic!("Priority function called on wrong id or attribute!"),
                    }
                },
            ))
        } else {
            None
        }
    }

    /// The method returns the artifact chunk tracker.
    fn get_chunk_tracker(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        match artifact_id.try_into() {
            Ok(artifact_id) => Some(self.client.as_ref().get_chunk_tracker(artifact_id)),
            Err(_) => None,
        }
    }
}

/// The *Consensus* `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct ConsensusClient<Pool> {
    /// The *Consensus* pool, protected by a read-write lock and automatic
    /// reference counting.
    consensus_pool: Arc<RwLock<Pool>>,
    /// The `ConsensusGossip` client.
    client: Arc<dyn ConsensusGossip>,
}

impl<Pool> ConsensusClient<Pool> {
    /// The constructor creates a `ConsensusClient` instance.
    pub fn new<T: ConsensusGossip + 'static>(
        consensus_pool: Arc<RwLock<Pool>>,
        consensus: T,
    ) -> Self {
        Self {
            consensus_pool,
            client: Arc::new(consensus),
        }
    }
}

/// The function checks if the version of the given artifact matches the default
/// protocol version and returns an error if it does not.
fn check_protocol_version<T: HasVersion>(artifact: &T) -> Result<(), ReplicaVersionMismatch> {
    let version = artifact.version();
    let expected_version = ReplicaVersion::default();
    if version != &expected_version {
        Err(ReplicaVersionMismatch {
            expected: expected_version,
            artifact: version.clone(),
        })
    } else {
        Ok(())
    }
}

impl<Pool: ConsensusPool + ConsensusGossipPool + Send + Sync> ArtifactClient<ConsensusArtifact>
    for ConsensusClient<Pool>
{
    /// The method checks if the protocol version in the *Consensus* message is
    /// correct.
    ///
    /// If the version is correct, the message is returned in an
    /// `ArtifactAcceptance` enum.
    fn check_artifact_acceptance(
        &self,
        msg: ConsensusMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<ConsensusMessage>, ArtifactPoolError> {
        check_protocol_version(&msg)?;
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    /// The method returns `true` if and only if the *Consensus* pool contains
    /// the given *Consensus* message ID.
    fn has_artifact(&self, msg_id: &ConsensusMessageId) -> bool {
        self.consensus_pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the *Consensus* message with the given ID from the
    /// *Consensus* pool if available.
    fn get_validated_by_identifier(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.consensus_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the *Consensus* message filter.
    fn get_filter(&self) -> ConsensusMessageFilter {
        self.client.get_filter()
    }

    /// The method returns all adverts for validated *Consensus* artifacts.
    fn get_all_validated_by_filter(
        &self,
        filter: &ConsensusMessageFilter,
    ) -> Vec<Advert<ConsensusArtifact>> {
        self.consensus_pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter.height)
            .map(|msg| ConsensusArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>> {
        let consensus_pool = &*self.consensus_pool.read().unwrap();
        Some(self.client.get_priority_function(consensus_pool))
    }

    /// The method returns the chunk tracker for the given *Consensus* message
    /// ID.
    fn get_chunk_tracker(&self, _id: &ConsensusMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Consensus)
    }
}

/// The ingress `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct IngressClient<Pool> {
    /// The time source.
    time_source: Arc<dyn TimeSource>,
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<Pool>>,
    /// The logger.
    log: ReplicaLogger,

    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
}

impl<Pool> IngressClient<Pool> {
    /// The constructor creates an `IngressClient` instance.
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        ingress_pool: Arc<RwLock<Pool>>,
        log: ReplicaLogger,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            time_source,
            ingress_pool,
            log,
            malicious_flags,
        }
    }
}

impl<Pool: IngressPool + IngressGossipPool + Send + Sync> ArtifactClient<IngressArtifact>
    for IngressClient<Pool>
{
    /// The method checks whether the given signed ingress bytes constitutes a
    /// valid singed ingress message.
    ///
    /// To this end, the method converts the signed bytes into a `SignedIngress`
    /// message (if possible) and verifies that the message expiry time is
    /// neither in the past nor too far in the future.
    fn check_artifact_acceptance(
        &self,
        bytes: SignedRequestBytes,
        peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<SignedIngress>, ArtifactPoolError> {
        let msg: SignedIngress = bytes
            .try_into()
            .map_err(|err| ArtifactPoolError::ArtifactRejected(Box::new(err)))?;

        #[cfg(feature = "malicious_code")]
        {
            if self.malicious_flags.maliciously_disable_ingress_validation {
                return Ok(ArtifactAcceptance::AcceptedForProcessing(msg));
            }
        }

        let time_now = self.time_source.get_relative_time();
        // We account for a bit of drift here and accept messages with a bit longer
        // than `MAX_INGRESS_TTL` time-to-live into the ingress pool.
        // The purpose is to be a bit more permissive than the HTTP handler when the
        // ingress was first accepted because here the ingress may have come
        // from the network.
        let time_plus_ttl = time_now + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_ARTIFACT_MANAGER;
        let msg_expiry_time = msg.expiry_time();
        if msg_expiry_time < time_now {
            Err(ArtifactPoolError::MessageExpired)
        } else if msg_expiry_time > time_plus_ttl {
            debug!(
                self.log,
                "check_artifact_acceptance";
                ingress_message.message_id => format!("{}", msg.id()),
                ingress_message.reason => "message_expiry_too_far_in_future",
                ingress_message.expiry_time => Some(msg_expiry_time.as_nanos_since_unix_epoch()),
                ingress_message.batch_time => Some(time_now.as_nanos_since_unix_epoch()),
                ingress_message.batch_time_plus_ttl => Some(time_plus_ttl.as_nanos_since_unix_epoch())
            );
            Err(ArtifactPoolError::MessageExpiryTooLong)
        } else {
            self.ingress_pool
                .read()
                .unwrap()
                .check_quota(&msg, peer_id)?;
            Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
        }
    }

    /// The method checks if the ingress pool contains an ingress message with
    /// the given ID.
    fn has_artifact(&self, msg_id: &IngressMessageId) -> bool {
        self.ingress_pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `SignedIngress` message with the given ingress
    /// message ID from the ingress pool (if available).
    fn get_validated_by_identifier(&self, msg_id: &IngressMessageId) -> Option<SignedIngress> {
        self.ingress_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the ingress message filter.
    fn get_filter(&self) -> IngressMessageFilter {
        Default::default()
    }

    /// The method returns all adverts for validated ingress messages.
    fn get_all_validated_by_filter(
        &self,
        _filter: &IngressMessageFilter,
    ) -> Vec<Advert<IngressArtifact>> {
        // TODO: Send adverts of ingress messages which are generated on this node (not
        // relayed from other node). P2P-381
        Vec::new()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<IngressMessageId, IngressMessageAttribute>> {
        let start = self.time_source.get_relative_time();
        let range = start..=start + MAX_INGRESS_TTL;
        Some(Box::new(move |ingress_id, _| {
            if range.contains(&ingress_id.expiry()) {
                Priority::Later
            } else {
                Priority::Drop
            }
        }))
    }

    /// The method returns a new chunk tracker for (single-chunked) ingress
    /// messages, ignoring the given ingress message ID.
    fn get_chunk_tracker(&self, _id: &IngressMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Ingress)
    }
}

/// The certification `ArtifactClient` to be managed by the `ArtifactManager`.
pub struct CertificationClient<PoolCertification> {
    /// The consensus pool cache.
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The certification pool, protected by a read-write lock and automatic
    /// reference counting.
    certification_pool: Arc<RwLock<PoolCertification>>,
    /// The `CertifierGossip` client.
    client: Arc<dyn CertifierGossip>,
}

impl<PoolCertification> CertificationClient<PoolCertification> {
    /// The constructor creates a `CertificationClient` instance.
    pub fn new<T: CertifierGossip + 'static>(
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        certifier: T,
    ) -> Self {
        Self {
            consensus_pool_cache,
            certification_pool,
            client: Arc::new(certifier),
        }
    }
}

impl<PoolCertification: CertificationPool + CertificationGossipPool + Send + Sync>
    ArtifactClient<CertificationArtifact> for CertificationClient<PoolCertification>
{
    /// The method always accepts the given `CertificationMessage`.
    fn check_artifact_acceptance(
        &self,
        msg: CertificationMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<CertificationMessage>, ArtifactPoolError> {
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    /// The method checks if the certification pool contains a certification
    /// message with the given ID.
    fn has_artifact(&self, msg_id: &CertificationMessageId) -> bool {
        self.certification_pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the `CertificationMessage` for the given
    /// certification message ID if available.
    fn get_validated_by_identifier(
        &self,
        msg_id: &CertificationMessageId,
    ) -> Option<CertificationMessage> {
        self.certification_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the certification message filter.
    fn get_filter(&self) -> CertificationMessageFilter {
        self.client.get_filter()
    }

    /// The method returns all adverts for validated certification messages.
    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<CertificationArtifact>> {
        self.certification_pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter.height)
            .map(|msg| CertificationArtifact::message_to_advert(&msg))
            .collect()
    }

    /// The method returns the priority function.
    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<CertificationMessageId, CertificationMessageAttribute>> {
        let consensus_pool_cache = self.consensus_pool_cache.as_ref();
        let certification_pool = &*self.certification_pool.read().unwrap();
        Some(
            self.client
                .get_priority_function(consensus_pool_cache, certification_pool),
        )
    }

    /// The method returns a new (single-chunked) certification tracker,
    /// ignoring the certification message ID.
    fn get_chunk_tracker(&self, _id: &CertificationMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Certification)
    }
}

/// The DKG client.
pub struct DkgClient<Pool> {
    /// The DKG pool, protected by a read-write lock and automatic reference
    /// counting.
    dkg_pool: Arc<RwLock<Pool>>,
    /// The `DkgGossip` client.
    client: Arc<dyn DkgGossip>,
}

impl<Pool> DkgClient<Pool> {
    /// The constructor creates a `DkgClient` instance.
    pub fn new<T: DkgGossip + 'static>(dkg_pool: Arc<RwLock<Pool>>, dkg: T) -> Self {
        Self {
            dkg_pool,
            client: Arc::new(dkg),
        }
    }
}

impl<Pool: DkgPool + DkgGossipPool + Send + Sync> ArtifactClient<DkgArtifact> for DkgClient<Pool> {
    /// The method checks if the protocol version is correct.
    ///
    /// If this is the case, the artifact is returned wrapped in an
    /// `ArtifactAcceptance` enum.
    fn check_artifact_acceptance(
        &self,
        msg: DkgMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<DkgMessage>, ArtifactPoolError> {
        check_protocol_version(&msg)?;
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    /// The method checks if the DKG pool contains a DKG message with the given
    /// ID.
    fn has_artifact(&self, msg_id: &DkgMessageId) -> bool {
        self.dkg_pool.read().unwrap().contains(msg_id)
    }

    /// The method returns the validated DKG message for the given DKG message
    /// if available.
    fn get_validated_by_identifier(&self, msg_id: &DkgMessageId) -> Option<DkgMessage> {
        self.dkg_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    /// The method returns the priority function.
    fn get_priority_function(&self) -> Option<PriorityFn<DkgMessageId, DkgMessageAttribute>> {
        let dkg_pool = &*self.dkg_pool.read().unwrap();
        Some(self.client.get_priority_function(dkg_pool))
    }

    /// The method returns a new (single-chunked) DKG message tracker.
    fn get_chunk_tracker(&self, _id: &DkgMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Dkg)
    }
}

/// The ECDSA client.
pub struct EcdsaClient<Pool> {
    ecdsa_pool: Arc<RwLock<Pool>>,
    ecdsa_gossip: Arc<dyn EcdsaGossip>,
}

impl<Pool> EcdsaClient<Pool> {
    pub fn new<T: EcdsaGossip + 'static>(ecdsa_pool: Arc<RwLock<Pool>>, gossip: T) -> Self {
        Self {
            ecdsa_pool,
            ecdsa_gossip: Arc::new(gossip),
        }
    }
}

impl<Pool: EcdsaPool + EcdsaGossipPool + Send + Sync> ArtifactClient<EcdsaArtifact>
    for EcdsaClient<Pool>
{
    fn check_artifact_acceptance(
        &self,
        msg: EcdsaMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<EcdsaMessage>, ArtifactPoolError> {
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    fn has_artifact(&self, msg_id: &EcdsaMessageId) -> bool {
        self.ecdsa_pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.ecdsa_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(&self) -> Option<PriorityFn<EcdsaMessageId, EcdsaMessageAttribute>> {
        let ecdsa_pool = &*self.ecdsa_pool.read().unwrap();
        Some(self.ecdsa_gossip.get_priority_function(ecdsa_pool))
    }

    fn get_chunk_tracker(&self, _id: &EcdsaMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Ecdsa)
    }
}
