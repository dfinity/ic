//! Artifact related types.
//!
//! Notably it includes the following definitions and their sub-types:
//!
//! - [`Artifact`]
//! - [`ArtifactTag`]
//! - [`ArtifactId`]
//! - [`ArtifactAttribute`]
//! - [`ArtifactFilter`]
//!
//! An [`ArtifactKind`] trait is provided for convenience to carry multiple type
//! definitions that belong to the same "artifact kind".
//!
//! All [`Artifact`] sub-types must also implement [`ChunkableArtifact`] trait
//! defined in the chunkable module.
use crate::{
    consensus::{certification::CertificationMessageHash, ConsensusMessageHash},
    crypto::{CryptoHash, CryptoHashOf},
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    messages::{MessageId, SignedRequestBytes},
    p2p::GossipAdvert,
    CryptoHashOfState, Height, Time,
};
use derive_more::{AsMut, AsRef, From, TryInto};
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use strum_macros::EnumIter;

pub use crate::{
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
        ConsensusMessageAttribute,
    },
    messages::SignedIngress,
};

/// The artifact type
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
#[allow(clippy::large_enum_variant)]
pub enum Artifact {
    ConsensusMessage(ConsensusMessage),
    IngressMessage(SignedRequestBytes),
    CertificationMessage(CertificationMessage),
    DkgMessage(DkgMessage),
    FileTreeSync(FileTreeSyncArtifact),
    StateSync(StateSyncMessage),
}

/// Artifact attribute type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactAttribute {
    ConsensusMessage(ConsensusMessageAttribute),
    IngressMessage(IngressMessageAttribute),
    DkgMessage(DkgMessageAttribute),
    CertificationMessage(CertificationMessageAttribute),
    FileTreeSync(FileTreeSyncAttribute),
    StateSync(StateSyncAttribute),
}

/// Artifact identifier type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactId {
    ConsensusMessage(ConsensusMessageId),
    IngressMessage(IngressMessageId),
    CertificationMessage(CertificationMessageId),
    DkgMessage(DkgMessageId),
    FileTreeSync(FileTreeSyncId),
    StateSync(StateSyncArtifactId),
}

/// Artifact tags is used to select an artifact subtype when we do not have
/// Artifact/ArtifactId/ArtifactAttribute. For example, when lookup quota
/// or filters.
#[derive(EnumIter, TryInto, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactTag {
    ConsensusArtifact,
    IngressArtifact,
    CertificationArtifact,
    DkgArtifact,
    FileTreeSyncArtifact,
    StateSyncArtifact,
}

impl std::fmt::Display for ArtifactTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ArtifactTag::ConsensusArtifact => "Consensus",
                ArtifactTag::IngressArtifact => "Ingress",
                ArtifactTag::CertificationArtifact => "Certification",
                ArtifactTag::DkgArtifact => "DKG",
                ArtifactTag::FileTreeSyncArtifact => "FileTreeSync",
                ArtifactTag::StateSyncArtifact => "StateSync",
            }
        )
    }
}

impl From<&ArtifactId> for ArtifactTag {
    fn from(id: &ArtifactId) -> ArtifactTag {
        match id {
            ArtifactId::ConsensusMessage(_) => ArtifactTag::ConsensusArtifact,
            ArtifactId::IngressMessage(_) => ArtifactTag::IngressArtifact,
            ArtifactId::CertificationMessage(_) => ArtifactTag::CertificationArtifact,
            ArtifactId::DkgMessage(_) => ArtifactTag::DkgArtifact,
            ArtifactId::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
            ArtifactId::StateSync(_) => ArtifactTag::StateSyncArtifact,
        }
    }
}

// This implementation is used to match the artifact with the right client
// in the ArtifactManager, which indexes all clients based on the ArtifactTag.
impl From<&Artifact> for ArtifactTag {
    fn from(id: &Artifact) -> ArtifactTag {
        match id {
            Artifact::ConsensusMessage(_) => ArtifactTag::ConsensusArtifact,
            Artifact::IngressMessage(_) => ArtifactTag::IngressArtifact,
            Artifact::CertificationMessage(_) => ArtifactTag::CertificationArtifact,
            Artifact::DkgMessage(_) => ArtifactTag::DkgArtifact,
            Artifact::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
            Artifact::StateSync(_) => ArtifactTag::StateSyncArtifact,
        }
    }
}

/// A collection of "filters" used by the gossip protocol for each kind
/// of artifact pools. At the moment it only has consensus filter.
/// Note that it is a struct instead of an enum, because we most likely
/// are interested in all filters.
#[derive(AsMut, AsRef, Default, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactFilter {
    pub consensus_filter: ConsensusMessageFilter,
    pub ingress_filter: IngressMessageFilter,
    pub certification_filter: CertificationMessageFilter,
    pub state_sync_filter: StateSyncFilter,
    pub no_filter: (),
}

/// Priority of artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter)]
pub enum Priority {
    /// Drop the advert, the IC doesn't need the corresponding artifact for
    /// making progress.
    Drop,
    /// Stash the advert. Processing of this advert is suspended, it's not going
    /// to be requested even if there is capacity available for download.
    Stash,

    // All downloadable priority classes. Downloads adhere to quota and
    // bandwidth constraints
    /// Low priority adverts to be considered for download, given that there is
    /// enough capacity.
    Later,
    /// Normal priority adverts.
    Fetch,
    /// High priority adverts.
    FetchNow,
}

/// Priority function used by `ArtifactClient`.
pub type PriorityFn<Id, Attribute> =
    Box<dyn Fn(&Id, &Attribute) -> Priority + Send + Sync + 'static>;

/// Wraps individual `PriorityFn`s, used by `ArtifactManager`.
pub type ArtifactPriorityFn =
    Box<dyn Fn(&ArtifactId, &ArtifactAttribute) -> Priority + Send + Sync + 'static>;

/// Related artifact sub-types (Message/Id/Attribute/Filter) are
/// parameterized by a type variable, which is of `ArtifactKind` trait.
/// It is mostly a convenience to pass around a collection of types
/// instead of all of them individually.
// The Unpin constraint is because the Message type was used to define an actor
// type, of which 'start_in_arbiter' is called, and actix requires Unpin.
pub trait ArtifactKind: Sized {
    const TAG: ArtifactTag;
    type Id;
    type Message: Unpin;
    type SerializeAs;
    type Attribute;
    type Filter: Default;

    /// Returns the advert of the given message.
    fn to_advert(msg: &<Self as ArtifactKind>::Message) -> Advert<Self>;

    /// Checks if the given advert matches what is computed from the message.
    /// Returns the advert derived from artifact on mismatch.
    fn check_advert(
        msg: &<Self as ArtifactKind>::Message,
        advert: &Advert<Self>,
    ) -> Result<(), Advert<Self>>
    where
        Advert<Self>: Eq,
    {
        let computed = Self::to_advert(msg);
        if advert == &computed {
            Ok(())
        } else {
            Err(computed)
        }
    }
}

/// A helper type that represents a type-indexed Advert.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Advert<Artifact: ArtifactKind> {
    pub id: Artifact::Id,
    pub attribute: Artifact::Attribute,
    pub size: usize,
    // IntegrityHash is just a CryptoHash
    // We don't polimorphise over different Artifacts because it makes no sense,
    // they are never compared, except in one instance where we compare something
    // in GossipAdvert and Advert<T>, so we can't make a mistake.
    pub integrity_hash: CryptoHash,
}

impl<Artifact: ArtifactKind> From<Advert<Artifact>> for GossipAdvert
where
    Artifact::Id: Into<ArtifactId>,
    Artifact::Attribute: Into<ArtifactAttribute>,
{
    fn from(advert: Advert<Artifact>) -> GossipAdvert {
        GossipAdvert {
            artifact_id: advert.id.into(),
            attribute: advert.attribute.into(),
            size: advert.size,
            integrity_hash: advert.integrity_hash,
        }
    }
}

// This instance is currently not used, but may become handy.
impl<Artifact: ArtifactKind> TryFrom<GossipAdvert> for Advert<Artifact>
where
    ArtifactId: TryInto<Artifact::Id, Error = ArtifactId> + From<Artifact::Id>,
    ArtifactAttribute:
        TryInto<Artifact::Attribute, Error = ArtifactAttribute> + From<Artifact::Attribute>,
{
    type Error = GossipAdvert;
    fn try_from(advert: GossipAdvert) -> Result<Advert<Artifact>, Self::Error> {
        let artifact_id = advert.artifact_id;
        let artifact_attribute = advert.attribute;
        let size = advert.size;
        match (artifact_id.try_into(), artifact_attribute.try_into()) {
            (Ok(id), Ok(attribute)) => Ok(Advert {
                id,
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Err(artifact_id), Ok(attribute)) => Err(GossipAdvert {
                artifact_id,
                attribute: attribute.into(),
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Ok(artifact_id), Err(attribute)) => Err(GossipAdvert {
                artifact_id: artifact_id.into(),
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
            (Err(artifact_id), Err(attribute)) => Err(GossipAdvert {
                artifact_id,
                attribute,
                size,
                integrity_hash: advert.integrity_hash,
            }),
        }
    }
}

// -----------------------------------------------------------------------------
// Consensus artifacts

/// Consensus message identifier carries both an message hash and a height,
/// which is used by the consensus pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusMessageId {
    pub hash: ConsensusMessageHash,
    pub height: Height,
}

/// Consensus message filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusMessageFilter {
    pub height: Height,
}

// -----------------------------------------------------------------------------
// Ingress artifacts

/// [`IngressMessageId`] includes expiry time in addition to [`MessageId`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IngressMessageId {
    expiry: Time,
    pub message_id: MessageId,
}

impl IngressMessageId {
    /// Create a new IngressMessageId
    pub fn new(expiry: Time, message_id: MessageId) -> Self {
        IngressMessageId { expiry, message_id }
    }

    pub fn expiry(&self) -> Time {
        self.expiry
    }
}

impl std::fmt::Display for IngressMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}@{:?}", self.message_id, self.expiry)
    }
}

impl std::fmt::Debug for IngressMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}@{:?}", self.message_id, self.expiry)
    }
}

impl From<&SignedIngress> for IngressMessageId {
    fn from(signed_ingress: &SignedIngress) -> Self {
        IngressMessageId::new(signed_ingress.expiry_time(), signed_ingress.id())
    }
}

impl From<&IngressMessageId> for MessageId {
    fn from(id: &IngressMessageId) -> MessageId {
        id.message_id.clone()
    }
}

/// Dummy definition of ingress message attribute for now.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IngressMessageAttribute;

// Placeholder for now.
impl IngressMessageAttribute {
    pub fn new(_message: &SignedIngress) -> Self {
        IngressMessageAttribute
    }
}

/// Ingress messages are filtered by their expiry time.
///
/// - 'None' means any message that has not expired.
///
/// - 'Some(expiry)' means messages whose expiry time is less than or equal to
///   'expiry', and not expired.
///
/// The notion of "not expired" is with respect to the local time source.
pub type IngressMessageFilter = Option<Time>;

// -----------------------------------------------------------------------------
// Certification artifacts

/// Certification message identifier carries both message hash and a height,
/// which is used by the certification pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageId {
    pub hash: CertificationMessageHash,
    pub height: Height,
}

/// The certification message attribute used by the priority function.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertificationMessageAttribute {
    Certification(Height),
    CertificationShare(Height),
}

/// Certification message filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageFilter {
    pub height: Height,
}

// -----------------------------------------------------------------------------
// DKG artifacts

/// Identifier of a DKG message.
pub type DkgMessageId = CryptoHashOf<DkgMessage>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgMessageAttribute {
    pub interval_start_height: Height,
}

// ------------------------------------------------------------------------------
// StateSync artifacts.

/// Identifier of a state sync artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSyncArtifactId {
    pub height: Height,
    pub hash: CryptoHashOfState,
}

type GetStateSyncChunk =
    fn(file_path: std::path::PathBuf, offset: u64, len: u32) -> std::io::Result<Vec<u8>>;

/// State sync message.
//
// NOTE: StateSyncMessage is never persisted or transferred over the wire
// (despite the Serialize/Deserialize bounds imposed by P2P interfaces), that's
// why it's fine to include an absolute path into it.
//
// P2P will call get_chunk() on it to get a byte array to send to a peer, and
// this byte array will be read from the FS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSyncMessage {
    pub height: Height,
    pub root_hash: CryptoHashOfState,
    /// Absolute path to the checkpoint root directory.
    pub checkpoint_root: std::path::PathBuf,
    /// The manifest containing the summary of the content.
    pub manifest: crate::state_sync::Manifest,

    #[serde(skip_serializing, skip_deserializing)]
    pub get_state_sync_chunk: Option<GetStateSyncChunk>,
}

// We need a custom Hash instance to skip checkpoint_root in order
// for integrity_hash to produce the same result on different nodes.
//
// Clippy gives a warning about having a derived PartialEq but a
// hand-rolled Hash instance. In our case this is acceptable because:
//
// 1. We only use use Hash for integrity check.
//
// 2. Even if we use it for other purposes (e.g. in a HashSet), this
//    is still safe because identical (height, root_hash) should
//    lead to identical checkpoint_root.
#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for StateSyncMessage {
    fn hash<Hasher: std::hash::Hasher>(&self, state: &mut Hasher) {
        self.height.hash(state);
        self.root_hash.hash(state);
        self.manifest.hash(state);
    }
}

/// State sync atrribute.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSyncAttribute {
    pub height: Height,

    // Note: the root hash is also an attribute so that we can access it from
    // the priority function.
    pub root_hash: CryptoHashOfState,
}

/// State sync filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateSyncFilter {
    pub height: Height,
}

// ------------------------------------------------------------------------------
// FileTreeSync artifacts

/// File tree sync attribute.
pub type FileTreeSyncAttribute = String;

// ------------------------------------------------------------------------------
// Conversions

impl From<ArtifactFilter> for pb::ArtifactFilter {
    fn from(filter: ArtifactFilter) -> Self {
        Self {
            consensus_filter: Some(filter.consensus_filter.into()),
            ingress_filter: Some(pb::IngressMessageFilter {
                time: filter
                    .ingress_filter
                    .unwrap_or_else(|| Time::from_nanos_since_unix_epoch(0))
                    .as_nanos_since_unix_epoch(),
            }),
            certification_message_filter: Some(filter.certification_filter.into()),
            state_sync_filter: Some(filter.state_sync_filter.into()),
        }
    }
}

impl TryFrom<pb::ArtifactFilter> for ArtifactFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::ArtifactFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            consensus_filter: try_from_option_field(
                filter.consensus_filter,
                "ArtifactFilter.consensus_filter",
            )?,
            ingress_filter: Some(Time::from_nanos_since_unix_epoch(
                filter
                    .ingress_filter
                    .ok_or(ProxyDecodeError::MissingField(
                        "ArtifactFilter.ingress_filter",
                    ))?
                    .time,
            )),
            certification_filter: try_from_option_field(
                filter.certification_message_filter,
                "ArtifactFilter.ingress_filter",
            )?,
            state_sync_filter: try_from_option_field(
                filter.state_sync_filter,
                "ArtifactFilter.state_sync_filter",
            )?,
            no_filter: (),
        })
    }
}

impl From<ConsensusMessageFilter> for pb::ConsensusMessageFilter {
    fn from(filter: ConsensusMessageFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::ConsensusMessageFilter> for ConsensusMessageFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::ConsensusMessageFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}

impl From<CertificationMessageFilter> for pb::CertificationMessageFilter {
    fn from(filter: CertificationMessageFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::CertificationMessageFilter> for CertificationMessageFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::CertificationMessageFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}

impl From<StateSyncFilter> for pb::StateSyncFilter {
    fn from(filter: StateSyncFilter) -> Self {
        Self {
            height: filter.height.get(),
        }
    }
}

impl TryFrom<pb::StateSyncFilter> for StateSyncFilter {
    type Error = ProxyDecodeError;
    fn try_from(filter: pb::StateSyncFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            height: Height::from(filter.height),
        })
    }
}
