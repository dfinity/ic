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
    canister_http::CanisterHttpResponseShare,
    consensus::{
        certification::{CertificationMessage, CertificationMessageHash},
        dkg::DkgMessageId,
        dkg::Message as DkgMessage,
        ecdsa::{EcdsaArtifactId, EcdsaMessage, EcdsaMessageAttribute},
        ConsensusMessage, ConsensusMessageAttribute, ConsensusMessageHash,
        ConsensusMessageHashable, HasHash, HasHeight,
    },
    crypto::{crypto_hash, CryptoHash},
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    messages::{HttpRequestError, MessageId, SignedIngress, SignedRequestBytes},
    p2p::GossipAdvert,
    Height, NodeId, Time,
};
use derive_more::{AsMut, AsRef, From, TryInto};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::types::{v1 as pb, v1::artifact::Kind};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    hash::Hash,
};
use strum_macros::{EnumIter, IntoStaticStr};

/// The artifact type
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
#[allow(clippy::large_enum_variant)]
pub enum Artifact {
    ConsensusMessage(ConsensusMessage),
    IngressMessage(SignedIngress),
    CertificationMessage(CertificationMessage),
    DkgMessage(DkgMessage),
    EcdsaMessage(EcdsaMessage),
    CanisterHttpMessage(CanisterHttpResponseShare),
    FileTreeSync(FileTreeSyncArtifact),
}

/// Artifact attribute type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactAttribute {
    ConsensusMessage(ConsensusMessageAttribute),
    EcdsaMessage(EcdsaMessageAttribute),
    Empty(()),
}

impl From<ArtifactAttribute> for pb::ArtifactAttribute {
    fn from(value: ArtifactAttribute) -> Self {
        use pb::artifact_attribute::Kind;
        let kind = match value {
            ArtifactAttribute::ConsensusMessage(x) => Kind::ConsensusMessage(x.into()),
            ArtifactAttribute::EcdsaMessage(x) => Kind::EcdsaMessage(x.into()),
            ArtifactAttribute::Empty(_) => Kind::Empty(()),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<pb::ArtifactAttribute> for ArtifactAttribute {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::ArtifactAttribute) -> Result<Self, Self::Error> {
        use pb::artifact_attribute::Kind;
        let Some(kind) = value.kind else {
            return Err(ProxyDecodeError::MissingField("ArtifactAttribute::kind"));
        };
        Ok(match kind {
            Kind::ConsensusMessage(x) => ArtifactAttribute::ConsensusMessage(x.try_into()?),
            Kind::EcdsaMessage(x) => ArtifactAttribute::EcdsaMessage(x.try_into()?),
            Kind::Empty(_) => ArtifactAttribute::Empty(()),
        })
    }
}

/// Artifact identifier type.
#[derive(From, TryInto, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[try_into(owned, ref, ref_mut)]
pub enum ArtifactId {
    ConsensusMessage(ConsensusMessageId),
    IngressMessage(IngressMessageId),
    CertificationMessage(CertificationMessageId),
    CanisterHttpMessage(CanisterHttpResponseId),
    DkgMessage(DkgMessageId),
    EcdsaMessage(EcdsaMessageId),
    FileTreeSync(FileTreeSyncId),
}

impl From<ArtifactId> for pb::ArtifactId {
    fn from(value: ArtifactId) -> Self {
        use pb::artifact_id::Kind;
        let kind = match value {
            ArtifactId::ConsensusMessage(x) => Kind::Consensus(x.into()),
            ArtifactId::IngressMessage(x) => Kind::Ingress(x.into()),
            ArtifactId::DkgMessage(x) => Kind::DkgMessage(x.into()),
            ArtifactId::CertificationMessage(x) => Kind::Certification(x.into()),
            ArtifactId::EcdsaMessage(x) => Kind::Ecdsa(x.into()),
            ArtifactId::CanisterHttpMessage(x) => Kind::CanisterHttp(x.into()),
            ArtifactId::FileTreeSync(x) => Kind::FileTreeSync(x.clone()),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<pb::ArtifactId> for ArtifactId {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::ArtifactId) -> Result<Self, Self::Error> {
        use pb::artifact_id::Kind;
        let kind = value
            .kind
            .ok_or_else(|| ProxyDecodeError::MissingField("ArtifactId::kind"))?;

        Ok(match kind {
            Kind::Consensus(x) => ArtifactId::ConsensusMessage(x.try_into()?),
            Kind::Ingress(x) => ArtifactId::IngressMessage(x.try_into()?),
            Kind::DkgMessage(x) => ArtifactId::DkgMessage(x.try_into()?),
            Kind::Certification(x) => ArtifactId::CertificationMessage(x.try_into()?),
            Kind::Ecdsa(x) => ArtifactId::EcdsaMessage(x.try_into()?),
            Kind::CanisterHttp(x) => ArtifactId::CanisterHttpMessage(x.clone().try_into()?),
            Kind::FileTreeSync(x) => ArtifactId::FileTreeSync(x.clone()),
        })
    }
}

/// Artifact tags is used to select an artifact subtype when we do not have
/// Artifact/ArtifactId/ArtifactAttribute. For example, when lookup quota
/// or filters.
#[derive(EnumIter, TryInto, Clone, Copy, Debug, PartialEq, Eq, Hash, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ArtifactTag {
    #[strum(serialize = "canister_http")]
    CanisterHttpArtifact,
    #[strum(serialize = "certification")]
    CertificationArtifact,
    #[strum(serialize = "consensus")]
    ConsensusArtifact,
    #[strum(serialize = "dkg")]
    DkgArtifact,
    #[strum(serialize = "ecdsa")]
    EcdsaArtifact,
    #[strum(serialize = "file_tree_sync")]
    FileTreeSyncArtifact,
    #[strum(serialize = "ingress")]
    IngressArtifact,
}

impl std::fmt::Display for ArtifactTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ArtifactTag::CanisterHttpArtifact => "CanisterHttp",
                ArtifactTag::CertificationArtifact => "Certification",
                ArtifactTag::ConsensusArtifact => "Consensus",
                ArtifactTag::DkgArtifact => "DKG",
                ArtifactTag::EcdsaArtifact => "ECDSA",
                ArtifactTag::FileTreeSyncArtifact => "FileTreeSync",
                ArtifactTag::IngressArtifact => "Ingress",
            }
        )
    }
}

impl From<&ArtifactId> for ArtifactTag {
    fn from(id: &ArtifactId) -> ArtifactTag {
        match id {
            ArtifactId::CanisterHttpMessage(_) => ArtifactTag::CanisterHttpArtifact,
            ArtifactId::CertificationMessage(_) => ArtifactTag::CertificationArtifact,
            ArtifactId::ConsensusMessage(_) => ArtifactTag::ConsensusArtifact,
            ArtifactId::DkgMessage(_) => ArtifactTag::DkgArtifact,
            ArtifactId::EcdsaMessage(_) => ArtifactTag::EcdsaArtifact,
            ArtifactId::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
            ArtifactId::IngressMessage(_) => ArtifactTag::IngressArtifact,
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
            Artifact::EcdsaMessage(_) => ArtifactTag::EcdsaArtifact,
            Artifact::CanisterHttpMessage(_) => ArtifactTag::CanisterHttpArtifact,
            Artifact::FileTreeSync(_) => ArtifactTag::FileTreeSyncArtifact,
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
    pub certification_filter: CertificationMessageFilter,
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

/// Related artifact sub-types (Message/Id/Attribute) are
/// parameterized by a type variable, which is of `ArtifactKind` trait.
/// It is mostly a convenience to pass around a collection of types
/// instead of all of them individually.
pub trait ArtifactKind: Send + Sized + 'static {
    const TAG: ArtifactTag;

    /// Protobuf ID wire type
    type PbId: prost::Message + Default;
    /// Protobuf to rust conversion error
    type PbIdError: std::error::Error + Into<ProxyDecodeError>;
    /// Rust artifact ID type. Needs to implement Hash etc. such that it can be used
    /// as an index in data structures.
    type Id: Into<Self::PbId>
        + TryFrom<Self::PbId, Error = Self::PbIdError>
        + Hash
        + Clone
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;

    type PbMessage: prost::Message + Default;
    type PbMessageError: std::error::Error + Into<ProxyDecodeError>;
    type Message: Into<Self::PbMessage>
        + TryFrom<Self::PbMessage, Error = Self::PbMessageError>
        + Send
        + Sync
        + 'static;

    type PbAttribute: prost::Message + Default;
    /// Protobuf to rust conversion error
    type PbAttributeError: std::error::Error + Into<ProxyDecodeError>;
    type Attribute: Into<Self::PbAttribute>
        + TryFrom<Self::PbAttribute, Error = Self::PbAttributeError>
        + Send
        + Sync
        + 'static;

    type PbFilter: prost::Message + Default;
    type PbFilterError: std::error::Error + Into<ProxyDecodeError>;
    type Filter: Into<Self::PbFilter>
        + TryFrom<Self::PbFilter, Error = Self::PbFilterError>
        + Default;

    /// Returns the advert of the given message.
    fn message_to_advert(msg: &<Self as ArtifactKind>::Message) -> Advert<Self>;
}

impl<Artifact: ArtifactKind> TryFrom<GossipAdvert> for Advert<Artifact>
where
    ArtifactId: TryInto<Artifact::Id, Error = ArtifactId> + From<Artifact::Id>,
    ArtifactAttribute:
        TryInto<Artifact::Attribute, Error = ArtifactAttribute> + From<Artifact::Attribute>,
{
    type Error = String;
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
            _ => Err(String::from(
                "Gossipadvert can not be converted to Advert<Artifact> type",
            )),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum UnvalidatedArtifactMutation<Artifact: ArtifactKind> {
    Insert((Artifact::Message, NodeId)),
    Remove(Artifact::Id),
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

// -----------------------------------------------------------------------------
// Consensus artifacts

/// Consensus message identifier carries both a message hash and a height,
/// which is used by the consensus pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusMessageId {
    pub hash: ConsensusMessageHash,
    pub height: Height,
}

impl HasHeight for ConsensusMessageId {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasHash for ConsensusMessageId {
    fn hash(&self) -> &CryptoHash {
        match &self.hash {
            ConsensusMessageHash::RandomBeacon(hash) => hash.get_ref(),
            ConsensusMessageHash::Finalization(hash) => hash.get_ref(),
            ConsensusMessageHash::Notarization(hash) => hash.get_ref(),
            ConsensusMessageHash::BlockProposal(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomBeaconShare(hash) => hash.get_ref(),
            ConsensusMessageHash::NotarizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::FinalizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTape(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTapeShare(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackage(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackageShare(hash) => hash.get_ref(),
        }
    }
}

impl From<ConsensusMessageId> for pb::ConsensusMessageId {
    fn from(value: ConsensusMessageId) -> Self {
        Self {
            hash: Some(pb::ConsensusMessageHash::from(&value.hash)),
            height: value.height.get(),
        }
    }
}

impl TryFrom<pb::ConsensusMessageId> for ConsensusMessageId {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::ConsensusMessageId) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: try_from_option_field(value.hash.as_ref(), "ConsensusMessageId::hash")?,
            height: Height::new(value.height),
        })
    }
}

impl From<&ConsensusMessage> for ConsensusMessageId {
    fn from(msg: &ConsensusMessage) -> ConsensusMessageId {
        msg.get_id()
    }
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
#[cfg_attr(test, derive(ExhaustiveSet))]
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

impl From<IngressMessageId> for pb::IngressMessageId {
    fn from(value: IngressMessageId) -> Self {
        Self {
            expiry: value.expiry.as_nanos_since_unix_epoch(),
            message_id: value.message_id.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<pb::IngressMessageId> for IngressMessageId {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::IngressMessageId) -> Result<Self, Self::Error> {
        Ok(Self {
            expiry: Time::from_nanos_since_unix_epoch(value.expiry),
            message_id: value.message_id.as_slice().try_into()?,
        })
    }
}

// -----------------------------------------------------------------------------
// Certification artifacts

/// Certification message identifier carries both message hash and a height,
/// which is used by the certification pool to help lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageId {
    pub hash: CertificationMessageHash,
    pub height: Height,
}

impl HasHeight for CertificationMessageId {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasHash for CertificationMessageId {
    fn hash(&self) -> &CryptoHash {
        match &self.hash {
            CertificationMessageHash::Certification(hash) => hash.get_ref(),
            CertificationMessageHash::CertificationShare(hash) => hash.get_ref(),
        }
    }
}

impl From<CertificationMessageId> for pb::CertificationMessageId {
    fn from(value: CertificationMessageId) -> Self {
        Self {
            hash: Some(pb::CertificationMessageHash::from(&value.hash)),
            height: value.height.get(),
        }
    }
}

/// Certification message filter is by height.
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationMessageFilter {
    pub height: Height,
}

// -----------------------------------------------------------------------------
// DKG artifacts

impl TryFrom<pb::CertificationMessageId> for CertificationMessageId {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CertificationMessageId) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: try_from_option_field(value.hash.as_ref(), "CertificationMessageId::hash")?,
            height: Height::new(value.height),
        })
    }
}

impl From<&CertificationMessage> for CertificationMessageId {
    fn from(msg: &CertificationMessage) -> CertificationMessageId {
        match msg {
            CertificationMessage::Certification(cert) => CertificationMessageId {
                height: cert.height,
                hash: CertificationMessageHash::Certification(crypto_hash(cert)),
            },
            CertificationMessage::CertificationShare(share) => CertificationMessageId {
                height: share.height,
                hash: CertificationMessageHash::CertificationShare(crypto_hash(share)),
            },
        }
    }
}

impl From<&CertificationMessage> for CertificationMessageHash {
    fn from(msg: &CertificationMessage) -> CertificationMessageHash {
        match msg {
            CertificationMessage::Certification(cert) => {
                CertificationMessageHash::Certification(crypto_hash(cert))
            }
            CertificationMessage::CertificationShare(share) => {
                CertificationMessageHash::CertificationShare(crypto_hash(share))
            }
        }
    }
}

// -----------------------------------------------------------------------------
// ECDSA artifacts

pub type EcdsaMessageId = EcdsaArtifactId;

// -----------------------------------------------------------------------------
// CanisterHttp artifacts

pub type CanisterHttpResponseId = CanisterHttpResponseShare;

// ------------------------------------------------------------------------------
// Conversions

impl From<Artifact> for pb::Artifact {
    fn from(value: Artifact) -> Self {
        let kind = match value {
            Artifact::ConsensusMessage(x) => Kind::Consensus(x.clone().into()),
            Artifact::IngressMessage(x) => Kind::SignedIngress(x.binary().clone().into()),
            Artifact::CertificationMessage(x) => Kind::Certification(x.clone().into()),
            Artifact::DkgMessage(x) => Kind::Dkg(x.into()),
            Artifact::EcdsaMessage(x) => Kind::Ecdsa(x.into()),
            Artifact::CanisterHttpMessage(x) => Kind::HttpShare(x.into()),
            Artifact::FileTreeSync(x) => Kind::FileTreeSync(x.clone().into()),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<pb::Artifact> for Artifact {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::Artifact) -> Result<Self, Self::Error> {
        let kind = value
            .kind
            .ok_or(ProxyDecodeError::MissingField("Artifact::msg"))?;

        Ok(match kind {
            Kind::Consensus(x) => Artifact::ConsensusMessage(x.try_into()?),
            Kind::SignedIngress(x) => Artifact::IngressMessage({
                SignedRequestBytes::from(x)
                    .try_into()
                    .map_err(|x: HttpRequestError| ProxyDecodeError::Other(x.to_string()))?
            }),
            Kind::Certification(x) => Artifact::CertificationMessage(x.try_into()?),
            Kind::Dkg(x) => Artifact::DkgMessage(x.try_into()?),
            Kind::Ecdsa(x) => Artifact::EcdsaMessage(x.try_into()?),
            Kind::HttpShare(x) => Artifact::CanisterHttpMessage(x.try_into()?),
            Kind::FileTreeSync(x) => Artifact::FileTreeSync(x.into()),
        })
    }
}

impl From<ArtifactFilter> for pb::ArtifactFilter {
    fn from(filter: ArtifactFilter) -> Self {
        Self {
            consensus_filter: Some(filter.consensus_filter.into()),
            certification_message_filter: Some(filter.certification_filter.into()),
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
            certification_filter: try_from_option_field(
                filter.certification_message_filter,
                "ArtifactFilter.certification_message_filter",
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
