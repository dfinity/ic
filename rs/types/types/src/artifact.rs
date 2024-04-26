//! Artifact related types.
//!
//! Notably it includes the following definitions and their sub-types:
//!
//! - [`Artifact`]
//! - [`ArtifactTag`]
//! - [`ArtifactId`]
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
        idkg::EcdsaArtifactId,
        ConsensusMessage, ConsensusMessageHash, ConsensusMessageHashable, HasHash, HasHeight,
    },
    crypto::{crypto_hash, CryptoHash},
    messages::{MessageId, SignedIngress},
    Height, NodeId, Time,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    hash::Hash,
};
use strum_macros::{EnumIter, IntoStaticStr};

/// Artifact tags is used to select an artifact subtype when we do not have
/// Artifact/ArtifactId/ArtifactAttribute. For example, when lookup quota
/// or filters.
#[derive(EnumIter, Clone, Copy, Debug, PartialEq, Eq, Hash, IntoStaticStr)]
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

    /// Returns the advert of the given message.
    fn message_to_advert(msg: &<Self as ArtifactKind>::Message) -> Advert<Self>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum UnvalidatedArtifactMutation<Artifact: ArtifactKind> {
    Insert((Artifact::Message, NodeId)),
    Remove(Artifact::Id),
}

/// A helper type that represents a type-indexed Advert.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Advert<Artifact: ArtifactKind> {
    /// The id _must_ contain the integrity hash of the message.
    pub id: Artifact::Id,
    pub attribute: Artifact::Attribute,
    pub size: usize,
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
