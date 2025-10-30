//! Artifact related types.
use crate::{
    Height, NodeId, Time,
    canister_http::CanisterHttpResponseShare,
    consensus::{
        ConsensusMessage, ConsensusMessageHash, ConsensusMessageHashable, HasHash, HasHeight,
        certification::{CertificationMessage, CertificationMessageHash},
        idkg::IDkgArtifactId,
    },
    crypto::{CryptoHash, crypto_hash},
    messages::{MessageId, SignedIngress},
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    hash::Hash,
};

pub trait IdentifiableArtifact: Send + 'static {
    const NAME: &'static str;
    type Id: Hash + Clone + PartialEq + Eq + Send + Sync + 'static;
    fn id(&self) -> Self::Id;
}

pub trait PbArtifact: IdentifiableArtifact + Send + Sized + 'static {
    /// Protobuf ID wire type
    type PbId: prost::Message
        + From<Self::Id>
        + TryInto<Self::Id, Error = Self::PbIdError>
        + Default;
    /// Protobuf to rust conversion error
    type PbIdError: std::error::Error + Into<ProxyDecodeError>;

    type PbMessage: prost::Message
        + From<Self>
        + TryInto<Self, Error = Self::PbMessageError>
        + Default;
    type PbMessageError: std::error::Error + Into<ProxyDecodeError>;
}

#[derive(Eq, PartialEq, Debug)]
pub enum UnvalidatedArtifactMutation<Artifact: IdentifiableArtifact> {
    Insert((Artifact, NodeId)),
    Remove(Artifact::Id),
}

// -----------------------------------------------------------------------------
// Consensus artifacts

/// Consensus message identifier carries both a message hash and a height,
/// which is used by the consensus pool to help lookup.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
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
        self.hash.digest()
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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
// IDKG artifacts

pub type IDkgMessageId = IDkgArtifactId;

// -----------------------------------------------------------------------------
// CanisterHttp artifacts

pub type CanisterHttpResponseId = CanisterHttpResponseShare;
