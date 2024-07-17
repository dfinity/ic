//! Defines types used for certification.

use crate::{
    artifact::{CertificationMessageId, IdentifiableArtifact, PbArtifact},
    consensus::{
        Committee, CountBytes, HasCommittee, HasHeight, IsShare, ThresholdSignature,
        ThresholdSignatureShare,
    },
    crypto::{CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator},
    CryptoHashOfPartialState, Height,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::ProxyDecodeError,
    types::v1::{self as pb, certification_message::Msg},
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// CertificationMessage captures the different types of messages sent around
/// for the purpose of state certification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CertificationMessage {
    /// Certification captures a full certification on behalf of a subnet
    Certification(Certification),
    /// CertificationShare captures a share of a certification created by a
    /// single replica
    CertificationShare(CertificationShare),
}

impl IdentifiableArtifact for CertificationMessage {
    const NAME: &'static str = "certification";
    type Id = CertificationMessageId;
    fn id(&self) -> Self::Id {
        self.into()
    }
}

impl PbArtifact for CertificationMessage {
    type PbId = ic_protobuf::types::v1::CertificationMessageId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = ic_protobuf::types::v1::CertificationMessage;
    type PbMessageError = ProxyDecodeError;
}

impl HasHeight for CertificationMessage {
    fn height(&self) -> Height {
        match self {
            CertificationMessage::Certification(c) => c.height,
            CertificationMessage::CertificationShare(c) => c.height,
        }
    }
}

impl IsShare for CertificationMessage {
    fn is_share(&self) -> bool {
        match self {
            CertificationMessage::Certification(_) => false,
            CertificationMessage::CertificationShare(_) => true,
        }
    }
}

impl TryFrom<CertificationMessage> for Certification {
    type Error = CertificationMessage;
    fn try_from(msg: CertificationMessage) -> Result<Self, Self::Error> {
        match msg {
            CertificationMessage::Certification(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<CertificationMessage> for CertificationShare {
    type Error = CertificationMessage;
    fn try_from(msg: CertificationMessage) -> Result<Self, Self::Error> {
        match msg {
            CertificationMessage::CertificationShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl From<Certification> for CertificationMessage {
    fn from(msg: Certification) -> Self {
        CertificationMessage::Certification(msg)
    }
}

impl From<CertificationShare> for CertificationMessage {
    fn from(msg: CertificationShare) -> Self {
        CertificationMessage::CertificationShare(msg)
    }
}

impl From<CertificationMessage> for pb::CertificationMessage {
    fn from(share: CertificationMessage) -> Self {
        match share {
            CertificationMessage::Certification(cert) => Self {
                msg: Some(Msg::Certification(cert.into())),
            },
            CertificationMessage::CertificationShare(share) => Self {
                msg: Some(Msg::CertificationShare(share.into())),
            },
        }
    }
}

impl TryFrom<pb::CertificationMessage> for CertificationMessage {
    type Error = ProxyDecodeError;
    fn try_from(share: pb::CertificationMessage) -> Result<Self, Self::Error> {
        let Some(msg) = share.msg else {
            return Err(ProxyDecodeError::MissingField("CertificationMessage::msg"));
        };
        Ok(match msg {
            Msg::Certification(inner) => Self::Certification(inner.try_into()?),
            Msg::CertificationShare(inner) => Self::CertificationShare(inner.try_into()?),
        })
    }
}

/// CertificationMessageHash contains the hash of a CertificationMessage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub enum CertificationMessageHash {
    /// Certification captures the hash of a full certification on behalf of a
    /// subnet
    Certification(CryptoHashOf<Certification>),
    /// CertificationShare captures the hash of a share of a certification
    /// created by a single replica
    CertificationShare(CryptoHashOf<CertificationShare>),
}

impl From<&CertificationMessageHash> for pb::CertificationMessageHash {
    fn from(value: &CertificationMessageHash) -> Self {
        use pb::certification_message_hash::Kind;
        let kind = match value.clone() {
            CertificationMessageHash::Certification(x) => Kind::Certification(x.get().0),
            CertificationMessageHash::CertificationShare(x) => Kind::CertificationShare(x.get().0),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<&pb::CertificationMessageHash> for CertificationMessageHash {
    type Error = ProxyDecodeError;
    fn try_from(value: &pb::CertificationMessageHash) -> Result<Self, Self::Error> {
        use pb::certification_message_hash::Kind;
        let kind = value
            .kind
            .clone()
            .ok_or_else(|| ProxyDecodeError::MissingField("CertificationMessageHash::kind"))?;

        Ok(match kind {
            Kind::Certification(x) => {
                CertificationMessageHash::Certification(CryptoHashOf::new(CryptoHash(x)))
            }
            Kind::CertificationShare(x) => {
                CertificationMessageHash::CertificationShare(CryptoHashOf::new(CryptoHash(x)))
            }
        })
    }
}

/// CertificationContent holds the data signed by certification
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CertificationContent {
    /// The hash of the relevant parts of the replicated state
    pub hash: CryptoHashOfPartialState,
}

impl CertificationContent {
    /// Create a new CertificationContent given a CryptoHashOfPartialState
    pub fn new(hash: CryptoHashOfPartialState) -> Self {
        CertificationContent { hash }
    }
}

impl SignedBytesWithoutDomainSeparator for CertificationContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.hash.get_ref().0.clone()
    }
}

// Returning a constant role is needed to work with the existing membership, to
// select correct threshold value.
impl HasCommittee for Certification {
    fn committee() -> Committee {
        Committee::HighThreshold
    }
}

impl AsRef<CertificationContent> for CertificationMessage {
    fn as_ref(&self) -> &CertificationContent {
        match self {
            CertificationMessage::Certification(sig) => &sig.signed.content,
            CertificationMessage::CertificationShare(sig) => &sig.signed.content,
        }
    }
}

/// A Certification is a CertificationContent that is cryptographically signed
/// by a subnet using a threshold signature
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Certification {
    /// the height that the CertificationContent belongs to
    pub height: Height,
    /// the signature on the CertificationContent
    pub signed: Signed<CertificationContent, ThresholdSignature<CertificationContent>>,
}

impl HasHeight for Certification {
    fn height(&self) -> Height {
        self.height
    }
}

impl CountBytes for Certification {
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Height>()
            + self.signed.content.hash.get_ref().0.len()
            + self.signed.signature.count_bytes()
    }
}

/// A certification share is the signature of a single replica on a
/// CertificationContent
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationShare {
    /// the height that the CertificationContent belongs to
    pub height: Height,
    /// the signature on the CertificationContent
    pub signed: Signed<CertificationContent, ThresholdSignatureShare<CertificationContent>>,
}

impl HasHeight for CertificationShare {
    fn height(&self) -> Height {
        self.height
    }
}
