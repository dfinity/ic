//! Defines types used for certification.

use crate::{
    consensus::{
        Committee, CountBytes, HasCommittee, HasHeight, ThresholdSignature, ThresholdSignatureShare,
    },
    crypto::{CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator},
    CryptoHashOfPartialState, Height,
};
use ic_protobuf::messaging::xnet::v1 as pb;
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

impl HasHeight for CertificationMessage {
    fn height(&self) -> Height {
        match self {
            CertificationMessage::Certification(c) => c.height,
            CertificationMessage::CertificationShare(c) => c.height,
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

/// CertificationMessageHash contains the hash of a CertificationMessage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CertificationMessageHash {
    /// Certification captures the hash of a full certification on behalf of a
    /// subnet
    Certification(CryptoHashOf<Certification>),
    /// CertificationShare captures the hash of a share of a certification
    /// created by a single replica
    CertificationShare(CryptoHashOf<CertificationShare>),
}

/// CertificationContent holds the data signed by certification
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

impl From<pb::CertificationContent> for CertificationContent {
    fn from(value: pb::CertificationContent) -> Self {
        CertificationContent {
            hash: CryptoHashOfPartialState::new(CryptoHash(value.hash)),
        }
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
