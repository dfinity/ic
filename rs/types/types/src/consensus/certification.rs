//! Defines types used for certification.

use crate::{
    CryptoHashOfPartialState, Height,
    artifact::{CertificationMessageId, IdentifiableArtifact, PbArtifact},
    consensus::{
        Committee, CountBytes, HasCommittee, HasHeight, IsShare, ThresholdSignature,
        ThresholdSignatureShare,
    },
    crypto::{CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator},
};
use ic_crypto_tree_hash::Witness;
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
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

impl TryFrom<pb::CertificationMessageHash> for CertificationMessageHash {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CertificationMessageHash) -> Result<Self, Self::Error> {
        use pb::certification_message_hash::Kind;
        let kind = value
            .kind
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
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

impl CountBytes for CertificationContent {
    fn count_bytes(&self) -> usize {
        self.hash.get_ref().0.len()
    }
}

impl SignedBytesWithoutDomainSeparator for CertificationContent {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.hash.get_ref().0);
    }
}

/// `CertificationContent` with the subnet's threshold signature on it.
pub type SignedCertificationContent =
    Signed<CertificationContent, ThresholdSignature<CertificationContent>>;

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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Certification {
    /// the height that the CertificationContent belongs to
    pub height: Height,
    /// the witness for the height
    pub height_witness: Witness,
    /// the signature on the CertificationContent
    pub signed: SignedCertificationContent,
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CertificationShare {
    /// the height that the CertificationContent belongs to
    pub height: Height,
    /// the witness for the height
    pub height_witness: Witness,
    /// the signature on the CertificationContent
    pub signed: Signed<CertificationContent, ThresholdSignatureShare<CertificationContent>>,
}

impl HasHeight for CertificationShare {
    fn height(&self) -> Height {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exhaustive::ExhaustiveSet;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use prost::Message;

    #[test]
    fn verify_exhaustive_certification_message() {
        let set = CertificationMessage::exhaustive_set(&mut reproducible_rng());
        println!("Number of certification message variants: {}", set.len());
        for msg in set {
            let bytes = pb::CertificationMessage::from(msg.clone()).encode_to_vec();
            let proto_msg = pb::CertificationMessage::decode(bytes.as_slice()).unwrap();
            let new_msg = CertificationMessage::try_from(proto_msg).unwrap();

            assert_eq!(
                msg, new_msg,
                "deserialized certification message is different from original"
            );
        }
    }

    /// As the certification pool is kept across replica versions, a replica must be able to
    /// read the certification messages persisted by the replica versions it is upgraded or
    /// downgraded from. These tests are not meant to be run as part of the regular test suite
    /// (hence the `ignore` attributes), but are invoked from the test binaries of the mainnet
    /// and branch versions by `//rs/tests/consensus/orchestrator:certification_compatibility_test`.
    /// Hence, they must not be moved or renamed.
    mod mainnet_compatibility_tests {
        use super::*;
        use std::{fs, path::Path};

        const OUTPUT_DIR: &str = "certification_messages";

        /// Serialize a set of [`CertificationMessage`]s to [`OUTPUT_DIR`], encoded as they
        /// are persisted in the certification pool.
        #[test]
        #[ignore]
        fn serialize() {
            let directory = Path::new(OUTPUT_DIR);
            fs::create_dir(directory).expect("Failed to create directory");
            let set = CertificationMessage::exhaustive_set(&mut reproducible_rng());
            println!("Number of certification message variants: {}", set.len());

            for (i, msg) in set.into_iter().enumerate() {
                let bytes = pb::CertificationMessage::from(msg).encode_to_vec();
                fs::write(directory.join(format!("{i}.pb")), bytes).expect("Failed to write bytes");
            }
        }

        /// Deserialize all [`CertificationMessage`]s found in [`OUTPUT_DIR`].
        #[test]
        #[ignore]
        fn deserialize() {
            for entry in fs::read_dir(OUTPUT_DIR).expect("Failed to read directory") {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).expect("Failed to read file");
                let proto_msg = pb::CertificationMessage::decode(bytes.as_slice())
                    .unwrap_or_else(|err| panic!("Failed to decode {path:?}: {err:?}"));
                CertificationMessage::try_from(proto_msg)
                    .unwrap_or_else(|err| panic!("Failed to deserialize {path:?}: {err:?}"));
            }
        }
    }
}
