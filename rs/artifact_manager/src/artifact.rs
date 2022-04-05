//! The module contains implementations for different artifact kinds.

use ic_consensus_message::ConsensusMessageHashable;
use ic_ecdsa_object::ecdsa_msg_hash;
use ic_types::{
    artifact::*, canister_http::CanisterHttpResponseShare,
    consensus::certification::CertificationMessageHash, consensus::ecdsa::EcdsaMessageAttribute,
    crypto::CryptoHashOf, messages::SignedRequestBytes, CountBytes,
};
use serde::{Deserialize, Serialize};

/// The `ArtifactKind` of *Consensus* messages.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ConsensusArtifact;

/// `ConsensusArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for ConsensusArtifact {
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    type Id = ConsensusMessageId;
    type Message = ConsensusMessage;
    type SerializeAs = ConsensusMessage;
    type Attribute = ConsensusMessageAttribute;
    type Filter = ConsensusMessageFilter;

    /// The function converts a `ConsensusMessage` into an advert for a
    /// `ConsensusArtifact`.
    fn message_to_advert(msg: &ConsensusMessage) -> Advert<ConsensusArtifact> {
        let binary_data = bincode::serialize(msg).unwrap();
        let attribute = ConsensusMessageAttribute::from(msg);
        let size = binary_data.len();
        Advert {
            id: msg.get_id(),
            attribute,
            size,
            integrity_hash: ic_crypto_hash::crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of ingress message.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IngressArtifact;

/// `IngressArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for IngressArtifact {
    const TAG: ArtifactTag = ArtifactTag::IngressArtifact;
    type Id = IngressMessageId;
    type Message = SignedIngress;
    type SerializeAs = SignedRequestBytes;
    type Attribute = IngressMessageAttribute;
    type Filter = IngressMessageFilter;

    /// The function converts a `SignedIngress` into an advert for an
    /// `IngressArtifact`.
    fn message_to_advert(msg: &SignedIngress) -> Advert<IngressArtifact> {
        Advert {
            id: IngressMessageId::from(msg),
            attribute: IngressMessageAttribute::new(msg),
            size: msg.count_bytes(),
            integrity_hash: ic_crypto_hash::crypto_hash(msg.binary()).get(),
        }
    }
}

/// The `ArtifactKind` of certification messages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertificationArtifact;

/// `CertificationArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CertificationArtifact {
    const TAG: ArtifactTag = ArtifactTag::CertificationArtifact;
    type Id = CertificationMessageId;
    type Message = CertificationMessage;
    type SerializeAs = CertificationMessage;
    type Attribute = CertificationMessageAttribute;
    type Filter = CertificationMessageFilter;

    /// The function converts a `CertificationMessage` into an advert for a
    /// `CertificationArtifact`.
    fn message_to_advert(msg: &CertificationMessage) -> Advert<CertificationArtifact> {
        use CertificationMessage::*;
        let (attribute, id) = match msg {
            Certification(cert) => (
                CertificationMessageAttribute::Certification(cert.height),
                CertificationMessageId {
                    height: cert.height,
                    hash: CertificationMessageHash::Certification(CryptoHashOf::from(
                        ic_crypto_hash::crypto_hash(cert).get(),
                    )),
                },
            ),
            CertificationShare(share) => (
                CertificationMessageAttribute::CertificationShare(share.height),
                CertificationMessageId {
                    height: share.height,
                    hash: CertificationMessageHash::CertificationShare(CryptoHashOf::from(
                        ic_crypto_hash::crypto_hash(share).get(),
                    )),
                },
            ),
        };
        Advert {
            id,
            attribute,
            size: bincode::serialize(msg).unwrap().len(),
            integrity_hash: ic_crypto_hash::crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of DKG messages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DkgArtifact;

/// `DkgArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for DkgArtifact {
    const TAG: ArtifactTag = ArtifactTag::DkgArtifact;
    type Id = DkgMessageId;
    type Message = DkgMessage;
    type SerializeAs = DkgMessage;
    type Attribute = DkgMessageAttribute;
    type Filter = ();

    /// The function converts a `DkgMessage` into an advert for a
    /// `DkgArtifact`.
    fn message_to_advert(msg: &DkgMessage) -> Advert<DkgArtifact> {
        let size = bincode::serialize(msg).unwrap().len();
        let attribute = DkgMessageAttribute {
            interval_start_height: msg.content.dkg_id.start_block_height,
        };
        let hash = ic_crypto_hash::crypto_hash(msg);
        Advert {
            id: hash.clone(),
            attribute,
            size,
            integrity_hash: hash.get(),
        }
    }
}

/// The `ArtifactKind` of ECDSA messages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EcdsaArtifact;

/// `EcdsaArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for EcdsaArtifact {
    const TAG: ArtifactTag = ArtifactTag::EcdsaArtifact;
    type Id = EcdsaMessageId;
    type Message = EcdsaMessage;
    type SerializeAs = EcdsaMessage;
    type Attribute = EcdsaMessageAttribute;
    type Filter = ();

    /// The function converts a `EcdsaMessage` into an advert for a
    /// `EcdsaArtifact`.
    fn message_to_advert(msg: &EcdsaMessage) -> Advert<EcdsaArtifact> {
        // TODO: use serialize_len() in all the clients
        let size = bincode::serialize(msg).unwrap().len();
        Advert {
            id: ecdsa_msg_hash(msg),
            attribute: EcdsaMessageAttribute::from(msg),
            size,
            integrity_hash: ic_crypto_hash::crypto_hash(msg).get(),
        }
    }
}

pub struct CanisterHttpArtifact;

/// `CanisterHttpArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CanisterHttpArtifact {
    const TAG: ArtifactTag = ArtifactTag::CanisterHttpArtifact;
    type Id = CanisterHttpResponseId;
    type Message = CanisterHttpResponseShare;
    type SerializeAs = CanisterHttpResponseShare;
    type Attribute = ();
    type Filter = ();

    /// This function converts a `CanisterHttpResponseShare` into an advert for a
    /// `CanisterHttpArtifact`.
    fn message_to_advert(msg: &CanisterHttpResponseShare) -> Advert<CanisterHttpArtifact> {
        // TODO: use serialize_len() in all the clients
        let size = bincode::serialize(msg).unwrap().len();
        let hash = ic_crypto_hash::crypto_hash(msg);
        Advert {
            id: hash.clone(),
            attribute: (),
            size,
            integrity_hash: hash.get(),
        }
    }
}
