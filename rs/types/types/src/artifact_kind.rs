//! The module contains implementations for different artifact kinds.
use crate::{
    artifact::*,
    canister_http::{CanisterHttpResponseAttribute, CanisterHttpResponseShare},
    consensus::{
        certification::CertificationMessageHash,
        ecdsa::{ecdsa_msg_id, EcdsaMessageAttribute},
        ConsensusMessageHashable,
    },
    crypto::crypto_hash,
    CountBytes,
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
    type Attribute = ConsensusMessageAttribute;
    type Filter = ConsensusMessageFilter;

    /// The function converts a `ConsensusMessage` into an advert for a
    /// `ConsensusArtifact`.
    fn message_to_advert(msg: &ConsensusMessage) -> Advert<ConsensusArtifact> {
        let size = bincode::serialized_size(&msg).unwrap() as usize;
        let attribute = ConsensusMessageAttribute::from(msg);
        Advert {
            id: msg.get_id(),
            attribute,
            size,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of ingress message.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct IngressArtifact;

/// `IngressArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for IngressArtifact {
    const TAG: ArtifactTag = ArtifactTag::IngressArtifact;
    type Id = IngressMessageId;
    type Message = SignedIngress;
    type Attribute = ();
    type Filter = ();

    /// The function converts a `SignedIngress` into an advert for an
    /// `IngressArtifact`.
    fn message_to_advert(msg: &SignedIngress) -> Advert<IngressArtifact> {
        Advert {
            id: IngressMessageId::from(msg),
            attribute: (),
            size: msg.count_bytes(),
            integrity_hash: crypto_hash(msg.binary()).get(),
        }
    }
}

/// The `ArtifactKind` of certification messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificationArtifact;

/// `CertificationArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CertificationArtifact {
    const TAG: ArtifactTag = ArtifactTag::CertificationArtifact;
    type Id = CertificationMessageId;
    type Message = CertificationMessage;
    type Attribute = ();
    type Filter = CertificationMessageFilter;

    /// The function converts a `CertificationMessage` into an advert for a
    /// `CertificationArtifact`.
    fn message_to_advert(msg: &CertificationMessage) -> Advert<CertificationArtifact> {
        use CertificationMessage::*;
        let id = match msg {
            Certification(cert) => CertificationMessageId {
                height: cert.height,
                hash: CertificationMessageHash::Certification(crypto_hash(cert)),
            },
            CertificationShare(share) => CertificationMessageId {
                height: share.height,
                hash: CertificationMessageHash::CertificationShare(crypto_hash(share)),
            },
        };
        Advert {
            id,
            attribute: (),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of DKG messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkgArtifact;

/// `DkgArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for DkgArtifact {
    const TAG: ArtifactTag = ArtifactTag::DkgArtifact;
    type Id = DkgMessageId;
    type Message = DkgMessage;
    type Attribute = DkgMessageAttribute;
    type Filter = ();

    /// The function converts a `DkgMessage` into an advert for a
    /// `DkgArtifact`.
    fn message_to_advert(msg: &DkgMessage) -> Advert<DkgArtifact> {
        let size = bincode::serialized_size(&msg).unwrap() as usize;
        let attribute = DkgMessageAttribute {
            interval_start_height: msg.content.dkg_id.start_block_height,
        };
        let hash = crypto_hash(msg);
        Advert {
            id: hash.clone(),
            attribute,
            size,
            integrity_hash: hash.get(),
        }
    }
}

/// The `ArtifactKind` of ECDSA messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct EcdsaArtifact;

/// `EcdsaArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for EcdsaArtifact {
    const TAG: ArtifactTag = ArtifactTag::EcdsaArtifact;
    type Id = EcdsaMessageId;
    type Message = EcdsaMessage;
    type Attribute = EcdsaMessageAttribute;
    type Filter = ();

    /// The function converts a `EcdsaMessage` into an advert for a
    /// `EcdsaArtifact`.
    fn message_to_advert(msg: &EcdsaMessage) -> Advert<EcdsaArtifact> {
        let size = bincode::serialized_size(&msg).unwrap() as usize;
        Advert {
            id: ecdsa_msg_id(msg),
            attribute: EcdsaMessageAttribute::from(msg),
            size,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of CanisterHttp messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanisterHttpArtifact;

/// `CanisterHttpArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CanisterHttpArtifact {
    const TAG: ArtifactTag = ArtifactTag::CanisterHttpArtifact;
    type Id = CanisterHttpResponseId;
    type Message = CanisterHttpResponseShare;
    type Attribute = CanisterHttpResponseAttribute;
    type Filter = ();

    /// This function converts a `CanisterHttpResponseShare` into an advert for a
    /// `CanisterHttpArtifact`.
    fn message_to_advert(msg: &CanisterHttpResponseShare) -> Advert<CanisterHttpArtifact> {
        let size = bincode::serialized_size(&msg).unwrap() as usize;
        let hash = crypto_hash(msg);
        Advert {
            id: hash.clone(),
            attribute: CanisterHttpResponseAttribute::Share(
                msg.content.registry_version,
                msg.content.id,
                msg.content.content_hash.clone(),
            ),
            size,
            integrity_hash: hash.get(),
        }
    }
}
