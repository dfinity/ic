//! The module contains implementations for different artifact kinds.
use crate::{
    artifact::*,
    canister_http::CanisterHttpResponseShare,
    consensus::{
        certification::CertificationMessage,
        dkg::DkgMessageId,
        dkg::Message as DkgMessage,
        ecdsa::{EcdsaMessage, EcdsaMessageAttribute},
        ConsensusMessage, ConsensusMessageAttribute,
    },
    crypto::crypto_hash,
    messages::SignedIngress,
    CountBytes,
};

/// The `ArtifactKind` of *Consensus* messages.
#[derive(Clone, Copy, Eq, PartialEq)]
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
        Advert {
            id: ConsensusMessageId::from(msg),
            attribute: ConsensusMessageAttribute::from(msg),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
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
#[derive(Clone, Copy, Eq, PartialEq)]
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
        Advert {
            id: CertificationMessageId::from(msg),
            attribute: (),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
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
    type Attribute = ();
    type Filter = ();

    /// The function converts a `DkgMessage` into an advert for a
    /// `DkgArtifact`.
    fn message_to_advert(msg: &DkgMessage) -> Advert<DkgArtifact> {
        Advert {
            id: DkgMessageId::from(msg),
            attribute: (),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
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
    type Attribute = EcdsaMessageAttribute;
    type Filter = ();

    /// The function converts a `EcdsaMessage` into an advert for a
    /// `EcdsaArtifact`.
    fn message_to_advert(msg: &EcdsaMessage) -> Advert<EcdsaArtifact> {
        Advert {
            id: EcdsaMessageId::from(msg),
            attribute: EcdsaMessageAttribute::from(msg),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of CanisterHttp messages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanisterHttpArtifact;

/// `CanisterHttpArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CanisterHttpArtifact {
    const TAG: ArtifactTag = ArtifactTag::CanisterHttpArtifact;
    type Id = CanisterHttpResponseId;
    type Message = CanisterHttpResponseShare;
    type Attribute = ();
    type Filter = ();

    /// This function converts a `CanisterHttpResponseShare` into an advert for a
    /// `CanisterHttpArtifact`.
    fn message_to_advert(msg: &CanisterHttpResponseShare) -> Advert<CanisterHttpArtifact> {
        Advert {
            id: msg.clone(),
            attribute: (),
            size: bincode::serialized_size(&msg).unwrap() as usize,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}
