//! The module contains implementations for different artifact kinds.
use std::convert::Infallible;

use crate::{
    artifact::*,
    canister_http::CanisterHttpResponseShare,
    consensus::{
        certification::CertificationMessage,
        dkg::DkgMessageId,
        dkg::Message as DkgMessage,
        idkg::{EcdsaMessage, EcdsaMessageAttribute},
        ConsensusMessage,
    },
    crypto::crypto_hash,
    messages::SignedIngress,
    CountBytes,
};
use ic_protobuf::proxy::ProxyDecodeError;
use prost::bytes::Bytes;
use serde::{Deserialize, Serialize};

/// The `ArtifactKind` of *Consensus* messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusArtifact;

/// `ConsensusArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for ConsensusArtifact {
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    type PbId = ic_protobuf::types::v1::ConsensusMessageId;
    type PbIdError = ProxyDecodeError;
    type Id = ConsensusMessageId;
    type PbMessage = ic_protobuf::types::v1::ConsensusMessage;
    type Message = ConsensusMessage;
    type PbMessageError = ProxyDecodeError;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
    type Attribute = ();
    type PbFilter = ic_protobuf::types::v1::ConsensusMessageFilter;
    type PbFilterError = ProxyDecodeError;
    type Filter = ConsensusMessageFilter;

    /// The function converts a `ConsensusMessage` into an advert for a
    /// `ConsensusArtifact`.
    fn message_to_advert(msg: &ConsensusMessage) -> Advert<ConsensusArtifact> {
        Advert {
            id: ConsensusMessageId::from(msg),
            attribute: (),
            size: bincode::serialized_size(&msg).unwrap() as usize,
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
    type PbId = ic_protobuf::types::v1::IngressMessageId;
    type PbIdError = ProxyDecodeError;
    type Id = IngressMessageId;
    type PbMessage = Bytes;
    type PbMessageError = ProxyDecodeError;
    type Message = SignedIngress;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
    type Attribute = ();
    type PbFilter = ();
    type PbFilterError = Infallible;
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
    type PbId = ic_protobuf::types::v1::CertificationMessageId;
    type PbIdError = ProxyDecodeError;
    type Id = CertificationMessageId;
    type PbMessage = ic_protobuf::types::v1::CertificationMessage;
    type PbMessageError = ProxyDecodeError;
    type Message = CertificationMessage;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
    type Attribute = ();
    type PbFilter = ic_protobuf::types::v1::CertificationMessageFilter;
    type PbFilterError = ProxyDecodeError;
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
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkgArtifact;

/// `DkgArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for DkgArtifact {
    const TAG: ArtifactTag = ArtifactTag::DkgArtifact;
    type PbId = ic_protobuf::types::v1::DkgMessageId;
    type PbIdError = ProxyDecodeError;
    type Id = DkgMessageId;
    type PbMessage = ic_protobuf::types::v1::DkgMessage;
    type PbMessageError = ProxyDecodeError;
    type Message = DkgMessage;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
    type Attribute = ();
    type PbFilter = ();
    type PbFilterError = Infallible;
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
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct EcdsaArtifact;

/// `EcdsaArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for EcdsaArtifact {
    const TAG: ArtifactTag = ArtifactTag::EcdsaArtifact;
    type PbId = ic_protobuf::types::v1::EcdsaArtifactId;
    type PbIdError = ProxyDecodeError;
    type Id = EcdsaMessageId;
    type PbMessage = ic_protobuf::types::v1::EcdsaMessage;
    type PbMessageError = ProxyDecodeError;
    type Message = EcdsaMessage;
    type PbAttribute = ic_protobuf::types::v1::EcdsaMessageAttribute;
    type PbAttributeError = ProxyDecodeError;
    type Attribute = EcdsaMessageAttribute;
    type PbFilter = ();
    type PbFilterError = Infallible;
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
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanisterHttpArtifact;

/// `CanisterHttpArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for CanisterHttpArtifact {
    const TAG: ArtifactTag = ArtifactTag::CanisterHttpArtifact;
    type PbId = ic_protobuf::types::v1::CanisterHttpShare;
    type PbIdError = ProxyDecodeError;
    type Id = CanisterHttpResponseId;
    type PbMessage = ic_protobuf::types::v1::CanisterHttpShare;
    type PbMessageError = ProxyDecodeError;
    type Message = CanisterHttpResponseShare;
    type PbAttribute = ();
    type PbAttributeError = Infallible;
    type Attribute = ();
    type PbFilterError = Infallible;
    type PbFilter = ();
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
