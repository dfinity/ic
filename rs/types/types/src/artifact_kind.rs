//! The module contains implementations for different artifact kinds.
use std::convert::Infallible;

use crate::{
    artifact::*,
    canister_http::CanisterHttpResponseShare,
    consensus::{
        certification::CertificationMessage,
        dkg::DkgMessageId,
        dkg::Message as DkgMessage,
        idkg::{IDkgMessage, IDkgMessageAttribute},
        ConsensusMessage,
    },
    messages::SignedIngress,
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

    /// The function converts a `ConsensusMessage` into an advert for a
    /// `ConsensusArtifact`.
    fn message_to_advert(msg: &ConsensusMessage) -> Advert<ConsensusArtifact> {
        Advert {
            id: ConsensusMessageId::from(msg),
            attribute: (),
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

    /// The function converts a `SignedIngress` into an advert for an
    /// `IngressArtifact`.
    fn message_to_advert(msg: &SignedIngress) -> Advert<IngressArtifact> {
        Advert {
            id: IngressMessageId::from(msg),
            attribute: (),
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

    /// The function converts a `CertificationMessage` into an advert for a
    /// `CertificationArtifact`.
    fn message_to_advert(msg: &CertificationMessage) -> Advert<CertificationArtifact> {
        Advert {
            id: CertificationMessageId::from(msg),
            attribute: (),
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

    /// The function converts a `DkgMessage` into an advert for a
    /// `DkgArtifact`.
    fn message_to_advert(msg: &DkgMessage) -> Advert<DkgArtifact> {
        Advert {
            id: DkgMessageId::from(msg),
            attribute: (),
        }
    }
}

/// The `ArtifactKind` of IDKG messages.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct IDkgArtifact;

/// `IDkgArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for IDkgArtifact {
    const TAG: ArtifactTag = ArtifactTag::IDkgArtifact;
    type PbId = ic_protobuf::types::v1::IDkgArtifactId;
    type PbIdError = ProxyDecodeError;
    type Id = IDkgMessageId;
    type PbMessage = ic_protobuf::types::v1::IDkgMessage;
    type PbMessageError = ProxyDecodeError;
    type Message = IDkgMessage;
    type PbAttribute = ic_protobuf::types::v1::IDkgMessageAttribute;
    type PbAttributeError = ProxyDecodeError;
    type Attribute = IDkgMessageAttribute;

    /// The function converts a `IDkgMessage` into an advert for a
    /// `IDkgArtifact`.
    fn message_to_advert(msg: &IDkgMessage) -> Advert<IDkgArtifact> {
        Advert {
            id: IDkgMessageId::from(msg),
            attribute: IDkgMessageAttribute::from(msg),
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

    /// This function converts a `CanisterHttpResponseShare` into an advert for a
    /// `CanisterHttpArtifact`.
    fn message_to_advert(msg: &CanisterHttpResponseShare) -> Advert<CanisterHttpArtifact> {
        Advert {
            id: msg.clone(),
            attribute: (),
        }
    }
}
