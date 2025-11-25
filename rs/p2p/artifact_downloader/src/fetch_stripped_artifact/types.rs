use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use ic_types::consensus::idkg::IDkgArtifactId;
use ic_types::crypto::CryptoHash;
use ic_types::crypto::canister_threshold_sig::idkg::SignedIDkgDealing;
use ic_types::messages::SignedIngress;
use ic_types::{CountBytes, NodeIndex};
use ic_types::{artifact::IngressMessageId, crypto::CryptoHashOf, messages::SignedRequestBytes};

pub(super) mod rpc;
pub(super) mod stripped;

type IngressBytesHash = CryptoHashOf<SignedRequestBytes>;

/// A unique identifier of a [`SignedIngress`].
/// Note that the hash of [`SignedIngress::binary`] should be enough to uniquely identify a
/// [`SignedIngress`] because all the fields of [`SignedIngress`] are derived from it.
/// Note also that [`IngressMessageId`] is not strictly required here to uniquely identify
/// [`SignedIngress`] but we keep it here because of [`IngressPool`] API.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SignedIngressId {
    pub(crate) ingress_message_id: IngressMessageId,
    pub(crate) ingress_bytes_hash: IngressBytesHash,
}

impl SignedIngressId {
    pub(crate) fn new(ingress_message_id: IngressMessageId, bytes: &SignedRequestBytes) -> Self {
        Self {
            ingress_message_id,
            ingress_bytes_hash: ic_types::crypto::crypto_hash(bytes),
        }
    }
}

impl From<&SignedIngress> for SignedIngressId {
    fn from(value: &SignedIngress) -> Self {
        Self::new(IngressMessageId::from(value), value.binary())
    }
}

impl TryFrom<pb::StrippedIngressMessage> for SignedIngressId {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedIngressMessage) -> Result<Self, Self::Error> {
        let ingress_message_id =
            try_from_option_field(value.stripped, "StrippedIngressMessage::stripped")?;
        let ingress_bytes_hash = CryptoHashOf::from(CryptoHash(value.ingress_bytes_hash));

        Ok(SignedIngressId {
            ingress_message_id,
            ingress_bytes_hash,
        })
    }
}

/// Unique identifiers for messages that may be stripped from block proposals.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum StrippedMessageId {
    Ingress(SignedIngressId),
    IDkgDealing(IDkgArtifactId, NodeIndex),
}

/// Messages that may be stripped from block proposals.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum StrippedMessage {
    Ingress(SignedIngressId, SignedIngress),
    IDkgDealing(IDkgArtifactId, NodeIndex, SignedIDkgDealing),
}

impl From<&StrippedMessage> for StrippedMessageId {
    fn from(message: &StrippedMessage) -> Self {
        match message {
            StrippedMessage::Ingress(id, _) => StrippedMessageId::Ingress(id.clone()),
            StrippedMessage::IDkgDealing(id, node_index, _) => {
                StrippedMessageId::IDkgDealing(id.clone(), *node_index)
            }
        }
    }
}

#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum StrippedMessageType {
    Ingress,
    IDkgDealing,
}

impl StrippedMessageType {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            StrippedMessageType::Ingress => "ingress",
            StrippedMessageType::IDkgDealing => "idkg_dealing",
        }
    }
}

impl From<&StrippedMessageId> for StrippedMessageType {
    fn from(id: &StrippedMessageId) -> Self {
        match id {
            StrippedMessageId::Ingress(_) => StrippedMessageType::Ingress,
            StrippedMessageId::IDkgDealing(_, _) => StrippedMessageType::IDkgDealing,
        }
    }
}

impl From<&StrippedMessage> for StrippedMessageType {
    fn from(id: &StrippedMessage) -> Self {
        match id {
            StrippedMessage::Ingress(_, _) => StrippedMessageType::Ingress,
            StrippedMessage::IDkgDealing(_, _, _) => StrippedMessageType::IDkgDealing,
        }
    }
}

impl CountBytes for StrippedMessage {
    fn count_bytes(&self) -> usize {
        match self {
            StrippedMessage::Ingress(_, ingress) => ingress.count_bytes(),
            StrippedMessage::IDkgDealing(_, _, dealing) => {
                dealing.content.internal_dealing_raw.len()
                    + dealing.signature.signature.get_ref().0.len()
                    + dealing.signature.signer.get_ref().0.as_ref().len()
            }
        }
    }
}
