use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use ic_types::crypto::CryptoHash;
use ic_types::messages::SignedIngress;
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
