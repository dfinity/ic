use crate::{
    artifact::IngressMessageId,
    messages::{SignedIngress, SignedRequestBytes},
    CountBytes,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Payload that contains Ingress messages
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IngressPayload {
    ingress_messages: Vec<SignedIngress>,
}

fn proto_to_ingress(proto: pb::IngressMessage) -> Result<SignedIngress, ProxyDecodeError> {
    SignedIngress::try_from(SignedRequestBytes::from(proto.content))
        .map_err(|err| ProxyDecodeError::Other(err.to_string()))
}

fn ingress_to_proto(ingress: SignedIngress) -> pb::IngressMessage {
    pb::IngressMessage {
        content: ingress.binary().as_ref().to_vec(),
    }
}

impl From<&IngressPayload> for pb::IngressPayload {
    fn from(ingress_payload: &IngressPayload) -> Self {
        Self {
            ingress_messages: ingress_payload
                .ingress_messages
                .iter()
                .cloned()
                .map(ingress_to_proto)
                .collect(),
        }
    }
}

impl TryFrom<pb::IngressPayload> for IngressPayload {
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::IngressPayload) -> Result<Self, Self::Error> {
        let ingress_messages = payload
            .ingress_messages
            .into_iter()
            .map(proto_to_ingress)
            .collect::<Result<_, _>>()?;

        Ok(Self { ingress_messages })
    }
}

/// Index of an ingress message in the IngressPayload.
type IngressIndex = usize;

/// Position of serialized ingress message in the payload buffer.
type BufferPosition = u64;

#[derive(Debug, Eq, PartialEq)]
/// Possible errors when accessing messages in an [`IngressPayload`].
pub enum IngressPayloadError {
    IndexOutOfBound(IngressIndex),
    IngressPositionOutOfBound(IngressIndex, BufferPosition),
    DeserializationFailure(String),
    MismatchedMessageIdAtIndex(IngressIndex),
}

impl IngressPayload {
    /// Return the number of ingress messages contained in this payload
    pub fn message_count(&self) -> usize {
        self.ingress_messages.len()
    }

    /// Return all MessageIds in the payload.
    pub fn message_ids(&self) -> Vec<IngressMessageId> {
        self.ingress_messages
            .iter()
            .map(IngressMessageId::from)
            .collect()
    }

    /// Return true if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.ingress_messages.is_empty()
    }
}

impl CountBytes for IngressPayload {
    fn count_bytes(&self) -> usize {
        self.ingress_messages
            .iter()
            .map(CountBytes::count_bytes)
            .sum()
    }
}

impl From<Vec<SignedIngress>> for IngressPayload {
    fn from(msgs: Vec<SignedIngress>) -> IngressPayload {
        Self {
            ingress_messages: msgs,
        }
    }
}

impl From<IngressPayload> for Vec<SignedIngress> {
    fn from(payload: IngressPayload) -> Vec<SignedIngress> {
        payload.ingress_messages
    }
}

impl AsRef<[SignedIngress]> for IngressPayload {
    fn as_ref(&self) -> &[SignedIngress] {
        &self.ingress_messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        messages::{
            Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope,
            SignedDelegation, SignedIngress,
        },
        time::expiry_time_from_now,
    };

    /// Build a Vec<SignedIngress>.  Convert to IngressPayload and then back to
    /// Vec<SignedIngress>.  Ensure that the two vectors are identical.
    #[test]
    fn into_ingress_payload_and_back() {
        let ingress_expiry = expiry_time_from_now();
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method".to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x05]),
                nonce: Some(Blob(vec![1, 2, 3, 4])),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            },
        };
        let update_messages = vec![
            HttpRequestEnvelope::<HttpCallContent> {
                content: content.clone(),
                sender_pubkey: Some(Blob(vec![2; 32])),
                sender_sig: Some(Blob(vec![1; 32])),
                sender_delegation: None,
            },
            HttpRequestEnvelope::<HttpCallContent> {
                content: content.clone(),
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
            HttpRequestEnvelope::<HttpCallContent> {
                content,
                sender_pubkey: Some(Blob(vec![2; 32])),
                sender_sig: Some(Blob(vec![1; 32])),
                sender_delegation: Some(vec![SignedDelegation::new(
                    Delegation::new(vec![1, 2], ingress_expiry),
                    vec![3, 4],
                )]),
            },
        ];
        let signed_ingresses: Vec<SignedIngress> = update_messages
            .into_iter()
            .map(|msg| SignedIngress::try_from(msg).unwrap())
            .collect();
        let ingress_payload = IngressPayload::from(signed_ingresses.clone());
        let signed_ingresses1 = Vec::<SignedIngress>::try_from(ingress_payload).unwrap();
        assert_eq!(signed_ingresses, signed_ingresses1);
    }
}
