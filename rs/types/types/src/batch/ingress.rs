use crate::{
    artifact::IngressMessageId,
    messages::{MessageId, SignedIngress, SignedRequestBytes, EXPECTED_MESSAGE_ID_LENGTH},
    CountBytes, Time,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct SerializedIngressMessage {
    ingress_message_id: IngressMessageId,
    #[serde(with = "serde_bytes")]
    buffer: Vec<u8>,
}

/// Payload that contains Ingress messages
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IngressPayload {
    ingress_messages: Vec<SerializedIngressMessage>,
}

impl From<SerializedIngressMessage> for pb::IngressMessage {
    fn from(message: SerializedIngressMessage) -> Self {
        Self {
            expiry: message
                .ingress_message_id
                .expiry()
                .as_nanos_since_unix_epoch(),
            message_id: message.ingress_message_id.message_id.as_bytes().to_vec(),
            ingress_message: message.buffer,
        }
    }
}

impl TryFrom<pb::IngressMessage> for SerializedIngressMessage {
    type Error = ProxyDecodeError;

    fn try_from(message: pb::IngressMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            ingress_message_id: IngressMessageId::new(
                Time::from_nanos_since_unix_epoch(message.expiry),
                MessageId::try_from(message.message_id.as_slice())?,
            ),
            buffer: message.ingress_message,
        })
    }
}

impl From<SignedIngress> for SerializedIngressMessage {
    fn from(ingress: SignedIngress) -> Self {
        Self {
            ingress_message_id: IngressMessageId::from(&ingress),
            buffer: ingress.binary().as_ref().to_vec(),
        }
    }
}

impl TryFrom<SerializedIngressMessage> for SignedIngress {
    type Error = IngressPayloadError;

    fn try_from(ingress_message: SerializedIngressMessage) -> Result<Self, Self::Error> {
        let ingress = SignedIngress::try_from(SignedRequestBytes::from(ingress_message.buffer))
            .map_err(|e| IngressPayloadError::DeserializationFailure(e.to_string()))?;
        let ingress_id = IngressMessageId::from(&ingress);
        if ingress_message.ingress_message_id == ingress_id {
            Ok(ingress)
        } else {
            // FIXME:
            Err(IngressPayloadError::MismatchedMessageIdAtIndex(0))
        }
    }
}

impl From<IngressPayload> for pb::IngressPayload {
    fn from(ingress_payload: IngressPayload) -> Self {
        Self {
            ingress_messages: ingress_payload
                .ingress_messages
                .into_iter()
                .map(pb::IngressMessage::from)
                .collect(),
        }
    }
}

impl TryFrom<pb::IngressPayload> for IngressPayload {
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::IngressPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            ingress_messages: payload
                .ingress_messages
                .into_iter()
                .map(SerializedIngressMessage::try_from)
                .collect::<Result<_, _>>()?,
        })
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
            .map(|ingress_message| ingress_message.ingress_message_id.clone())
            .collect::<Vec<_>>()
    }

    /// Return true if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.ingress_messages.is_empty()
    }

    /// Return the ingress message at a given index, which is expected to be
    /// less than `message_count`.
    pub fn get(
        &self,
        index: usize,
    ) -> Result<(IngressMessageId, SignedIngress), IngressPayloadError> {
        self.ingress_messages
            .get(index)
            .ok_or(IngressPayloadError::IndexOutOfBound(index))
            .and_then(|ingress_message| {
                let ingress = SignedIngress::try_from(SignedRequestBytes::from(
                    ingress_message.buffer.clone(),
                ))
                .map_err(|e| IngressPayloadError::DeserializationFailure(e.to_string()))?;
                let ingress_id = IngressMessageId::from(&ingress);
                if ingress_message.ingress_message_id == ingress_id {
                    Ok((ingress_id, ingress))
                } else {
                    Err(IngressPayloadError::MismatchedMessageIdAtIndex(index))
                }
            })
    }
}

impl CountBytes for IngressPayload {
    fn count_bytes(&self) -> usize {
        self.ingress_messages
            .iter()
            .map(|message| message.buffer.len() + EXPECTED_MESSAGE_ID_LENGTH)
            .sum()
    }
}

impl From<Vec<SignedIngress>> for IngressPayload {
    fn from(msgs: Vec<SignedIngress>) -> IngressPayload {
        Self {
            ingress_messages: msgs
                .into_iter()
                .map(SerializedIngressMessage::from)
                .collect(),
        }
    }
}

impl TryFrom<IngressPayload> for Vec<SignedIngress> {
    type Error = IngressPayloadError;
    fn try_from(payload: IngressPayload) -> Result<Vec<SignedIngress>, Self::Error> {
        payload
            .ingress_messages
            .into_iter()
            .map(SignedIngress::try_from)
            .collect()
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
