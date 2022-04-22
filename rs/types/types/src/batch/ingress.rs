use crate::{
    artifact::{IngressMessageId, SignedIngress},
    messages::{MessageId, EXPECTED_MESSAGE_ID_LENGTH},
    CountBytes, Time,
};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, io::Cursor};
/// Payload that contains Ingress messages
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IngressPayload {
    /// Pairs of MessageId and its serialized byte position in the buffer.
    id_and_pos: Vec<(IngressMessageId, u64)>,
    /// All messages are serialized in a single byte buffer, so individual
    /// deserialization is delayed. This allows faster deserialization of
    /// IngressPayload when individual message is not needed (e.g. in
    /// ingress payload deduplication).
    #[serde(with = "serde_bytes")]
    buffer: Vec<u8>,
}

impl From<&IngressPayload> for pb::IngressPayload {
    fn from(ingress_payload: &IngressPayload) -> Self {
        Self {
            id_and_pos: ingress_payload
                .id_and_pos
                .iter()
                .map(|(msg_id, offset)| pb::IngressIdOffset {
                    expiry: msg_id.expiry().as_nanos_since_unix_epoch(),
                    message_id: msg_id.message_id.as_bytes().to_vec(),
                    offset: *offset,
                })
                .collect(),
            buffer: ingress_payload.buffer.clone(),
        }
    }
}

impl TryFrom<pb::IngressPayload> for IngressPayload {
    type Error = String;
    fn try_from(payload: pb::IngressPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            id_and_pos: payload
                .id_and_pos
                .iter()
                .map(|ingress_offset| {
                    Ok((
                        IngressMessageId::new(
                            Time::from_nanos_since_unix_epoch(ingress_offset.expiry),
                            MessageId::try_from(ingress_offset.message_id.as_slice())
                                .map_err(|e| format!("{:?}", e))?,
                        ),
                        ingress_offset.offset,
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?,
            buffer: payload.buffer,
        })
    }
}

/// Index of an ingress message in the IngressPayload.
type IngressIndex = usize;

/// Position of serialized ingress message in the payload buffer.
type BufferPosition = u64;

#[derive(Debug)]
/// Possible errors when accessing messages in an [`IngressPayload`].
pub enum IngressPayloadError {
    IndexOutOfBound(IngressIndex),
    IngressPositionOutOfBound(IngressIndex, BufferPosition),
    DeserializationFailure(bincode::Error),
    MismatchedMessageIdAtIndex(IngressIndex),
}

impl IngressPayload {
    /// Return the number of ingress messages contained in this payload
    pub fn message_count(&self) -> usize {
        self.id_and_pos.len()
    }

    /// Return all MessageIds in the payload.
    pub fn message_ids(&self) -> Vec<IngressMessageId> {
        self.id_and_pos
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    }

    /// Return true if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.id_and_pos.is_empty()
    }

    /// Return the ingress message at a given index, which is expected to be
    /// less than `message_count`.
    pub fn get(
        &self,
        index: usize,
    ) -> Result<(IngressMessageId, SignedIngress), IngressPayloadError> {
        let mut buf = Cursor::new(&self.buffer);
        self.id_and_pos
            .get(index)
            .ok_or(IngressPayloadError::IndexOutOfBound(index))
            .and_then(|(id, pos)| {
                // Return error if pos is out of bound.
                if *pos > self.buffer.len() as u64 {
                    Err(IngressPayloadError::IngressPositionOutOfBound(index, *pos))
                } else {
                    buf.set_position(*pos);
                    bincode::deserialize_from::<Cursor<&Vec<u8>>, SignedIngress>(buf)
                        .map_err(IngressPayloadError::DeserializationFailure)
                        .and_then(|ingress| {
                            let ingress_id = IngressMessageId::from(&ingress);
                            if *id == ingress_id {
                                Ok((ingress_id, ingress))
                            } else {
                                Err(IngressPayloadError::MismatchedMessageIdAtIndex(index))
                            }
                        })
                }
            })
    }
}

impl CountBytes for IngressPayload {
    fn count_bytes(&self) -> usize {
        self.buffer.len() + self.id_and_pos.len() * EXPECTED_MESSAGE_ID_LENGTH
    }
}

impl From<Vec<SignedIngress>> for IngressPayload {
    fn from(msgs: Vec<SignedIngress>) -> IngressPayload {
        let mut buf = Cursor::new(Vec::new());
        let mut id_and_pos = Vec::new();
        for ingress in msgs {
            let id = IngressMessageId::from(&ingress);
            id_and_pos.push((id, buf.position()));
            // This panic will only happen when we run out of memory.
            // Also if the given SignIngress comes from external source, it must
            // have been deserialized previously from some byte buffer, so serializing
            // it again should succeed.
            bincode::serialize_into(&mut buf, &ingress)
                .unwrap_or_else(|err| panic!("SignedIngress serialization error: {:?}", err));
        }
        IngressPayload {
            id_and_pos,
            buffer: buf.into_inner(),
        }
    }
}

/// Possible errors when converting from an [`IngressPayload`] to a
/// `Vec<SignedIngress>`.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum InvalidIngressPayload {
    DeserializationError(MessageId, bincode::Error),
    MismatchedMessageId(MessageId, SignedIngress),
}

impl TryFrom<IngressPayload> for Vec<SignedIngress> {
    type Error = InvalidIngressPayload;

    fn try_from(payload: IngressPayload) -> Result<Vec<SignedIngress>, Self::Error> {
        let mut buf = Cursor::new(payload.buffer);
        let mut msgs = Vec::new();
        for (id, _) in payload.id_and_pos.iter() {
            let ingress: SignedIngress = bincode::deserialize_from(&mut buf)
                .map_err(|err| InvalidIngressPayload::DeserializationError(id.into(), err))?;
            if id != &IngressMessageId::from(&ingress) {
                return Err(InvalidIngressPayload::MismatchedMessageId(
                    id.into(),
                    ingress,
                ));
            } else {
                msgs.push(ingress);
            }
        }
        Ok(msgs)
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
        time::current_time_and_expiry_time,
    };

    /// Build a Vec<SignedIngress>.  Convert to IngressPayload and then back to
    /// Vec<SignedIngress>.  Ensure that the two vectors are identical.
    #[test]
    fn into_ingress_payload_and_back() {
        let ingress_expiry = current_time_and_expiry_time().1;
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
