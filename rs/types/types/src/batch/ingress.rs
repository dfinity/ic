use crate::{
    artifact::IngressMessageId,
    messages::{MessageId, SignedIngress, SignedRequestBytes, EXPECTED_MESSAGE_ID_LENGTH},
    CountBytes, Time,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    io::{Cursor, Write},
};

/// Payload that contains Ingress messages
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
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
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::IngressPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            id_and_pos: payload
                .id_and_pos
                .iter()
                .map(|ingress_offset| {
                    Ok((
                        IngressMessageId::new(
                            Time::from_nanos_since_unix_epoch(ingress_offset.expiry),
                            MessageId::try_from(ingress_offset.message_id.as_slice())?,
                        ),
                        ingress_offset.offset,
                    ))
                })
                .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
            buffer: payload.buffer,
        })
    }
}

/// Index of an ingress message in the IngressPayload.
type IngressIndex = usize;

/// Position of serialized ingress message in the payload buffer.
type BufferPosition = u64;

#[derive(Eq, PartialEq, Debug)]
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

    // TODO(kpop): run some benchmarks and see if it makes sense to change the type of
    // `[IngressPayload::id_and_pos]`
    pub fn get_by_id(&self, ingress_message_id: &IngressMessageId) -> Option<SignedIngress> {
        let (index, _) = self
            .id_and_pos
            .iter()
            .enumerate()
            .find(|(_, (id, _))| id == ingress_message_id)?;

        self.get(index)
            .map(|(_, ingress_message)| ingress_message)
            .ok()
    }

    /// Return the ingress message at a given index, which is expected to be
    /// less than `message_count`.
    pub fn get(
        &self,
        index: usize,
    ) -> Result<(IngressMessageId, SignedIngress), IngressPayloadError> {
        self.id_and_pos
            .get(index)
            .ok_or(IngressPayloadError::IndexOutOfBound(index))
            .and_then(|(id, pos)| {
                // Return error if pos is out of bound.
                if *pos > self.buffer.len() as u64 {
                    Err(IngressPayloadError::IngressPositionOutOfBound(index, *pos))
                } else {
                    let end = {
                        if index == self.id_and_pos.len() - 1 {
                            self.buffer.len()
                        } else {
                            self.id_and_pos[index + 1].1 as usize
                        }
                    };
                    let ingress = SignedIngress::try_from(SignedRequestBytes::from(Vec::from(
                        &self.buffer[*pos as usize..end],
                    )))
                    .map_err(|e| IngressPayloadError::DeserializationFailure(e.to_string()))?;
                    let ingress_id = IngressMessageId::from(&ingress);
                    if *id == ingress_id {
                        Ok((ingress_id, ingress))
                    } else {
                        Err(IngressPayloadError::MismatchedMessageIdAtIndex(index))
                    }
                }
            })
    }
}

impl CountBytes for IngressPayload {
    fn count_bytes(&self) -> usize {
        self.buffer.len() + self.id_and_pos.len() * EXPECTED_MESSAGE_ID_LENGTH
    }
}

impl<'a> FromIterator<&'a SignedIngress> for IngressPayload {
    fn from_iter<I: IntoIterator<Item = &'a SignedIngress>>(msgs: I) -> Self {
        let mut buf = Cursor::new(Vec::new());
        let mut id_and_pos = Vec::new();
        for ingress in msgs {
            let id = IngressMessageId::from(ingress);
            let pos = buf.position();
            // This panic will only happen when we run out of memory.
            buf.write_all(ingress.binary().as_ref())
                .unwrap_or_else(|err| panic!("SignedIngress serialization error: {:?}", err));

            id_and_pos.push((id, pos));
        }
        Self {
            id_and_pos,
            buffer: buf.into_inner(),
        }
    }
}

impl From<Vec<SignedIngress>> for IngressPayload {
    fn from(msgs: Vec<SignedIngress>) -> IngressPayload {
        IngressPayload::from_iter(&msgs)
    }
}

impl TryFrom<IngressPayload> for Vec<SignedIngress> {
    type Error = IngressPayloadError;
    fn try_from(payload: IngressPayload) -> Result<Vec<SignedIngress>, Self::Error> {
        payload
            .id_and_pos
            .iter()
            .enumerate()
            .map(|(i, _)| payload.get(i).map(|m| m.1))
            .collect::<Result<_, _>>()
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
    use assert_matches::assert_matches;
    use std::convert::TryFrom;

    fn fake_http_call_content(method_name: &str) -> HttpCallContent {
        HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: method_name.to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x05]),
                nonce: Some(Blob(vec![1, 2, 3, 4])),
                ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
            },
        }
    }

    /// Build a Vec<SignedIngress>.  Convert to IngressPayload and then back to
    /// Vec<SignedIngress>.  Ensure that the two vectors are identical.
    #[test]
    fn into_ingress_payload_and_back() {
        let update_messages = vec![
            HttpRequestEnvelope::<HttpCallContent> {
                content: fake_http_call_content("1"),
                sender_pubkey: Some(Blob(vec![2; 32])),
                sender_sig: Some(Blob(vec![1; 32])),
                sender_delegation: None,
            },
            HttpRequestEnvelope::<HttpCallContent> {
                content: fake_http_call_content("2"),
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
            HttpRequestEnvelope::<HttpCallContent> {
                content: fake_http_call_content("3"),
                sender_pubkey: Some(Blob(vec![2; 32])),
                sender_sig: Some(Blob(vec![1; 32])),
                sender_delegation: Some(vec![SignedDelegation::new(
                    Delegation::new(vec![1, 2], expiry_time_from_now()),
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

    #[test]
    fn test_ingress_payload_deserialization() {
        // serialization/deserialization of empty payload.
        let payload = IngressPayload::default();
        let bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );

        let fake_ingress_message = |method_name| {
            let message = HttpRequestEnvelope::<HttpCallContent> {
                content: fake_http_call_content(method_name),
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            SignedIngress::try_from(message).unwrap()
        };

        // Some test messages.
        let m1 = fake_ingress_message("m1");
        let m1_id = m1.id();
        let m2 = fake_ingress_message("m2");
        let m3 = fake_ingress_message("m3");

        let msgs = vec![m1, m2, m3];
        let payload = IngressPayload::from(msgs.clone());
        // Serialization/deserialization works.
        let mut bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );
        // Individual lookup works.
        assert_matches!(payload.get(0).unwrap(), (_, msg) if msg == msgs[0]);
        assert_matches!(payload.get(1).unwrap(), (_, msg) if msg == msgs[1]);
        assert_matches!(payload.get(2).unwrap(), (_, msg) if msg == msgs[2]);
        // Test IndexOutOfBound.
        assert_matches!(payload.get(3), Err(IngressPayloadError::IndexOutOfBound(3)));
        // Converting back to messages should match original
        assert_eq!(msgs, <Vec<SignedIngress>>::try_from(payload).unwrap());

        // A sub-sequence search function
        fn find(array: &[u8], subseq: &[u8]) -> Option<usize> {
            (0..array.len() - subseq.len() + 1).find(|&i| array[i..i + subseq.len()] == subseq[..])
        }

        // Mutate some byte, deserialization works, but casting back to messages fail.
        let pos = find(&bytes, m1_id.as_bytes()).unwrap();
        // `+= 1` may overflow in debug mode.
        bytes[pos] ^= 1;
        let payload = bincode::deserialize::<IngressPayload>(&bytes);
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        // get(0) should return error.
        assert_matches!(
            payload.get(0),
            Err(IngressPayloadError::MismatchedMessageIdAtIndex(0))
        );
        // Conversion should also fail.
        assert!(<Vec<_>>::try_from(payload).is_err());
    }
}
