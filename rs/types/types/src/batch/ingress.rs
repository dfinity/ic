use crate::{
    Time,
    artifact::IngressMessageId,
    messages::{
        EXPECTED_MESSAGE_ID_LENGTH, HttpRequestError, MessageId, SignedIngress, SignedRequestBytes,
    },
};
use ic_base_types::NumBytes;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom, fmt::Display};

/// Payload that contains Ingress messages
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IngressPayload {
    /// Keep ingress messages in a serialized form, so individual
    /// deserialization is delayed. This allows faster deserialization of
    /// IngressPayload when individual message is not needed (e.g. in
    /// ingress payload deduplication).
    serialized_ingress_messages: BTreeMap<IngressMessageId, SignedRequestBytes>,
}

impl From<&IngressPayload> for pb::IngressPayload {
    fn from(ingress_payload: &IngressPayload) -> Self {
        let ingress_messages = ingress_payload
            .serialized_ingress_messages
            .iter()
            .map(
                |(ingress_message_id, serialized_ingress_message)| pb::IngressMessage {
                    expiry: ingress_message_id.expiry().as_nanos_since_unix_epoch(),
                    message_id: ingress_message_id.message_id.as_bytes().to_vec(),
                    signed_request_bytes: serialized_ingress_message.as_ref().to_vec(),
                },
            )
            .collect();

        pb::IngressPayload { ingress_messages }
    }
}

impl From<IngressPayload> for pb::IngressPayload {
    fn from(ingress_payload: IngressPayload) -> Self {
        let ingress_messages = ingress_payload
            .serialized_ingress_messages
            .into_iter()
            .map(
                |(ingress_message_id, serialized_ingress_message)| pb::IngressMessage {
                    expiry: ingress_message_id.expiry().as_nanos_since_unix_epoch(),
                    message_id: ingress_message_id.message_id.as_bytes().to_vec(),
                    signed_request_bytes: serialized_ingress_message.into(),
                },
            )
            .collect();

        pb::IngressPayload { ingress_messages }
    }
}

impl TryFrom<pb::IngressPayload> for IngressPayload {
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::IngressPayload) -> Result<Self, Self::Error> {
        let mut serialized_ingress_messages = BTreeMap::new();

        for ingress_message_proto in payload.ingress_messages {
            let ingress_message_id = IngressMessageId::new(
                Time::from_nanos_since_unix_epoch(ingress_message_proto.expiry),
                MessageId::try_from(ingress_message_proto.message_id.as_slice())?,
            );

            serialized_ingress_messages.insert(
                ingress_message_id,
                SignedRequestBytes::from(ingress_message_proto.signed_request_bytes),
            );
        }

        Ok(Self {
            serialized_ingress_messages,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IngressPayloadError(HttpRequestError);

impl Display for IngressPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl IngressPayload {
    /// Return the number of ingress messages contained in this payload
    pub fn message_count(&self) -> usize {
        self.serialized_ingress_messages.len()
    }

    /// Return all [`IngressMessageId`]s in the payload.
    pub fn message_ids(&self) -> impl Iterator<Item = &IngressMessageId> {
        self.serialized_ingress_messages.keys()
    }

    /// Return true if the payload is empty.
    pub fn is_empty(&self) -> bool {
        let IngressPayload {
            serialized_ingress_messages,
        } = &self;
        serialized_ingress_messages.is_empty()
    }

    /// Return the [`SignedRequestBytes`] referenced by the [`IngressMessageId`].
    pub fn get_serialized_by_id(
        &self,
        ingress_message_id: &IngressMessageId,
    ) -> Option<&SignedRequestBytes> {
        self.serialized_ingress_messages.get(ingress_message_id)
    }

    /// Iterates over the ingress messages in their deserialized form.
    pub fn iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &IngressMessageId,
            Result<SignedIngress, IngressPayloadError>,
        ),
    > {
        self.serialized_ingress_messages.iter().map(|(id, bytes)| {
            (
                id,
                SignedIngress::try_from(bytes.clone()).map_err(IngressPayloadError),
            )
        })
    }

    pub fn iter_serialized(
        &self,
    ) -> impl Iterator<Item = (&IngressMessageId, &SignedRequestBytes)> {
        self.serialized_ingress_messages.iter()
    }

    pub fn total_messages_size_estimate(&self) -> NumBytes {
        let messages_total_size: usize = self
            .serialized_ingress_messages
            .values()
            .map(SignedRequestBytes::len)
            .sum();

        NumBytes::new(messages_total_size as u64)
    }

    pub fn total_ids_size_estimate(&self) -> NumBytes {
        let ids_total_size = self.serialized_ingress_messages.len() * EXPECTED_MESSAGE_ID_LENGTH;

        NumBytes::new(ids_total_size as u64)
    }
}

impl<'a> FromIterator<&'a SignedIngress> for IngressPayload {
    fn from_iter<I: IntoIterator<Item = &'a SignedIngress>>(msgs: I) -> Self {
        let serialized_ingress_messages = msgs
            .into_iter()
            .map(|ingress| (IngressMessageId::from(ingress), ingress.binary().clone()))
            .collect();

        Self {
            serialized_ingress_messages,
        }
    }
}

impl From<Vec<SignedIngress>> for IngressPayload {
    fn from(msgs: Vec<SignedIngress>) -> IngressPayload {
        IngressPayload::from_iter(&msgs)
    }
}

impl From<Vec<(IngressMessageId, SignedIngress)>> for IngressPayload {
    fn from(msgs: Vec<(IngressMessageId, SignedIngress)>) -> IngressPayload {
        let serialized_ingress_messages = msgs
            .into_iter()
            .map(|(id, ingress)| (id, SignedRequestBytes::from(ingress)))
            .collect();

        Self {
            serialized_ingress_messages,
        }
    }
}

impl TryFrom<IngressPayload> for Vec<SignedIngress> {
    type Error = IngressPayloadError;
    fn try_from(payload: IngressPayload) -> Result<Vec<SignedIngress>, Self::Error> {
        payload
            .serialized_ingress_messages
            .into_values()
            .map(SignedIngress::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(IngressPayloadError)
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
        let mut signed_ingresses: Vec<SignedIngress> = update_messages
            .into_iter()
            .map(|msg| SignedIngress::try_from(msg).unwrap())
            .collect();

        let ingress_payload = IngressPayload::from(signed_ingresses.clone());
        let signed_ingresses1 = Vec::<SignedIngress>::try_from(ingress_payload).unwrap();
        // ingress messages are sorted by id in the ingress payload, hence the sort below
        signed_ingresses.sort_by(|msg_1, msg_2| {
            IngressMessageId::from(msg_1)
                .partial_cmp(&IngressMessageId::from(msg_2))
                .unwrap()
        });
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

            let ingress = SignedIngress::try_from(message).unwrap();
            let id = IngressMessageId::from(&ingress);

            (ingress, id)
        };

        // Some test messages.
        let (m1, id1) = fake_ingress_message("m1");
        let (m2, id2) = fake_ingress_message("m2");
        let (m3, id3) = fake_ingress_message("m3");
        let (_m4, id4) = fake_ingress_message("m4");

        let msgs = vec![m1.clone(), m2.clone(), m3.clone()];
        let payload = IngressPayload::from(msgs.clone());
        // Serialization/deserialization works.
        let bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );
        // Individual lookup works.
        assert_eq!(payload.get_serialized_by_id(&id1), Some(m1.binary()));
        assert_eq!(payload.get_serialized_by_id(&id2), Some(m2.binary()));
        assert_eq!(payload.get_serialized_by_id(&id3), Some(m3.binary()));
        assert_eq!(payload.get_serialized_by_id(&id4), None);
        // Converting back to messages should match original
        assert_eq!(msgs, <Vec<SignedIngress>>::try_from(payload).unwrap());
    }
}
