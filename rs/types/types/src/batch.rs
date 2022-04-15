//! Contains Batch, Payload, and specific Payload types that are passed between
//! Consensus and Message Routing.
use super::{
    artifact::IngressMessageId,
    messages::{MessageId, Response, SignedIngress, EXPECTED_MESSAGE_ID_LENGTH},
    xnet::CertifiedStreamSlice,
    CountBytes, Height, Randomness, RegistryVersion, SubnetId, Time,
};
use crate::{
    canister_http::{
        CanisterHttpHeader, CanisterHttpPayload as CanisterHttpResponsePayload, CanisterHttpReject,
        CanisterHttpRequestId, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseMetadata, CanisterHttpResponseWithConsensus,
    },
    crypto::{
        canister_threshold_sig::MasterEcdsaPublicKey, CombinedMultiSig, CombinedMultiSigOf,
        CryptoHash, CryptoHashOf, Signed,
    },
    signature::MultiSignature,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_btc_types_internal::BitcoinAdapterResponse;
use ic_error_types::RejectCode;
use ic_protobuf::{
    canister_http::v1 as canister_http_pb, messaging::xnet::v1 as messaging_pb, types::v1 as pb,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    io::Cursor,
};

/// The `Batch` provided to Message Routing for deterministic processing.
#[derive(Clone, Debug, PartialEq)]
pub struct Batch {
    /// The sequence number attached to the batch.
    pub batch_number: Height,
    /// Whether the state obtained by executing this batch needs to be fully
    /// hashed to be eligible for StateSync.
    pub requires_full_state_hash: bool,
    /// The payload to be processed.
    pub payload: BatchPayload,
    /// A source of randomness for processing the Batch.
    pub randomness: Randomness,
    /// The ECDSA public key of the subnet.
    pub ecdsa_subnet_public_key: Option<MasterEcdsaPublicKey>,
    /// The version of the registry to be referenced when processing the batch.
    pub registry_version: RegistryVersion,
    /// A clock time to be used for processing messages.
    pub time: Time,
    /// Responses to subnet calls that require consensus' involvement.
    pub consensus_responses: Vec<Response>,
}

/// The context built by Consensus for deterministic processing. Captures all
/// fields that have semantic meaning within the Chain Consensus protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidationContext {
    /// The registry version to be associated with the payload.
    pub registry_version: RegistryVersion,
    /// The certified state height necessary for the validation of a payload.
    pub certified_height: Height,
    /// The clock time being used for the payload.
    pub time: Time,
}

impl ValidationContext {
    /// The derived PartialOrd trait implementation uses a lexicographic
    /// ordering over its fields, which is not what we want in the case of
    /// ValidationContext. We need every single field to be equal or greater
    /// than those of 'other' to return true. Otherwise, we return false.
    pub fn greater_or_equal(&self, other: &ValidationContext) -> bool {
        self.registry_version >= other.registry_version
            && self.certified_height >= other.certified_height
            && self.time >= other.time
    }
}

/// The payload of a batch.
///
/// Contains ingress messages, XNet messages and self-validating messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchPayload {
    pub ingress: IngressPayload,
    pub xnet: XNetPayload,
    pub self_validating: SelfValidatingPayload,
}

/// Return ingress messages, xnet messages, and responses from the bitcoin adapter.
pub type BatchMessages = (
    Vec<SignedIngress>,
    BTreeMap<SubnetId, CertifiedStreamSlice>,
    Vec<BitcoinAdapterResponse>,
);

impl BatchPayload {
    pub fn new(
        ingress: IngressPayload,
        xnet: XNetPayload,
        self_validating: SelfValidatingPayload,
    ) -> Self {
        BatchPayload {
            ingress,
            xnet,
            self_validating,
        }
    }

    /// Extract and return the set of ingress and xnet messages in a
    /// BatchPayload.
    /// Return error if deserialization of ingress payload fails.
    pub fn into_messages(self) -> Result<BatchMessages, InvalidIngressPayload> {
        Ok((
            self.ingress.try_into()?,
            self.xnet.stream_slices,
            self.self_validating.0,
        ))
    }

    pub fn is_empty(&self) -> bool {
        self.ingress.is_empty() && self.xnet.stream_slices.is_empty()
    }
}

/// Payload that contains SelfValidating messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SelfValidatingPayload(Vec<BitcoinAdapterResponse>);

impl SelfValidatingPayload {
    pub fn new(responses: Vec<BitcoinAdapterResponse>) -> SelfValidatingPayload {
        SelfValidatingPayload(responses)
    }

    pub fn get(&self) -> &[BitcoinAdapterResponse] {
        &self.0
    }
}

impl From<&SelfValidatingPayload> for pb::SelfValidatingPayload {
    fn from(self_validating_payload: &SelfValidatingPayload) -> Self {
        Self {
            bitcoin_testnet_payload: self_validating_payload.0.iter().map(|x| x.into()).collect(),
        }
    }
}

impl TryFrom<pb::SelfValidatingPayload> for SelfValidatingPayload {
    type Error = String;

    fn try_from(value: pb::SelfValidatingPayload) -> Result<Self, Self::Error> {
        let mut responses = vec![];
        for r in value.bitcoin_testnet_payload.into_iter() {
            responses.push(BitcoinAdapterResponse::try_from(r).map_err(|err| err.to_string())?);
        }
        Ok(Self(responses))
    }
}

impl CountBytes for SelfValidatingPayload {
    fn count_bytes(&self) -> usize {
        self.0.iter().map(|x| x.count_bytes()).sum()
    }
}

/// Payload that contains XNet messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XNetPayload {
    pub stream_slices: BTreeMap<SubnetId, CertifiedStreamSlice>,
}

impl From<&XNetPayload> for pb::XNetPayload {
    fn from(payload: &XNetPayload) -> Self {
        Self {
            stream_slices: payload
                .stream_slices
                .iter()
                .map(|(subnet_id, stream_slice)| pb::SubnetStreamSlice {
                    subnet_id: Some(crate::subnet_id_into_protobuf(*subnet_id)),
                    stream_slice: Some(messaging_pb::CertifiedStreamSlice::from(
                        stream_slice.clone(),
                    )),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb::XNetPayload> for XNetPayload {
    type Error = String;
    fn try_from(payload: pb::XNetPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            stream_slices: payload
                .stream_slices
                .into_iter()
                .map(|subnet_stream_slice| {
                    Ok((
                        crate::subnet_id_try_from_protobuf(
                            subnet_stream_slice.subnet_id.ok_or_else(|| {
                                String::from("Error: stream_slices missing subnet_id")
                            })?,
                        )
                        .map_err(|e| format!("{:?}", e))?,
                        CertifiedStreamSlice::try_from(
                            subnet_stream_slice.stream_slice.ok_or_else(|| {
                                String::from("Error: stream_slices missing from XNetPayload")
                            })?,
                        )
                        .map_err(|e| format!("{:?}", e))?,
                    ))
                })
                .collect::<Result<BTreeMap<SubnetId, CertifiedStreamSlice>, String>>()?,
        })
    }
}

impl CountBytes for XNetPayload {
    /// Returns the approximate amount of bytes in xnet payload.
    fn count_bytes(&self) -> usize {
        self.stream_slices
            .values()
            .map(|slice| {
                slice.payload.len() + slice.merkle_proof.len() + slice.certification.count_bytes()
            })
            .sum()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Payload that contains Ingress messages
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

/// Payload that contains CanisterHttpPayload messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpPayload(Vec<CanisterHttpResponseWithConsensus>);

impl From<&CanisterHttpPayload> for pb::CanisterHttpPayload {
    fn from(payload: &CanisterHttpPayload) -> Self {
        Self {
            payload: payload
                .0
                .iter()
                .map(
                    |payload| canister_http_pb::CanisterHttpResponseWithConsensus {
                        response: Some(canister_http_pb::CanisterHttpResponse {
                            id: payload.content.id.get(),
                            timeout: payload.content.timeout.as_nanos_since_unix_epoch(),
                            content: Some(canister_http_pb::CanisterHttpResponseContent::from(
                                &payload.content.content,
                            )),
                        }),
                        hash: payload.proof.content.content_hash.clone().get().0,
                        registry_version: payload.proof.content.registry_version.get(),
                        signature: payload.proof.signature.signature.clone().get().0,
                        signers: payload
                            .proof
                            .signature
                            .signers
                            .iter()
                            .map(|node_id| (*node_id).get().into_vec())
                            .collect(),
                    },
                )
                .collect(),
        }
    }
}

impl TryFrom<pb::CanisterHttpPayload> for CanisterHttpPayload {
    type Error = String;

    fn try_from(mut payload: pb::CanisterHttpPayload) -> Result<Self, Self::Error> {
        Ok(CanisterHttpPayload(
            payload
                .payload
                .drain(..)
                .map(
                    |payload| -> Result<CanisterHttpResponseWithConsensus, String> {
                        let response = payload
                            .response
                            .ok_or("Error: canister_http_payload does not contain a response")?;
                        let id = CanisterHttpRequestId::new(response.id);
                        let timeout = Time::from_nanos_since_unix_epoch(response.timeout);

                        Ok(CanisterHttpResponseWithConsensus {
                            content: CanisterHttpResponse {
                                id,
                                timeout,
                                content: CanisterHttpResponseContent::try_from(
                                    response.content.ok_or(
                                        "Error: canistrer_http_response does not contain content",
                                    )?,
                                )?,
                            },
                            proof: Signed {
                                content: CanisterHttpResponseMetadata {
                                    id,
                                    timeout,
                                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(
                                        CryptoHash(payload.hash),
                                    ),
                                    registry_version: RegistryVersion::new(
                                        payload.registry_version,
                                    ),
                                },
                                signature: MultiSignature {
                                    signature: CombinedMultiSigOf::from(CombinedMultiSig(
                                        payload.signature,
                                    )),
                                    signers: payload
                                        .signers
                                        .iter()
                                        .map(|n| {
                                            Ok(NodeId::from(
                                                PrincipalId::try_from(&n[..])
                                                    .map_err(|err| format!("{:?}", err))?,
                                            ))
                                        })
                                        .collect::<Result<Vec<NodeId>, String>>()?,
                                },
                            },
                        })
                    },
                )
                .collect::<Result<Vec<CanisterHttpResponseWithConsensus>, String>>()?,
        ))
    }
}

impl CountBytes for CanisterHttpPayload {
    fn count_bytes(&self) -> usize {
        self.0.iter().map(CountBytes::count_bytes).sum()
    }
}

impl From<&CanisterHttpResponseContent> for canister_http_pb::CanisterHttpResponseContent {
    fn from(content: &CanisterHttpResponseContent) -> Self {
        let inner = match content {
            CanisterHttpResponseContent::Success(payload) => {
                canister_http_pb::canister_http_response_content::Status::Success(
                    canister_http_pb::CanisterHttpResponsePayload {
                        status: payload.status as u32,
                        headers: payload
                            .headers
                            .iter()
                            .map(|header| canister_http_pb::HttpHeader {
                                name: header.name.clone(),
                                value: header.value.as_bytes().to_vec(),
                            })
                            .collect(),
                        body: payload.body.clone(),
                    },
                )
            }
            CanisterHttpResponseContent::Failed(error) => {
                canister_http_pb::canister_http_response_content::Status::Failed(
                    canister_http_pb::CanisterHttpReject {
                        reject_code: error.reject_code as u32,
                        message: error.message.clone(),
                    },
                )
            }
        };

        canister_http_pb::CanisterHttpResponseContent {
            status: Some(inner),
        }
    }
}

impl TryFrom<canister_http_pb::CanisterHttpResponseContent> for CanisterHttpResponseContent {
    type Error = String;

    fn try_from(value: canister_http_pb::CanisterHttpResponseContent) -> Result<Self, Self::Error> {
        Ok(
            match value
                .status
                .ok_or("Error: canister_http_content does not contain any value ")?
            {
                canister_http_pb::canister_http_response_content::Status::Success(mut payload) => {
                    CanisterHttpResponseContent::Success(CanisterHttpResponsePayload {
                        status: payload.status as u64,
                        headers: payload
                            .headers
                            .drain(..)
                            .map(|header| {
                                Ok(CanisterHttpHeader {
                                    name: header.name,
                                    value: String::from_utf8(header.value)
                                        .map_err(|err| format!("{:?}", err))?,
                                })
                            })
                            .collect::<Result<Vec<CanisterHttpHeader>, String>>()?,
                        body: payload.body,
                    })
                }
                canister_http_pb::canister_http_response_content::Status::Failed(error) => {
                    CanisterHttpResponseContent::Failed(CanisterHttpReject {
                        reject_code: RejectCode::try_from(error.reject_code as u64)
                            .map_err(|err| format!("{:?}", err))?,
                        message: error.message,
                    })
                }
            },
        )
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

    #[test]
    fn test_validation_context_ordering() {
        let context1 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        let context2 = ValidationContext {
            registry_version: RegistryVersion::new(2),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context2));
        assert!(context2.greater_or_equal(&context1));

        let context3 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(2),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context3));
        assert!(context3.greater_or_equal(&context1));

        let context4 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(2),
        };
        assert!(!context1.greater_or_equal(&context4));
        assert!(context4.greater_or_equal(&context1));

        let context5 = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(2),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context5));
        assert!(!context5.greater_or_equal(&context1));
    }

    /// Tests, whether a roundtrip of protobuf conversions generates the same
    /// `CanisterHttpPayload`
    #[test]
    fn into_canister_http_payload_and_back() {
        let payload = CanisterHttpPayload(vec![CanisterHttpResponseWithConsensus {
            content: CanisterHttpResponse {
                id: CanisterHttpRequestId::new(1),
                timeout: Time::from_nanos_since_unix_epoch(1234),
                content: CanisterHttpResponseContent::Success(CanisterHttpResponsePayload {
                    status: 200,
                    headers: [("test_header1", "value1"), ("test_header2", "value2")]
                        .iter()
                        .map(|(name, value)| CanisterHttpHeader {
                            name: name.to_string(),
                            value: value.to_string(),
                        })
                        .collect(),
                    body: b"Test data in body".to_vec(),
                }),
            },
            proof: Signed {
                content: CanisterHttpResponseMetadata {
                    id: CanisterHttpRequestId::new(1),
                    timeout: Time::from_nanos_since_unix_epoch(1234),
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                        0, 1, 2, 3,
                    ])),
                    registry_version: RegistryVersion::new(1),
                },
                signature: MultiSignature {
                    signature: CombinedMultiSigOf::from(CombinedMultiSig(vec![0, 1, 2, 3])),
                    signers: vec![NodeId::from(PrincipalId::new_node_test_id(1))],
                },
            },
        }]);

        let pb_payload = pb::CanisterHttpPayload::from(&payload);
        let new_payload = CanisterHttpPayload::try_from(pb_payload).unwrap();

        assert_eq!(payload, new_payload)
    }
}
