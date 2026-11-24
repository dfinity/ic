use ic_interfaces::batch_payload::PastPayload;
use ic_logger::{ReplicaLogger, error};
use ic_protobuf::{
    proxy::ProxyDecodeError,
    types::v1 as pb,
    types::v1::{CanisterHttpResponseMessage, canister_http_response_message::MessageType},
};
use ic_types::{
    NodeId, NumBytes, PrincipalId,
    batch::{
        CanisterHttpOutOfCycles, CanisterHttpPayload, FlexibleCanisterHttpError,
        FlexibleCanisterHttpResponses, iterator_to_bytes, slice_to_messages,
    },
    canister_http::{
        CanisterHttpResponseDivergence, CanisterHttpResponseShare,
        CanisterHttpResponseWithConsensus,
    },
    messages::CallbackId,
};
use prost::Message;
use std::collections::{BTreeMap, HashSet};

pub(crate) fn bytes_to_payload(data: &[u8]) -> Result<CanisterHttpPayload, ProxyDecodeError> {
    slice_to_messages::<CanisterHttpResponseMessage>(data)
        .map_err(ProxyDecodeError::DecodeError)?
        .into_iter()
        .map(PayloadMessage::try_from)
        .collect::<Result<_, _>>()
        .map(messages_to_payload)
}

/// Decodes the messages of a payload, and fails unless every message encodes to the very
/// bytes it was decoded from, as [`messages_to_bytes`] writes it.
pub(crate) fn canonical_bytes_to_messages(
    data: &[u8],
) -> Result<Vec<PayloadMessage>, ProxyDecodeError> {
    let mut messages = vec![];
    let mut remaining = data;
    let mut encoding = vec![];

    while !remaining.is_empty() {
        let start = data.len() - remaining.len();
        let message = CanisterHttpResponseMessage::decode_length_delimited(&mut remaining)
            .map_err(ProxyDecodeError::DecodeError)?;
        let end = data.len() - remaining.len();

        encoding.clear();
        message
            .encode_length_delimited(&mut encoding)
            .expect("Encoding into a Vec never runs out of space");
        if encoding[..] != data[start..end] {
            return Err(ProxyDecodeError::Other(format!(
                "The canister http message at byte {start} is not canonically encoded"
            )));
        }
        messages.push(PayloadMessage::try_from(message)?);
    }

    Ok(messages)
}

/// The payload made up of the given messages.
pub(crate) fn messages_to_payload(messages: Vec<PayloadMessage>) -> CanisterHttpPayload {
    let mut payload = CanisterHttpPayload::default();
    for message in messages {
        match message {
            PayloadMessage::Timeout(callback_id) => payload.timeouts.push(callback_id),
            PayloadMessage::Divergence(divergence) => payload.divergence_responses.push(divergence),
            PayloadMessage::Response(response) => payload.responses.push(response),
            PayloadMessage::FlexibleResponses(group) => payload.flexible_responses.push(group),
            PayloadMessage::FlexibleError(error) => payload.flexible_errors.push(error),
            PayloadMessage::OutOfCycles(error) => payload.out_of_cycles.push(error),
            PayloadMessage::AsyncReceipt(share) => payload.async_receipts.push(share),
        }
    }
    payload
}

/// A message of a canister http payload.
pub(crate) enum PayloadMessage {
    Timeout(CallbackId),
    Divergence(CanisterHttpResponseDivergence),
    Response(CanisterHttpResponseWithConsensus),
    FlexibleResponses(FlexibleCanisterHttpResponses),
    FlexibleError(FlexibleCanisterHttpError),
    OutOfCycles(CanisterHttpOutOfCycles),
    AsyncReceipt(CanisterHttpResponseShare),
}

impl PayloadMessage {
    /// Whether the message counts towards the limit on responses per block, as in
    /// [`CanisterHttpPayload::num_limited_responses`].
    pub(crate) fn counts_towards_response_limit(&self) -> bool {
        match self {
            Self::Response(_)
            | Self::Divergence(_)
            | Self::OutOfCycles(_)
            | Self::FlexibleResponses(_)
            | Self::FlexibleError(
                FlexibleCanisterHttpError::TooManyRejects { .. }
                | FlexibleCanisterHttpError::ResponsesTooLarge { .. }
                | FlexibleCanisterHttpError::OutOfCycles { .. },
            ) => true,
            Self::Timeout(_)
            | Self::FlexibleError(FlexibleCanisterHttpError::Timeout { .. })
            | Self::AsyncReceipt(_) => false,
        }
    }
}

impl TryFrom<CanisterHttpResponseMessage> for PayloadMessage {
    type Error = ProxyDecodeError;

    fn try_from(message: CanisterHttpResponseMessage) -> Result<Self, Self::Error> {
        Ok(
            match message
                .message_type
                .ok_or(ProxyDecodeError::MissingField("message_type"))?
            {
                MessageType::Timeout(callback_id) => Self::Timeout(CallbackId::new(callback_id)),
                MessageType::Response(response) => Self::Response(response.try_into()?),
                MessageType::DivergenceResponse(divergence) => {
                    Self::Divergence(divergence.try_into()?)
                }
                MessageType::FlexibleResponses(group) => Self::FlexibleResponses(group.try_into()?),
                MessageType::FlexibleError(error) => Self::FlexibleError(error.try_into()?),
                MessageType::OutOfCycles(error) => Self::OutOfCycles(error.try_into()?),
                MessageType::AsyncReceipt(share) => Self::AsyncReceipt(share.try_into()?),
            },
        )
    }
}

impl From<PayloadMessage> for CanisterHttpResponseMessage {
    fn from(message: PayloadMessage) -> Self {
        let message_type = match message {
            PayloadMessage::Timeout(callback_id) => MessageType::Timeout(callback_id.get()),
            PayloadMessage::Divergence(divergence) => {
                MessageType::DivergenceResponse(divergence.into())
            }
            PayloadMessage::Response(response) => MessageType::Response(response.into()),
            PayloadMessage::FlexibleResponses(group) => {
                MessageType::FlexibleResponses(group.into())
            }
            PayloadMessage::FlexibleError(error) => MessageType::FlexibleError(error.into()),
            PayloadMessage::OutOfCycles(error) => MessageType::OutOfCycles(error.into()),
            PayloadMessage::AsyncReceipt(share) => MessageType::AsyncReceipt(share.into()),
        };
        Self {
            message_type: Some(message_type),
        }
    }
}

/// Serializes the messages in the given order, leaving out every message that does not
/// fit within `max_size`.
pub(crate) fn messages_to_bytes(
    messages: impl IntoIterator<Item = PayloadMessage>,
    max_size: NumBytes,
) -> Vec<u8> {
    iterator_to_bytes(
        messages.into_iter().map(CanisterHttpResponseMessage::from),
        max_size,
    )
}

/// Relevant data of payloads between the certified height and the block being built.
#[derive(Default)]
pub struct PastPayloads {
    /// The callback ids that have already been responded to.
    pub delivered_ids: HashSet<CallbackId>,
    /// Per callback id, the replicas whose spend has already been reported
    /// asynchronously, i.e. that must not be refunded again.
    pub refunded_nodes: BTreeMap<CallbackId, HashSet<NodeId>>,
}

/// Collects from the `past_payloads` everything a new payload must not repeat:
/// the responses already delivered and the asynchronous receipts already
/// reported.
pub(crate) fn parse_past_payloads(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> PastPayloads {
    let mut parsed = PastPayloads::default();
    for payload in past_payloads {
        let messages = slice_to_messages::<CanisterHttpResponseMessage>(payload.payload)
            .unwrap_or_else(|err| {
                error!(
                    log,
                    "Failed to parse CanisterHttp past payload for height {}. Error: {}",
                    payload.height,
                    err
                );
                vec![]
            });
        for message in messages {
            if let Some(MessageType::AsyncReceipt(share)) = &message.message_type {
                if let Some((callback_id, signer)) = callback_and_signer_of_share(share) {
                    parsed
                        .refunded_nodes
                        .entry(callback_id)
                        .or_default()
                        .insert(signer);
                }
                continue;
            }
            if let Some(id) = get_id_from_message(message) {
                parsed.delivered_ids.insert(CallbackId::new(id));
            }
        }
    }
    parsed
}

/// Extracts the callback and signer IDs of a [`pb::CanisterHttpShare`], or
/// `None` if either is missing or malformed. Such a share would have failed
/// payload validation, so it cannot appear in a past payload.
fn callback_and_signer_of_share(share: &pb::CanisterHttpShare) -> Option<(CallbackId, NodeId)> {
    let callback_id = CallbackId::new(share.metadata.as_ref()?.id);
    let signer = PrincipalId::try_from(share.signature.as_ref()?.signer.as_slice()).ok()?;
    Some((callback_id, NodeId::from(signer)))
}

/// Extracts the CallbackId (as u64) from a [`CanisterHttpResponseMessage`]
fn get_id_from_message(message: CanisterHttpResponseMessage) -> Option<u64> {
    match message.message_type {
        Some(MessageType::Response(response)) => response.response.map(|response| response.id),
        // NOTE: We simply use the id from the first metadata share
        // All metadata shares have the same id, otherwise they would not have been included as a past payload
        Some(MessageType::DivergenceResponse(response)) => response
            .shares
            .first()
            .and_then(|share| share.metadata.as_ref().map(|md| md.id)),
        Some(MessageType::FlexibleResponses(flex_responses)) => Some(flex_responses.callback_id),
        Some(MessageType::FlexibleError(flex_error)) => Some(flex_error.callback_id),
        Some(MessageType::OutOfCycles(out_of_cycles)) => Some(out_of_cycles.callback_id),
        Some(MessageType::Timeout(id)) => Some(id),
        // Handled by `parse_past_payloads`, which does not deliver a response for it.
        Some(MessageType::AsyncReceipt(_)) => None,
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types_cycles::Cycles;
    use prost::encoding::{WireType, encode_key, encode_varint};

    fn bytes_field(tag: u32, value: &[u8]) -> Vec<u8> {
        let mut field = vec![];
        encode_key(tag, WireType::LengthDelimited, &mut field);
        encode_varint(value.len() as u64, &mut field);
        field.extend_from_slice(value);
        field
    }

    fn varint_field(tag: u32, value: u64) -> Vec<u8> {
        let mut field = vec![];
        encode_key(tag, WireType::Varint, &mut field);
        encode_varint(value, &mut field);
        field
    }

    /// A `response` message whose `CanisterHttpResponseWithConsensus` consists of
    /// the given fields, framed the way `iterator_to_bytes` frames it.
    fn response_message(fields: &[Vec<u8>]) -> Vec<u8> {
        let message = bytes_field(1, &fields.concat());
        let mut framed = vec![];
        encode_varint(message.len() as u64, &mut framed);
        framed.extend(message);
        framed
    }

    fn response() -> Vec<u8> {
        let content = bytes_field(3, b"body");
        bytes_field(1, &[varint_field(1, 4), bytes_field(3, &content)].concat())
    }

    fn hash() -> Vec<u8> {
        bytes_field(2, &[7; 32])
    }

    fn replica_version() -> Vec<u8> {
        bytes_field(8, b"1")
    }

    fn content_size() -> Vec<u8> {
        varint_field(9, 5)
    }

    fn is_reject(value: u64) -> Vec<u8> {
        varint_field(10, value)
    }

    fn initial_spent() -> Vec<u8> {
        bytes_field(11, &bytes_field(2, &[0; 16]))
    }

    fn canonical() -> Vec<u8> {
        response_message(&[
            response(),
            hash(),
            replica_version(),
            content_size(),
            is_reject(1),
            initial_spent(),
        ])
    }

    #[test]
    fn canonical_messages_are_accepted_test() {
        let with_consensus = pb::CanisterHttpResponseWithConsensus {
            response: Some(pb::CanisterHttpResponse {
                id: 4,
                content: Some(pb::CanisterHttpResponseContent {
                    status: Some(pb::canister_http_response_content::Status::Success(
                        b"body".to_vec(),
                    )),
                }),
            }),
            hash: vec![7; 32],
            replica_version: "1".to_string(),
            content_size: 5,
            is_reject: true,
            initial_spent: Some(Cycles::new(0).into()),
            ..Default::default()
        };
        let canonical = canonical();
        let timeout = iterator_to_bytes(
            std::iter::once(CanisterHttpResponseMessage {
                message_type: Some(MessageType::Timeout(3)),
            }),
            NumBytes::new(1024),
        );

        // The fields above are exactly how prost encodes the message.
        assert_eq!(
            canonical,
            iterator_to_bytes(
                std::iter::once(CanisterHttpResponseMessage {
                    message_type: Some(MessageType::Response(with_consensus)),
                }),
                NumBytes::new(1024),
            )
        );
        let payload = [canonical, timeout].concat();
        let messages = canonical_bytes_to_messages(&payload).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages_to_payload(messages),
            bytes_to_payload(&payload).unwrap()
        );
    }

    /// Each of these decodes to the very same messages as the canonical encoding, but
    /// is not what prost writes for them. The first two even have the same length as
    /// the canonical encoding, so comparing lengths would not catch them.
    #[test]
    fn non_canonical_encodings_are_rejected_test() {
        let canonical = canonical();
        let non_minimal_length = [&[canonical[0] | 0x80, 0x00][..], &canonical[1..]].concat();

        for (name, non_canonical, same_length) in [
            (
                "fields out of tag order",
                response_message(&[
                    response(),
                    content_size(),
                    hash(),
                    replica_version(),
                    is_reject(1),
                    initial_spent(),
                ]),
                true,
            ),
            (
                "a bool other than 0 and 1",
                response_message(&[
                    response(),
                    hash(),
                    replica_version(),
                    content_size(),
                    is_reject(2),
                    initial_spent(),
                ]),
                true,
            ),
            (
                "an unknown field",
                response_message(&[
                    response(),
                    hash(),
                    replica_version(),
                    content_size(),
                    is_reject(1),
                    initial_spent(),
                    varint_field(15, 0),
                ]),
                false,
            ),
            (
                "a repeated field",
                response_message(&[
                    response(),
                    hash(),
                    replica_version(),
                    content_size(),
                    is_reject(1),
                    initial_spent(),
                    content_size(),
                ]),
                false,
            ),
            ("a non-minimal length prefix", non_minimal_length, false),
        ] {
            assert_eq!(
                slice_to_messages::<CanisterHttpResponseMessage>(&non_canonical).unwrap(),
                slice_to_messages::<CanisterHttpResponseMessage>(&canonical).unwrap(),
                "{name}"
            );
            assert_eq!(
                non_canonical.len() == canonical.len(),
                same_length,
                "{name}"
            );
            assert!(
                matches!(
                    canonical_bytes_to_messages(&non_canonical),
                    Err(ProxyDecodeError::Other(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn undecodable_payloads_are_rejected_test() {
        assert!(matches!(
            canonical_bytes_to_messages(&[0xff; 16]),
            Err(ProxyDecodeError::DecodeError(_))
        ));
    }
}
