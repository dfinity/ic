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
    canister_http::CanisterHttpResponseShare,
    messages::CallbackId,
};
use prost::Message;
use std::collections::{BTreeMap, HashSet};

pub(crate) fn bytes_to_payload(data: &[u8]) -> Result<CanisterHttpPayload, ProxyDecodeError> {
    messages_to_payload(slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?)
}

/// Like [`bytes_to_payload`], but fails unless `data` is exactly what
/// [`payload_to_bytes`] writes, i.e. unless every message encodes to the very bytes
/// it was decoded from.
pub(crate) fn canonical_bytes_to_payload(
    data: &[u8],
) -> Result<CanisterHttpPayload, ProxyDecodeError> {
    messages_to_payload(slice_to_canonical_messages(data)?)
}

fn slice_to_canonical_messages(
    data: &[u8],
) -> Result<Vec<CanisterHttpResponseMessage>, ProxyDecodeError> {
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
        messages.push(message);
    }

    Ok(messages)
}

fn messages_to_payload(
    messages: Vec<CanisterHttpResponseMessage>,
) -> Result<CanisterHttpPayload, ProxyDecodeError> {
    let mut payload = CanisterHttpPayload::default();

    for message in messages {
        match message.message_type {
            Some(MessageType::Timeout(timeout)) => payload.timeouts.push(CallbackId::new(timeout)),
            Some(MessageType::Response(response)) => payload.responses.push(response.try_into()?),
            Some(MessageType::DivergenceResponse(response)) => {
                payload.divergence_responses.push(response.try_into()?)
            }
            Some(MessageType::FlexibleResponses(flex_responses)) => payload
                .flexible_responses
                .push(FlexibleCanisterHttpResponses::try_from(flex_responses)?),
            Some(MessageType::FlexibleError(flex_error)) => payload
                .flexible_errors
                .push(FlexibleCanisterHttpError::try_from(flex_error)?),
            Some(MessageType::OutOfCycles(out_of_cycles)) => payload
                .out_of_cycles
                .push(CanisterHttpOutOfCycles::try_from(out_of_cycles)?),
            Some(MessageType::AsyncReceipt(share)) => payload
                .async_receipts
                .push(CanisterHttpResponseShare::try_from(share)?),
            None => return Err(ProxyDecodeError::MissingField("message_type")),
        }
    }

    Ok(payload)
}

pub(crate) fn payload_to_bytes(payload: CanisterHttpPayload, max_size: NumBytes) -> Vec<u8> {
    let CanisterHttpPayload {
        timeouts,
        divergence_responses,
        out_of_cycles,
        responses,
        flexible_responses,
        flexible_errors,
        async_receipts,
    } = payload;

    let message_iterator =
        timeouts
            .into_iter()
            .map(|timeout| CanisterHttpResponseMessage {
                message_type: Some(MessageType::Timeout(timeout.get())),
            })
            .chain(
                divergence_responses
                    .into_iter()
                    .map(|response| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::DivergenceResponse(
                            pb::CanisterHttpResponseDivergence::from(response),
                        )),
                    }),
            )
            .chain(
                responses
                    .into_iter()
                    .map(|response| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::Response(
                            pb::CanisterHttpResponseWithConsensus::from(response),
                        )),
                    }),
            )
            .chain(flexible_responses.into_iter().map(|flex_responses| {
                CanisterHttpResponseMessage {
                    message_type: Some(MessageType::FlexibleResponses(
                        pb::FlexibleCanisterHttpResponses::from(flex_responses),
                    )),
                }
            }))
            .chain(
                flexible_errors
                    .into_iter()
                    .map(|flex_error| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::FlexibleError(
                            pb::FlexibleCanisterHttpError::from(flex_error),
                        )),
                    }),
            )
            .chain(
                out_of_cycles
                    .into_iter()
                    .map(|out_of_cycles| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::OutOfCycles(
                            pb::CanisterHttpOutOfCycles::from(out_of_cycles),
                        )),
                    }),
            )
            .chain(
                async_receipts
                    .into_iter()
                    .map(|share| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::AsyncReceipt(pb::CanisterHttpShare::from(
                            share,
                        ))),
                    }),
            );

    iterator_to_bytes(message_iterator, max_size)
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

    fn hash() -> Vec<u8> {
        bytes_field(2, &[7; 32])
    }

    fn content_size() -> Vec<u8> {
        varint_field(9, 5)
    }

    fn is_reject(value: u64) -> Vec<u8> {
        varint_field(10, value)
    }

    fn canonical() -> Vec<u8> {
        response_message(&[hash(), content_size(), is_reject(1)])
    }

    #[test]
    fn canonical_messages_are_accepted_test() {
        let with_consensus = pb::CanisterHttpResponseWithConsensus {
            hash: vec![7; 32],
            content_size: 5,
            is_reject: true,
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
        assert_eq!(
            slice_to_canonical_messages(&payload).unwrap(),
            slice_to_messages::<CanisterHttpResponseMessage>(&payload).unwrap()
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
                response_message(&[content_size(), hash(), is_reject(1)]),
                true,
            ),
            (
                "a bool other than 0 and 1",
                response_message(&[hash(), content_size(), is_reject(2)]),
                true,
            ),
            (
                "an unknown field",
                response_message(&[hash(), content_size(), is_reject(1), varint_field(15, 0)]),
                false,
            ),
            (
                "a repeated field",
                response_message(&[hash(), content_size(), is_reject(1), content_size()]),
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
                    slice_to_canonical_messages(&non_canonical),
                    Err(ProxyDecodeError::Other(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn undecodable_payloads_are_rejected_test() {
        assert!(matches!(
            slice_to_canonical_messages(&[0xff; 16]),
            Err(ProxyDecodeError::DecodeError(_))
        ));
    }
}
