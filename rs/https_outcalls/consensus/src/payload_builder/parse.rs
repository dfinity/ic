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
use std::collections::{BTreeMap, HashSet};

pub(crate) fn bytes_to_payload(data: &[u8]) -> Result<CanisterHttpPayload, ProxyDecodeError> {
    let messages: Vec<CanisterHttpResponseMessage> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
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
            Some(MessageType::AsyncRefund(share)) => payload
                .async_refunds
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
        async_refunds,
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
                async_refunds
                    .into_iter()
                    .map(|share| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::AsyncRefund(pb::CanisterHttpShare::from(
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

/// Collects from the `past_payloads` everything a new payload not repeat:
/// the responses already delivered and the asynchronous refunds already
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
            if let Some(MessageType::AsyncRefund(share)) = &message.message_type {
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
    let signer = share.signature.as_ref()?.signer.clone();
    let signer = NodeId::from(PrincipalId::try_from(signer).ok()?);
    Some((callback_id, signer))
}

/// Extracts the CanisterId (as u64) from a [`CanisterHttpResponseMessage`]
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
        Some(MessageType::AsyncRefund(_)) => None,
        None => None,
    }
}
