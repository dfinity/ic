use ic_interfaces::batch_payload::PastPayload;
use ic_logger::{ReplicaLogger, error};
use ic_protobuf::{
    proxy::ProxyDecodeError,
    types::v1 as pb,
    types::v1::{CanisterHttpResponseMessage, canister_http_response_message::MessageType},
};
use ic_types::{
    NumBytes,
    batch::{CanisterHttpPayload, iterator_to_bytes, slice_to_messages},
    messages::CallbackId,
};
use std::collections::HashSet;

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
            None => return Err(ProxyDecodeError::MissingField("message_type")),
        }
    }

    Ok(payload)
}

pub(crate) fn payload_to_bytes(payload: &CanisterHttpPayload, max_size: NumBytes) -> Vec<u8> {
    let message_iterator =
        payload
            .timeouts
            .iter()
            .map(|timeout| CanisterHttpResponseMessage {
                message_type: Some(MessageType::Timeout(timeout.get())),
            })
            .chain(payload.divergence_responses.iter().map(|response| {
                CanisterHttpResponseMessage {
                    message_type: Some(MessageType::DivergenceResponse(
                        pb::CanisterHttpResponseDivergence::from(response),
                    )),
                }
            }))
            .chain(
                payload
                    .responses
                    .iter()
                    .map(|response| CanisterHttpResponseMessage {
                        message_type: Some(MessageType::Response(
                            pb::CanisterHttpResponseWithConsensus::from(response),
                        )),
                    }),
            );

    iterator_to_bytes(message_iterator, max_size)
}

pub(crate) fn parse_past_payload_ids(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            slice_to_messages::<CanisterHttpResponseMessage>(payload.payload).unwrap_or_else(
                |err| {
                    error!(
                        log,
                        "Failed to parse CanisterHttp past payload for height {}. Error: {}",
                        payload.height,
                        err
                    );
                    vec![]
                },
            )
        })
        .filter_map(get_id_from_message)
        .map(CallbackId::new)
        .collect()
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
        Some(MessageType::Timeout(id)) => Some(id),
        None => None,
    }
}
