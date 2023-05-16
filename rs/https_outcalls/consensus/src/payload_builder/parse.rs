use ic_interfaces::{
    batch_payload::PastPayload, canister_http::CanisterHttpPermanentValidationError,
};
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use ic_types::{batch::CanisterHttpPayload, messages::CallbackId};
use prost::Message;
use std::collections::HashSet;

pub(crate) fn bytes_to_payload(
    data: &[u8],
) -> Result<CanisterHttpPayload, CanisterHttpPermanentValidationError> {
    let pb_payload = pb::CanisterHttpPayload::decode(data).map_err(|e| {
        CanisterHttpPermanentValidationError::DecodeError(ProxyDecodeError::DecodeError(e))
    })?;
    pb_payload
        .try_into()
        .map_err(|e| CanisterHttpPermanentValidationError::DecodeError(ProxyDecodeError::Other(e)))
}

pub(crate) fn payload_to_bytes(payload: &CanisterHttpPayload) -> Vec<u8> {
    pb::CanisterHttpPayload::from(payload).encode_to_vec()
}

pub(crate) fn parse_past_payload_ids(past_payloads: &[PastPayload]) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        // TODO: Error handling here
        .map(|payload| pb::CanisterHttpPayload::decode(payload.payload).unwrap())
        .flat_map(|payload| {
            payload
                .responses
                .into_iter()
                .filter_map(|response| response.response)
                .map(|content| content.id)
                .chain(payload.timeouts)
        })
        .map(CallbackId::new)
        .collect()
}
