use ic_interfaces::batch_payload::{iterator_to_bytes, slice_to_messages, PastPayload};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::{
    bitcoin::v1::BitcoinAdapterResponse as PbBitcoinAdapterResponse, proxy::ProxyDecodeError,
};
use ic_types::{batch::SelfValidatingPayload, NumBytes};
use std::collections::BTreeSet;

pub(crate) fn bytes_to_payload(data: &[u8]) -> Result<SelfValidatingPayload, ProxyDecodeError> {
    let messages: Vec<PbBitcoinAdapterResponse> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;

    let messages = messages
        .into_iter()
        .map(|message| message.try_into())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SelfValidatingPayload::new(messages))
}

pub(crate) fn payload_to_bytes(payload: &SelfValidatingPayload, max_size: NumBytes) -> Vec<u8> {
    iterator_to_bytes(
        payload.get().iter().map(PbBitcoinAdapterResponse::from),
        max_size,
    )
}

pub(crate) fn parse_past_payload_ids(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> BTreeSet<u64> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            slice_to_messages::<PbBitcoinAdapterResponse>(payload.payload).unwrap_or_else(|err| {
                error!(
                    log,
                    "Failed to parse Bitcoin past payload for height {}. Error {}",
                    payload.height,
                    err
                );
                vec![]
            })
        })
        .map(|payload| payload.callback_id)
        .collect()
}
