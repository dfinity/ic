use ic_btc_replica_types::BitcoinAdapterResponse;
use ic_interfaces::batch_payload::{iterator_to_bytes, slice_to_messages, PastPayload};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::{
    bitcoin::v1::BitcoinAdapterResponse as PbBitcoinAdapterResponse, proxy::ProxyDecodeError,
};
use ic_types::{
    batch::{SelfValidatingPayload, MAX_BITCOIN_PAYLOAD_IN_BYTES},
    NumBytes,
};
use prost::Message;
use std::collections::BTreeSet;

pub(crate) fn bytes_to_payload(
    data: &[u8],
) -> Result<Vec<BitcoinAdapterResponse>, ProxyDecodeError> {
    let messages: Vec<PbBitcoinAdapterResponse> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;

    let messages = messages
        .into_iter()
        .map(|message| message.try_into())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(messages)
}

pub(crate) fn payload_to_bytes(
    payload: &SelfValidatingPayload,
    max_size: NumBytes,
    log: &ReplicaLogger,
) -> Vec<u8> {
    // Return empty payload, if there are no messages
    if payload.is_empty() {
        return vec![];
    }

    let output = iterator_to_bytes(
        payload.get().iter().map(PbBitcoinAdapterResponse::from),
        max_size,
    );

    // NOTE: Bitcoin blocks might be up to 4MB large. This special case guarantees, that we are able
    // to add at least one bitcoin block to the payload, even if it would not fit into a block.
    // We only allow this, if the bitcoin payload builder is the first payload builder to be called,
    // which we detect by checking, that we have more then MAX_BITCOIN_PAYLOAD_IN_BYTES bytes space.
    if output.is_empty() && max_size.get() >= MAX_BITCOIN_PAYLOAD_IN_BYTES {
        warn!(log, "Building a slightly oversized BitcoinPayload");

        let mut output = vec![];
        let _ =
            PbBitcoinAdapterResponse::from(&payload.get()[0]).encode_length_delimited(&mut output);
        output
    } else {
        output
    }
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
