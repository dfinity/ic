use crate::CountBytes;
use ic_btc_replica_types::BitcoinAdapterResponse;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

// The theoretical maximum for the size of a bitcoin block.
//
// If in the future, the bitcoin network decides to increase the block size,
// this value needs to be increased too.
const MAX_BITCOIN_BLOCK_IN_BYTES: u64 = 4_000_000;

// An additional buffer for metadata that's added with a bitcoin block (e.g. next block hashes).
const BITCOIN_PAYLOAD_BUFFER_IN_BYTES: u64 = 100_000;

/// The maximum size of a bitcoin payload.
pub const MAX_BITCOIN_PAYLOAD_IN_BYTES: u64 =
    MAX_BITCOIN_BLOCK_IN_BYTES + BITCOIN_PAYLOAD_BUFFER_IN_BYTES;

/// Payload that contains SelfValidating messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct SelfValidatingPayload(pub(super) Vec<BitcoinAdapterResponse>);

impl SelfValidatingPayload {
    pub fn new(responses: Vec<BitcoinAdapterResponse>) -> SelfValidatingPayload {
        SelfValidatingPayload(responses)
    }

    pub fn get(&self) -> &[BitcoinAdapterResponse] {
        &self.0
    }

    /// Returns true if the payload is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    type Error = ProxyDecodeError;

    fn try_from(value: pb::SelfValidatingPayload) -> Result<Self, Self::Error> {
        let mut responses = vec![];
        for r in value.bitcoin_testnet_payload.into_iter() {
            responses.push(BitcoinAdapterResponse::try_from(r)?);
        }
        Ok(Self(responses))
    }
}

impl CountBytes for SelfValidatingPayload {
    fn count_bytes(&self) -> usize {
        self.0.iter().map(|x| x.count_bytes()).sum()
    }
}
