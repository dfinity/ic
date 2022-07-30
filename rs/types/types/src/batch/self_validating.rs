use crate::CountBytes;
use ic_btc_types_internal::{BitcoinAdapterResponse, BitcoinAdapterResponseWrapper};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// The theoretical maximum for the size of a bitcoin block.
///
/// If in the future, the bitcoin network decides to increase the block size,
/// this value needs to be increased too.
pub const MAX_BITCOIN_BLOCK_SIZE: u64 = 4 * 1024 * 1024;

/// Payload that contains SelfValidating messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SelfValidatingPayload(pub(super) Vec<BitcoinAdapterResponse>);

impl SelfValidatingPayload {
    pub fn new(responses: Vec<BitcoinAdapterResponse>) -> SelfValidatingPayload {
        SelfValidatingPayload(responses)
    }

    pub fn get(&self) -> &[BitcoinAdapterResponse] {
        &self.0
    }

    /// Returns the number of Bitcoin blocks included in this payload.
    pub fn num_bitcoin_blocks(&self) -> usize {
        let mut res = 0;
        for response in self.0.iter() {
            match &response.response {
                BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) => res += r.blocks.len(),
                BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => (),
            }
        }
        res
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
