use crate::CountBytes;
use ic_btc_types_internal::BitcoinAdapterResponse;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

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
