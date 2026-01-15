use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::PayloadValidationError,
};
use ic_types::{
    Height, NumBytes,
    batch::{CanisterHttpPayload, ValidationContext},
    canister_http::CanisterHttpResponseWithConsensus,
};

use crate::payload_builder::parse::payload_to_bytes;

#[derive(Default)]
pub struct FakeCanisterHttpPayloadBuilder(Vec<CanisterHttpResponseWithConsensus>);

impl FakeCanisterHttpPayloadBuilder {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn with_responses(mut self, responses: Vec<CanisterHttpResponseWithConsensus>) -> Self {
        self.0 = responses;
        self
    }
}

impl BatchPayloadBuilder for FakeCanisterHttpPayloadBuilder {
    fn build_payload(
        &self,
        _height: Height,
        max_size: NumBytes,
        _past_payloads: &[PastPayload],
        _context: &ValidationContext,
    ) -> Vec<u8> {
        let payload = CanisterHttpPayload {
            responses: self.0.clone(),
            timeouts: vec![],
            divergence_responses: vec![],
        };
        payload_to_bytes(&payload, max_size)
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        _payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        Ok(())
    }
}
