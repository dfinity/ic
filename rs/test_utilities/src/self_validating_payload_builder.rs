use ic_btc_replica_types::BitcoinAdapterResponse;
use ic_interfaces::self_validating_payload::{
    SelfValidatingPayloadBuilder, SelfValidatingPayloadValidationError,
};
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    NumBytes,
};

#[derive(Default)]
pub struct FakeSelfValidatingPayloadBuilder(Vec<BitcoinAdapterResponse>);

impl FakeSelfValidatingPayloadBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_responses(mut self, responses: Vec<BitcoinAdapterResponse>) -> Self {
        self.0 = responses;
        self
    }

    pub fn build(&self) -> SelfValidatingPayload {
        SelfValidatingPayload::new(self.0.clone())
    }
}

impl SelfValidatingPayloadBuilder for FakeSelfValidatingPayloadBuilder {
    fn get_self_validating_payload(
        &self,
        _validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
        _byte_limit: NumBytes,
    ) -> (SelfValidatingPayload, NumBytes) {
        let size: usize = self.0.iter().map(|response| response.count_bytes()).sum();

        (
            SelfValidatingPayload::new(self.0.clone()),
            NumBytes::new(size as u64),
        )
    }

    fn validate_self_validating_payload(
        &self,
        _payload: &SelfValidatingPayload,
        _validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        Ok(0.into())
    }
}
