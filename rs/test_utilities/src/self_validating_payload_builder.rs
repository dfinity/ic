use ic_interfaces::self_validating_payload::{
    SelfValidatingPayloadBuilder, SelfValidatingPayloadValidationError,
};
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    NumBytes,
};

#[derive(Default)]
pub struct FakeSelfValidatingPayloadBuilder {}

impl FakeSelfValidatingPayloadBuilder {
    pub fn new() -> FakeSelfValidatingPayloadBuilder {
        FakeSelfValidatingPayloadBuilder {}
    }
}

impl SelfValidatingPayloadBuilder for FakeSelfValidatingPayloadBuilder {
    fn get_self_validating_payload(
        &self,
        _validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
        _byte_limit: NumBytes,
    ) -> SelfValidatingPayload {
        SelfValidatingPayload::new()
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
