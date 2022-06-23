use ic_consensus::consensus::{payload_builder::PayloadBuilder, SubnetRecords};
use ic_interfaces::{consensus::PayloadValidationError, validation::ValidationResult};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::Payload,
    Height, Time,
};

/// A mock we're using to instantiate the consensus Validator. Since notarizations
/// are available for all blocks, we will never validate payloads.
pub(crate) struct MockPayloadBuilder {}

impl PayloadBuilder for MockPayloadBuilder {
    fn get_payload<'a>(
        &self,
        _height: Height,
        _past_payloads: &[(Height, Time, Payload)],
        _context: &ValidationContext,
        _subnet_records: &SubnetRecords,
    ) -> BatchPayload {
        Default::default()
    }

    fn validate_payload(
        &self,
        _height: Height,
        _payload: &Payload,
        _past_payloads: &[(Height, Time, Payload)],
        _context: &ValidationContext,
    ) -> ValidationResult<PayloadValidationError> {
        Ok(())
    }
}
