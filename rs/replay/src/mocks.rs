use ic_interfaces::{
    batch_payload::ProposalContext,
    consensus::{PayloadBuilder, PayloadValidationError},
    validation::ValidationResult,
};
use ic_types::{
    Height, Time,
    batch::{BatchPayload, ValidationContext},
    consensus::{Payload, block_maker::SubnetRecords},
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
        _proposal_context: &ProposalContext,
        _payload: &Payload,
        _past_payloads: &[(Height, Time, Payload)],
    ) -> ValidationResult<PayloadValidationError> {
        Ok(())
    }
}
