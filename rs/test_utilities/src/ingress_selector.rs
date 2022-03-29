use crate::util::FakeQueue;
use ic_interfaces::{
    ingress_manager::{IngressPayloadValidationError, IngressSelector, IngressSetQuery},
    validation::ValidationResult,
};
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    consensus::Payload,
    ingress::IngressSets,
    messages::SignedIngress,
    time::UNIX_EPOCH,
    Height, NumBytes, Time,
};

/// A fake `IngressSelector` implementation based on a `FakeQueue` of ingress
/// message batches.
pub type FakeIngressSelector = FakeQueue<Vec<SignedIngress>>;

impl IngressSelector for FakeIngressSelector {
    fn get_ingress_payload(
        &self,
        _past_payloads: &dyn IngressSetQuery,
        _context: &ValidationContext,
        _byte_limit: NumBytes,
    ) -> IngressPayload {
        self.dequeue().unwrap_or_default().into()
    }
    fn validate_ingress_payload(
        &self,
        _payload: &IngressPayload,
        _past_payloads: &dyn IngressSetQuery,
        _context: &ValidationContext,
    ) -> ValidationResult<IngressPayloadValidationError> {
        Ok(())
    }

    fn filter_past_payloads(
        &self,
        _past_payloads: &[(Height, Time, Payload)],
        _context: &ValidationContext,
    ) -> IngressSets {
        // NOTE: This is valid, since we never look at the past_payloads in
        // `get_ingress_payload` and `validate_ingress_payload`
        IngressSets::new(vec![], UNIX_EPOCH)
    }

    fn request_purge_finalized_messages(&self, _message_ids: Vec<IngressMessageId>) {}
}
