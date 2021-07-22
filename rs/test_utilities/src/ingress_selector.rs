use crate::util::FakeQueue;
use ic_interfaces::{
    ingress_manager::{IngressPayloadValidationError, IngressSelector, IngressSetQuery},
    ingress_pool::IngressPoolSelect,
    validation::ValidationResult,
};
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    messages::SignedIngress,
};

/// A fake `IngressSelector` implementation based on a `FakeQueue` of ingress
/// message batches.
pub type FakeIngressSelector = FakeQueue<Vec<SignedIngress>>;

impl IngressSelector for FakeIngressSelector {
    fn get_ingress_payload(
        &self,
        _ingress_pool: &dyn IngressPoolSelect,
        _past_payloads: &dyn IngressSetQuery,
        _context: &ValidationContext,
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

    fn request_purge_finalized_messages(&self, _message_ids: Vec<IngressMessageId>) {}
}
