use crate::util::FakeQueue;
use ic_interfaces::{
    ingress_manager::{IngressPayloadValidationError, IngressSelector, IngressSetQuery},
    ingress_pool::IngressPoolSelect,
    validation::ValidationResult,
};
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    consensus::Payload,
    messages::SignedIngress,
    Height, NumBytes, Time,
};
use std::{collections::HashSet, sync::Arc};

/// A fake `IngressSelector` implementation based on a `FakeQueue` of ingress
/// message batches.
pub type FakeIngressSelector = FakeQueue<Vec<SignedIngress>>;

impl IngressSelector for FakeIngressSelector {
    fn get_ingress_payload(
        &self,
        _ingress_pool: &dyn IngressPoolSelect,
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
    ) -> Vec<Arc<HashSet<IngressMessageId>>> {
        // NOTE: This is valid, since we never look at the past_payloads in
        // `get_ingress_payload` and `validate_ingress_payload`
        vec![]
    }

    fn request_purge_finalized_messages(&self, _message_ids: Vec<IngressMessageId>) {}
}
