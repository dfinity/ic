use ic_interfaces::{
    ingress_manager::{IngressPayloadValidationError, IngressSelector, IngressSetQuery},
    validation::ValidationResult,
};
use ic_types::{
    CountBytes, Height, NumBytes, Time,
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    consensus::Payload,
    ingress::IngressSets,
    messages::SignedIngress,
    time::UNIX_EPOCH,
};
use std::collections::VecDeque;
use std::sync::Mutex;

// A mock object that wraps a queue
#[derive(Default)]
pub struct FakeQueue<T> {
    pub queue: Mutex<VecDeque<T>>,
}

impl<T> FakeQueue<T> {
    pub fn new() -> FakeQueue<T> {
        FakeQueue {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn enqueue(&self, elem: T) {
        let mut q = self.queue.lock().unwrap();
        q.push_back(elem)
    }

    pub fn dequeue(&self) -> Option<T> {
        let mut q = self.queue.lock().unwrap();
        q.pop_front()
    }

    pub fn dump(&self) -> VecDeque<T> {
        self.replace(VecDeque::new())
    }

    pub fn replace(&self, new_value: VecDeque<T>) -> VecDeque<T> {
        let mut q = self.queue.lock().unwrap();
        std::mem::replace(&mut *q, new_value)
    }
}

/// A fake `IngressSelector` implementation based on a `FakeQueue` of ingress
/// message batches.
pub type FakeIngressSelector = FakeQueue<Vec<SignedIngress>>;

impl IngressSelector for FakeIngressSelector {
    fn get_ingress_payload(
        &self,
        _past_payloads: &dyn IngressSetQuery,
        _context: &ValidationContext,
        byte_limit: NumBytes,
    ) -> IngressPayload {
        let mut queue = self.queue.lock().unwrap();

        // Find the index of a payload that fits in byte_limit
        let payload_idx = queue
            .iter()
            .enumerate()
            .find(|(_, payloads)| {
                (payloads
                    .iter()
                    .map(|payload| payload.count_bytes())
                    .sum::<usize>() as u64)
                    < byte_limit.get()
            })
            .map(|(idx, _)| idx);

        // Return the found payload or default
        match payload_idx {
            Some(idx) => queue
                .remove(idx)
                .map(|payload| payload.into())
                .unwrap_or_default(),
            None => IngressPayload::default(),
        }
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
