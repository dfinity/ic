//! Message Routing public interfaces.
use crate::{payload::BatchPayloadSectionType, validation::ValidationError};
use ic_types::{
    batch::{Batch, ValidationContext, XNetPayload},
    consensus::Payload,
    Height, NumBytes, Time,
};

/// Errors that `MessageRouting` may return.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageRoutingError {
    /// The batch was not delivered because the batch queue is full.
    QueueIsFull,
    /// The batch is ignored because its number is not the one we
    /// expected.
    Ignored {
        expected_height: Height,
        actual_height: Height,
    },
}

/// XNet payload validation error details.
#[derive(Debug)]
pub enum InvalidXNetPayload {
    InvalidSlice(String),
    StateRemoved(Height),
}

#[derive(Debug)]
pub enum XNetTransientValidationError {
    StateNotCommittedYet(Height),
}

pub type XNetPayloadValidationError =
    ValidationError<InvalidXNetPayload, XNetTransientValidationError>;

impl BatchPayloadSectionType for XNetPayload {
    type PermanentValidationError = InvalidXNetPayload;
    type TransientValidationError = XNetTransientValidationError;
}
/// The public interface for the MessageRouting layer.
pub trait MessageRouting: Send + Sync {
    /// Delivers a finalized `Batch` for deterministic processing.
    ///
    /// Repeated calls with the same batch result in
    /// `MessageRoutingError::Ignored`.
    ///
    /// This function is asynchronous: it returns immediately after enqueuing
    /// the batch for processing and doesn't wait for execution of the batch to
    /// complete.
    fn deliver_batch(&self, b: Batch) -> Result<(), MessageRoutingError>;

    /// Returns the height of the next expected batch.
    fn expected_batch_height(&self) -> Height;
}

/// Interface for selecting `Streams` for inclusion into a `Payload`.
pub trait XNetPayloadBuilder: Send + Sync {
    /// Produces an `XNetPayload` of maximum byte size `byte_limit` that is
    /// valid given a `ValidationContext` (certified height plus registry
    /// version) and `past_payloads` (the `XNetPayloads` from all blocks
    /// above the certified height, in descending block height order).
    fn get_xnet_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> XNetPayload;

    /// Checks whether the provided `XNetPayload` is valid given a
    /// `ValidationContext` (certified height and registry version) and
    /// `past_payloads` (the `XNetPayloads` from all blocks above the certified
    /// height, in descending block height order).
    ///
    /// If valid, returns the payload's `CountBytes`-like byte size (estimated,
    /// deterministic, using the exact same logic that`get_xnet_payload()` uses
    /// for enforcing `byte_limit`); else returns a permanent or transient
    /// `ValidationError`.
    fn validate_xnet_payload(
        &self,
        payload: &XNetPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
    ) -> Result<NumBytes, XNetPayloadValidationError>;

    /// Extracts the sequence of past `XNetPayloads` from `past_payloads`.
    fn filter_past_payloads<'a>(
        &self,
        past_payloads: &'a [(Height, Time, Payload)],
    ) -> Vec<&'a XNetPayload> {
        past_payloads
            .iter()
            .filter_map(|(_, _, payload)| {
                if payload.is_summary() {
                    None
                } else {
                    Some(&payload.as_ref().as_data().batch.xnet)
                }
            })
            .collect()
    }
}
