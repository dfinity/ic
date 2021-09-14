//! Message Routing public interfaces.
use crate::validation::ValidationError;
use ic_types::{
    batch::{Batch, ValidationContext, XNetPayload},
    Height, NumBytes,
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
        height: Height,
        validation_context: &ValidationContext,
        past_payloads: &[&XNetPayload],
        byte_limit: NumBytes,
    ) -> Result<XNetPayload, XNetPayloadError>;

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
}

/// Possible errors in making XNetPayload.
#[derive(Clone, Debug)]
pub enum XNetPayloadError {
    /// Payload making has started, but the result is not ready yet.
    Pending,
}

impl std::fmt::Display for XNetPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for XNetPayloadError {}
