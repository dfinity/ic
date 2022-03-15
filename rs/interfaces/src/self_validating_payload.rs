use crate::validation::ValidationError;

use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    consensus::Payload,
    Height, NumBytes, Time,
};

/// A SelfValidatingPayload error from which it is not possible to recover.
#[derive(Debug)]
pub enum InvalidSelfValidatingPayload {}

/// A SelfValidatingPayload error from which it may be possible to recover.
#[derive(Debug)]
pub enum SelfValidatingTransientValidationError {}

/// A SelfValidationPayload error that results from payload validation.
pub type SelfValidatingPayloadValidationError =
    ValidationError<InvalidSelfValidatingPayload, SelfValidatingTransientValidationError>;

pub trait SelfValidatingPayloadBuilder: Send + Sync {
    /// Produces a `SelfValidatingPayload` of maximum byte size `byte_limit`
    /// that is valid given a `ValidationContext` (certified height plus
    /// registry version) and `past_payloads` (the `SelfValidatingPayloads`
    /// from all blocks above the certified height, in descending block
    /// height order).
    fn get_self_validating_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
        byte_limit: NumBytes,
    ) -> SelfValidatingPayload;

    /// Checks whether the provided `SelfValidatingPayload` is valid given a
    /// `ValidationContext` (certified height and registry version) and
    /// `past_payloads` (the `SelfValidatingPayloads` from all blocks above the
    /// certified height, in descending block height order).
    ///
    /// If valid, returns the payload's `CountBytes`-like byte size (estimated,
    /// deterministic, using the exact same logic that
    /// `get_self_validating_payload()` uses for enforcing `byte_limit`);
    /// else returns a permanent or transient `ValidationError`.
    fn validate_self_validating_payload(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError>;

    /// Extracts the sequence of past `SelfValidatingPayloads` from `past_payloads`.
    fn filter_past_payloads<'a>(
        &self,
        past_payloads: &'a [(Height, Time, Payload)],
    ) -> Vec<&'a SelfValidatingPayload> {
        past_payloads
            .iter()
            .filter_map(|(_, _, payload)| {
                if payload.is_summary() {
                    None
                } else {
                    Some(&payload.as_ref().as_data().batch.self_validating)
                }
            })
            .collect()
    }
}

// TODO: Remove this once a real SelfValidatingPayloadBuilder is ready.
pub struct NoOpSelfValidatingPayloadBuilder {}

impl SelfValidatingPayloadBuilder for NoOpSelfValidatingPayloadBuilder {
    fn get_self_validating_payload(
        &self,
        _validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
        _byte_limit: NumBytes,
    ) -> SelfValidatingPayload {
        SelfValidatingPayload::default()
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
