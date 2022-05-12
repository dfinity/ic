use crate::{payload::BatchPayloadSectionType, validation::ValidationError};
use ic_interfaces_state_manager::StateManagerError;

use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    consensus::Payload,
    registry::RegistryClientError,
    Height, NumBytes, Time,
};

/// A SelfValidatingPayload error from which it is not possible to recover.
#[derive(Debug)]
pub enum InvalidSelfValidatingPayload {
    Disabled,
}

/// A SelfValidatingPayload error from which it may be possible to recover.
#[derive(Debug)]
pub enum SelfValidatingTransientValidationError {
    GetStateFailed(Height, StateManagerError),
    GetRegistryFailed(RegistryClientError),
}

/// A SelfValidationPayload error that results from payload validation.
pub type SelfValidatingPayloadValidationError =
    ValidationError<InvalidSelfValidatingPayload, SelfValidatingTransientValidationError>;

impl BatchPayloadSectionType for SelfValidatingPayload {
    type PermanentValidationError = InvalidSelfValidatingPayload;
    type TransientValidationError = SelfValidatingTransientValidationError;
}

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
        priority: usize,
    ) -> (SelfValidatingPayload, NumBytes);

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
