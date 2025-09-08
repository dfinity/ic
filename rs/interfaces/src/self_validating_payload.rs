use crate::validation::ValidationError;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    Height, NumBytes, Time,
    batch::{SelfValidatingPayload, ValidationContext},
    consensus::Payload,
};

/// A SelfValidatingPayload is invalid.
#[derive(Debug)]
pub enum InvalidSelfValidatingPayloadReason {
    PayloadTooBig,
    DecodeError(ProxyDecodeError),
}

/// A SelfValidatingPayload validation failure which prevents us to determine whether the payload is
/// valid or not.
#[derive(Debug)]
pub enum SelfValidatingPayloadValidationFailure {}

/// A SelfValidationPayload error that results from payload validation.
pub type SelfValidatingPayloadValidationError =
    ValidationError<InvalidSelfValidatingPayloadReason, SelfValidatingPayloadValidationFailure>;

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
