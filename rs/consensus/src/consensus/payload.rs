// TODO: Remove after implementing functional change
#![allow(dead_code)]

//! Consensus internal traits that are used in the `payload_builder`.
use ic_interfaces::{consensus::PayloadValidationError, payload::BatchPayloadSectionBuilder};
use ic_types::{
    batch::{
        BatchPayload, CanisterHttpPayload, IngressPayload, SelfValidatingPayload,
        ValidationContext, XNetPayload,
    },
    consensus::Payload,
    Height, NumBytes, Time,
};

// NOTE: Unfortunately, the BatchPayloadSectionAdapter has to be implemented as an enum, because of a compiler bug,
// that effectively prevents mutually exclusive traits to be implemted.
// See: https://github.com/rust-lang/rust/issues/20400

/// Maps [`BatchPayloadSectionBuilder`] implementations onto the
/// [`BatchPayload`]. By requiring this adapter, we can eliminate the generic inside [`BatchPayloadSectionBuilder`] and
/// make sure that only the consensus crate has access to the whole [`BatchPayload`].
enum BatchPayloadSectionAdapter {
    Ingress(Box<dyn BatchPayloadSectionBuilder<IngressPayload>>),
    XNet(Box<dyn BatchPayloadSectionBuilder<XNetPayload>>),
    SelfValidating(Box<dyn BatchPayloadSectionBuilder<SelfValidatingPayload>>),
    CanisterHttps(Box<dyn BatchPayloadSectionBuilder<CanisterHttpPayload>>),
}

impl BatchPayloadSectionAdapter {
    fn build_payload(
        &self,
        payload: &mut BatchPayload,
        validation_context: &ValidationContext,
        max_size: NumBytes,
        priority: usize,
        past_payloads: &[(Height, Time, Payload)],
    ) -> NumBytes {
        match self {
            Self::Ingress(builder) => {
                let (payload_section, size) =
                    builder.build_payload(validation_context, max_size, priority, past_payloads);
                payload.ingress = payload_section;
                size
            }
            Self::XNet(builder) => {
                let (payload_section, size) =
                    builder.build_payload(validation_context, max_size, priority, past_payloads);
                payload.xnet = payload_section;
                size
            }
            Self::SelfValidating(builder) => {
                let (payload_section, size) =
                    builder.build_payload(validation_context, max_size, priority, past_payloads);
                payload.self_validating = payload_section;
                size
            }
            Self::CanisterHttps(builder) => {
                let (payload_section, size) =
                    builder.build_payload(validation_context, max_size, priority, past_payloads);
                payload.canister_http = payload_section;
                size
            }
        }
    }

    fn validate_payload(
        &self,
        payload: &BatchPayload,
        validation_context: &ValidationContext,
        past_payloads: &[(Height, Time, Payload)],
    ) -> Result<NumBytes, PayloadValidationError> {
        match self {
            Self::Ingress(builder) => builder
                .validate_payload(&payload.ingress, validation_context, past_payloads)
                .map_err(PayloadValidationError::from),
            Self::XNet(builder) => builder
                .validate_payload(&payload.xnet, validation_context, past_payloads)
                .map_err(PayloadValidationError::from),
            Self::SelfValidating(builder) => builder
                .validate_payload(&payload.self_validating, validation_context, past_payloads)
                .map_err(PayloadValidationError::from),
            Self::CanisterHttps(builder) => builder
                .validate_payload(&payload.canister_http, validation_context, past_payloads)
                .map_err(PayloadValidationError::from),
        }
    }
}
