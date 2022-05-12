use std::sync::Arc;

use ic_interfaces::{
    canister_http::CanisterHttpPayloadBuilder, consensus::PayloadValidationError,
    ingress_manager::IngressSelector, messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::Payload,
    CountBytes, Height, NumBytes, Time,
};

/// A [`BatchPayloadSectionBuilder`] builds an individual section of the
/// [`BatchPayload`](ic_types::batch::BatchPayload).
///
/// # Invariants:
/// It is **crucial** that any payload returned by
/// [`build_payload`](BatchPayloadSectionBuilder::build_payload)
/// succeeds when passed into
/// [`validate_payload`](BatchPayloadSectionBuilder::validate_payload),
/// given the same arguments for [`ValidationContext`] and `past_payloads`,
/// and that the following constraints are satisfied:
///
/// - Payload size returned by [`build_payload`](BatchPayloadSectionBuilder::build_payload)
///     `<=` `max_size` passed into [`build_payload`](BatchPayloadSectionBuilder::build_payload)
/// - Payload size returned by [`validate_payload`](BatchPayloadSectionBuilder::validate_payload)
///     `<=` payload size returned by [`build_payload`](BatchPayloadSectionBuilder::build_payload)
///
/// It is advised to call the validation function after building the payload to be 100% sure.
// [build_payload]: (BatchPayloadSectionBuilder::build_payload)
// [validate_payload]: (BatchPayloadSectionBuilder::validate_payload)
pub(crate) enum BatchPayloadSectionBuilder {
    Ingress(Arc<dyn IngressSelector>),
    XNet(Arc<dyn XNetPayloadBuilder>),
    SelfValidating(Arc<dyn SelfValidatingPayloadBuilder>),
    CanisterHttp(Arc<dyn CanisterHttpPayloadBuilder>),
}

impl BatchPayloadSectionBuilder {
    /// Called to build the payload.
    ///
    /// # Arguments:
    /// - `validation_context`: The [`ValidationContext`], under which the payload must be valid.
    /// - `max_size`: The maximum size in [`NumBytes`], that the payload section has available in the current block.
    /// - `priority`: The order in which the individual [`BatchPayloadSectionBuilder`] have been called.
    /// - `past_payloads`: All [`BatchPayload`]s from the certified height to the tip.
    ///
    /// # Returns:
    /// The [`BatchPayloadSectionType`]. If there is no suitable payload, return [`Default`].
    /// The size of the payload in [`NumBytes`].
    pub(crate) fn build_payload(
        &self,
        payload: &mut BatchPayload,
        validation_context: &ValidationContext,
        max_size: NumBytes,
        priority: usize,
        past_payloads: &[(Height, Time, Payload)],
    ) -> NumBytes {
        match self {
            Self::Ingress(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads, validation_context);
                let ingress =
                    builder.get_ingress_payload(&past_payloads, validation_context, max_size);
                let size = NumBytes::new(ingress.count_bytes() as u64);

                payload.ingress = ingress;
                size
            }
            Self::XNet(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                let xnet = builder.get_xnet_payload(validation_context, &past_payloads, max_size);
                let size = NumBytes::new(xnet.count_bytes() as u64);

                payload.xnet = xnet;
                size
            }
            Self::SelfValidating(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                let (self_validating, size) = builder.get_self_validating_payload(
                    validation_context,
                    &past_payloads,
                    max_size,
                    priority,
                );

                payload.self_validating = self_validating;
                size
            }
            Self::CanisterHttp(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);

                let canister_http =
                    builder.get_canister_http_payload(validation_context, &past_payloads, max_size);
                let size = NumBytes::new(canister_http.count_bytes() as u64);

                payload.canister_http = canister_http;
                size
            }
        }
    }

    /// Called to validate the payload.
    ///
    /// # Argument:
    /// - `payload`: The payload to verify.
    /// - `validation_context`: The [`ValidationContext`], under which to validate the payload.
    /// - `past_payloads`: All [`Payload`]s from the certified height to the tip.
    ///
    /// # Returns:
    /// **On success:** The size of the section as [`NumBytes`].
    /// **On error:**: Either a transient or permantent error.
    pub(crate) fn validate_payload(
        &self,
        payload: &BatchPayload,
        validation_context: &ValidationContext,
        past_payloads: &[(Height, Time, Payload)],
    ) -> Result<NumBytes, PayloadValidationError> {
        match self {
            Self::Ingress(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads, validation_context);
                builder.validate_ingress_payload(
                    &payload.ingress,
                    &past_payloads,
                    validation_context,
                )?;
                Ok(NumBytes::new(payload.ingress.count_bytes() as u64))
            }
            Self::XNet(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                Ok(builder.validate_xnet_payload(
                    &payload.xnet,
                    validation_context,
                    &past_payloads,
                )?)
            }
            Self::SelfValidating(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                Ok(builder.validate_self_validating_payload(
                    &payload.self_validating,
                    validation_context,
                    &past_payloads,
                )?)
            }
            BatchPayloadSectionBuilder::CanisterHttp(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                Ok(builder.validate_canister_http_payload(
                    &payload.canister_http,
                    validation_context,
                    &past_payloads,
                )?)
            }
        }
    }
}
