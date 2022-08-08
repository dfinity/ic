use crate::consensus::metrics::{
    PayloadBuilderMetrics, CRITICAL_ERROR_PAYLOAD_TOO_LARGE, CRITICAL_ERROR_VALIDATION_NOT_PASSED,
};
use ic_interfaces::{
    canister_http::CanisterHttpPayloadBuilder, consensus::PayloadValidationError,
    ingress_manager::IngressSelector, messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
};
use ic_logger::{error, warn, ReplicaLogger};
use ic_types::{
    batch::{
        BatchPayload, CanisterHttpPayload, IngressPayload, SelfValidatingPayload, ValidationContext,
    },
    consensus::Payload,
    CountBytes, Height, NumBytes, Time,
};
use std::sync::Arc;

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
    /// - `past_payloads`: All [`BatchPayload`]s from the certified height to the tip.
    /// - `logger`: Access to a [`ReplicaLogger`]
    ///
    /// # Returns:
    /// - The size of the payload in [`NumBytes`]
    pub(crate) fn build_payload(
        &self,
        payload: &mut BatchPayload,
        height: Height,
        validation_context: &ValidationContext,
        max_size: NumBytes,
        past_payloads: &[(Height, Time, Payload)],
        metrics: &PayloadBuilderMetrics,
        logger: &ReplicaLogger,
    ) -> NumBytes {
        match self {
            Self::Ingress(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads, validation_context);
                let ingress =
                    builder.get_ingress_payload(&past_payloads, validation_context, max_size);
                let size = NumBytes::new(ingress.count_bytes() as u64);

                // Validate the ingress payload as a safety measure
                if let Err(err) =
                    builder.validate_ingress_payload(&ingress, &past_payloads, validation_context)
                {
                    error!(
                        logger,
                        "Ingress payload did not pass validation, this is a bug, {:?} @{}",
                        err,
                        CRITICAL_ERROR_VALIDATION_NOT_PASSED
                    );

                    metrics.critical_error_validation_not_passed.inc();
                    payload.ingress = IngressPayload::default();
                    return NumBytes::new(0);
                }

                // Perform an additional size check
                if size > max_size {
                    error!(
                        logger,
                        "IngressPayload is larger than byte limits, this is a bug, @{}",
                        CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                    );

                    metrics.cricital_error_payload_too_large.inc();
                    payload.ingress = IngressPayload::default();
                    return NumBytes::new(0);
                }

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
                );

                // NOTE: At the moment, the payload builder is calling it's own validator,
                // so we don't have to do that here

                // Check that the size limit is respected
                if size > max_size {
                    error!(
                        logger,
                        "SelfValidatingPayload is larger than byte_limit. This is a bug, @{}",
                        CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                    );

                    metrics.cricital_error_payload_too_large.inc();
                    payload.self_validating = SelfValidatingPayload::default();
                    NumBytes::new(0)
                } else {
                    payload.self_validating = self_validating;
                    size
                }
            }
            Self::CanisterHttp(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);

                let canister_http = builder.get_canister_http_payload(
                    height,
                    validation_context,
                    &past_payloads,
                    max_size,
                );
                let size = NumBytes::new(canister_http.count_bytes() as u64);

                // Check validation as safety measure
                match builder.validate_canister_http_payload(
                    height,
                    &canister_http,
                    validation_context,
                    &past_payloads,
                ) {
                    Ok(validation_size) => {
                        if validation_size > size {
                            error!(
                                logger,
                                "CanisterHttp is larger than byte_limit. This is a bug, @{}",
                                CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                            );

                            metrics.cricital_error_payload_too_large.inc();
                            payload.canister_http = CanisterHttpPayload::default();
                            return NumBytes::new(0);
                        }

                        // NOTE: This is not a critical error, since it does not break any invariants.
                        // It is nice to know about it nonetheless
                        if validation_size < size {
                            warn!(
                                logger,
                                "CanisterHttp validator reported size different from builder"
                            );
                        }

                        payload.canister_http = canister_http;
                        size
                    }
                    Err(err) => {
                        error!(
                            logger,
                            "CanisterHttp payload did not pass validation, this is a bug, {:?} @{}",
                            err,
                            CRITICAL_ERROR_VALIDATION_NOT_PASSED
                        );

                        metrics.critical_error_validation_not_passed.inc();
                        payload.canister_http = CanisterHttpPayload::default();
                        NumBytes::new(0)
                    }
                }
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
        height: Height,
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
                    height,
                    &payload.canister_http,
                    validation_context,
                    &past_payloads,
                )?)
            }
        }
    }
}
