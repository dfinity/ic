use crate::consensus::metrics::{
    PayloadBuilderMetrics, CRITICAL_ERROR_PAYLOAD_TOO_LARGE, CRITICAL_ERROR_VALIDATION_NOT_PASSED,
};
use ic_consensus_utils::pool_reader::filter_past_payloads;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload},
    consensus::PayloadValidationError,
    ingress_manager::IngressSelector,
    messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
};
use ic_logger::{error, ReplicaLogger};
use ic_types::{
    batch::{BatchPayload, IngressPayload, SelfValidatingPayload, ValidationContext, XNetPayload},
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
    CanisterHttp(Arc<dyn BatchPayloadBuilder>),
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

                    metrics.critical_error_payload_too_large.inc();
                    payload.ingress = IngressPayload::default();
                    return NumBytes::new(0);
                }

                payload.ingress = ingress;
                size
            }
            Self::XNet(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                let (xnet, size) =
                    builder.get_xnet_payload(validation_context, &past_payloads, max_size);

                if size > max_size {
                    error!(
                        logger,
                        "XNetPayload is larger than byte_limit. This is a bug, @{}",
                        CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                    );

                    metrics.critical_error_payload_too_large.inc();
                    payload.xnet = XNetPayload::default();
                    NumBytes::new(0)
                } else {
                    payload.xnet = xnet;
                    size
                }
            }
            Self::SelfValidating(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                let (self_validating, size) = builder.get_self_validating_payload(
                    validation_context,
                    &past_payloads,
                    max_size,
                );

                // As a safety measure, the payload is validated, before submitting it.
                if let Err(e) = builder.validate_self_validating_payload(
                    &self_validating,
                    validation_context,
                    &past_payloads,
                ) {
                    error!(logger, "Created an invalid SelfValidatingPayload: {:?}", e);
                    payload.self_validating = SelfValidatingPayload::default();
                    return NumBytes::new(0);
                }

                // Check that the size limit is respected
                if size > max_size {
                    error!(
                        logger,
                        "SelfValidatingPayload is larger than byte_limit. This is a bug, @{}",
                        CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                    );

                    metrics.critical_error_payload_too_large.inc();
                    payload.self_validating = SelfValidatingPayload::default();
                    NumBytes::new(0)
                } else {
                    payload.self_validating = self_validating;
                    size
                }
            }
            Self::CanisterHttp(builder) => {
                let past_payloads: Vec<PastPayload> =
                    filter_past_payloads(past_payloads, |_, _, payload| {
                        if payload.is_summary() {
                            None
                        } else {
                            Some(&payload.as_ref().as_data().batch.canister_http)
                        }
                    });

                let canister_http =
                    builder.build_payload(height, max_size, &past_payloads, validation_context);
                let size = NumBytes::new(canister_http.len() as u64);

                // Check validation as safety measure
                match builder.validate_payload(
                    height,
                    &canister_http,
                    &past_payloads,
                    validation_context,
                ) {
                    Ok(()) => {
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
                        payload.canister_http = vec![];
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
            Self::CanisterHttp(builder) => {
                let past_payloads: Vec<PastPayload> =
                    filter_past_payloads(past_payloads, |_, _, payload| {
                        if payload.is_summary() {
                            None
                        } else {
                            Some(&payload.as_ref().as_data().batch.canister_http)
                        }
                    });

                builder.validate_payload(
                    height,
                    &payload.canister_http,
                    &past_payloads,
                    validation_context,
                )?;

                Ok(NumBytes::new(payload.canister_http.len() as u64))
            }
        }
    }
}
