use crate::consensus::metrics::{
    PayloadBuilderMetrics, CRITICAL_ERROR_PAYLOAD_TOO_LARGE, CRITICAL_ERROR_VALIDATION_NOT_PASSED,
};
use ic_consensus_utils::pool_reader::filter_past_payloads;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::PayloadValidationError,
    ingress_manager::IngressSelector,
    messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
};
use ic_logger::{error, warn, ReplicaLogger};
use ic_types::{
    batch::{BatchPayload, IngressPayload, SelfValidatingPayload, XNetPayload},
    consensus::Payload,
    messages::MAX_XNET_PAYLOAD_SIZE_ERROR_MARGIN_PERCENT,
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
    QueryStats(Arc<dyn BatchPayloadBuilder>),
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
        proposal_context: &ProposalContext,
        max_size: NumBytes,
        past_payloads: &[(Height, Time, Payload)],
        payload_priority: usize,
        metrics: &PayloadBuilderMetrics,
        logger: &ReplicaLogger,
    ) -> NumBytes {
        match self {
            Self::Ingress(builder) => {
                let past_payloads = builder
                    .filter_past_payloads(past_payloads, proposal_context.validation_context);
                let ingress = builder.get_ingress_payload(
                    &past_payloads,
                    proposal_context.validation_context,
                    max_size,
                );
                let size = NumBytes::new(ingress.count_bytes() as u64);

                // Validate the ingress payload as a safety measure
                if let Err(err) = builder.validate_ingress_payload(
                    &ingress,
                    &past_payloads,
                    proposal_context.validation_context,
                ) {
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
                // NOTE: The XNetPayloadBuilder has some special properties that requires some extra logic.
                // The paylaod builder can not precisely predict the size of the payload, since it is an
                // underlying merkle tree (while most other payloads are simply vectors of messages).
                // If we would give the XNetPayloadBuilder the precise byte limit, it would occasionally
                // build oversized payloads. This would not be a soundness problem, since we currently
                // allow a 2x oversize margin. However, it would trigger errors. Therefore we only hand
                // the payload builder 95% of the available space. Though we can not prove that this would
                // never create an oversized payload, we no longer spuriously trigger errors.

                let past_payloads = builder.filter_past_payloads(past_payloads);
                let (xnet, size) = builder.get_xnet_payload(
                    proposal_context.validation_context,
                    &past_payloads,
                    max_size * (100 - MAX_XNET_PAYLOAD_SIZE_ERROR_MARGIN_PERCENT) / 100,
                );

                if size > max_size {
                    if size > max_size * 2 {
                        error!(
                            logger,
                            "XNetPayload is larger than byte_limit. Max size: {} Actual size: {} \
                            This is a bug: {}",
                            max_size,
                            size,
                            CRITICAL_ERROR_PAYLOAD_TOO_LARGE
                        );

                        metrics.critical_error_payload_too_large.inc();
                        payload.xnet = XNetPayload::default();
                        return NumBytes::new(0);
                    } else {
                        warn!(
                            logger,
                            "XNetPayload is oversized but within margin. \
                            Max size: {} Actual size: {}",
                            max_size,
                            size
                        );
                    }
                }

                payload.xnet = xnet;
                size
            }
            Self::SelfValidating(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                let (self_validating, size) = builder.get_self_validating_payload(
                    proposal_context.validation_context,
                    &past_payloads,
                    max_size,
                    payload_priority,
                );

                // As a safety measure, the payload is validated, before submitting it.
                if let Err(e) = builder.validate_self_validating_payload(
                    &self_validating,
                    proposal_context.validation_context,
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

                let canister_http = builder.build_payload(
                    height,
                    max_size,
                    &past_payloads,
                    proposal_context.validation_context,
                );
                let size = NumBytes::new(canister_http.len() as u64);

                // Check validation as safety measure
                match builder.validate_payload(
                    height,
                    proposal_context,
                    &canister_http,
                    &past_payloads,
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
            Self::QueryStats(builder) => {
                let past_payloads: Vec<PastPayload> =
                    filter_past_payloads(past_payloads, |_, _, payload| {
                        if payload.is_summary() {
                            None
                        } else {
                            Some(&payload.as_ref().as_data().batch.query_stats)
                        }
                    });

                let query_stats = builder.build_payload(
                    height,
                    max_size,
                    &past_payloads,
                    proposal_context.validation_context,
                );
                let size = NumBytes::new(query_stats.len() as u64);

                // Check validation as safety measure
                match builder.validate_payload(
                    height,
                    proposal_context,
                    &query_stats,
                    &past_payloads,
                ) {
                    Ok(()) => {
                        payload.query_stats = query_stats;
                        size
                    }
                    Err(err) => {
                        error!(
                            logger,
                            "QueryStats payload did not pass validation, this is a bug, {:?} @{}",
                            err,
                            CRITICAL_ERROR_VALIDATION_NOT_PASSED
                        );

                        metrics.critical_error_validation_not_passed.inc();
                        payload.query_stats = vec![];
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
        proposal_context: &ProposalContext,
        past_payloads: &[(Height, Time, Payload)],
    ) -> Result<NumBytes, PayloadValidationError> {
        match self {
            Self::Ingress(builder) => {
                let past_payloads = builder
                    .filter_past_payloads(past_payloads, proposal_context.validation_context);
                builder.validate_ingress_payload(
                    &payload.ingress,
                    &past_payloads,
                    proposal_context.validation_context,
                )?;
                Ok(NumBytes::new(payload.ingress.count_bytes() as u64))
            }
            Self::XNet(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                Ok(builder.validate_xnet_payload(
                    &payload.xnet,
                    proposal_context.validation_context,
                    &past_payloads,
                )?)
            }
            Self::SelfValidating(builder) => {
                let past_payloads = builder.filter_past_payloads(past_payloads);
                Ok(builder.validate_self_validating_payload(
                    &payload.self_validating,
                    proposal_context.validation_context,
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
                    proposal_context,
                    &payload.canister_http,
                    &past_payloads,
                )?;

                Ok(NumBytes::new(payload.canister_http.len() as u64))
            }
            Self::QueryStats(builder) => {
                let past_payloads: Vec<PastPayload> =
                    filter_past_payloads(past_payloads, |_, _, payload| {
                        if payload.is_summary() {
                            None
                        } else {
                            Some(&payload.as_ref().as_data().batch.query_stats)
                        }
                    });

                builder.validate_payload(
                    height,
                    proposal_context,
                    &payload.query_stats,
                    &past_payloads,
                )?;

                Ok(NumBytes::new(payload.query_stats.len() as u64))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::messaging::XNetPayloadValidationError;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{batch::ValidationContext, time::UNIX_EPOCH, RegistryVersion};

    struct TestXNetPayloadBuilder {
        return_size: u64,
        assert_size_min: u64,
        assert_size_max: u64,
    }

    impl XNetPayloadBuilder for TestXNetPayloadBuilder {
        fn get_xnet_payload(
            &self,
            _validation_context: &ValidationContext,
            _past_payloads: &[&XNetPayload],
            byte_limit: NumBytes,
        ) -> (XNetPayload, NumBytes) {
            assert!(byte_limit <= self.assert_size_max.into());
            assert!(byte_limit >= self.assert_size_min.into());
            (XNetPayload::default(), NumBytes::new(self.return_size))
        }

        fn validate_xnet_payload(
            &self,
            _payload: &XNetPayload,
            _validation_context: &ValidationContext,
            _past_payloads: &[&XNetPayload],
        ) -> Result<NumBytes, XNetPayloadValidationError> {
            Ok(NumBytes::new(self.return_size))
        }
    }

    /// Test that the margin for XNet is calculated correctly
    #[test]
    fn xnet_margin() {
        let validation_context = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &validation_context,
        };

        let metrics = PayloadBuilderMetrics::new(MetricsRegistry::default());
        let mut payload = BatchPayload::default();

        // Test that the size passed to the XNetPayloadBuilder is actually smaller than the maximum size
        // and that a slightly larger payload will still pass
        let payload_builder = BatchPayloadSectionBuilder::XNet(Arc::new(TestXNetPayloadBuilder {
            return_size: 4 * 1024 * 1024 + 1000,
            assert_size_min: 3 * 1024 * 1024,
            assert_size_max: 4 * 1024 * 1024 - 1000,
        }));
        payload_builder.build_payload(
            &mut payload,
            Height::new(1),
            &proposal_context,
            NumBytes::new(4 * 1024 * 1024),
            &[],
            0,
            &metrics,
            &no_op_logger(),
        );
        assert_eq!(metrics.critical_error_payload_too_large.get(), 0);

        // Test that for small limits the passed size will be 0
        // and that a 2x oversized payload will raise a critical error
        let payload_builder = BatchPayloadSectionBuilder::XNet(Arc::new(TestXNetPayloadBuilder {
            return_size: 8 * 1024 * 1024 + 1000,
            assert_size_min: 0,
            assert_size_max: 19_000,
        }));
        payload_builder.build_payload(
            &mut payload,
            Height::new(1),
            &proposal_context,
            NumBytes::new(20_000),
            &[],
            0,
            &metrics,
            &no_op_logger(),
        );
        assert_eq!(metrics.critical_error_payload_too_large.get(), 1);
        assert_eq!(payload.xnet, XNetPayload::default());
    }
}
