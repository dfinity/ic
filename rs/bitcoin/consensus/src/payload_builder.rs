use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_interfaces::{
    self_validating_payload::{SelfValidatingPayloadBuilder, SelfValidatingPayloadValidationError},
    state_manager::{StateManager, StateManagerError},
};
use ic_logger::{log, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    CountBytes, Height, NumBytes,
};
use std::sync::Arc;
use thiserror::Error;

const BUILD_PAYLOAD_STATUS_SUCCESS: &str = "success";
const VALIDATION_STATUS_VALID: &str = "valid";
const INVALID_SELF_VALIDATING_PAYLOAD: &str = "InvalidSelfValidatingPayload";

// Internal error type, to simplify error handling.
#[derive(Error, Debug)]
enum GetPayloadError {
    #[error("Error retrieving state at height {0}: {1}")]
    GetStateFailed(Height, StateManagerError),
}

impl GetPayloadError {
    // Returns the desired log level to be used with this `Error`.
    fn log_level(&self) -> slog::Level {
        match self {
            Self::GetStateFailed(..) => slog::Level::Warning,
        }
    }

    // Maps the `Error` to a `status` label value.
    fn to_label_value(&self) -> &str {
        match self {
            Self::GetStateFailed(..) => "GetStateFailed",
        }
    }
}

pub struct BitcoinPayloadBuilder {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: Arc<BitcoinPayloadBuilderMetrics>,
    log: ReplicaLogger,
}

impl BitcoinPayloadBuilder {
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            metrics: Arc::new(BitcoinPayloadBuilderMetrics::new(metrics_registry)),
            log,
        }
    }

    fn get_self_validating_payload_impl(
        &self,
        validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
        _byte_limit: NumBytes,
    ) -> Result<SelfValidatingPayload, GetPayloadError> {
        // Retrieve the `ReplicatedState` required by `validation_context`.
        let _state = self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|e| GetPayloadError::GetStateFailed(validation_context.certified_height, e))?
            .take();

        // TODO(EXC-784): read the requests from the state.
        // TODO(EXC-785): send request to bitcoin adapter and get response.

        Ok(SelfValidatingPayload {})
    }
}

impl SelfValidatingPayloadBuilder for BitcoinPayloadBuilder {
    fn get_self_validating_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
        byte_limit: NumBytes,
    ) -> SelfValidatingPayload {
        let timer = Timer::start();
        let payload = match self.get_self_validating_payload_impl(
            validation_context,
            past_payloads,
            byte_limit,
        ) {
            Ok(payload) => {
                match self.validate_self_validating_payload(
                    &payload,
                    validation_context,
                    past_payloads,
                ) {
                    Ok(_) => {
                        self.metrics
                            .observe_build_duration(BUILD_PAYLOAD_STATUS_SUCCESS, timer);
                        payload
                    }
                    Err(e) => {
                        log!(
                            self.log,
                            slog::Level::Error,
                            "Created an invalid SelfValidatingPayload: {:?}",
                            e
                        );
                        self.metrics
                            .observe_build_duration(INVALID_SELF_VALIDATING_PAYLOAD, timer);
                        SelfValidatingPayload::default()
                    }
                }
            }

            Err(e) => {
                log!(self.log, e.log_level(), "{}", e);
                self.metrics
                    .observe_build_duration(e.to_label_value(), timer);

                SelfValidatingPayload::default()
            }
        };

        debug_assert!(payload.count_bytes() <= byte_limit.get() as usize);
        payload
    }

    fn validate_self_validating_payload(
        &self,
        _payload: &SelfValidatingPayload,
        _validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let timer = Timer::start();

        // TODO(EXC-786): Validate the payload. For now we rubberstamp all payloads as
        // valid.

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, timer);
        Ok(0.into())
    }
}
