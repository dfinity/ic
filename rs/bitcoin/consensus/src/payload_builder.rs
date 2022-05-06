use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_btc_types_internal::{BitcoinAdapterResponse, BitcoinAdapterResponseWrapper};
use ic_interfaces::{
    payload::BatchPayloadSectionBuilder,
    self_validating_payload::{SelfValidatingPayloadBuilder, SelfValidatingPayloadValidationError},
};
use ic_interfaces_bitcoin_adapter_client::{BitcoinAdapterClient, Options};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{log, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_subnet_features::BitcoinFeature;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    consensus::Payload,
    CountBytes, Height, NumBytes, Time,
};
use std::sync::Arc;
use thiserror::Error;

const ADAPTER_REQUEST_STATUS_FAILURE: &str = "failed";
const ADAPTER_REQUEST_STATUS_SUCCESS: &str = "success";
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
    _bitcoin_mainnet_adapter_client: Arc<dyn BitcoinAdapterClient>,
    bitcoin_testnet_adapter_client: Arc<dyn BitcoinAdapterClient>,
    log: ReplicaLogger,
}

impl BitcoinPayloadBuilder {
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        bitcoin_mainnet_adapter_client: Arc<dyn BitcoinAdapterClient>,
        bitcoin_testnet_adapter_client: Arc<dyn BitcoinAdapterClient>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            metrics: Arc::new(BitcoinPayloadBuilderMetrics::new(metrics_registry)),
            _bitcoin_mainnet_adapter_client: bitcoin_mainnet_adapter_client,
            bitcoin_testnet_adapter_client,
            log,
        }
    }

    fn get_self_validating_payload_impl(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
        byte_limit: NumBytes,
    ) -> Result<SelfValidatingPayload, GetPayloadError> {
        // Retrieve the `ReplicatedState` required by `validation_context`.
        let state = self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|e| GetPayloadError::GetStateFailed(validation_context.certified_height, e))?
            .take();

        // We should only send requests to the adapter if the bitcoin testnet
        // feature is enabled, otherwise return an empty payload.
        match state.metadata.own_subnet_features.bitcoin_testnet() {
            BitcoinFeature::Disabled => Ok(SelfValidatingPayload::default()),
            BitcoinFeature::Paused => Ok(SelfValidatingPayload::default()),
            BitcoinFeature::Enabled => {
                let past_callback_ids: std::collections::HashSet<u64> = past_payloads
                    .iter()
                    .flat_map(|x| x.get())
                    .map(|x| x.callback_id)
                    .collect();

                let mut responses = vec![];
                let mut current_payload_size: u64 = 0;
                for (callback_id, request) in state.bitcoin_testnet().adapter_requests_iter() {
                    // We have already created a payload with the response for
                    // this callback id, so skip it.
                    if past_callback_ids.contains(callback_id) {
                        continue;
                    }

                    // If we're above the allowed byte_limit, stop sending more requests.
                    if current_payload_size >= byte_limit.get() {
                        break;
                    }

                    let timer = Timer::start();
                    let result = self
                        .bitcoin_testnet_adapter_client
                        .send_request(request.request.clone(), Options::default());
                    match result {
                        Ok(response_wrapper) => {
                            self.metrics.observe_adapter_request_duration(
                                ADAPTER_REQUEST_STATUS_SUCCESS,
                                request.request.to_request_type_label(),
                                timer,
                            );
                            if let BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) =
                                &response_wrapper
                            {
                                self.metrics
                                    .observe_blocks_per_get_successors_response(r.blocks.len());
                            }
                            let response = BitcoinAdapterResponse {
                                response: response_wrapper,
                                callback_id: *callback_id,
                            };
                            let response_size = response.count_bytes() as u64;
                            self.metrics.observe_adapter_response_size(response_size);
                            // Ensure we don't exceed the byte limit by
                            // adding a new response but also ensure we
                            // allow at least one response to be included.
                            if !responses.is_empty()
                                && response_size + current_payload_size > byte_limit.get()
                            {
                                break;
                            }
                            current_payload_size += response_size;
                            responses.push(response);
                        }
                        Err(err) => {
                            self.metrics.observe_adapter_request_duration(
                                ADAPTER_REQUEST_STATUS_FAILURE,
                                request.request.to_request_type_label(),
                                timer,
                            );
                            log!(
                                self.log,
                                slog::Level::Error,
                                "Sending the request with callback id {} to the adapter failed with {:?}",
                                callback_id, err
                            );
                        }
                    }
                }
                Ok(SelfValidatingPayload::new(responses))
            }
        }
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

impl BatchPayloadSectionBuilder<SelfValidatingPayload> for BitcoinPayloadBuilder {
    fn build_payload(
        &self,
        validation_context: &ValidationContext,
        max_size: NumBytes,
        _priority: usize,
        past_payloads: &[(Height, Time, Payload)],
    ) -> (SelfValidatingPayload, NumBytes) {
        let past_payloads = self.filter_past_payloads(past_payloads);
        let payload =
            self.get_self_validating_payload(validation_context, &past_payloads, max_size);
        let size = NumBytes::new(payload.count_bytes() as u64);
        (payload, size)
    }

    fn validate_payload(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
        past_payloads: &[(Height, Time, Payload)],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let past_payloads = self.filter_past_payloads(past_payloads);
        self.validate_self_validating_payload(payload, validation_context, &past_payloads)
    }
}

#[cfg(test)]
mod tests;
