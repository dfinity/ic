use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_btc_types::{Network, NetworkSnakeCase};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
};
use ic_interfaces::{
    registry::RegistryClient,
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadBuilder,
        SelfValidatingPayloadValidationError, SelfValidatingTransientValidationError,
    },
};
use ic_interfaces_bitcoin_adapter_client::{BitcoinAdapterClient, Options};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{log, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::BitcoinFeatureStatus;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    registry::RegistryClientError,
    CountBytes, Height, NumBytes, SubnetId,
};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
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

    #[error("Error retrieving registry {0}")]
    GetRegistryFailed(RegistryClientError),
}

impl GetPayloadError {
    // Returns the desired log level to be used with this `Error`.
    fn log_level(&self) -> slog::Level {
        match self {
            Self::GetStateFailed(..) => slog::Level::Warning,
            Self::GetRegistryFailed(..) => slog::Level::Warning,
        }
    }

    // Maps the `Error` to a `status` label value.
    fn to_label_value(&self) -> &str {
        match self {
            Self::GetStateFailed(..) => "GetStateFailed",
            Self::GetRegistryFailed(..) => "GetRegistryFailed",
        }
    }
}

pub struct BitcoinPayloadBuilder {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: Arc<BitcoinPayloadBuilderMetrics>,
    bitcoin_mainnet_adapter_client: Box<dyn BitcoinAdapterClient>,
    bitcoin_testnet_adapter_client: Box<dyn BitcoinAdapterClient>,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient + Send + Sync>,
    log: ReplicaLogger,
}

impl BitcoinPayloadBuilder {
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        bitcoin_mainnet_adapter_client: Box<dyn BitcoinAdapterClient>,
        bitcoin_testnet_adapter_client: Box<dyn BitcoinAdapterClient>,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient + Send + Sync>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            metrics: Arc::new(BitcoinPayloadBuilderMetrics::new(metrics_registry)),
            bitcoin_mainnet_adapter_client,
            bitcoin_testnet_adapter_client,
            subnet_id,
            registry,
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

        // If there are requests from the bitcoin wasm canister, then process those.
        if !state
            .metadata
            .subnet_call_context_manager
            .bitcoin_get_successors_contexts
            .is_empty()
        {
            return Ok(self.build_canister_payload(state, past_payloads, byte_limit));
        }

        let bitcoin_feature = self
            .registry
            .get_features(self.subnet_id, validation_context.registry_version)
            .map_err(GetPayloadError::GetRegistryFailed)?
            .unwrap_or_default()
            .bitcoin();

        // We should only send requests to the adapter if the bitcoin feature
        // is enabled or syncing, otherwise return an empty payload.
        match bitcoin_feature.status {
            BitcoinFeatureStatus::Disabled | BitcoinFeatureStatus::Paused => {
                Ok(SelfValidatingPayload::default())
            }
            BitcoinFeatureStatus::Enabled | BitcoinFeatureStatus::Syncing => {
                let adapter_client = match bitcoin_feature.network {
                    Network::Mainnet => &self.bitcoin_mainnet_adapter_client,
                    Network::Testnet | Network::Regtest => &self.bitcoin_testnet_adapter_client,
                };

                let past_callback_ids: std::collections::HashSet<u64> = past_payloads
                    .iter()
                    .flat_map(|x| x.get())
                    .map(|x| x.callback_id)
                    .collect();

                let mut responses = vec![];
                let mut current_payload_size: u64 = 0;
                for (callback_id, request) in state.bitcoin().adapter_requests_iter() {
                    // We have already created a payload with the response for
                    // this callback id, so skip it.
                    if past_callback_ids.contains(callback_id) {
                        continue;
                    }

                    // If we've reached the byte_limit, stop sending more requests.
                    if current_payload_size >= byte_limit.get() {
                        break;
                    }

                    let timer = Timer::start();
                    let result = adapter_client.send_request(
                        request.request.clone(),
                        Options {
                            timeout: Duration::from_millis(50),
                        },
                    );
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

                            if response_size + current_payload_size > byte_limit.get() {
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

    // Builds a payload for requests from the Bitcoin Wasm canister.
    // Support for the bitcoin replica requests will be removed from this file once the transition
    // to the bitcoin canister is complete (EXC-1239).
    fn build_canister_payload(
        &self,
        state: Arc<ReplicatedState>,
        past_payloads: &[&SelfValidatingPayload],
        byte_limit: NumBytes,
    ) -> SelfValidatingPayload {
        let mut responses = vec![];
        let mut current_payload_size: u64 = 0;

        let past_callback_ids: BTreeSet<u64> = past_payloads
            .iter()
            .flat_map(|x| x.get())
            .map(|x| x.callback_id)
            .collect();

        for (callback_id, context) in state
            .metadata
            .subnet_call_context_manager
            .bitcoin_get_successors_contexts
            .iter()
        {
            // We have already created a payload with the response for
            // this callback id, so skip it.
            if past_callback_ids.contains(&callback_id.get()) {
                continue;
            }

            let adapter_client = match context.payload.network {
                NetworkSnakeCase::Mainnet => &self.bitcoin_mainnet_adapter_client,
                NetworkSnakeCase::Testnet | NetworkSnakeCase::Regtest => {
                    &self.bitcoin_testnet_adapter_client
                }
            };

            // Send request to the adapter.
            let request =
                BitcoinAdapterRequestWrapper::CanisterGetSuccessorsRequest(context.payload.clone());
            let timer = Timer::start();
            let result = adapter_client.send_request(
                request.clone(),
                Options {
                    timeout: Duration::from_millis(50),
                },
            );

            match result {
                Ok(response_wrapper) => {
                    self.metrics.observe_adapter_request_duration(
                        ADAPTER_REQUEST_STATUS_SUCCESS,
                        request.to_request_type_label(),
                        timer,
                    );

                    if let BitcoinAdapterResponseWrapper::CanisterGetSuccessorsResponse(r) =
                        &response_wrapper
                    {
                        self.metrics
                            .observe_blocks_per_get_successors_response(r.blocks.len());
                    }

                    let response = BitcoinAdapterResponse {
                        response: response_wrapper,
                        callback_id: callback_id.get(),
                    };

                    let response_size = response.count_bytes() as u64;
                    self.metrics.observe_adapter_response_size(response_size);
                    if response_size + current_payload_size > byte_limit.get() {
                        // Stop if we're about to exceed the byte limit.
                        break;
                    }
                    current_payload_size += response_size;
                    responses.push(response);
                }
                Err(err) => {
                    self.metrics.observe_adapter_request_duration(
                        ADAPTER_REQUEST_STATUS_FAILURE,
                        request.to_request_type_label(),
                        timer,
                    );
                    log!(
                        self.log,
                        slog::Level::Error,
                        "Sending the request with callback id {} to the adapter failed with {:?}",
                        callback_id,
                        err
                    );
                }
            }
        }

        SelfValidatingPayload::new(responses)
    }

    fn validate_self_validating_payload_impl(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let timer = Timer::start();

        // An empty block is always valid.
        if *payload == SelfValidatingPayload::default() {
            return Ok(0.into());
        }

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, timer);

        let size = NumBytes::new(payload.count_bytes() as u64);

        // Check that the payload does not exceed the maximum block size
        let max_block_size = self
            .registry
            .get_max_block_payload_size_bytes(self.subnet_id, validation_context.registry_version)
            .map_err(|err| {
                SelfValidatingPayloadValidationError::Transient(
                    SelfValidatingTransientValidationError::GetRegistryFailed(err),
                )
            })?
            .unwrap_or_else(|| size.get());

        if size.get() > max_block_size {
            Err(SelfValidatingPayloadValidationError::Permanent(
                InvalidSelfValidatingPayload::PayloadTooBig,
            ))
        } else {
            Ok(size)
        }
    }
}

impl SelfValidatingPayloadBuilder for BitcoinPayloadBuilder {
    fn get_self_validating_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
        byte_limit: NumBytes,
    ) -> (SelfValidatingPayload, NumBytes) {
        let timer = Timer::start();
        let payload = match self.get_self_validating_payload_impl(
            validation_context,
            past_payloads,
            byte_limit,
        ) {
            Ok(payload) => {
                // As a safety measure, the payload is validated, before submitting it.
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

        let size = NumBytes::new(payload.count_bytes() as u64);
        (payload, size.min(byte_limit))
    }

    fn validate_self_validating_payload(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        self.validate_self_validating_payload_impl(payload, validation_context, past_payloads)
    }
}

#[cfg(test)]
mod tests;
