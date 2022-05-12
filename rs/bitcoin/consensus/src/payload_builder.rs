use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_btc_types_internal::{BitcoinAdapterResponse, BitcoinAdapterResponseWrapper};
use ic_interfaces::{
    registry::RegistryClient,
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadBuilder,
        SelfValidatingPayloadValidationError, SelfValidatingTransientValidationError,
    },
};
use ic_interfaces_bitcoin_adapter_client::{BitcoinAdapterClient, Options};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{log, warn, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::BitcoinFeature;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    registry::RegistryClientError,
    CountBytes, Height, NumBytes, SubnetId,
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
    _bitcoin_mainnet_adapter_client: Box<dyn BitcoinAdapterClient>,
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
            _bitcoin_mainnet_adapter_client: bitcoin_mainnet_adapter_client,
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
        priority: usize,
    ) -> Result<SelfValidatingPayload, GetPayloadError> {
        // Retrieve the `ReplicatedState` required by `validation_context`.
        let state = self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|e| GetPayloadError::GetStateFailed(validation_context.certified_height, e))?
            .take();

        let bitcoin_feature = self
            .registry
            .get_features(self.subnet_id, validation_context.registry_version)
            .map_err(GetPayloadError::GetRegistryFailed)?
            .unwrap_or_default()
            .bitcoin_testnet();

        // We should only send requests to the adapter if the bitcoin testnet
        // feature is enabled, otherwise return an empty payload.
        match bitcoin_feature {
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
                for (callback_id, request) in state.bitcoin().adapter_requests_iter() {
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
                    let result = self.bitcoin_testnet_adapter_client.send_request(
                        request.request.clone(),
                        Options {
                            timeout: Some(std::time::Duration::from_millis(50)),
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

                            // This is a special case:
                            // If priority is 0 (i.e. highest), and we have not included a response yet, but the next block is already
                            // oversized, we include that single block anyway and immidiately return.
                            // We will also report `byte_limit` as the size.
                            //
                            // For this block to be accepted by the validator, it is crucial that the following invariant holds:
                            // if priority == 0 then byte_size == max_block_payload_size_bytes.
                            // Just to be 100% sure, we also check that invariant here as well.
                            if priority == 0
                                && responses.is_empty()
                                && response_size > byte_limit.get()
                                && self
                                    .registry
                                    .get_max_block_payload_size_bytes(
                                        self.subnet_id,
                                        validation_context.registry_version,
                                    )
                                    .unwrap_or(None)
                                    .unwrap_or(0)
                                    == byte_limit.get()
                            {
                                warn!(
                                    self.log,
                                    "SelfValidatingPayload Size exception was triggered"
                                );
                                responses.push(response);
                                return Ok(SelfValidatingPayload::new(responses));
                            }

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

    fn validate_self_validating_payload_impl(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
        _past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let timer = Timer::start();

        // TODO(EXC-786): Validate the payload. For now we rubberstamp all payloads as
        // valid.

        // An empty block is always valid.
        if *payload == SelfValidatingPayload::default() {
            return Ok(0.into());
        }

        // Reject nonempty payloads, if the bitcoin feature is disabled in the registry
        let bitcoin_feature = self
            .registry
            .get_features(self.subnet_id, validation_context.registry_version)
            .map_err(|err| {
                SelfValidatingPayloadValidationError::Transient(
                    SelfValidatingTransientValidationError::GetRegistryFailed(err),
                )
            })?
            .unwrap_or_default()
            .bitcoin_testnet();

        if bitcoin_feature != BitcoinFeature::Enabled {
            return Err(SelfValidatingPayloadValidationError::Permanent(
                InvalidSelfValidatingPayload::Disabled,
            ));
        }

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, timer);

        let size = NumBytes::new(payload.count_bytes() as u64);

        // NOTE: Bitcoin payload is special in that the IC can not ultimately decide the size of the blocks.
        // Rather, it is up to the bitcoin network to decide the block sizes.
        // For that reason, the validator allows oversized blocks, if there is only one block in the payload.
        // Exploiting this as a DOS is infeasible, since it would require the attacker to bloat the blocks on the
        // bitcoin network.
        if payload.num_bitcoin_blocks() == 1 {
            Ok(size.min(NumBytes::from(
                self.registry
                    .get_max_block_payload_size_bytes(
                        self.subnet_id,
                        validation_context.registry_version,
                    )
                    .map_err(|err| {
                        SelfValidatingPayloadValidationError::Transient(
                            SelfValidatingTransientValidationError::GetRegistryFailed(err),
                        )
                    })?
                    .unwrap_or_else(|| size.get()),
            )))
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
        priority: usize,
    ) -> (SelfValidatingPayload, NumBytes) {
        let timer = Timer::start();
        let payload = match self.get_self_validating_payload_impl(
            validation_context,
            past_payloads,
            byte_limit,
            priority,
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
