#![allow(dead_code, unused_variables)]

mod parse;
#[cfg(test)]
mod tests;

use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_btc_interface::Network;
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
};
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload},
    consensus::{PayloadPermanentError, PayloadValidationError},
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadBuilder,
        SelfValidatingPayloadValidationError, SelfValidatingTransientValidationError,
    },
    validation::ValidationError,
};
use ic_interfaces_adapter_client::{Options, RpcAdapterClient};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManagerError, StateReader};
use ic_logger::{log, ReplicaLogger};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext},
    messages::CallbackId,
    CountBytes, Height, NumBytes, SubnetId,
};
use std::{collections::BTreeSet, sync::Arc};
use thiserror::Error;

const ADAPTER_REQUEST_STATUS_FAILURE: &str = "failed";
const ADAPTER_REQUEST_STATUS_SUCCESS: &str = "success";
const BUILD_PAYLOAD_STATUS_SUCCESS: &str = "success";
const VALIDATION_STATUS_VALID: &str = "valid";

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
    state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
    metrics: Arc<BitcoinPayloadBuilderMetrics>,
    bitcoin_mainnet_adapter_client: Box<
        dyn RpcAdapterClient<
            BitcoinAdapterRequestWrapper,
            Response = BitcoinAdapterResponseWrapper,
        >,
    >,
    bitcoin_testnet_adapter_client: Box<
        dyn RpcAdapterClient<
            BitcoinAdapterRequestWrapper,
            Response = BitcoinAdapterResponseWrapper,
        >,
    >,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient + Send + Sync>,
    log: ReplicaLogger,
}

impl BitcoinPayloadBuilder {
    pub fn new(
        state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        bitcoin_mainnet_adapter_client: Box<
            dyn RpcAdapterClient<
                BitcoinAdapterRequestWrapper,
                Response = BitcoinAdapterResponseWrapper,
            >,
        >,
        bitcoin_testnet_adapter_client: Box<
            dyn RpcAdapterClient<
                BitcoinAdapterRequestWrapper,
                Response = BitcoinAdapterResponseWrapper,
            >,
        >,
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
        past_callback_ids: BTreeSet<u64>,
        byte_limit: NumBytes,
    ) -> Result<SelfValidatingPayload, GetPayloadError> {
        // Retrieve the `ReplicatedState` required by `validation_context`.
        let state = self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|e| GetPayloadError::GetStateFailed(validation_context.certified_height, e))?
            .take();

        let mut responses = vec![];
        let mut current_payload_size: u64 = 0;

        for (callback_id, request) in bitcoin_requests_iter(&state) {
            // We have already created a payload with the response for
            // this callback id, so skip it.
            if past_callback_ids.contains(&callback_id.get()) {
                continue;
            }

            let adapter_client = match request.network() {
                Network::Mainnet => &self.bitcoin_mainnet_adapter_client,
                Network::Testnet | Network::Regtest => &self.bitcoin_testnet_adapter_client,
            };

            // Send request to the adapter.
            let timer = Timer::start();
            let result = adapter_client.send_blocking(request.clone(), Options::default());

            match result {
                Ok(response_wrapper) => {
                    self.metrics.observe_adapter_request_duration(
                        ADAPTER_REQUEST_STATUS_SUCCESS,
                        request.to_request_type_label(),
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

        Ok(SelfValidatingPayload::new(responses))
    }

    fn validate_self_validating_payload_impl(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
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

        let past_callback_ids: BTreeSet<u64> = past_payloads
            .iter()
            .flat_map(|x| x.get())
            .map(|x| x.callback_id)
            .collect();

        let payload = match self.get_self_validating_payload_impl(
            validation_context,
            past_callback_ids,
            byte_limit,
        ) {
            Ok(payload) => {
                self.metrics
                    .observe_build_duration(BUILD_PAYLOAD_STATUS_SUCCESS, timer);
                payload
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
        _past_payloads: &[&SelfValidatingPayload],
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        self.validate_self_validating_payload_impl(payload, validation_context)
    }
}

// Returns an iterator that iterates through the bitcoin requests in the state.
fn bitcoin_requests_iter(
    state: &ReplicatedState,
) -> impl std::iter::Iterator<Item = (&CallbackId, BitcoinAdapterRequestWrapper)> {
    let subnet_call_context_manager = &state.metadata.subnet_call_context_manager;
    subnet_call_context_manager
        .bitcoin_send_transaction_internal_contexts
        .iter()
        .map(|(callback_id, context)| {
            (
                callback_id,
                BitcoinAdapterRequestWrapper::SendTransactionRequest(context.payload.clone()),
            )
        })
        .chain(
            subnet_call_context_manager
                .bitcoin_get_successors_contexts
                .iter()
                .map(|(callback_id, context)| {
                    (
                        callback_id,
                        BitcoinAdapterRequestWrapper::GetSuccessorsRequest(context.payload.clone()),
                    )
                }),
        )
}

impl BatchPayloadBuilder for BitcoinPayloadBuilder {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        let timer = Timer::start();

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = match self.get_self_validating_payload_impl(context, delivered_ids, max_size)
        {
            Ok(payload) => payload,
            Err(e) => {
                log!(self.log, e.log_level(), "{}", e);
                self.metrics
                    .observe_build_duration(e.to_label_value(), timer);

                return vec![];
            }
        };

        parse::payload_to_bytes(&payload, max_size)
    }

    fn validate_payload(
        &self,
        height: Height,
        payload: &[u8],
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = parse::bytes_to_payload(payload).map_err(|e| {
            ValidationError::Permanent(PayloadPermanentError::SelfValidatingPayloadValidationError(
                InvalidSelfValidatingPayload::DecodeError(e),
            ))
        })?;

        let _ = self.validate_self_validating_payload_impl(&payload, context)?;
        Ok(())
    }
}

// TODO: Into Messages
