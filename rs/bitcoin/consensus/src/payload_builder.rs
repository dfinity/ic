#![allow(dead_code, unused_variables)]

mod parse;
#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "proptest"))]
mod proptests;

use crate::metrics::BitcoinPayloadBuilderMetrics;
use ic_btc_interface::Network;
use ic_btc_replica_types::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    BitcoinReject,
};
use ic_config::bitcoin_payload_builder_config::Config;
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    consensus::{self, PayloadValidationError},
    self_validating_payload::{
        InvalidSelfValidatingPayloadReason, SelfValidatingPayloadBuilder,
        SelfValidatingPayloadValidationError,
    },
    validation::ValidationError,
};
use ic_interfaces_adapter_client::{Options, RpcAdapterClient};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManagerError, StateReader};
use ic_logger::{log, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{SelfValidatingPayload, ValidationContext, MAX_BITCOIN_PAYLOAD_IN_BYTES},
    messages::CallbackId,
    CountBytes, Height, NumBytes, SubnetId,
};
use std::{collections::BTreeSet, sync::Arc, time::Instant};
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
    config: Config,
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
        config: Config,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            metrics: Arc::new(BitcoinPayloadBuilderMetrics::new(metrics_registry)),
            bitcoin_mainnet_adapter_client,
            bitcoin_testnet_adapter_client,
            subnet_id,
            registry,
            config,
            log,
        }
    }

    fn get_self_validating_payload_impl(
        &self,
        validation_context: &ValidationContext,
        past_callback_ids: BTreeSet<u64>,
        byte_limit: NumBytes,
        priority: usize,
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
            let since = Instant::now();
            let result = adapter_client.send_blocking(
                request.clone(),
                Options {
                    timeout: self.config.adapter_timeout,
                },
            );

            // Update logs and metrics.
            match &result {
                Ok(wrapped_response) => {
                    self.metrics.observe_adapter_request_duration(
                        ADAPTER_REQUEST_STATUS_SUCCESS,
                        request.to_request_type_label(),
                        since,
                    );

                    if let BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) =
                        wrapped_response
                    {
                        self.metrics
                            .observe_blocks_per_get_successors_response(r.blocks.len());
                    }
                }
                Err(err) => {
                    self.metrics.observe_adapter_request_duration(
                        ADAPTER_REQUEST_STATUS_FAILURE,
                        request.to_request_type_label(),
                        since,
                    );

                    warn!(
                        self.log,
                        "Sending the request with callback id {} to the adapter failed with {:?}",
                        callback_id,
                        err
                    );
                }
            };

            // Build response.
            let response = BitcoinAdapterResponse {
                response: match result {
                    Ok(response_wrapper) => response_wrapper,
                    Err(err) => {
                        let error_message = err.to_string();
                        match request {
                            BitcoinAdapterRequestWrapper::SendTransactionRequest(context) => {
                                BitcoinAdapterResponseWrapper::SendTransactionReject(
                                    BitcoinReject {
                                        reject_code: RejectCode::SysTransient,
                                        message: error_message,
                                    },
                                )
                            }
                            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(context) => {
                                BitcoinAdapterResponseWrapper::GetSuccessorsReject(BitcoinReject {
                                    reject_code: RejectCode::SysTransient,
                                    message: error_message,
                                })
                            }
                        }
                    }
                },
                callback_id: callback_id.get(),
            };

            let response_size = response.count_bytes() as u64;
            self.metrics.observe_adapter_response_size(response_size);

            // NOTE: Currently, the theoretical maximum block size of Bitcoin is 4MiB, while the
            // maximum block size of the IC is also 4MiB. This makes it impossible to transport a
            // BTC block via an IC block, since including the metadata would make the block too
            // large. We therefore allow a response to be oversized, if it is the first response in
            // the block.
            // Since we tolerate up to 2x the size margin currently, this will pass validation
            // but trigger a warning.
            let first_response_in_block = current_payload_size == 0 && priority == 0;
            if response_size + current_payload_size > byte_limit.get() && !first_response_in_block {
                // Stop if we're about to exceed the byte limit.
                break;
            }
            current_payload_size += response_size;
            responses.push(response);
        }

        Ok(SelfValidatingPayload::new(responses))
    }

    fn validate_self_validating_payload_impl(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let since = Instant::now();

        // An empty block is always valid.
        if *payload == SelfValidatingPayload::default() {
            return Ok(0.into());
        }

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, since);
        let size = NumBytes::new(payload.count_bytes() as u64);

        Ok(size)
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
        let since = Instant::now();

        let past_callback_ids: BTreeSet<u64> = past_payloads
            .iter()
            .flat_map(|x| x.get())
            .map(|x| x.callback_id)
            .collect();

        let payload = match self.get_self_validating_payload_impl(
            validation_context,
            past_callback_ids,
            byte_limit,
            priority,
        ) {
            Ok(payload) => {
                self.metrics
                    .observe_build_duration(BUILD_PAYLOAD_STATUS_SUCCESS, since);
                payload
            }
            Err(e) => {
                log!(self.log, e.log_level(), "{}", e);
                self.metrics
                    .observe_build_duration(e.to_label_value(), since);

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
        let since = Instant::now();

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload =
            match self.get_self_validating_payload_impl(context, delivered_ids, max_size, 0) {
                Ok(payload) => payload,
                Err(e) => {
                    log!(self.log, e.log_level(), "{}", e);
                    self.metrics
                        .observe_build_duration(e.to_label_value(), since);

                    return vec![];
                }
            };

        parse::payload_to_bytes(&payload, max_size, &self.log)
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let raw_payload_len = payload.len();

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = parse::bytes_to_payload(payload).map_err(|e| {
            ValidationError::InvalidArtifact(
                consensus::InvalidPayloadReason::InvalidSelfValidatingPayload(
                    InvalidSelfValidatingPayloadReason::DecodeError(e),
                ),
            )
        })?;
        let num_responses = payload.len();

        let _ = self.validate_self_validating_payload_impl(
            &SelfValidatingPayload::new(payload),
            proposal_context.validation_context,
        )?;

        if raw_payload_len as u64 > MAX_BITCOIN_PAYLOAD_IN_BYTES {
            if num_responses == 1 {
                warn!(self.log, "Bitcoin Payload oversized");
            } else {
                return Err(ValidationError::InvalidArtifact(
                    consensus::InvalidPayloadReason::InvalidSelfValidatingPayload(
                        InvalidSelfValidatingPayloadReason::PayloadTooBig,
                    ),
                ));
            }
        }

        Ok(())
    }
}

impl IntoMessages<Vec<BitcoinAdapterResponse>> for BitcoinPayloadBuilder {
    fn into_messages(payload: &[u8]) -> Vec<BitcoinAdapterResponse> {
        parse::bytes_to_payload(payload)
            .expect("Failed to parse a payload that was already validated")
    }
}
