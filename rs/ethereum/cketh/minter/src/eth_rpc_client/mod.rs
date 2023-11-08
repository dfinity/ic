use crate::eth_rpc::{self, JsonRpcError, RpcError};
use crate::eth_rpc::{
    are_errors_consistent, Block, BlockSpec, FeeHistory, FeeHistoryParams, GetLogsParam, Hash,
    HttpResponsePayload, LogEntry, ResponseSizeEstimate, SendRawTransactionResult,
};
use crate::eth_rpc_client::providers::{RpcNodeProvider, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EvmNetwork;
use crate::logs::{DEBUG, INFO};
use crate::numeric::TransactionCount;
use crate::state::State;
use async_trait::async_trait;
use candid::CandidType;
use ic_canister_log::log;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;

pub mod providers;
pub mod requests;
pub mod responses;

#[cfg(test)]
mod tests;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RpcTransport: Debug {
    // TODO: remove after refactoring to `call_json_rpc()`
    fn get_subnet_size() -> u32;

    async fn call_json_rpc<T: DeserializeOwned>(
        service: RpcNodeProvider,
        json: &str,
        max_response_bytes: u64,
    ) -> Result<T, RpcError>;
}

// Placeholder during refactoring
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for DefaultTransport {
    fn get_subnet_size() -> u32 {
        unimplemented!()
    }

    async fn call_json_rpc<T: DeserializeOwned>(
        _service: RpcNodeProvider,
        _json: &str,
        _max_response_bytes: u64,
    ) -> Result<T, RpcError> {
        unimplemented!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthRpcClient<T: RpcTransport> {
    chain: EvmNetwork,
    providers: Option<Vec<RpcNodeProvider>>,
    phantom: PhantomData<T>,
}

impl<T: RpcTransport> EthRpcClient<T> {
    pub const fn new(chain: EvmNetwork, providers: Option<Vec<RpcNodeProvider>>) -> Self {
        Self {
            chain,
            providers,
            phantom: PhantomData,
        }
    }

    pub const fn from_state(state: &State) -> Self {
        Self::new(state.ethereum_network(), None)
    }

    fn providers(&self) -> &[RpcNodeProvider] {
        match self.providers {
            Some(ref providers) => providers,
            None => match self.chain {
                EvmNetwork::Ethereum => MAINNET_PROVIDERS,
                EvmNetwork::Sepolia => SEPOLIA_PROVIDERS,
            },
        }
    }

    /// Query all providers in sequence until one returns an ok result
    /// (which could still be a JsonRpcResult::Error).
    /// If none of the providers return an ok result, return the last error.
    /// This method is useful in case a provider is temporarily down but should only be for
    /// querying data that is **not** critical since the returned value comes from a single provider.
    async fn sequential_call_until_ok<I, O>(
        &self,
        method: impl Into<String> + Clone,
        params: I,
        response_size_estimate: ResponseSizeEstimate,
    ) -> Result<O, RpcError>
    where
        I: Serialize + Clone,
        O: DeserializeOwned + HttpResponsePayload + Debug,
    {
        let mut last_result: Option<Result<O, RpcError>> = None;
        for provider in self.providers() {
            log!(
                DEBUG,
                "[sequential_call_until_ok]: calling provider: {:?}",
                provider
            );
            let result = eth_rpc::call::<T, _, _>(
                provider.api::<T>(),
                method.clone(),
                params.clone(),
                response_size_estimate,
            )
            .await;
            match result {
                Ok(value) => return Ok(value),
                Err(RpcError::JsonRpcError(json_rpc_error @ JsonRpcError { .. })) => {
                    log!(
                        INFO,
                        "Provider {provider:?} returned JSON-RPC error {json_rpc_error:?}",
                    );
                    last_result = Some(Err(json_rpc_error.into()));
                }
                Err(e) => {
                    log!(INFO, "Querying provider {provider:?} returned error {e:?}");
                    last_result = Some(Err(e));
                }
            };
        }
        last_result.unwrap_or_else(|| panic!("BUG: No providers in RPC client {:?}", self))
    }

    /// Query all providers in parallel and return all results.
    /// It's up to the caller to decide how to handle the results, which could be inconsistent among one another,
    /// (e.g., if different providers gave different responses).
    /// This method is useful for querying data that is critical for the system to ensure that there is no single point of failure,
    /// e.g., ethereum logs upon which ckETH will be minted.
    async fn parallel_call<I, O>(
        &self,
        method: impl Into<String> + Clone,
        params: I,
        response_size_estimate: ResponseSizeEstimate,
    ) -> MultiCallResults<O>
    where
        I: Serialize + Clone,
        O: DeserializeOwned + HttpResponsePayload,
    {
        let providers = self.providers();
        let results = {
            let mut fut = Vec::with_capacity(providers.len());
            for provider in providers {
                log!(DEBUG, "[parallel_call]: will call provider: {:?}", provider);
                fut.push(eth_rpc::call::<T, _, _>(
                    provider.api::<T>(),
                    method.clone(),
                    params.clone(),
                    response_size_estimate,
                ));
            }
            futures::future::join_all(fut).await
        };
        MultiCallResults::from_non_empty_iter(providers.iter().cloned().zip(results.into_iter()))
    }

    pub async fn eth_get_logs(
        &self,
        params: GetLogsParam,
    ) -> Result<Vec<LogEntry>, MultiCallError<Vec<LogEntry>>> {
        // We expect most of the calls to contain zero events.
        let results: MultiCallResults<Vec<LogEntry>> = self
            .parallel_call("eth_getLogs", vec![params], ResponseSizeEstimate::new(100))
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: BlockSpec,
    ) -> Result<Block, MultiCallError<Block>> {
        use crate::eth_rpc::GetBlockByNumberParams;

        let results: MultiCallResults<Block> = self
            .parallel_call(
                "eth_getBlockByNumber",
                GetBlockByNumberParams {
                    block,
                    include_full_transactions: false,
                },
                ResponseSizeEstimate::new(6 * 1024),
            )
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<TransactionReceipt>, MultiCallError<Option<TransactionReceipt>>> {
        let results: MultiCallResults<Option<TransactionReceipt>> = self
            .parallel_call(
                "eth_getTransactionReceipt",
                vec![tx_hash],
                ResponseSizeEstimate::new(700),
            )
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_fee_history(&self, params: FeeHistoryParams) -> Result<FeeHistory, RpcError> {
        // A typical response is slightly above 300 bytes.
        self.sequential_call_until_ok("eth_feeHistory", params, ResponseSizeEstimate::new(512))
            .await
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> Result<SendRawTransactionResult, RpcError> {
        // A successful reply is under 256 bytes, but we expect most calls to end with an error
        // since we submit the same transaction from multiple nodes.
        self.sequential_call_until_ok(
            "eth_sendRawTransaction",
            vec![raw_signed_transaction_hex],
            ResponseSizeEstimate::new(256),
        )
        .await
    }

    pub async fn eth_get_transaction_count(
        &self,
        params: GetTransactionCountParams,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        let results = self
            .parallel_call(
                "eth_getTransactionCount",
                params,
                ResponseSizeEstimate::new(50),
            )
            .await;
        results.reduce_with_equality()
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq, CandidType)]
pub struct MultiCallResults<T> {
    pub results: BTreeMap<RpcNodeProvider, Result<T, RpcError>>,
}

impl<T> MultiCallResults<T> {
    fn from_non_empty_iter<I: IntoIterator<Item = (RpcNodeProvider, Result<T, RpcError>)>>(
        iter: I,
    ) -> Self {
        let results = BTreeMap::from_iter(iter);
        if results.is_empty() {
            panic!("BUG: MultiCallResults cannot be empty!")
        }
        Self { results }
    }
}

impl<T: PartialEq> MultiCallResults<T> {
    /// Expects all results to be ok or return the following error:
    /// * MultiCallError::ConsistentJsonRpcError: all errors are the same JSON-RPC error.
    /// * MultiCallError::ConsistentHttpOutcallError: all errors are the same HTTP outcall error.
    /// * MultiCallError::InconsistentResults if there are different errors.
    fn all_ok(self) -> Result<BTreeMap<RpcNodeProvider, T>, MultiCallError<T>> {
        let mut results = BTreeMap::new();
        let mut first_error: Option<(RpcNodeProvider, Result<T, RpcError>)> = None;
        for (provider, result) in self.results.into_iter() {
            match result {
                Ok(value) => {
                    results.insert(provider, value);
                }
                _ => match first_error {
                    None => {
                        first_error = Some((provider, result));
                    }
                    Some((first_error_provider, error)) => {
                        if !are_errors_consistent(&error, &result) {
                            return Err(MultiCallError::InconsistentResults(
                                MultiCallResults::from_non_empty_iter(vec![
                                    (first_error_provider, error),
                                    (provider, result),
                                ]),
                            ));
                        }
                        first_error = Some((first_error_provider, error));
                    }
                },
            }
        }
        match first_error {
            None => Ok(results),
            Some((_provider, Err(RpcError::JsonRpcError(JsonRpcError { code, message })))) => Err(
                MultiCallError::ConsistentError(JsonRpcError { code, message }.into()),
            ),
            Some((_provider, Err(error))) => Err(MultiCallError::ConsistentError(error)),
            Some((_, Ok(_))) => {
                panic!("BUG: first_error should be an error type")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, CandidType)]
pub enum MultiCallError<T> {
    ConsistentError(RpcError),
    InconsistentResults(MultiCallResults<T>),
}

impl<T: Debug + PartialEq> MultiCallResults<T> {
    pub fn reduce_with_equality(self) -> Result<T, MultiCallError<T>> {
        let mut results = self.all_ok()?.into_iter();
        let (base_node_provider, base_result) = results
            .next()
            .expect("BUG: MultiCallResults is guaranteed to be non-empty");
        let mut inconsistent_results: Vec<_> = results
            .filter(|(_provider, result)| result != &base_result)
            .collect();
        if !inconsistent_results.is_empty() {
            inconsistent_results.push((base_node_provider, base_result));
            let error = MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(
                inconsistent_results
                    .into_iter()
                    .map(|(provider, result)| (provider, Ok(result))),
            ));
            log!(
                INFO,
                "[reduce_with_equality]: inconsistent results {error:?}"
            );
            return Err(error);
        }
        Ok(base_result)
    }

    pub fn reduce_with_min_by_key<F: FnMut(&T) -> K, K: Ord>(
        self,
        extractor: F,
    ) -> Result<T, MultiCallError<T>> {
        let min = self
            .all_ok()?
            .into_values()
            .min_by_key(extractor)
            .expect("BUG: MultiCallResults is guaranteed to be non-empty");
        Ok(min)
    }
}
