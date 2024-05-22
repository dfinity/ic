use crate::eth_rpc::{
    self, are_errors_consistent, Block, BlockSpec, FeeHistory, FeeHistoryParams, GetLogsParam,
    Hash, HttpOutcallError, HttpResponsePayload, JsonRpcError, LogEntry, ProviderError,
    ResponseSizeEstimate, RpcError, SendRawTransactionResult,
};
use crate::eth_rpc_client::eth_rpc::HEADER_SIZE_LIMIT;
use crate::eth_rpc_client::providers::{
    RpcService, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS, UNKNOWN_PROVIDERS,
    ARBITRUM_PROVIDERS, BASE_PROVIDERS, OPTIMISM_PROVIDERS,
};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EthereumNetwork;
use crate::logs::{DEBUG, INFO};
use crate::numeric::TransactionCount;
use crate::state::State;
use async_trait::async_trait;
use candid::CandidType;
use ic_canister_log::log;
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use self::providers::RpcApi;

pub mod providers;
pub mod requests;
pub mod responses;

#[cfg(test)]
mod tests;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RpcTransport: Debug {
    fn resolve_api(provider: &RpcService) -> Result<RpcApi, ProviderError>;

    async fn http_request(
        provider: &RpcService,
        method: &str,
        request: CanisterHttpRequestArgument,
        effective_size_estimate: u64,
    ) -> Result<HttpResponse, RpcError>;
}

// Placeholder during refactoring
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for DefaultTransport {
    fn resolve_api(_provider: &RpcService) -> Result<RpcApi, ProviderError> {
        unimplemented!()
    }

    async fn http_request(
        _provider: &RpcService,
        _method: &str,
        _request: CanisterHttpRequestArgument,
        _effective_size_estimate: u64,
    ) -> Result<HttpResponse, RpcError> {
        unimplemented!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
pub struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthRpcClient<T: RpcTransport> {
    chain: EthereumNetwork,
    providers: Option<Vec<RpcService>>,
    config: RpcConfig,
    phantom: PhantomData<T>,
}

impl<T: RpcTransport> EthRpcClient<T> {
    pub const fn new(
        chain: EthereumNetwork,
        providers: Option<Vec<RpcService>>,
        config: RpcConfig,
    ) -> Self {
        Self {
            chain,
            providers,
            config,
            phantom: PhantomData,
        }
    }

    pub fn from_state(state: &State) -> Self {
        Self::new(state.ethereum_network(), None, RpcConfig::default())
    }

    fn providers(&self) -> &[RpcService] {
        match self.providers {
            Some(ref providers) => providers,
            None => match self.chain {
                EthereumNetwork::MAINNET => MAINNET_PROVIDERS,
                EthereumNetwork::SEPOLIA => SEPOLIA_PROVIDERS,
                EthereumNetwork::ARBITRUM => ARBITRUM_PROVIDERS,
                EthereumNetwork::BASE => BASE_PROVIDERS,
                EthereumNetwork::OPTIMISM => OPTIMISM_PROVIDERS,
                _ => UNKNOWN_PROVIDERS,
            },
        }
    }

    fn response_size_estimate(&self, estimate: u64) -> ResponseSizeEstimate {
        ResponseSizeEstimate::new(self.config.response_size_estimate.unwrap_or(estimate))
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
                provider,
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
                        "{provider:?} returned JSON-RPC error {json_rpc_error:?}",
                    );
                    last_result = Some(Err(json_rpc_error.into()));
                }
                Err(e) => {
                    log!(INFO, "Querying {provider:?} returned error {e:?}");
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
                fut.push(async {
                    eth_rpc::call::<T, _, _>(
                        provider,
                        method.clone(),
                        params.clone(),
                        response_size_estimate,
                    )
                    .await
                });
            }
            futures::future::join_all(fut).await
        };
        MultiCallResults::from_non_empty_iter(providers.iter().cloned().zip(results.into_iter()))
    }

    pub async fn eth_get_logs(
        &self,
        params: GetLogsParam,
    ) -> Result<Vec<LogEntry>, MultiCallError<Vec<LogEntry>>> {
        let results: MultiCallResults<Vec<LogEntry>> = self
            .parallel_call(
                "eth_getLogs",
                vec![params],
                self.response_size_estimate(1024 + HEADER_SIZE_LIMIT),
            )
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: BlockSpec,
    ) -> Result<Block, MultiCallError<Block>> {
        use crate::eth_rpc::GetBlockByNumberParams;

        let expected_block_size = match self.chain {
            EthereumNetwork::SEPOLIA => 12 * 1024,
            EthereumNetwork::MAINNET => 24 * 1024,
            _ => 24 * 1024, // Default for unknown networks
        };

        let results: MultiCallResults<Block> = self
            .parallel_call(
                "eth_getBlockByNumber",
                GetBlockByNumberParams {
                    block,
                    include_full_transactions: false,
                },
                self.response_size_estimate(expected_block_size + HEADER_SIZE_LIMIT),
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
                self.response_size_estimate(700 + HEADER_SIZE_LIMIT),
            )
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryParams,
    ) -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        // A typical response is slightly above 300 bytes.
        let results: MultiCallResults<FeeHistory> = self
            .parallel_call(
                "eth_feeHistory",
                params,
                self.response_size_estimate(512 + HEADER_SIZE_LIMIT),
            )
            .await;
        results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block)
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
            self.response_size_estimate(256 + HEADER_SIZE_LIMIT),
        )
        .await
    }

    pub async fn multi_eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> Result<SendRawTransactionResult, MultiCallError<SendRawTransactionResult>> {
        self.parallel_call(
            "eth_sendRawTransaction",
            vec![raw_signed_transaction_hex],
            self.response_size_estimate(256 + HEADER_SIZE_LIMIT),
        )
        .await
        .reduce_with_equality()
    }

    pub async fn eth_get_transaction_count(
        &self,
        params: GetTransactionCountParams,
    ) -> MultiCallResults<TransactionCount> {
        self.parallel_call(
            "eth_getTransactionCount",
            params,
            self.response_size_estimate(50 + HEADER_SIZE_LIMIT),
        )
        .await
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq, CandidType)]
pub struct MultiCallResults<T> {
    pub results: BTreeMap<RpcService, Result<T, RpcError>>,
}

impl<T> MultiCallResults<T> {
    fn from_non_empty_iter<I: IntoIterator<Item = (RpcService, Result<T, RpcError>)>>(
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
    fn all_ok(self) -> Result<BTreeMap<RpcService, T>, MultiCallError<T>> {
        let mut has_ok = false;
        let mut first_error: Option<(RpcService, &Result<T, RpcError>)> = None;
        for (provider, result) in self.results.iter() {
            match result {
                Ok(_value) => {
                    has_ok = true;
                }
                _ => match first_error {
                    None => {
                        first_error = Some((provider.clone(), result));
                    }
                    Some((first_error_provider, error)) => {
                        if !are_errors_consistent(&error, result) {
                            return Err(MultiCallError::InconsistentResults(self));
                        }
                        first_error = Some((first_error_provider, error));
                    }
                },
            }
        }
        match first_error {
            None => Ok(self
                .results
                .into_iter()
                .map(|(provider, result)| {
                    (provider, result.expect("BUG: all results should be ok"))
                })
                .collect()),
            Some((_, Err(error))) => {
                if has_ok {
                    Err(MultiCallError::InconsistentResults(self))
                } else {
                    Err(MultiCallError::ConsistentError(error.clone()))
                }
            }
            Some((_, Ok(_))) => {
                panic!("BUG: first_error should be an error type")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, CandidType)]
pub enum SingleCallError {
    HttpOutcallError(HttpOutcallError),
    JsonRpcError { code: i64, message: String },
}
#[derive(Debug, PartialEq, Eq, CandidType)]
pub enum MultiCallError<T> {
    ConsistentError(RpcError),
    InconsistentResults(MultiCallResults<T>),
}

impl<T> MultiCallError<T> {
    pub fn has_http_outcall_error_matching<P: Fn(&HttpOutcallError) -> bool>(
        &self,
        predicate: P,
    ) -> bool {
        match self {
            MultiCallError::ConsistentError(RpcError::HttpOutcallError(error)) => predicate(error),
            MultiCallError::ConsistentError(_) => false,
            MultiCallError::InconsistentResults(results) => {
                results.results.values().any(|result| match result {
                    Err(RpcError::HttpOutcallError(error)) => predicate(error),
                    _ => false,
                })
            }
        }
    }
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

    pub fn reduce_with_strict_majority_by_key<F: Fn(&T) -> K, K: Ord>(
        self,
        extractor: F,
    ) -> Result<T, MultiCallError<T>> {
        let mut votes_by_key: BTreeMap<K, BTreeMap<RpcService, T>> = BTreeMap::new();
        for (provider, result) in self.all_ok()?.into_iter() {
            let key = extractor(&result);
            match votes_by_key.remove(&key) {
                Some(mut votes_for_same_key) => {
                    let (_other_provider, other_result) = votes_for_same_key
                        .last_key_value()
                        .expect("BUG: results_with_same_key is non-empty");
                    if &result != other_result {
                        let error = MultiCallError::InconsistentResults(
                            MultiCallResults::from_non_empty_iter(
                                votes_for_same_key
                                    .into_iter()
                                    .chain(std::iter::once((provider, result)))
                                    .map(|(provider, result)| (provider, Ok(result))),
                            ),
                        );
                        log!(
                            INFO,
                            "[reduce_with_strict_majority_by_key]: inconsistent results {error:?}"
                        );
                        return Err(error);
                    }
                    votes_for_same_key.insert(provider, result);
                    votes_by_key.insert(key, votes_for_same_key);
                }
                None => {
                    let _ = votes_by_key.insert(key, BTreeMap::from([(provider, result)]));
                }
            }
        }

        let mut tally: Vec<(K, BTreeMap<RpcService, T>)> = Vec::from_iter(votes_by_key);
        tally.sort_unstable_by(|(_left_key, left_ballot), (_right_key, right_ballot)| {
            left_ballot.len().cmp(&right_ballot.len())
        });
        match tally.len() {
            0 => panic!("BUG: tally should be non-empty"),
            1 => Ok(tally
                .pop()
                .and_then(|(_key, mut ballot)| ballot.pop_last())
                .expect("BUG: tally is non-empty")
                .1),
            _ => {
                let mut first = tally.pop().expect("BUG: tally has at least 2 elements");
                let second = tally.pop().expect("BUG: tally has at least 2 elements");
                if first.1.len() > second.1.len() {
                    Ok(first
                        .1
                        .pop_last()
                        .expect("BUG: tally should be non-empty")
                        .1)
                } else {
                    let error =
                        MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(
                            first
                                .1
                                .into_iter()
                                .chain(second.1)
                                .map(|(provider, result)| (provider, Ok(result))),
                        ));
                    log!(
                        INFO,
                        "[reduce_with_strict_majority_by_key]: no strict majority {error:?}"
                    );
                    Err(error)
                }
            }
        }
    }
}
