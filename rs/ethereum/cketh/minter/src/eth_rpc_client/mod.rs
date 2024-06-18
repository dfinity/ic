use crate::eth_rpc::{
    self, Block, BlockSpec, FeeHistory, FeeHistoryParams, GetLogsParam, Hash, HttpOutcallError,
    HttpOutcallResult, HttpResponsePayload, JsonRpcResult, LogEntry, ResponseSizeEstimate,
    SendRawTransactionResult,
};
use crate::eth_rpc_client::providers::{RpcNodeProvider, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EthereumNetwork;
use crate::logs::{DEBUG, INFO};
use crate::numeric::TransactionCount;
use crate::state::State;
use ic_canister_log::log;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;

mod providers;
pub mod requests;
pub mod responses;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthRpcClient {
    chain: EthereumNetwork,
}

impl EthRpcClient {
    const fn new(chain: EthereumNetwork) -> Self {
        Self { chain }
    }

    pub const fn from_state(state: &State) -> Self {
        if state.evm_rpc_id.is_some() {
            //TODO XC-131: use EVM-RPC canister to retrieve last finalized block
            unimplemented!();
        }
        Self::new(state.ethereum_network())
    }

    fn providers(&self) -> &[RpcNodeProvider] {
        match self.chain {
            EthereumNetwork::Mainnet => &MAINNET_PROVIDERS,
            EthereumNetwork::Sepolia => &SEPOLIA_PROVIDERS,
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
    ) -> HttpOutcallResult<JsonRpcResult<O>>
    where
        I: Serialize + Clone,
        O: DeserializeOwned + HttpResponsePayload + Debug,
    {
        let mut last_result: Option<HttpOutcallResult<JsonRpcResult<O>>> = None;
        for provider in self.providers() {
            log!(
                DEBUG,
                "[sequential_call_until_ok]: calling provider: {:?}",
                provider
            );
            let result = eth_rpc::call(
                provider.url().to_string(),
                method.clone(),
                params.clone(),
                response_size_estimate,
            )
            .await;
            match result {
                Ok(JsonRpcResult::Result(value)) => return Ok(JsonRpcResult::Result(value)),
                Ok(json_rpc_error @ JsonRpcResult::Error { .. }) => {
                    log!(
                        INFO,
                        "Provider {provider:?} returned JSON-RPC error {json_rpc_error:?}",
                    );
                    last_result = Some(Ok(json_rpc_error));
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
                fut.push(eth_rpc::call(
                    provider.url().to_string(),
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

        let expected_block_size = match self.chain {
            EthereumNetwork::Sepolia => 12 * 1024,
            EthereumNetwork::Mainnet => 24 * 1024,
        };

        let results: MultiCallResults<Block> = self
            .parallel_call(
                "eth_getBlockByNumber",
                GetBlockByNumberParams {
                    block,
                    include_full_transactions: false,
                },
                ResponseSizeEstimate::new(expected_block_size),
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

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryParams,
    ) -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        // A typical response is slightly above 300 bytes.
        let results: MultiCallResults<FeeHistory> = self
            .parallel_call("eth_feeHistory", params, ResponseSizeEstimate::new(512))
            .await;
        results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block)
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> HttpOutcallResult<JsonRpcResult<SendRawTransactionResult>> {
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
    ) -> MultiCallResults<TransactionCount> {
        self.parallel_call(
            "eth_getTransactionCount",
            params,
            ResponseSizeEstimate::new(50),
        )
        .await
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCallResults<T> {
    ok_results: BTreeMap<RpcNodeProvider, T>,
    errors: BTreeMap<RpcNodeProvider, SingleCallError>,
}

impl<T> MultiCallResults<T> {
    fn from_non_empty_iter<
        I: IntoIterator<Item = (RpcNodeProvider, HttpOutcallResult<JsonRpcResult<T>>)>,
    >(
        iter: I,
    ) -> Self {
        let results = BTreeMap::from_iter(iter);
        if results.is_empty() {
            panic!("BUG: MultiCallResults cannot be empty!")
        }
        let mut ok_results = BTreeMap::new();
        let mut errors = BTreeMap::new();
        for (provider, result) in results.into_iter() {
            match result {
                Ok(JsonRpcResult::Result(value)) => {
                    assert!(ok_results.insert(provider, value).is_none());
                }
                Ok(JsonRpcResult::Error { code, message }) => {
                    assert!(errors
                        .insert(provider, SingleCallError::JsonRpcError { code, message })
                        .is_none());
                }
                Err(error) => {
                    assert!(errors
                        .insert(provider, SingleCallError::HttpOutcallError(error))
                        .is_none());
                }
            }
        }
        Self { ok_results, errors }
    }
}

impl<T: PartialEq> MultiCallResults<T> {
    /// Expects all results to be ok or return the following error:
    /// * MultiCallError::ConsistentJsonRpcError: all errors are the same JSON-RPC error.
    /// * MultiCallError::ConsistentHttpOutcallError: all errors are the same HTTP outcall error.
    /// * MultiCallError::InconsistentResults if there are different errors.
    fn all_ok(self) -> Result<BTreeMap<RpcNodeProvider, T>, MultiCallError<T>> {
        if self.errors.is_empty() {
            return Ok(self.ok_results);
        }
        Err(self.expect_error())
    }

    /// Expects at least 2 ok results to be ok or return the following error:
    /// * MultiCallError::ConsistentJsonRpcError: all errors are the same JSON-RPC error.
    /// * MultiCallError::ConsistentHttpOutcallError: all errors are the same HTTP outcall error.
    /// * MultiCallError::InconsistentResults if there are different errors or an ok result with some errors.
    fn at_least_two_ok(self) -> Result<BTreeMap<RpcNodeProvider, T>, MultiCallError<T>> {
        match self.ok_results.len() {
            0 => Err(self.expect_error()),
            1 => Err(MultiCallError::InconsistentResults(self)),
            _ => Ok(self.ok_results),
        }
    }

    fn expect_error(self) -> MultiCallError<T> {
        let mut errors_iter = self.errors.into_iter();
        let (first_provider, first_error) = errors_iter
            .next()
            .expect("BUG: expect errors should be non-empty");
        for (provider, error) in errors_iter {
            if first_error != error {
                return MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(
                    vec![
                        (first_provider, first_error.into()),
                        (provider, error.into()),
                    ],
                ));
            }
        }
        match first_error {
            SingleCallError::HttpOutcallError(error) => {
                MultiCallError::ConsistentHttpOutcallError(error)
            }
            SingleCallError::JsonRpcError { code, message } => {
                MultiCallError::ConsistentJsonRpcError { code, message }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SingleCallError {
    HttpOutcallError(HttpOutcallError),
    JsonRpcError { code: i64, message: String },
}

impl<T> From<SingleCallError> for HttpOutcallResult<JsonRpcResult<T>> {
    fn from(value: SingleCallError) -> Self {
        match value {
            SingleCallError::HttpOutcallError(error) => Err(error),
            SingleCallError::JsonRpcError { code, message } => {
                Ok(JsonRpcResult::Error { code, message })
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    InconsistentResults(MultiCallResults<T>),
}

impl<T> MultiCallError<T> {
    pub fn has_http_outcall_error_matching<P: Fn(&HttpOutcallError) -> bool>(
        &self,
        predicate: P,
    ) -> bool {
        match self {
            MultiCallError::ConsistentHttpOutcallError(error) => predicate(error),
            MultiCallError::ConsistentJsonRpcError { .. } => false,
            MultiCallError::InconsistentResults(results) => {
                results
                    .errors
                    .values()
                    .any(|single_call_error| match single_call_error {
                        SingleCallError::HttpOutcallError(error) => predicate(error),
                        SingleCallError::JsonRpcError { .. } => false,
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
                    .map(|(provider, result)| (provider, Ok(JsonRpcResult::Result(result)))),
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
            .at_least_two_ok()?
            .into_values()
            .min_by_key(extractor)
            .expect("BUG: MultiCallResults is guaranteed to be non-empty");
        Ok(min)
    }

    pub fn reduce_with_strict_majority_by_key<F: Fn(&T) -> K, K: Ord>(
        self,
        extractor: F,
    ) -> Result<T, MultiCallError<T>> {
        let mut votes_by_key: BTreeMap<K, BTreeMap<RpcNodeProvider, T>> = BTreeMap::new();
        for (provider, result) in self.at_least_two_ok()?.into_iter() {
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
                                    .map(|(provider, result)| {
                                        (provider, Ok(JsonRpcResult::Result(result)))
                                    }),
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

        let mut tally: Vec<(K, BTreeMap<RpcNodeProvider, T>)> = Vec::from_iter(votes_by_key);
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
                                .map(|(provider, result)| {
                                    (provider, Ok(JsonRpcResult::Result(result)))
                                }),
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
