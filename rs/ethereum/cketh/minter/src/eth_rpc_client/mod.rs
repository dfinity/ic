use crate::eth_rpc::{
    self, Block, BlockSpec, BlockTag, FeeHistory, FeeHistoryParams, GetLogsParam, Hash,
    HttpOutcallError, HttpOutcallResult, HttpResponsePayload, JsonRpcResult, LogEntry,
    ResponseSizeEstimate, SendRawTransactionResult,
};
use crate::eth_rpc_client::providers::{
    EthereumProvider, RpcNodeProvider, SepoliaProvider, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS,
};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EthereumNetwork;
use crate::logs::{PrintProxySink, DEBUG, INFO, TRACE_HTTP};
use crate::numeric::{BlockNumber, TransactionCount, Wei};
use crate::state::State;
use evm_rpc_client::{
    types::candid::{
        Block as EvmBlock, BlockTag as EvmBlockTag, MultiRpcResult as EvmMultiRpcResult,
        RpcError as EvmRpcError, RpcResult as EvmRpcResult,
    },
    EvmRpcClient, IcRuntime,
};
use ic_canister_log::log;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};

mod providers;
pub mod requests;
pub mod responses;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct EthRpcClient {
    evm_rpc_client: Option<EvmRpcClient<IcRuntime, PrintProxySink>>,
    chain: EthereumNetwork,
}

impl EthRpcClient {
    const fn new(chain: EthereumNetwork) -> Self {
        Self {
            evm_rpc_client: None,
            chain,
        }
    }

    pub fn from_state(state: &State) -> Self {
        let mut client = Self::new(state.ethereum_network());
        if let Some(evm_rpc_id) = state.evm_rpc_id {
            let providers = match client.chain {
                EthereumNetwork::Mainnet => EthereumProvider::evm_rpc_node_providers(),
                EthereumNetwork::Sepolia => SepoliaProvider::evm_rpc_node_providers(),
            };
            client.evm_rpc_client = Some(
                EvmRpcClient::builder_for_ic(TRACE_HTTP)
                    .with_providers(providers)
                    .with_evm_canister_id(evm_rpc_id)
                    .build(),
            );
        }
        client
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

        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            let result = evm_rpc_client
                .eth_get_block_by_number(match block {
                    BlockSpec::Number(n) => EvmBlockTag::Number(n.into()),
                    BlockSpec::Tag(BlockTag::Latest) => EvmBlockTag::Latest,
                    BlockSpec::Tag(BlockTag::Safe) => EvmBlockTag::Safe,
                    BlockSpec::Tag(BlockTag::Finalized) => EvmBlockTag::Finalized,
                })
                .await;
            return ReducedResult::from(result).into();
        }

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

impl<T> Default for MultiCallResults<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MultiCallResults<T> {
    pub fn new() -> Self {
        Self {
            ok_results: BTreeMap::new(),
            errors: BTreeMap::new(),
        }
    }

    fn map<U, E: Display, F: Fn(T) -> Result<U, E>, O: Fn(E) -> SingleCallError>(
        self,
        f: &F,
        map_err: &O,
    ) -> MultiCallResults<U> {
        let mut errors = self.errors;
        let ok_results = self
            .ok_results
            .into_iter()
            .filter_map(|(provider, v)| match f(v) {
                Ok(value) => Some((provider, value)),
                Err(e) => {
                    errors.insert(provider, map_err(e));
                    None
                }
            })
            .collect();
        MultiCallResults { ok_results, errors }
    }

    fn insert_once(&mut self, provider: RpcNodeProvider, result: Result<T, SingleCallError>) {
        match result {
            Ok(value) => {
                assert!(!self.errors.contains_key(&provider));
                assert!(self.ok_results.insert(provider, value).is_none());
            }
            Err(error) => {
                assert!(!self.ok_results.contains_key(&provider));
                assert!(self.errors.insert(provider, error).is_none());
            }
        }
    }

    fn from_non_empty_iter<
        I: IntoIterator<Item = (RpcNodeProvider, HttpOutcallResult<JsonRpcResult<T>>)>,
    >(
        iter: I,
    ) -> Self {
        let mut results = MultiCallResults::new();
        for (provider, result) in iter {
            let result: Result<T, SingleCallError> = match result {
                Ok(JsonRpcResult::Result(value)) => Ok(value),
                Ok(JsonRpcResult::Error { code, message }) => {
                    Err(SingleCallError::JsonRpcError { code, message })
                }
                Err(error) => Err(SingleCallError::HttpOutcallError(error)),
            };
            results.insert_once(provider, result);
        }
        if results.is_empty() {
            panic!("BUG: MultiCallResults cannot be empty!")
        }
        results
    }

    fn from_iter<I: IntoIterator<Item = (RpcNodeProvider, Result<T, SingleCallError>)>>(
        iter: I,
    ) -> Self {
        let mut results = MultiCallResults::new();
        for (provider, result) in iter {
            results.insert_once(provider, result);
        }
        if results.is_empty() {
            panic!("BUG: MultiCallResults cannot be empty!")
        }
        results
    }

    pub fn is_empty(&self) -> bool {
        self.ok_results.is_empty() && self.errors.is_empty()
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
                return MultiCallError::InconsistentResults(MultiCallResults::from_iter(vec![
                    (first_provider, Err(first_error)),
                    (provider, Err(error)),
                ]));
            }
        }
        match first_error {
            SingleCallError::HttpOutcallError(error) => {
                MultiCallError::ConsistentHttpOutcallError(error)
            }
            SingleCallError::JsonRpcError { code, message } => {
                MultiCallError::ConsistentJsonRpcError { code, message }
            }
            SingleCallError::EvmRpcError(error) => {
                MultiCallError::ConsistentEvmRpcCanisterError(error)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SingleCallError {
    HttpOutcallError(HttpOutcallError),
    JsonRpcError { code: i64, message: String },
    EvmRpcError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    ConsistentEvmRpcCanisterError(String),
    InconsistentResults(MultiCallResults<T>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReducedResult<T> {
    result: Result<T, MultiCallError<T>>,
}

impl<T> ReducedResult<T> {
    /// Transform a `ReducedResult<T>` into a `ReducedResult<U>` by applying a mapping function `F`.
    /// The mapping function is also applied to the elements contained in the error `MultiCallError::InconsistentResults`,
    /// which depending on the mapping function could lead to the mapped results no longer being inconsistent.
    /// The final result in that case is given by applying the reduction function `R` to the mapped results.
    pub fn map_reduce<
        U,
        E: Display,
        F: Fn(T) -> Result<U, E>,
        R: FnOnce(MultiCallResults<U>) -> Result<U, MultiCallError<U>>,
    >(
        self,
        faillible_op: &F,
        reduction: R,
    ) -> ReducedResult<U> {
        let result = match self.result {
            Ok(t) => faillible_op(t)
                .map_err(|e| MultiCallError::<U>::ConsistentEvmRpcCanisterError(e.to_string())),
            Err(MultiCallError::ConsistentHttpOutcallError(e)) => {
                Err(MultiCallError::<U>::ConsistentHttpOutcallError(e))
            }
            Err(MultiCallError::ConsistentJsonRpcError { code, message }) => {
                Err(MultiCallError::<U>::ConsistentJsonRpcError { code, message })
            }
            Err(MultiCallError::ConsistentEvmRpcCanisterError(e)) => {
                Err(MultiCallError::<U>::ConsistentEvmRpcCanisterError(e))
            }
            Err(MultiCallError::InconsistentResults(results)) => {
                reduction(results.map(faillible_op, &|e| {
                    SingleCallError::EvmRpcError(e.to_string())
                }))
            }
        };
        ReducedResult { result }
    }

    fn from_internal(value: EvmMultiRpcResult<T>) -> Self {
        fn into_single_call_result<T>(result: EvmRpcResult<T>) -> Result<T, SingleCallError> {
            match result {
                Ok(t) => Ok(t),
                Err(e) => match e {
                    EvmRpcError::ProviderError(e) => {
                        Err(SingleCallError::EvmRpcError(e.to_string()))
                    }
                    EvmRpcError::HttpOutcallError(e) => {
                        Err(SingleCallError::HttpOutcallError(e.into()))
                    }
                    EvmRpcError::JsonRpcError(e) => Err(SingleCallError::JsonRpcError {
                        code: e.code,
                        message: e.message,
                    }),
                    EvmRpcError::ValidationError(e) => {
                        Err(SingleCallError::EvmRpcError(e.to_string()))
                    }
                },
            }
        }

        let result = match value {
            EvmMultiRpcResult::Consistent(result) => match result {
                Ok(t) => Ok(t),
                Err(e) => match e {
                    EvmRpcError::ProviderError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                    EvmRpcError::HttpOutcallError(e) => {
                        Err(MultiCallError::ConsistentHttpOutcallError(e.into()))
                    }
                    EvmRpcError::JsonRpcError(e) => Err(MultiCallError::ConsistentJsonRpcError {
                        code: e.code,
                        message: e.message,
                    }),
                    EvmRpcError::ValidationError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                },
            },
            EvmMultiRpcResult::Inconsistent(results) => {
                let mut multi_results = MultiCallResults::new();
                results.into_iter().for_each(|(provider, result)| {
                    multi_results.insert_once(
                        RpcNodeProvider::EvmRpc(provider),
                        into_single_call_result(result),
                    );
                });
                Err(MultiCallError::InconsistentResults(multi_results))
            }
        };
        Self { result }
    }
}

impl<T> From<Result<T, MultiCallError<T>>> for ReducedResult<T> {
    fn from(result: Result<T, MultiCallError<T>>) -> Self {
        Self { result }
    }
}

impl<T> From<ReducedResult<T>> for Result<T, MultiCallError<T>> {
    fn from(value: ReducedResult<T>) -> Self {
        value.result
    }
}

impl From<EvmMultiRpcResult<EvmBlock>> for ReducedResult<Block> {
    fn from(value: EvmMultiRpcResult<EvmBlock>) -> Self {
        ReducedResult::from_internal(value).map_reduce(
            &|block: EvmBlock| {
                Ok::<Block, String>(Block {
                    number: BlockNumber::try_from(block.number)?,
                    base_fee_per_gas: Wei::try_from(block.base_fee_per_gas)?,
                })
            },
            MultiCallResults::reduce_with_equality,
        )
    }
}

// TODO XC-131: add proptest to ensure HttpOutcallError are kept, so that the halving
// of the log scrapping happens correctly

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
                        SingleCallError::JsonRpcError { .. } | SingleCallError::EvmRpcError(_) => {
                            false
                        }
                    })
            }
            MultiCallError::ConsistentEvmRpcCanisterError(_) => false,
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
            let error = MultiCallError::InconsistentResults(MultiCallResults::from_iter(
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
                        let error =
                            MultiCallError::InconsistentResults(MultiCallResults::from_iter(
                                votes_for_same_key
                                    .into_iter()
                                    .chain(std::iter::once((provider, result)))
                                    .map(|(provider, result)| (provider, Ok(result))),
                            ));
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
                    let error = MultiCallError::InconsistentResults(MultiCallResults::from_iter(
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
