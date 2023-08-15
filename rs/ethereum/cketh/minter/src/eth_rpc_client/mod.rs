use crate::eth_rpc;
use crate::eth_rpc::{
    Block, FeeHistory, FeeHistoryParams, GetLogsParam, Hash, HttpOutcallError, HttpOutcallResult,
    JsonRpcResult, LogEntry, Transaction,
};
use crate::eth_rpc_client::providers::{RpcNodeProvider, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;

mod providers;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum EthereumChain {
    Mainnet,
    Sepolia,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct EthRpcClient {
    chain: EthereumChain,
}

impl EthRpcClient {
    pub const fn new(chain: EthereumChain) -> Self {
        Self { chain }
    }

    fn providers(&self) -> &[RpcNodeProvider] {
        match self.chain {
            EthereumChain::Mainnet => &MAINNET_PROVIDERS,
            EthereumChain::Sepolia => &SEPOLIA_PROVIDERS,
        }
    }

    /// Query all providers in sequence until one returns an ok result
    /// (which could still be a JsonRpcResult::Error).
    /// If none of the providers return an ok result, return the last error.
    /// This method is useful in case a provider is temporarily down but should only be for
    /// querying data that is **not** critical since the returned value comes from a single provider.
    async fn sequential_call_until_ok<I: Serialize + Clone, O: DeserializeOwned>(
        &self,
        method: impl Into<String> + Clone,
        params: I,
    ) -> HttpOutcallResult<JsonRpcResult<O>> {
        let mut last_result: Option<HttpOutcallResult<JsonRpcResult<O>>> = None;
        for provider in self.providers() {
            ic_cdk::println!("Calling provider {:?}", provider);
            let result =
                eth_rpc::call(provider.url().to_string(), method.clone(), params.clone()).await;
            if result.is_ok() {
                return result;
            }
            last_result = Some(result);
        }
        last_result.unwrap_or_else(|| panic!("BUG: No providers in RPC client {:?}", self))
    }

    /// Query all providers in parallel and return all results.
    /// It's up to the caller to decide how to handle the results, which could be inconsistent among one another,
    /// (e.g., if different providers gave different responses).
    /// This method is useful for querying data that is critical for the system to ensure that there is no single point of failure,
    /// e.g., ethereum logs upon which ckETH will be minted.
    async fn parallel_call<I: Serialize + Clone, O: DeserializeOwned>(
        &self,
        method: impl Into<String> + Clone,
        params: I,
    ) -> MultiCallResults<O> {
        let providers = self.providers();
        let results = {
            let mut fut = Vec::with_capacity(providers.len());
            for provider in providers {
                ic_cdk::println!("Will call provider {:?}", provider);
                fut.push(eth_rpc::call(
                    provider.url().to_string(),
                    method.clone(),
                    params.clone(),
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
        let results: MultiCallResults<Vec<LogEntry>> =
            self.parallel_call("eth_getLogs", vec![params]).await;
        results.reduce_with_equality()
    }

    pub async fn eth_get_last_finalized_block(&self) -> Result<Block, MultiCallError<Block>> {
        use crate::eth_rpc::{BlockSpec, BlockTag, GetBlockByNumberParams};

        let results: MultiCallResults<Block> = self
            .parallel_call(
                "eth_getBlockByNumber",
                GetBlockByNumberParams {
                    block: BlockSpec::Tag(BlockTag::Finalized),
                    include_full_transactions: false,
                },
            )
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_get_transaction_by_hash(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<Transaction>, MultiCallError<Option<Transaction>>> {
        let results: MultiCallResults<Option<Transaction>> = self
            .parallel_call("eth_getTransactionByHash", vec![tx_hash])
            .await;
        results.reduce_with_equality()
    }

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryParams,
    ) -> HttpOutcallResult<JsonRpcResult<FeeHistory>> {
        self.sequential_call_until_ok("eth_feeHistory", params)
            .await
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> HttpOutcallResult<JsonRpcResult<Hash>> {
        self.sequential_call_until_ok("eth_sendRawTransaction", vec![raw_signed_transaction_hex])
            .await
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCallResults<T> {
    results: BTreeMap<RpcNodeProvider, HttpOutcallResult<JsonRpcResult<T>>>,
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
        Self { results }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    InconsistentResults(MultiCallResults<T>),
}

impl<T: Debug + PartialEq> MultiCallResults<T> {
    pub fn reduce_with_equality(self) -> Result<T, MultiCallError<T>> {
        let mut results = self.results.into_iter();
        let (base_node_provider, base_result) = results
            .next()
            .expect("BUG: MultiCallResults is guaranteed to be non-empty");
        for (provider, result) in results {
            if result != base_result {
                ic_cdk::println!(
                    "WARN: Provider {:?} returned a different result than {:?}. Result {:?} is not equal to {:?}",
                    provider,
                    base_node_provider,
                    result,
                    base_result
                );
                return Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (base_node_provider, base_result),
                        (provider, result),
                    ]),
                ));
            }
        }
        match base_result {
            Ok(json_rpc_result) => match json_rpc_result {
                JsonRpcResult::Result(v) => Ok(v),
                JsonRpcResult::Error { code, message } => {
                    Err(MultiCallError::ConsistentJsonRpcError { code, message })
                }
            },
            Err(error) => Err(MultiCallError::ConsistentHttpOutcallError(error)),
        }
    }
}
