use crate::checked_amount::CheckedAmountOf;
use crate::eth_rpc::{
    self, Block, BlockSpec, BlockTag, Data, FeeHistory, FeeHistoryParams, FixedSizeData,
    GetLogsParam, Hash, HttpOutcallError, HttpResponsePayload, LogEntry, ResponseSizeEstimate,
    SendRawTransactionResult, Topic, HEADER_SIZE_LIMIT,
};
use crate::eth_rpc_client::providers::{
    EthereumProvider, RpcNodeProvider, SepoliaProvider, MAINNET_PROVIDERS, SEPOLIA_PROVIDERS,
};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::logs::{PrintProxySink, DEBUG, INFO, TRACE_HTTP};
use crate::numeric::{BlockNumber, GasAmount, LogIndex, TransactionCount, Wei, WeiPerGas};
use crate::state::State;
use candid::Nat;
use evm_rpc_client::{
    types::candid::{
        Block as EvmBlock, BlockTag as EvmBlockTag, FeeHistory as EvmFeeHistory,
        FeeHistoryArgs as EvmFeeHistoryArgs, GetLogsArgs as EvmGetLogsArgs,
        GetTransactionCountArgs as EvmGetTransactionCountArgs, LogEntry as EvmLogEntry,
        MultiRpcResult as EvmMultiRpcResult, RpcConfig as EvmRpcConfig, RpcError as EvmRpcError,
        RpcResult as EvmRpcResult, SendRawTransactionStatus as EvmSendRawTransactionStatus,
        TransactionReceipt as EvmTransactionReceipt,
    },
    EvmRpcClient, IcRuntime, OverrideRpcConfig,
};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use num_traits::ToPrimitive;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt::{Debug, Display};
use std::str::FromStr;

mod providers;
pub mod requests;
pub mod responses;

#[cfg(test)]
mod tests;

// We expect most of the calls to contain zero events.
const ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE: u64 = 100;

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
            const MIN_ATTACHED_CYCLES: u128 = 300_000_000_000;

            let providers = match client.chain {
                EthereumNetwork::Mainnet => EthereumProvider::evm_rpc_node_providers(),
                EthereumNetwork::Sepolia => SepoliaProvider::evm_rpc_node_providers(),
            };
            client.evm_rpc_client = Some(
                EvmRpcClient::builder_for_ic(TRACE_HTTP)
                    .with_providers(providers)
                    .with_evm_canister_id(evm_rpc_id)
                    .with_min_attached_cycles(MIN_ATTACHED_CYCLES)
                    .with_override_rpc_config(OverrideRpcConfig {
                        eth_get_logs: Some(EvmRpcConfig {
                            response_size_estimate: Some(
                                ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT,
                            ),
                        }),
                        ..Default::default()
                    })
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
    ) -> MultiCallResults<O>
    where
        I: Serialize + Clone,
        O: DeserializeOwned + HttpResponsePayload + Debug,
    {
        let mut results: MultiCallResults<O> = MultiCallResults::new();
        for provider in self.providers() {
            log!(
                DEBUG,
                "[sequential_call_until_ok]: calling provider: {:?}",
                provider
            );
            let result: Result<O, SingleCallError> = eth_rpc::call(
                provider.url().to_string(),
                method.clone(),
                params.clone(),
                response_size_estimate,
            )
            .await;
            results.insert_once(provider.clone(), result);
            if results.has_ok_results() {
                return results;
            }
        }
        results
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
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_get_logs(EvmGetLogsArgs {
                    from_block: Some(into_evm_block_tag(params.from_block)),
                    to_block: Some(into_evm_block_tag(params.to_block)),
                    addresses: params.address.into_iter().map(|a| a.to_string()).collect(),
                    topics: Some(into_evm_topic(params.topics)),
                })
                .await
                .reduce()
                .into();
        }

        let results: MultiCallResults<Vec<LogEntry>> = self
            .parallel_call(
                "eth_getLogs",
                vec![params],
                ResponseSizeEstimate::new(ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE),
            )
            .await;
        results.reduce().into()
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: BlockSpec,
    ) -> Result<Block, MultiCallError<Block>> {
        use crate::eth_rpc::GetBlockByNumberParams;

        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_get_block_by_number(into_evm_block_tag(block))
                .await
                .reduce()
                .into();
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
        results.reduce().into()
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<TransactionReceipt>, MultiCallError<Option<TransactionReceipt>>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_get_transaction_receipt(tx_hash.to_string())
                .await
                .reduce()
                .into();
        }
        let results: MultiCallResults<Option<TransactionReceipt>> = self
            .parallel_call(
                "eth_getTransactionReceipt",
                vec![tx_hash],
                ResponseSizeEstimate::new(700),
            )
            .await;
        results.reduce().into()
    }

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryParams,
    ) -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_fee_history(EvmFeeHistoryArgs {
                    block_count: params.block_count.as_u128(),
                    newest_block: into_evm_block_tag(params.highest_block),
                    reward_percentiles: Some(params.reward_percentiles),
                })
                .await
                .reduce()
                .into();
        }
        // A typical response is slightly above 300 bytes.
        let results: MultiCallResults<FeeHistory> = self
            .parallel_call("eth_feeHistory", params, ResponseSizeEstimate::new(512))
            .await;
        results.reduce().into()
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> Result<SendRawTransactionResult, MultiCallError<SendRawTransactionResult>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_send_raw_transaction(raw_signed_transaction_hex)
                .await
                .reduce()
                .into();
        }
        // A successful reply is under 256 bytes, but we expect most calls to end with an error
        // since we submit the same transaction from multiple nodes.
        let results: MultiCallResults<SendRawTransactionResult> = self
            .sequential_call_until_ok(
                "eth_sendRawTransaction",
                vec![raw_signed_transaction_hex],
                ResponseSizeEstimate::new(256),
            )
            .await;
        results.reduce().into()
    }

    pub async fn eth_get_finalized_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            let results = evm_rpc_client
                .eth_get_transaction_count(EvmGetTransactionCountArgs {
                    address: address.to_string(),
                    block: EvmBlockTag::Finalized,
                })
                .await;
            return ReduceWithStrategy::<Equality>::reduce(results).into();
        }
        let results: MultiCallResults<TransactionCount> = self
            .eth_get_transaction_count(GetTransactionCountParams {
                address,
                block: BlockSpec::Tag(BlockTag::Finalized),
            })
            .await;
        ReduceWithStrategy::<Equality>::reduce(results).into()
    }

    pub async fn eth_get_latest_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            let results = evm_rpc_client
                .eth_get_transaction_count(EvmGetTransactionCountArgs {
                    address: address.to_string(),
                    block: EvmBlockTag::Latest,
                })
                .await;
            return ReduceWithStrategy::<MinByKey>::reduce(results).into();
        }
        let results: MultiCallResults<TransactionCount> = self
            .eth_get_transaction_count(GetTransactionCountParams {
                address,
                block: BlockSpec::Tag(BlockTag::Latest),
            })
            .await;
        ReduceWithStrategy::<MinByKey>::reduce(results).into()
    }

    async fn eth_get_transaction_count(
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
#[derive(Clone, Eq, PartialEq, Debug)]
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

    fn has_ok_results(&self) -> bool {
        !self.ok_results.is_empty()
    }

    fn from_non_empty_iter<
        I: IntoIterator<Item = (RpcNodeProvider, Result<T, SingleCallError>)>,
    >(
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

    fn at_least_one_ok(self) -> Result<(RpcNodeProvider, T), MultiCallError<T>> {
        match self.ok_results.len() {
            0 => Err(self.expect_error()),
            _ => Ok(self.ok_results.into_iter().next().unwrap()),
        }
    }

    fn expect_error(self) -> MultiCallError<T> {
        let distinct_errors: BTreeSet<_> = self.errors.values().collect();
        match distinct_errors.len() {
            0 => panic!("BUG: expect errors should be non-empty"),
            1 => match distinct_errors.into_iter().next().unwrap().clone() {
                SingleCallError::HttpOutcallError(error) => {
                    MultiCallError::ConsistentHttpOutcallError(error)
                }
                SingleCallError::JsonRpcError { code, message } => {
                    MultiCallError::ConsistentJsonRpcError { code, message }
                }
                SingleCallError::EvmRpcError(error) => {
                    MultiCallError::ConsistentEvmRpcCanisterError(error)
                }
            },
            _ => MultiCallError::InconsistentResults(self),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum SingleCallError {
    HttpOutcallError(HttpOutcallError),
    JsonRpcError { code: i64, message: String },
    EvmRpcError(String),
}

impl From<EvmRpcError> for SingleCallError {
    fn from(value: EvmRpcError) -> Self {
        match value {
            EvmRpcError::ProviderError(e) => SingleCallError::EvmRpcError(e.to_string()),
            EvmRpcError::HttpOutcallError(e) => SingleCallError::HttpOutcallError(e.into()),
            EvmRpcError::JsonRpcError(e) => SingleCallError::JsonRpcError {
                code: e.code,
                message: e.message,
            },
            EvmRpcError::ValidationError(e) => SingleCallError::EvmRpcError(e.to_string()),
        }
    }
}

impl From<HttpOutcallError> for SingleCallError {
    fn from(value: HttpOutcallError) -> Self {
        SingleCallError::HttpOutcallError(value)
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    ConsistentEvmRpcCanisterError(String),
    InconsistentResults(MultiCallResults<T>),
}

#[derive(Eq, PartialEq, Debug)]
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
        fallible_op: &F,
        reduction: R,
    ) -> ReducedResult<U> {
        let result = match self.result {
            Ok(t) => fallible_op(t)
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
                reduction(results.map(fallible_op, &|e| {
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
                Err(e) => Err(SingleCallError::from(e)),
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

impl<T> AsRef<Result<T, MultiCallError<T>>> for ReducedResult<T> {
    fn as_ref(&self) -> &Result<T, MultiCallError<T>> {
        &self.result
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

trait Reduce {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
}

impl Reduce for EvmMultiRpcResult<EvmBlock> {
    type Item = Block;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
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

impl Reduce for MultiCallResults<Block> {
    type Item = Block;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_equality().into()
    }
}

impl Reduce for EvmMultiRpcResult<Vec<EvmLogEntry>> {
    type Item = Vec<LogEntry>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_logs(logs: Vec<EvmLogEntry>) -> Result<Vec<LogEntry>, String> {
            logs.into_iter().map(map_single_log).collect()
        }

        fn map_single_log(log: EvmLogEntry) -> Result<LogEntry, String> {
            Ok(LogEntry {
                address: Address::from_str(&log.address)?,
                topics: log
                    .topics
                    .into_iter()
                    .map(|t| FixedSizeData::from_str(&t))
                    .collect::<Result<_, _>>()?,
                data: Data::from_str(&log.data)?,
                block_number: log.block_number.map(BlockNumber::try_from).transpose()?,
                transaction_hash: log
                    .transaction_hash
                    .as_deref()
                    .map(Hash::from_str)
                    .transpose()?,
                transaction_index: log
                    .transaction_index
                    .map(|i| CheckedAmountOf::<()>::try_from(i).map(|c| c.into_inner()))
                    .transpose()?,
                block_hash: log.block_hash.as_deref().map(Hash::from_str).transpose()?,
                log_index: log.log_index.map(LogIndex::try_from).transpose()?,
                removed: log.removed,
            })
        }

        ReducedResult::from_internal(self)
            .map_reduce(&map_logs, MultiCallResults::reduce_with_equality)
    }
}

impl Reduce for MultiCallResults<Vec<LogEntry>> {
    type Item = Vec<LogEntry>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_equality().into()
    }
}

impl Reduce for EvmMultiRpcResult<Option<EvmFeeHistory>> {
    type Item = FeeHistory;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_fee_history(fee_history: Option<EvmFeeHistory>) -> Result<FeeHistory, String> {
            let fee_history = fee_history.ok_or("No fee history available")?;
            Ok(FeeHistory {
                oldest_block: BlockNumber::try_from(fee_history.oldest_block)?,
                base_fee_per_gas: wei_per_gas_iter(fee_history.base_fee_per_gas)?,
                reward: fee_history
                    .reward
                    .into_iter()
                    .map(wei_per_gas_iter)
                    .collect::<Result<_, _>>()?,
            })
        }

        fn wei_per_gas_iter(values: Vec<Nat>) -> Result<Vec<WeiPerGas>, String> {
            values.into_iter().map(WeiPerGas::try_from).collect()
        }

        ReducedResult::from_internal(self).map_reduce(&map_fee_history, |results| {
            results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block)
        })
    }
}

impl Reduce for MultiCallResults<FeeHistory> {
    type Item = FeeHistory;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block)
            .into()
    }
}

impl Reduce for EvmMultiRpcResult<Option<EvmTransactionReceipt>> {
    type Item = Option<TransactionReceipt>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_transaction_receipt(
            receipt: Option<EvmTransactionReceipt>,
        ) -> Result<Option<TransactionReceipt>, String> {
            receipt
                .map(|evm_receipt| {
                    Ok(TransactionReceipt {
                        block_hash: Hash::from_str(&evm_receipt.block_hash)?,
                        block_number: BlockNumber::try_from(evm_receipt.block_number)?,
                        effective_gas_price: WeiPerGas::try_from(evm_receipt.effective_gas_price)?,
                        gas_used: GasAmount::try_from(evm_receipt.gas_used)?,
                        status: TransactionStatus::try_from(
                            evm_receipt
                                .status
                                .0
                                .to_u8()
                                .ok_or("invalid transaction status")?,
                        )?,
                        transaction_hash: Hash::from_str(&evm_receipt.transaction_hash)?,
                    })
                })
                .transpose()
        }

        ReducedResult::from_internal(self).map_reduce(
            &map_transaction_receipt,
            MultiCallResults::reduce_with_equality,
        )
    }
}

impl Reduce for MultiCallResults<Option<TransactionReceipt>> {
    type Item = Option<TransactionReceipt>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_equality().into()
    }
}

impl Reduce for EvmMultiRpcResult<EvmSendRawTransactionStatus> {
    type Item = SendRawTransactionResult;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|tx_status| {
                Ok::<SendRawTransactionResult, Infallible>(SendRawTransactionResult::from(
                    tx_status,
                ))
            },
            |results| results.at_least_one_ok().map(|(_provider, result)| result),
        )
    }
}

impl Reduce for MultiCallResults<SendRawTransactionResult> {
    type Item = SendRawTransactionResult;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.at_least_one_ok()
            .map(|(_provider, result)| result)
            .into()
    }
}

trait ReduceWithStrategy<S> {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
}

pub enum Equality {}
pub enum MinByKey {}

impl ReduceWithStrategy<Equality> for MultiCallResults<TransactionCount> {
    type Item = TransactionCount;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_equality().into()
    }
}

impl ReduceWithStrategy<Equality> for EvmMultiRpcResult<Nat> {
    type Item = TransactionCount;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|tx_count: Nat| TransactionCount::try_from(tx_count),
            MultiCallResults::reduce_with_equality,
        )
    }
}

impl ReduceWithStrategy<MinByKey> for MultiCallResults<TransactionCount> {
    type Item = TransactionCount;

    fn reduce(self) -> ReducedResult<Self::Item> {
        self.reduce_with_min_by_key(|transaction_count| *transaction_count)
            .into()
    }
}

impl ReduceWithStrategy<MinByKey> for EvmMultiRpcResult<Nat> {
    type Item = TransactionCount;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|tx_count: Nat| TransactionCount::try_from(tx_count),
            |results| results.reduce_with_min_by_key(|transaction_count| *transaction_count),
        )
    }
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

fn into_evm_block_tag(block: BlockSpec) -> EvmBlockTag {
    match block {
        BlockSpec::Number(n) => EvmBlockTag::Number(n.into()),
        BlockSpec::Tag(BlockTag::Latest) => EvmBlockTag::Latest,
        BlockSpec::Tag(BlockTag::Safe) => EvmBlockTag::Safe,
        BlockSpec::Tag(BlockTag::Finalized) => EvmBlockTag::Finalized,
    }
}

fn into_evm_topic(topics: Vec<Topic>) -> Vec<Vec<String>> {
    let mut result = Vec::with_capacity(topics.len());
    for topic in topics {
        result.push(match topic {
            Topic::Single(single_topic) => vec![single_topic.to_string()],
            Topic::Multiple(multiple_topic) => {
                multiple_topic.into_iter().map(|t| t.to_string()).collect()
            }
        });
    }
    result
}
