use crate::eth_rpc::{Data, FixedSizeData, Hash, LogEntry, Quantity, HEADER_SIZE_LIMIT};
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::logs::{PrintProxySink, INFO, TRACE_HTTP};
use crate::numeric::{BlockNumber, GasAmount, LogIndex, TransactionCount, WeiPerGas};
use crate::state::State;
use candid::Nat;
use evm_rpc_client::{
    Block, BlockTag, ConsensusStrategy, EthSepoliaService, EvmRpcClient, FeeHistory,
    FeeHistoryArgs, GetLogsArgs, GetTransactionCountArgs as EvmGetTransactionCountArgs, Hex20,
    HttpOutcallError, IcRuntime, LogEntry as EvmLogEntry, MultiRpcResult as EvmMultiRpcResult,
    Nat256, OverrideRpcConfig, RpcConfig as EvmRpcConfig, RpcError, RpcService as EvmRpcService,
    RpcServices as EvmRpcServices, SendRawTransactionStatus,
    TransactionReceipt as EvmTransactionReceipt, ValidationError,
};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use num_traits::ToPrimitive;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt::{Debug, Display};

pub mod responses;

#[cfg(test)]
mod tests;

// We expect most of the calls to contain zero events.
const ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE: u64 = 100;
const TOTAL_NUMBER_OF_PROVIDERS: u8 = 4;

#[derive(Debug)]
pub struct EthRpcClient {
    evm_rpc_client: EvmRpcClient<IcRuntime, PrintProxySink>,
}

impl EthRpcClient {
    pub fn from_state(state: &State) -> Self {
        let chain = state.ethereum_network();
        let evm_rpc_id = state.evm_rpc_id();
        const MIN_ATTACHED_CYCLES: u128 = 500_000_000_000;

        let providers = match chain {
            EthereumNetwork::Mainnet => EvmRpcServices::EthMainnet(None),
            EthereumNetwork::Sepolia => EvmRpcServices::EthSepolia(Some(vec![
                EthSepoliaService::BlockPi,
                EthSepoliaService::PublicNode,
                EthSepoliaService::Alchemy,
                EthSepoliaService::Ankr,
            ])),
        };
        let min_threshold = match chain {
            EthereumNetwork::Mainnet => 3_u8,
            EthereumNetwork::Sepolia => 2_u8,
        };
        assert!(
            min_threshold <= TOTAL_NUMBER_OF_PROVIDERS,
            "BUG: min_threshold too high"
        );
        let threshold_strategy = EvmRpcConfig {
            response_consensus: Some(ConsensusStrategy::Threshold {
                total: Some(TOTAL_NUMBER_OF_PROVIDERS),
                min: min_threshold,
            }),
            ..EvmRpcConfig::default()
        };
        let evm_rpc_client = EvmRpcClient::builder_for_ic(TRACE_HTTP)
            .with_providers(providers)
            .with_evm_canister_id(evm_rpc_id)
            .with_min_attached_cycles(MIN_ATTACHED_CYCLES)
            .with_override_rpc_config(OverrideRpcConfig {
                eth_get_block_by_number: Some(threshold_strategy.clone()),
                eth_get_logs: Some(EvmRpcConfig {
                    response_size_estimate: Some(
                        ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT,
                    ),
                    ..threshold_strategy.clone()
                }),
                eth_fee_history: Some(threshold_strategy.clone()),
                eth_get_transaction_receipt: Some(threshold_strategy.clone()),
                eth_get_transaction_count: Some(threshold_strategy.clone()),
                eth_send_raw_transaction: Some(threshold_strategy),
            })
            .build();

        Self { evm_rpc_client }
    }

    pub async fn eth_get_logs(
        &self,
        params: GetLogsArgs,
    ) -> Result<Vec<LogEntry>, MultiCallError<Vec<LogEntry>>> {
        self.evm_rpc_client
            .eth_get_logs(params)
            .await
            .reduce()
            .into()
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: BlockTag,
    ) -> Result<Block, MultiCallError<Block>> {
        convert_multirpcresult(self.evm_rpc_client.eth_get_block_by_number(block).await)
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<TransactionReceipt>, MultiCallError<Option<TransactionReceipt>>> {
        self.evm_rpc_client
            .eth_get_transaction_receipt(tx_hash.to_string())
            .await
            .reduce()
            .into()
    }

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryArgs,
    ) -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        self.evm_rpc_client
            .eth_fee_history(params)
            .await
            .reduce()
            .into()
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> Result<SendRawTransactionStatus, MultiCallError<SendRawTransactionStatus>> {
        self.evm_rpc_client
            .eth_send_raw_transaction(raw_signed_transaction_hex)
            .await
            .reduce()
            .into()
    }

    pub async fn eth_get_finalized_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        convert_multirpcresult(
            self.evm_rpc_client
                .eth_get_transaction_count(EvmGetTransactionCountArgs {
                    address: Hex20::from(address.into_bytes()),
                    block: BlockTag::Finalized,
                })
                .await
                .map(&|tx_count: Nat256| TransactionCount::from(tx_count)),
        )
    }

    pub async fn eth_get_latest_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        let results = self
            .evm_rpc_client
            .eth_get_transaction_count(EvmGetTransactionCountArgs {
                address: Hex20::from(address.into_bytes()),
                block: BlockTag::Latest,
            })
            .await;
        ReduceWithStrategy::<MinByKey>::reduce(results).into()
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MultiCallResults<T> {
    ok_results: BTreeMap<EvmRpcService, T>,
    errors: BTreeMap<EvmRpcService, RpcError>,
}

impl<T> From<ReducedResult<T>> for Result<T, MultiCallError<T>> {
    fn from(value: ReducedResult<T>) -> Self {
        value.result
    }
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

    fn map<U, E: Display, F: Fn(T) -> Result<U, E>, O: Fn(E) -> RpcError>(
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

    fn insert_once(&mut self, provider: EvmRpcService, result: Result<T, RpcError>) {
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

    fn from_non_empty_iter<I: IntoIterator<Item = (EvmRpcService, Result<T, RpcError>)>>(
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
    fn all_ok(self) -> Result<BTreeMap<EvmRpcService, T>, MultiCallError<T>> {
        if self.errors.is_empty() {
            return Ok(self.ok_results);
        }
        Err(self.expect_error())
    }

    /// Expects at least 2 ok results to be ok or return the following error:
    /// * MultiCallError::ConsistentJsonRpcError: all errors are the same JSON-RPC error.
    /// * MultiCallError::ConsistentHttpOutcallError: all errors are the same HTTP outcall error.
    /// * MultiCallError::InconsistentResults if there are different errors or an ok result with some errors.
    fn at_least_two_ok(self) -> Result<BTreeMap<EvmRpcService, T>, MultiCallError<T>> {
        match self.ok_results.len() {
            0 => Err(self.expect_error()),
            1 => Err(MultiCallError::InconsistentResults(self)),
            _ => Ok(self.ok_results),
        }
    }

    fn at_least_one_ok(self) -> Result<(EvmRpcService, T), MultiCallError<T>> {
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
                RpcError::HttpOutcallError(error) => {
                    MultiCallError::ConsistentHttpOutcallError(error)
                }
                RpcError::JsonRpcError(error) => MultiCallError::ConsistentJsonRpcError {
                    code: error.code,
                    message: error.message,
                },
                RpcError::ProviderError(error) => {
                    MultiCallError::ConsistentEvmRpcCanisterError(error.to_string())
                }
                RpcError::ValidationError(error) => {
                    MultiCallError::ConsistentEvmRpcCanisterError(error.to_string())
                }
            },
            _ => MultiCallError::InconsistentResults(self),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    ConsistentEvmRpcCanisterError(String),
    InconsistentResults(MultiCallResults<T>),
}

fn convert_multirpcresult<T>(result: EvmMultiRpcResult<T>) -> Result<T, MultiCallError<T>> {
    match result {
        EvmMultiRpcResult::Consistent(Ok(t)) => Ok(t),
        EvmMultiRpcResult::Consistent(Err(RpcError::HttpOutcallError(e))) => {
            Err(MultiCallError::ConsistentHttpOutcallError(e))
        }
        EvmMultiRpcResult::Consistent(Err(RpcError::JsonRpcError(e))) => {
            Err(MultiCallError::ConsistentJsonRpcError {
                code: e.code,
                message: e.message,
            })
        }
        EvmMultiRpcResult::Consistent(Err(RpcError::ProviderError(e))) => {
            Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
        }
        EvmMultiRpcResult::Consistent(Err(RpcError::ValidationError(e))) => {
            Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
        }
        EvmMultiRpcResult::Inconsistent(results) => {
            let mut multi_results = MultiCallResults::new();
            results.into_iter().for_each(|(provider, result)| {
                multi_results.insert_once(provider, result);
            });
            Err(MultiCallError::InconsistentResults(multi_results))
        }
    }
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
                    RpcError::ValidationError(ValidationError::Custom(e.to_string()))
                }))
            }
        };
        ReducedResult { result }
    }

    fn from_internal(value: EvmMultiRpcResult<T>) -> Self {
        let result = match value {
            EvmMultiRpcResult::Consistent(result) => match result {
                Ok(t) => Ok(t),
                Err(e) => match e {
                    RpcError::ProviderError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                    RpcError::HttpOutcallError(e) => {
                        Err(MultiCallError::ConsistentHttpOutcallError(e))
                    }
                    RpcError::JsonRpcError(e) => Err(MultiCallError::ConsistentJsonRpcError {
                        code: e.code,
                        message: e.message,
                    }),
                    RpcError::ValidationError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                },
            },
            EvmMultiRpcResult::Inconsistent(results) => {
                let mut multi_results = MultiCallResults::new();
                results.into_iter().for_each(|(provider, result)| {
                    multi_results.insert_once(provider, result);
                });
                Err(MultiCallError::InconsistentResults(multi_results))
            }
        };
        Self { result }
    }
}

trait Reduce {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
}

trait ReduceWithStrategy<S> {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
}

pub enum MinByKey {}

impl Reduce for EvmMultiRpcResult<Vec<EvmLogEntry>> {
    type Item = Vec<LogEntry>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_logs(logs: Vec<EvmLogEntry>) -> Result<Vec<LogEntry>, String> {
            logs.into_iter().map(map_single_log).collect()
        }

        fn map_single_log(log: EvmLogEntry) -> Result<LogEntry, String> {
            Ok(LogEntry {
                address: Address::new(log.address.into()),
                topics: log
                    .topics
                    .into_iter()
                    .map(|t| FixedSizeData(t.into()))
                    .collect(),
                data: Data(log.data.into()),
                block_number: log.block_number.map(BlockNumber::from),
                transaction_hash: log.transaction_hash.map(|h| Hash(h.into())),
                transaction_index: log
                    .transaction_index
                    .map(|i| Quantity::from_be_bytes(i.into_be_bytes())),
                block_hash: log.block_hash.map(|h| Hash(h.into())),
                log_index: log.log_index.map(LogIndex::from),
                removed: log.removed,
            })
        }

        ReducedResult::from_internal(self)
            .map_reduce(&map_logs, MultiCallResults::reduce_with_equality)
    }
}

impl Reduce for EvmMultiRpcResult<Option<FeeHistory>> {
    type Item = FeeHistory;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|fee_history| fee_history.ok_or("No fee history available".to_string()),
            |results| {
                results.reduce_with_strict_majority_by_key(|fee_history| {
                    Nat::from(fee_history.oldest_block.clone())
                })
            },
        )
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
                        block_hash: Hash(evm_receipt.block_hash.into()),
                        block_number: BlockNumber::from(evm_receipt.block_number),
                        effective_gas_price: WeiPerGas::from(evm_receipt.effective_gas_price),
                        gas_used: GasAmount::from(evm_receipt.gas_used),
                        status: TransactionStatus::try_from(
                            evm_receipt
                                .status
                                .and_then(|s| s.as_ref().0.to_u8())
                                .ok_or("invalid transaction status")?,
                        )?,
                        transaction_hash: Hash(evm_receipt.transaction_hash.into()),
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

impl Reduce for EvmMultiRpcResult<SendRawTransactionStatus> {
    type Item = SendRawTransactionStatus;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|tx_status| Ok::<SendRawTransactionStatus, Infallible>(tx_status),
            |results| results.at_least_one_ok().map(|(_provider, result)| result),
        )
    }
}

impl ReduceWithStrategy<MinByKey> for EvmMultiRpcResult<Nat256> {
    type Item = TransactionCount;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_internal(self).map_reduce(
            &|tx_count: Nat256| {
                Ok::<TransactionCount, Infallible>(TransactionCount::from(tx_count))
            },
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
                        RpcError::HttpOutcallError(error) => predicate(error),
                        RpcError::JsonRpcError { .. }
                        | RpcError::ProviderError(_)
                        | RpcError::ValidationError(_) => false,
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
        let mut votes_by_key: BTreeMap<K, BTreeMap<EvmRpcService, T>> = BTreeMap::new();
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

        let mut tally: Vec<(K, BTreeMap<EvmRpcService, T>)> = Vec::from_iter(votes_by_key);
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
