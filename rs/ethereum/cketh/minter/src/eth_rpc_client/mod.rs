use crate::{
    eth_rpc::Hash,
    lifecycle::EthereumNetwork,
    logs::{INFO, PrintProxySink, TRACE_HTTP},
    numeric::TransactionCount,
    state::State,
};
use candid::Nat;
use evm_rpc_client::{EvmRpcClient, IcRuntime, OverrideRpcConfig};
use evm_rpc_types::{
    Block, BlockTag, ConsensusStrategy, EthSepoliaService, FeeHistory, FeeHistoryArgs, GetLogsArgs,
    GetLogsRpcConfig as EvmGetLogsRpcConfig, GetTransactionCountArgs as EvmGetTransactionCountArgs,
    Hex20, HttpOutcallError, LogEntry, MultiRpcResult as EvmMultiRpcResult,
    RpcConfig as EvmRpcConfig, RpcError, RpcService as EvmRpcService,
    RpcServices as EvmRpcServices, SendRawTransactionStatus, TransactionReceipt,
};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

pub mod responses;

#[cfg(test)]
mod tests;

// This constant is our approximation of the expected header size.
// The HTTP standard doesn't define any limit, and many implementations limit
// the headers size to 8 KiB. We chose a lower limit because headers observed on most providers
// fit in the constant defined below, and if there is spike, then the payload size adjustment
// should take care of that.
const HEADER_SIZE_LIMIT: u64 = 2 * 1024;
// We expect most of the calls to contain zero events.
const ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE: u64 = 100;
const TOTAL_NUMBER_OF_PROVIDERS: u8 = 4;

#[derive(Debug)]
pub struct EthRpcClient {
    evm_rpc_client: EvmRpcClient<IcRuntime, PrintProxySink>,
}

impl EthRpcClient {
    pub fn from_state(state: &State) -> Self {
        fn rpc_config(strategy: ConsensusStrategy) -> EvmRpcConfig {
            EvmRpcConfig {
                response_consensus: Some(strategy),
                ..EvmRpcConfig::default()
            }
        }

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
        let response_consensus = ConsensusStrategy::Threshold {
            total: Some(TOTAL_NUMBER_OF_PROVIDERS),
            min: min_threshold,
        };
        let evm_rpc_client = EvmRpcClient::builder_for_ic(TRACE_HTTP)
            .with_providers(providers)
            .with_evm_canister_id(evm_rpc_id)
            .with_min_attached_cycles(MIN_ATTACHED_CYCLES)
            .with_override_rpc_config(OverrideRpcConfig {
                eth_get_block_by_number: Some(rpc_config(response_consensus.clone())),
                eth_get_logs: Some(EvmGetLogsRpcConfig {
                    response_size_estimate: Some(
                        ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT,
                    ),
                    response_consensus: Some(response_consensus.clone()),
                    ..Default::default()
                }),
                eth_fee_history: Some(rpc_config(response_consensus.clone())),
                eth_get_transaction_receipt: Some(rpc_config(response_consensus.clone())),
                eth_get_transaction_count: Some(rpc_config(response_consensus.clone())),
                eth_send_raw_transaction: Some(rpc_config(response_consensus)),
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
            .reduce_with_strategy(NoReduction)
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: BlockTag,
    ) -> Result<Block, MultiCallError<Block>> {
        self.evm_rpc_client
            .eth_get_block_by_number(block)
            .await
            .reduce_with_strategy(NoReduction)
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<TransactionReceipt>, MultiCallError<Option<TransactionReceipt>>> {
        self.evm_rpc_client
            .eth_get_transaction_receipt(tx_hash.to_string())
            .await
            .reduce_with_strategy(NoReduction)
    }

    pub async fn eth_fee_history(
        &self,
        params: FeeHistoryArgs,
    ) -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        self.evm_rpc_client
            .eth_fee_history(params)
            .await
            .reduce_with_strategy(StrictMajorityByKey::new(|fee_history: &FeeHistory| {
                Nat::from(fee_history.oldest_block.clone())
            }))
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> Result<SendRawTransactionStatus, MultiCallError<SendRawTransactionStatus>> {
        self.evm_rpc_client
            .eth_send_raw_transaction(raw_signed_transaction_hex)
            .await
            .reduce_with_strategy(AnyOf)
    }

    pub async fn eth_get_finalized_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        self.evm_rpc_client
            .eth_get_transaction_count(EvmGetTransactionCountArgs {
                address: Hex20::from(address.into_bytes()),
                block: BlockTag::Finalized,
            })
            .await
            .map(TransactionCount::from)
            .reduce_with_strategy(NoReduction)
    }

    pub async fn eth_get_latest_transaction_count(
        &self,
        address: Address,
    ) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
        self.evm_rpc_client
            .eth_get_transaction_count(EvmGetTransactionCountArgs {
                address: Hex20::from(address.into_bytes()),
                block: BlockTag::Latest,
            })
            .await
            .map(TransactionCount::from)
            .reduce_with_strategy(MinByKey::new(|count: &TransactionCount| *count))
    }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MultiCallResults<T> {
    ok_results: BTreeMap<EvmRpcService, T>,
    errors: BTreeMap<EvmRpcService, RpcError>,
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
            1 => {
                MultiCallError::ConsistentError(distinct_errors.into_iter().next().unwrap().clone())
            }
            _ => MultiCallError::InconsistentResults(self),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum MultiCallError<T> {
    ConsistentError(RpcError),
    InconsistentResults(MultiCallResults<T>),
}

pub type ReducedMultiCallResult<T> = Result<T, MultiCallError<T>>;

pub trait ReductionStrategy<T> {
    fn reduce(&self, results: MultiCallResults<T>) -> ReducedMultiCallResult<T>;
}

pub struct NoReduction;

impl<T> ReductionStrategy<T> for NoReduction {
    fn reduce(&self, results: MultiCallResults<T>) -> ReducedMultiCallResult<T> {
        Err(MultiCallError::InconsistentResults(results))
    }
}

pub struct AnyOf;

impl<T> ReductionStrategy<T> for AnyOf
where
    T: PartialEq,
{
    fn reduce(&self, results: MultiCallResults<T>) -> ReducedMultiCallResult<T> {
        results.at_least_one_ok().map(|(_, result)| result)
    }
}

pub struct MinByKey<F> {
    get_key: F,
}

impl<F> MinByKey<F> {
    pub fn new(get_key: F) -> Self {
        Self { get_key }
    }
}

impl<T, F, K> ReductionStrategy<T> for MinByKey<F>
where
    T: Debug + PartialEq,
    F: Fn(&T) -> K,
    K: Ord,
{
    fn reduce(&self, results: MultiCallResults<T>) -> ReducedMultiCallResult<T> {
        results.reduce_with_min_by_key(|result| (self.get_key)(result))
    }
}

pub struct StrictMajorityByKey<F> {
    get_key: F,
}

impl<F> StrictMajorityByKey<F> {
    pub fn new(get_key: F) -> Self {
        Self { get_key }
    }
}

impl<T, F, K> ReductionStrategy<T> for StrictMajorityByKey<F>
where
    T: Debug + PartialEq,
    F: Fn(&T) -> K,
    K: Ord,
{
    fn reduce(&self, results: MultiCallResults<T>) -> ReducedMultiCallResult<T> {
        results.reduce_with_strict_majority_by_key(|result| (self.get_key)(result))
    }
}

pub trait ToReducedWithStrategy<T> {
    fn reduce_with_strategy(self, strategy: impl ReductionStrategy<T>)
    -> ReducedMultiCallResult<T>;
}

impl<T> ToReducedWithStrategy<T> for EvmMultiRpcResult<T> {
    fn reduce_with_strategy(
        self,
        strategy: impl ReductionStrategy<T>,
    ) -> ReducedMultiCallResult<T> {
        match self {
            EvmMultiRpcResult::Consistent(result) => {
                result.map_err(MultiCallError::ConsistentError)
            }
            EvmMultiRpcResult::Inconsistent(results) => {
                strategy.reduce(MultiCallResults::from_non_empty_iter(results))
            }
        }
    }
}

impl<T> MultiCallError<T> {
    pub fn has_http_outcall_error_matching<P: Fn(&HttpOutcallError) -> bool>(
        &self,
        predicate: P,
    ) -> bool {
        match self {
            MultiCallError::ConsistentError(RpcError::HttpOutcallError(error)) => predicate(error),
            MultiCallError::ConsistentError(RpcError::JsonRpcError { .. }) => false,
            MultiCallError::ConsistentError(RpcError::ProviderError(_)) => false,
            MultiCallError::ConsistentError(RpcError::ValidationError(_)) => false,
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
        }
    }
}

impl<T: Debug + PartialEq> MultiCallResults<T> {
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
