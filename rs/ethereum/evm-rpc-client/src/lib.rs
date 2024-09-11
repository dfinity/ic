#[cfg(test)]
mod tests;

pub mod types;

use crate::types::candid::{
    Block, BlockTag, FeeHistory, FeeHistoryArgs, GetLogsArgs, GetTransactionCountArgs, LogEntry,
    MultiRpcResult, ProviderError, RpcConfig, RpcError, RpcServices, SendRawTransactionStatus,
    TransactionReceipt,
};
use async_trait::async_trait;
use candid::utils::ArgumentEncoder;
use candid::{CandidType, Nat, Principal};
use ic_canister_log::{log, Sink};
use ic_cdk::api::call::RejectionCode;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

#[async_trait]
pub trait Runtime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
        cycles: u128,
    ) -> Result<Out, (RejectionCode, String)>
    where
        In: ArgumentEncoder + Send + 'static,
        Out: CandidType + DeserializeOwned + 'static;
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EvmRpcClient<R: Runtime, L: Sink> {
    runtime: R,
    logger: L,
    providers: RpcServices,
    evm_canister_id: Principal,
    override_rpc_config: OverrideRpcConfig,
    min_attached_cycles: u128,
    max_num_retries: u32,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct OverrideRpcConfig {
    pub eth_get_block_by_number: Option<RpcConfig>,
    pub eth_get_logs: Option<RpcConfig>,
    pub eth_fee_history: Option<RpcConfig>,
    pub eth_get_transaction_receipt: Option<RpcConfig>,
    pub eth_get_transaction_count: Option<RpcConfig>,
    pub eth_send_raw_transaction: Option<RpcConfig>,
}

impl<L: Sink> EvmRpcClient<IcRuntime, L> {
    pub fn builder_for_ic(logger: L) -> EvmRpcClientBuilder<IcRuntime, L> {
        EvmRpcClientBuilder::new(IcRuntime {}, logger)
    }
}

impl<R: Runtime, L: Sink> EvmRpcClient<R, L> {
    pub fn builder(runtime: R, logger: L) -> EvmRpcClientBuilder<R, L> {
        EvmRpcClientBuilder::new(runtime, logger)
    }

    pub async fn eth_get_block_by_number(&self, block: BlockTag) -> MultiRpcResult<Block> {
        self.call_internal(
            "eth_getBlockByNumber",
            self.override_rpc_config.eth_get_block_by_number.clone(),
            block,
        )
        .await
    }

    pub async fn eth_get_logs(&self, args: GetLogsArgs) -> MultiRpcResult<Vec<LogEntry>> {
        self.call_internal(
            "eth_getLogs",
            self.override_rpc_config.eth_get_logs.clone(),
            args,
        )
        .await
    }

    pub async fn eth_fee_history(
        &self,
        args: FeeHistoryArgs,
    ) -> MultiRpcResult<Option<FeeHistory>> {
        self.call_internal(
            "eth_feeHistory",
            self.override_rpc_config.eth_fee_history.clone(),
            args,
        )
        .await
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        transaction_hash: String,
    ) -> MultiRpcResult<Option<TransactionReceipt>> {
        self.call_internal(
            "eth_getTransactionReceipt",
            self.override_rpc_config.eth_get_transaction_receipt.clone(),
            transaction_hash,
        )
        .await
    }

    pub async fn eth_get_transaction_count(
        &self,
        args: GetTransactionCountArgs,
    ) -> MultiRpcResult<Nat> {
        self.call_internal(
            "eth_getTransactionCount",
            self.override_rpc_config.eth_get_transaction_count.clone(),
            args,
        )
        .await
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_tx_hex: String,
    ) -> MultiRpcResult<SendRawTransactionStatus> {
        self.call_internal(
            "eth_sendRawTransaction",
            self.override_rpc_config.eth_send_raw_transaction.clone(),
            raw_signed_tx_hex,
        )
        .await
    }

    async fn call_internal<In, Out>(
        &self,
        method: &str,
        config: Option<RpcConfig>,
        args: In,
    ) -> MultiRpcResult<Out>
    where
        In: CandidType + Send + Clone + Debug + 'static,
        Out: CandidType + DeserializeOwned + Debug + 'static,
    {
        let mut retries = 0;
        let mut attached_cycles = self.min_attached_cycles;

        loop {
            log!(
                self.logger,
                "[{}]: Calling providers {:?} for {} with arguments '{:?}' and {} cycles (retry {})",
                self.evm_canister_id,
                self.providers,
                method,
                args,
                attached_cycles,
                retries
            );
            let result: MultiRpcResult<Out> = self
                .runtime
                .call(
                    self.evm_canister_id,
                    method,
                    (self.providers.clone(), config.clone(), args.clone()),
                    attached_cycles,
                )
                .await
                .unwrap_or_else(|(code, msg)| {
                    MultiRpcResult::Consistent(Err(RpcError::from_rejection(code, msg)))
                });
            log!(
                self.logger,
                "[{}]: Response to {} after {} retries: {:?}",
                self.evm_canister_id,
                method,
                retries,
                result
            );
            if let Some(expected) = max_expected_too_few_cycles_error(&result) {
                if retries < self.max_num_retries {
                    retries += 1;
                    attached_cycles = attached_cycles.saturating_mul(2).max(expected);
                    continue;
                } else {
                    log!(
                        self.logger,
                        "Too few cycles error after {} retries. Needed at least: {} cycles",
                        retries,
                        expected
                    );
                }
            }
            return result;
        }
    }
}

fn max_expected_too_few_cycles_error<Out>(result: &MultiRpcResult<Out>) -> Option<u128> {
    result
        .iter()
        .filter_map(|res| match res {
            Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                expected,
                received: _,
            })) => Some(*expected),
            _ => None,
        })
        .max()
}

pub struct EvmRpcClientBuilder<R: Runtime, L: Sink> {
    runtime: R,
    logger: L,
    providers: RpcServices,
    evm_canister_id: Principal,
    override_rpc_config: OverrideRpcConfig,
    min_attached_cycles: u128,
    max_num_retries: u32,
}

impl<R: Runtime, L: Sink> EvmRpcClientBuilder<R, L> {
    pub fn new(runtime: R, logger: L) -> Self {
        const DEFAULT_PROVIDERS: RpcServices = RpcServices::EthMainnet(None);
        const EVM_RPC_CANISTER_ID_FIDUCIARY: Principal =
            Principal::from_slice(&[0_u8, 0, 0, 0, 2, 48, 0, 204, 1, 1]);
        const DEFAULT_MIN_ATTACHED_CYCLES: u128 = 3_000_000_000;
        const DEFAULT_MAX_NUM_RETRIES: u32 = 10;

        debug_assert_eq!(
            EVM_RPC_CANISTER_ID_FIDUCIARY,
            Principal::from_text("7hfb6-caaaa-aaaar-qadga-cai").unwrap()
        );

        Self {
            runtime,
            logger,
            providers: DEFAULT_PROVIDERS,
            evm_canister_id: EVM_RPC_CANISTER_ID_FIDUCIARY,
            override_rpc_config: Default::default(),
            min_attached_cycles: DEFAULT_MIN_ATTACHED_CYCLES,
            max_num_retries: DEFAULT_MAX_NUM_RETRIES,
        }
    }

    pub fn with_runtime<OtherRuntime: Runtime>(
        self,
        runtime: OtherRuntime,
    ) -> EvmRpcClientBuilder<OtherRuntime, L> {
        EvmRpcClientBuilder {
            runtime,
            logger: self.logger,
            providers: self.providers,
            evm_canister_id: self.evm_canister_id,
            override_rpc_config: self.override_rpc_config,
            min_attached_cycles: self.min_attached_cycles,
            max_num_retries: self.max_num_retries,
        }
    }

    pub fn with_providers(mut self, providers: RpcServices) -> Self {
        self.providers = providers;
        self
    }

    pub fn with_evm_canister_id(mut self, evm_canister_id: Principal) -> Self {
        self.evm_canister_id = evm_canister_id;
        self
    }

    pub fn with_override_rpc_config(mut self, override_rpc_config: OverrideRpcConfig) -> Self {
        self.override_rpc_config = override_rpc_config;
        self
    }

    pub fn with_min_attached_cycles(mut self, min_attached_cycles: u128) -> Self {
        self.min_attached_cycles = min_attached_cycles;
        self
    }

    pub fn with_max_num_retries(mut self, max_num_retries: u32) -> Self {
        self.max_num_retries = max_num_retries;
        self
    }

    pub fn build(self) -> EvmRpcClient<R, L> {
        EvmRpcClient {
            runtime: self.runtime,
            logger: self.logger,
            providers: self.providers,
            evm_canister_id: self.evm_canister_id,
            override_rpc_config: self.override_rpc_config,
            min_attached_cycles: self.min_attached_cycles,
            max_num_retries: self.max_num_retries,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct IcRuntime {}

#[async_trait]
impl Runtime for IcRuntime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
        cycles: u128,
    ) -> Result<Out, (RejectionCode, String)>
    where
        In: ArgumentEncoder + Send + 'static,
        Out: CandidType + DeserializeOwned + 'static,
    {
        ic_cdk::api::call::call_with_payment128(id, method, args, cycles)
            .await
            .map(|(res,)| res)
    }
}
