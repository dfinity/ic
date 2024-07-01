#[cfg(test)]
mod tests;

pub mod types;

use crate::types::candid::{
    Block, BlockTag, MultiRpcResult, ProviderError, RpcConfig, RpcError, RpcServices,
};
use async_trait::async_trait;
use candid::utils::ArgumentEncoder;
use candid::{CandidType, Principal};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmRpcClient<R: Runtime, L: Sink> {
    runtime: R,
    logger: L,
    providers: RpcServices,
    evm_canister_id: Principal,
    min_attached_cycles: u128,
    max_num_retries: u32,
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
        self.call_internal("eth_getBlockByNumber", block).await
    }

    async fn call_internal<In, Out>(&self, method: &str, args: In) -> MultiRpcResult<Out>
    where
        In: CandidType + Send + Clone + Debug + 'static,
        Out: CandidType + DeserializeOwned + Debug + 'static,
    {
        let mut retries = 0;
        let mut attached_cycles = self.min_attached_cycles;

        loop {
            log!(
                self.logger,
                "[{}]: Calling providers {:?} for {} with arguments '{:?}' and {} cycles",
                self.evm_canister_id,
                self.providers,
                method,
                args,
                attached_cycles
            );
            let result: MultiRpcResult<Out> = self
                .runtime
                .call(
                    self.evm_canister_id,
                    method,
                    (self.providers.clone(), None::<RpcConfig>, args.clone()),
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
            min_attached_cycles: self.min_attached_cycles,
            max_num_retries: self.max_num_retries,
        }
    }
}

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
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
