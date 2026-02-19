use crate::{DEFAULT_CALLER_TEST_ID, DEFAULT_CONTROLLER_TEST_ID, INITIAL_CYCLES, MOCK_API_KEY};
use candid::{CandidType, Decode, Encode, Nat, Principal};
use canlog::{Log, LogEntry};
use evm_rpc::{
    logs::Priority,
    providers::PROVIDERS,
    types::{ProviderId, RpcAccess},
};
use evm_rpc_client::{AlloyResponseConverter, ClientBuilder, EvmRpcClient, NoRetry};
use evm_rpc_types::{InstallArgs, Provider, RpcResult, RpcService};
use ic_canister_runtime::{CyclesWalletRuntime, Runtime};
use ic_http_types::{HttpRequest, HttpResponse};
use ic_management_canister_types::{CanisterId, CanisterSettings};
use ic_metrics_assert::{MetricsAssert, PocketIcAsyncHttpQuery};
use ic_pocket_canister_runtime::{MockHttpOutcalls, PocketIcRuntime};
use ic_test_utilities_load_wasm::load_wasm;
use num_traits::ToPrimitive;
use pocket_ic::{nonblocking::PocketIc, ErrorCode, PocketIcBuilder, RejectResponse};
use serde::de::DeserializeOwned;
use std::{
    env::{set_var, var},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
pub struct EvmRpcSetup {
    pub env: Arc<PocketIc>,
    pub caller: Principal,
    pub controller: Principal,
    pub evm_rpc_canister_id: CanisterId,
    pub wallet_canister_id: CanisterId,
}

impl EvmRpcSetup {
    pub async fn new() -> Self {
        Self::with_args(InstallArgs::default()).await
    }

    pub async fn with_args(args: InstallArgs) -> Self {
        // The `with_fiduciary_subnet` setup below requires that `nodes_in_subnet`
        // setting (part of InstallArgs) to be set appropriately. Otherwise
        // http outcall will fail due to insufficient cycles, even when `demo` is
        // enabled (which is the default above).
        //
        // As of writing, the default value of `nodes_in_subnet` is 34, which is
        // also the node count in fiduciary subnet.
        let pocket_ic = PocketIcBuilder::new()
            .with_fiduciary_subnet()
            .build_async()
            .await;
        let env = Arc::new(pocket_ic);

        let controller = DEFAULT_CONTROLLER_TEST_ID;
        let evm_rpc_canister_id = env
            .create_canister_with_settings(
                None,
                Some(CanisterSettings {
                    controllers: Some(vec![controller]),
                    ..CanisterSettings::default()
                }),
            )
            .await;
        env.add_cycles(evm_rpc_canister_id, INITIAL_CYCLES).await;
        env.install_canister(
            evm_rpc_canister_id,
            evm_rpc_wasm(),
            Encode!(&args).unwrap(),
            Some(controller),
        )
        .await;

        let wallet = DEFAULT_CALLER_TEST_ID;
        let wallet_canister_id = env
            .create_canister_with_id(
                None,
                Some(CanisterSettings {
                    controllers: Some(vec![controller]),
                    ..CanisterSettings::default()
                }),
                wallet,
            )
            .await
            .unwrap();
        env.add_cycles(wallet_canister_id, u64::MAX as u128).await;
        env.install_canister(wallet_canister_id, wallet_wasm(), vec![], Some(controller))
            .await;

        let caller = DEFAULT_CALLER_TEST_ID;

        Self {
            env,
            caller,
            controller,
            evm_rpc_canister_id,
            wallet_canister_id,
        }
    }

    pub async fn upgrade_canister(&self, args: InstallArgs) {
        for _ in 0..100 {
            self.env.tick().await;
            // Avoid `CanisterInstallCodeRateLimited` error
            self.env.advance_time(Duration::from_secs(600)).await;
            self.env.tick().await;
            match self
                .env
                .upgrade_canister(
                    self.evm_rpc_canister_id,
                    evm_rpc_wasm(),
                    Encode!(&args).unwrap(),
                    Some(self.controller),
                )
                .await
            {
                Ok(_) => return,
                Err(e) if e.error_code == ErrorCode::CanisterInstallCodeRateLimited => continue,
                Err(e) => panic!("Error while upgrading canister: {e:?}"),
            }
        }
        panic!("Failed to upgrade canister after many trials!")
    }

    pub fn client(
        &self,
        mocks: impl Into<MockHttpOutcalls>,
    ) -> ClientBuilder<CyclesWalletRuntime<PocketIcRuntime<'_>>, AlloyResponseConverter, NoRetry>
    {
        EvmRpcClient::builder(
            self.new_mock_http_runtime_with_wallet(mocks),
            self.evm_rpc_canister_id,
        )
        .with_alloy()
    }

    pub fn new_mock_http_runtime_with_wallet(
        &self,
        mocks: impl Into<MockHttpOutcalls>,
    ) -> CyclesWalletRuntime<PocketIcRuntime<'_>> {
        CyclesWalletRuntime::new(
            // Call the cycles wallet as controller so we are allowed to attach cycles
            PocketIcRuntime::new(self.env.as_ref(), self.controller).with_http_mocks(mocks.into()),
            self.wallet_canister_id,
        )
    }

    pub async fn evm_rpc_canister_cycles_balance(&self) -> u128 {
        self.env
            .canister_status(self.evm_rpc_canister_id, Some(self.controller))
            .await
            .unwrap()
            .cycles
            .0
            .to_u128()
            .unwrap()
    }

    pub async fn update_api_keys(
        &self,
        api_keys: &[(ProviderId, Option<String>)],
        caller: Principal,
    ) {
        self.call_update::<()>(
            "updateApiKeys",
            Encode!(&api_keys).expect("Failed to encode arguments."),
            caller,
        )
        .await;
    }

    pub async fn mock_api_keys(self) -> Self {
        self.update_api_keys(
            &PROVIDERS
                .iter()
                .filter_map(|provider| {
                    Some((
                        provider.provider_id,
                        match provider.access {
                            RpcAccess::Authenticated { .. } => Some(MOCK_API_KEY.to_string()),
                            RpcAccess::Unauthenticated { .. } => None?,
                        },
                    ))
                })
                .collect::<Vec<_>>(),
            self.controller,
        )
        .await;
        self
    }

    pub async fn http_get_logs(&self, priority: &str) -> Vec<LogEntry<Priority>> {
        let request = HttpRequest {
            method: "".to_string(),
            url: format!("/logs?priority={priority}"),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let response: HttpResponse = self
            .call_query(
                "http_request",
                Encode!(&request).unwrap(),
                Principal::anonymous(),
            )
            .await;
        serde_json::from_slice::<Log<Priority>>(&response.body)
            .expect("failed to parse EVM_RPC minter log")
            .entries
    }

    pub async fn get_service_provider_map(&self) -> Vec<(RpcService, ProviderId)> {
        self.call_query(
            "getServiceProviderMap",
            Encode!().unwrap(),
            Principal::anonymous(),
        )
        .await
    }

    pub async fn get_providers(&self) -> Vec<Provider> {
        self.call_query("getProviders", Encode!().unwrap(), Principal::anonymous())
            .await
    }

    pub async fn get_nodes_in_subnet(&self) -> u32 {
        self.call_query(
            "getNodesInSubnet",
            Encode!().unwrap(),
            Principal::anonymous(),
        )
        .await
    }

    pub async fn check_metrics(self) -> MetricsAssert<Self> {
        MetricsAssert::from_async_http_query(self).await
    }

    // Legacy endpoint, not supported by the `evm_rpc_client::EvmRpcClient`
    pub async fn request(
        &self,
        runtime: &CyclesWalletRuntime<PocketIcRuntime<'_>>,
        (source, json_rpc_payload, max_response_bytes): (RpcService, &str, u64),
        cycles: u128,
    ) -> RpcResult<String> {
        runtime
            .update_call(
                self.evm_rpc_canister_id,
                "request",
                (source, json_rpc_payload, max_response_bytes),
                cycles, // dummy value
            )
            .await
            .unwrap()
    }

    // Legacy endpoint, not supported by the `evm_rpc_client::EvmRpcClient`
    pub async fn request_cost(
        &self,
        source: RpcService,
        json_rpc_payload: &str,
        max_response_bytes: u64,
    ) -> RpcResult<u128> {
        self.call_query::<RpcResult<Nat>>(
            "requestCost",
            Encode!(&source, &json_rpc_payload, &max_response_bytes).unwrap(),
            Principal::anonymous(),
        )
        .await
        .map(|cycles_cost| cycles_cost.0.to_u128().unwrap())
    }

    async fn call_query<R: CandidType + DeserializeOwned>(
        &self,
        method: &str,
        input: Vec<u8>,
        caller: Principal,
    ) -> R {
        decode_reply(
            self.env
                .query_call(self.evm_rpc_canister_id, caller, method, input)
                .await,
        )
    }

    async fn call_update<R: CandidType + DeserializeOwned>(
        &self,
        method: &str,
        input: Vec<u8>,
        caller: Principal,
    ) -> R {
        decode_reply(
            self.env
                .update_call(self.evm_rpc_canister_id, caller, method, input)
                .await,
        )
    }
}

impl PocketIcAsyncHttpQuery for EvmRpcSetup {
    fn get_pocket_ic(&self) -> &PocketIc {
        &self.env
    }

    fn get_canister_id(&self) -> CanisterId {
        self.evm_rpc_canister_id
    }
}

fn evm_rpc_wasm() -> Vec<u8> {
    load_wasm(var("CARGO_MANIFEST_DIR").unwrap(), "evm_rpc", &[])
}

fn wallet_wasm() -> Vec<u8> {
    if var("WALLET_WASM_PATH").is_err() {
        set_var(
            "WALLET_WASM_PATH",
            PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap()).join("wallet.wasm.gz"),
        )
    };
    load_wasm(PathBuf::new(), "wallet", &[])
}

fn decode_reply<R: CandidType + DeserializeOwned>(result: Result<Vec<u8>, RejectResponse>) -> R {
    Decode!(
        &result.unwrap_or_else(|e| panic!("Expected a successful reply, got error {e}")),
        R
    )
    .unwrap_or_else(|e| panic!("Error while decoding Candid response: {e}"))
}
