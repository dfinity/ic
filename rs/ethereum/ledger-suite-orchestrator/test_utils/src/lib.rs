use crate::flow::{AddErc20TokenFlow, ManagedCanistersAssert};
use crate::metrics::MetricsAssert;
use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::management_canister::main::CanisterStatusResponse;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, CyclesManagement, Erc20Contract, InitArg, LedgerInitArg, ManagedCanisterIds,
    OrchestratorArg, OrchestratorInfo, UpgradeArg,
};
use ic_ledger_suite_orchestrator::state::{ArchiveWasm, IndexWasm, LedgerWasm, Wasm, WasmHash};
use ic_management_canister_types::{
    CanisterInstallMode, CanisterStatusType, InstallCodeArgs, Method, Payload,
};
use ic_state_machine_tests::{
    CanisterStatusResultV2, Cycles, StateMachine, StateMachineBuilder, UserError, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
pub use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;
pub use icrc_ledger_types::icrc1::account::Account as LedgerAccount;
use std::sync::Arc;

pub mod arbitrary;
pub mod flow;
pub mod metrics;
pub mod universal_canister;

const MAX_TICKS: usize = 10;
const GIT_COMMIT_HASH: &str = "6a8e5fca2c6b4e12966638c444e994e204b42989";
pub const GIT_COMMIT_HASH_UPGRADE: &str = "b7fef0f57ca246b18deda3efd34a24bb605c8199";
pub const CKERC20_TRANSFER_FEE: u64 = 4_000; //0.004 USD for ckUSDC/ckUSDT

pub const NNS_ROOT_PRINCIPAL: Principal = Principal::from_slice(&[0_u8]);

pub struct LedgerSuiteOrchestrator {
    pub env: Arc<StateMachine>,
    pub ledger_suite_orchestrator_id: CanisterId,
    pub ledger_suite_orchestrator_wasm: Vec<u8>,
    pub embedded_ledger_wasm_hash: WasmHash,
    pub embedded_index_wasm_hash: WasmHash,
    pub embedded_archive_wasm_hash: WasmHash,
}

impl Default for LedgerSuiteOrchestrator {
    fn default() -> Self {
        Self::new(Arc::new(new_state_machine()), default_init_arg())
    }
}

impl AsRef<StateMachine> for LedgerSuiteOrchestrator {
    fn as_ref(&self) -> &StateMachine {
        &self.env
    }
}

impl LedgerSuiteOrchestrator {
    pub fn with_cycles_management(cycles_management: CyclesManagement) -> Self {
        let init_arg = InitArg {
            cycles_management: Some(cycles_management),
            ..default_init_arg()
        };
        Self::new(Arc::new(new_state_machine()), init_arg)
    }

    pub fn new(env: Arc<StateMachine>, init_arg: InitArg) -> Self {
        let ledger_suite_orchestrator_id =
            env.create_canister_with_cycles(None, Cycles::new(u128::MAX), None);
        Self {
            env,
            ledger_suite_orchestrator_id,
            ledger_suite_orchestrator_wasm: ledger_suite_orchestrator_wasm(),
            embedded_ledger_wasm_hash: ledger_wasm().hash().clone(),
            embedded_index_wasm_hash: index_wasm().hash().clone(),
            embedded_archive_wasm_hash: archive_wasm().hash().clone(),
        }
        .install_ledger_suite_orchestrator(init_arg)
    }

    pub fn new_with_ledger_get_blocks_disabled(env: Arc<StateMachine>, init_arg: InitArg) -> Self {
        let ledger_suite_orchestrator_id =
            env.create_canister_with_cycles(None, Cycles::new(u128::MAX), None);
        Self {
            env,
            ledger_suite_orchestrator_id,
            ledger_suite_orchestrator_wasm: ledger_suite_orchestrator_get_blocks_disabled_wasm(),
            embedded_ledger_wasm_hash: ledger_get_blocks_disabled_wasm().hash().clone(),
            embedded_index_wasm_hash: index_wasm().hash().clone(),
            embedded_archive_wasm_hash: archive_wasm().hash().clone(),
        }
        .install_ledger_suite_orchestrator(init_arg)
    }

    fn install_ledger_suite_orchestrator(self, init_arg: InitArg) -> Self {
        self.env
            .install_existing_canister(
                self.ledger_suite_orchestrator_id,
                self.ledger_suite_orchestrator_wasm.clone(),
                Encode!(&OrchestratorArg::InitArg(init_arg)).unwrap(),
            )
            .unwrap();
        self
    }

    fn upgrade_ledger_suite_orchestrator_expecting_ok(self, upgrade_arg: &OrchestratorArg) -> Self {
        self.upgrade_ledger_suite_orchestrator_with_same_wasm(upgrade_arg)
            .expect("Failed to upgrade ledger suite orchestrator");
        self
    }

    pub fn upgrade_ledger_suite_orchestrator_with_same_wasm(
        &self,
        upgrade_arg: &OrchestratorArg,
    ) -> Result<(), UserError> {
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.env.upgrade_canister(
            self.ledger_suite_orchestrator_id,
            self.ledger_suite_orchestrator_wasm.clone(),
            Encode!(upgrade_arg).unwrap(),
        )
    }

    pub fn get_canister_status(&self) -> CanisterStatusResponse {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.ledger_suite_orchestrator_id,
                        "get_canister_status",
                        Encode!().unwrap()
                    )
                    .expect("failed to call get_canister_status")
            ),
            CanisterStatusResponse
        )
        .unwrap()
    }

    pub fn assert_managed_canisters(self, contract: &Erc20Contract) -> ManagedCanistersAssert {
        let canister_ids = self
            .call_orchestrator_canister_ids(contract)
            .unwrap_or_else(|| panic!("No managed canister IDs found for contract {:?}", contract));

        assert_ne!(
            canister_ids.ledger, canister_ids.index,
            "BUG: ledger and index canister IDs MUST be different"
        );

        ManagedCanistersAssert {
            setup: self,
            canister_ids,
        }
    }

    pub fn add_erc20_token(self, params: AddErc20Arg) -> AddErc20TokenFlow {
        let setup = self.upgrade_ledger_suite_orchestrator_expecting_ok(
            &OrchestratorArg::AddErc20Arg(params.clone()),
        );
        AddErc20TokenFlow { setup, params }
    }

    pub fn upgrade_ledger_suite_orchestrator(
        self,
        new_ledger_suite_orchestrator_wasm: Vec<u8>,
        upgrade_arg: UpgradeArg,
    ) -> Self {
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        let new_embedded_ledger_wasm_hash = upgrade_arg
            .ledger_compressed_wasm_hash
            .clone()
            .map(|s| s.parse().unwrap())
            .unwrap_or(self.embedded_ledger_wasm_hash);
        let new_embedded_index_wasm_hash = upgrade_arg
            .index_compressed_wasm_hash
            .clone()
            .map(|s| s.parse().unwrap())
            .unwrap_or(self.embedded_index_wasm_hash);
        let new_embedded_archive_wasm_hash = upgrade_arg
            .archive_compressed_wasm_hash
            .clone()
            .map(|s| s.parse().unwrap())
            .unwrap_or(self.embedded_archive_wasm_hash);
        self.env
            .upgrade_canister(
                self.ledger_suite_orchestrator_id,
                new_ledger_suite_orchestrator_wasm.clone(),
                Encode!(&OrchestratorArg::UpgradeArg(upgrade_arg)).unwrap(),
            )
            .expect("Failed to upgrade ERC20");
        Self {
            env: self.env,
            ledger_suite_orchestrator_id: self.ledger_suite_orchestrator_id,
            ledger_suite_orchestrator_wasm: new_ledger_suite_orchestrator_wasm,
            embedded_ledger_wasm_hash: new_embedded_ledger_wasm_hash,
            embedded_index_wasm_hash: new_embedded_index_wasm_hash,
            embedded_archive_wasm_hash: new_embedded_archive_wasm_hash,
        }
    }

    pub fn call_orchestrator_canister_ids(
        &self,
        contract: &Erc20Contract,
    ) -> Option<ManagedCanisterIds> {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.ledger_suite_orchestrator_id,
                        "canister_ids",
                        Encode!(contract).unwrap()
                    )
                    .expect("failed to execute token transfer")
            ),
            Option<ManagedCanisterIds>
        )
        .unwrap()
    }

    pub fn advance_time_for_cycles_top_up(&self) {
        self.env
            .advance_time(std::time::Duration::from_secs(60 * 60 + 1));
        self.env.tick();
        self.env.tick();
        self.env.tick();
        self.env.tick();
        self.env.tick();
        self.env.tick();
    }

    pub fn advance_time_for_upgrade(&self) {
        self.env.tick();
        self.env.tick();
        self.env.tick();
        self.env.tick();
        self.env.tick();
    }

    pub fn canister_status_of(&self, controlled_canister_id: CanisterId) -> CanisterStatusResultV2 {
        self.env
            .canister_status_as(
                self.ledger_suite_orchestrator_id.into(),
                controlled_canister_id,
            )
            .unwrap()
            .unwrap()
    }

    pub fn get_orchestrator_info(&self) -> OrchestratorInfo {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_suite_orchestrator_id,
                        "get_orchestrator_info",
                        Encode!().unwrap()
                    )
                    .unwrap()
            ),
            OrchestratorInfo
        )
        .unwrap()
    }

    pub fn check_metrics(self) -> MetricsAssert<Self> {
        let canister_id = self.ledger_suite_orchestrator_id;
        MetricsAssert::from_querying_metrics(self, canister_id)
    }
}

pub fn default_init_arg() -> InitArg {
    InitArg {
        more_controller_ids: vec![NNS_ROOT_PRINCIPAL],
        minter_id: None,
        cycles_management: None,
    }
}

pub fn new_state_machine() -> StateMachine {
    StateMachineBuilder::new()
        .with_default_canister_range()
        .build()
}

pub fn ledger_suite_orchestrator_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_suite_orchestrator",
        &[],
    )
}

pub fn ledger_suite_orchestrator_get_blocks_disabled_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_suite_orchestrator_get_blocks_disabled",
        &[],
    )
}

pub fn ledger_wasm() -> LedgerWasm {
    LedgerWasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_canister",
        &[],
    ))
}

fn ledger_get_blocks_disabled_wasm() -> LedgerWasm {
    LedgerWasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_canister_get_blocks_disabled",
        &[],
    ))
}

pub fn index_wasm() -> IndexWasm {
    IndexWasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "index_canister",
        &[],
    ))
}

fn archive_wasm() -> ArchiveWasm {
    ArchiveWasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_archive_node_canister",
        &[],
    ))
}

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

fn modify_wasm<T>(wasm: Wasm<T>) -> Wasm<T> {
    let wasm_bytes = wasm.to_bytes();
    // wasm_bytes are gzipped and the subslice [4..8]
    // is the little endian representation of a timestamp
    // so we just flip a bit in the timestamp
    assert!(is_gzipped_blob(&wasm_bytes));
    let mut new_wasm_bytes = wasm_bytes.clone();
    *new_wasm_bytes.get_mut(7).expect("cannot be empty") ^= 1;
    assert_ne!(wasm_bytes, new_wasm_bytes);
    Wasm::from(new_wasm_bytes)
}

pub fn tweak_ledger_suite_wasms() -> (LedgerWasm, IndexWasm, ArchiveWasm) {
    (
        LedgerWasm::from(modify_wasm(ledger_wasm())),
        IndexWasm::from(modify_wasm(index_wasm())),
        ArchiveWasm::from(modify_wasm(archive_wasm())),
    )
}

pub fn supported_erc20_tokens(
    minter: Principal,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> Vec<AddErc20Arg> {
    vec![
        usdc(
            minter,
            ledger_compressed_wasm_hash.clone(),
            index_compressed_wasm_hash.clone(),
        ),
        usdt(
            minter,
            ledger_compressed_wasm_hash,
            index_compressed_wasm_hash,
        ),
    ]
}

pub fn usdc(
    minter: Principal,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> AddErc20Arg {
    AddErc20Arg {
        contract: usdc_erc20_contract(),
        ledger_init_arg: ledger_init_arg(minter, "Chain-Key USD Coin", "ckUSDC"),
        git_commit_hash: GIT_COMMIT_HASH.to_string(),
        ledger_compressed_wasm_hash: ledger_compressed_wasm_hash.to_string(),
        index_compressed_wasm_hash: index_compressed_wasm_hash.to_string(),
    }
}

pub fn usdc_erc20_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
    }
}

pub fn usdt(
    minter: Principal,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> AddErc20Arg {
    AddErc20Arg {
        contract: usdt_erc20_contract(),
        ledger_init_arg: ledger_init_arg(minter, "Chain-Key Tether USD", "ckUSDT"),
        git_commit_hash: GIT_COMMIT_HASH.to_string(),
        ledger_compressed_wasm_hash: ledger_compressed_wasm_hash.to_string(),
        index_compressed_wasm_hash: index_compressed_wasm_hash.to_string(),
    }
}

pub fn usdt_erc20_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
    }
}

fn ledger_init_arg<U: Into<String>, V: Into<String>>(
    minter: Principal,
    token_name: U,
    token_symbol: V,
) -> LedgerInitArg {
    LedgerInitArg {
        minting_account: LedgerAccount {
            owner: minter,
            subaccount: None,
        },
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: CKERC20_TRANSFER_FEE.into(),
        decimals: None,
        token_name: token_name.into(),
        token_symbol: token_symbol.into(),
        token_logo: "".to_string(),
        max_memo_length: Some(80),
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }
}

pub fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}

pub fn out_of_band_upgrade<T: AsRef<StateMachine>>(
    env: T,
    controller: PrincipalId,
    target: CanisterId,
    wasm: Vec<u8>,
) -> Result<(), UserError> {
    env.as_ref()
        .execute_ingress_as(
            controller,
            CanisterId::ic_00(),
            Method::InstallCode,
            InstallCodeArgs::new(
                CanisterInstallMode::Upgrade,
                target,
                wasm,
                Encode!(&()).unwrap(),
                None,
                None,
            )
            .encode(),
        )
        .map(|_| ())
}

pub fn stop_canister<T: AsRef<StateMachine>, P: Into<PrincipalId>>(
    env: T,
    controller: P,
    target: CanisterId,
) {
    let controller = controller.into();
    let stop_res = env.as_ref().stop_canister_as(controller, target);
    assert_matches!(stop_res, Ok(WasmResult::Reply(_)));
    let status = env
        .as_ref()
        .canister_status_as(controller, target)
        .unwrap()
        .unwrap();
    assert_eq!(status.status(), CanisterStatusType::Stopped);
}
