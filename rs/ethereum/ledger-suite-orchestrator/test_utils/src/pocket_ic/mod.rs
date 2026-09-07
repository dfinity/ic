use crate::pocket_ic::flow::{AddErc20TokenFlow, ManagedCanistersAssert};
use crate::{
    GIT_COMMIT_HASH, MAX_TICKS, archive_wasm, default_init_arg, index_wasm,
    ledger_get_blocks_disabled_wasm, ledger_suite_orchestrator_get_blocks_disabled_wasm,
    ledger_suite_orchestrator_wasm, ledger_wasm,
};
use candid::{Decode, Encode, Principal};
use ic_cdk_management_canister::CanisterStatusResult as CdkCanisterStatusResult;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, CyclesManagement, Erc20Contract, InitArg, InstalledLedgerSuite,
    ManagedCanisterIds, OrchestratorArg, OrchestratorInfo, UpgradeArg,
};
use ic_ledger_suite_orchestrator::state::{LedgerSuiteVersion, WasmHash};
use ic_management_canister_types::{CanisterId, CanisterStatusResult, CanisterStatusType};
use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
use pocket_ic::common::rest::{IcpConfig, IcpConfigFlag};
use pocket_ic::{PocketIc, PocketIcBuilder, RejectResponse};
use std::sync::Arc;

pub mod flow;
pub mod universal_canister;

pub struct LedgerSuiteOrchestrator {
    pub env: Arc<PocketIc>,
    pub ledger_suite_orchestrator_id: Principal,
    pub ledger_suite_orchestrator_wasm: Vec<u8>,
    pub embedded_ledger_wasm_hash: WasmHash,
    pub embedded_index_wasm_hash: WasmHash,
    pub embedded_archive_wasm_hash: WasmHash,
}

impl Default for LedgerSuiteOrchestrator {
    fn default() -> Self {
        Self::new(Arc::new(new_pocket_ic()), default_init_arg()).register_embedded_wasms()
    }
}

impl LedgerSuiteOrchestrator {
    pub fn with_cycles_management(cycles_management: CyclesManagement) -> Self {
        let init_arg = InitArg {
            cycles_management: Some(cycles_management),
            ..default_init_arg()
        };
        Self::new(Arc::new(new_pocket_ic()), init_arg)
    }

    pub fn new(env: Arc<PocketIc>, init_arg: InitArg) -> Self {
        let ledger_suite_orchestrator_id = env.create_canister();
        env.add_cycles(ledger_suite_orchestrator_id, u128::MAX);
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

    pub fn new_with_ledger_get_blocks_disabled(env: Arc<PocketIc>, init_arg: InitArg) -> Self {
        let ledger_suite_orchestrator_id = env.create_canister();
        env.add_cycles(ledger_suite_orchestrator_id, u128::MAX);
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
        self.env.install_canister(
            self.ledger_suite_orchestrator_id,
            self.ledger_suite_orchestrator_wasm.clone(),
            Encode!(&OrchestratorArg::InitArg(init_arg)).unwrap(),
            None,
        );
        self
    }

    pub fn upgrade_ledger_suite_orchestrator_expecting_ok(
        self,
        upgrade_arg: &OrchestratorArg,
    ) -> Self {
        self.upgrade_ledger_suite_orchestrator_with_same_wasm(upgrade_arg)
            .expect("Failed to upgrade ledger suite orchestrator");
        self
    }

    pub fn register_embedded_wasms(self) -> Self {
        self.upgrade_ledger_suite_orchestrator_expecting_ok(&OrchestratorArg::UpgradeArg(
            UpgradeArg {
                git_commit_hash: Some(GIT_COMMIT_HASH.to_string()),
                ledger_compressed_wasm_hash: None,
                index_compressed_wasm_hash: None,
                archive_compressed_wasm_hash: None,
                cycles_management: None,
                manage_ledger_suites: None,
                ledger_upgrade_arg: None,
            },
        ))
    }

    pub fn embedded_ledger_suite_version(&self) -> LedgerSuiteVersion {
        LedgerSuiteVersion {
            ledger_compressed_wasm_hash: self.embedded_ledger_wasm_hash.clone(),
            index_compressed_wasm_hash: self.embedded_index_wasm_hash.clone(),
            archive_compressed_wasm_hash: self.embedded_archive_wasm_hash.clone(),
        }
    }

    pub fn upgrade_ledger_suite_orchestrator_with_same_wasm(
        &self,
        upgrade_arg: &OrchestratorArg,
    ) -> Result<(), RejectResponse> {
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.env.upgrade_canister(
            self.ledger_suite_orchestrator_id,
            self.ledger_suite_orchestrator_wasm.clone(),
            Encode!(upgrade_arg).unwrap(),
            None,
        )
    }

    pub fn get_canister_status(&self) -> CdkCanisterStatusResult {
        Decode!(
            &self
                .env
                .update_call(
                    self.ledger_suite_orchestrator_id,
                    Principal::anonymous(),
                    "get_canister_status",
                    Encode!().unwrap()
                )
                .expect("failed to call get_canister_status"),
            CdkCanisterStatusResult
        )
        .unwrap()
    }

    pub fn assert_managed_canisters(self, contract: &Erc20Contract) -> ManagedCanistersAssert {
        let canister_ids = self
            .call_orchestrator_canister_ids(contract)
            .unwrap_or_else(|| panic!("No managed canister IDs found for contract {contract:?}"));

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

    pub fn manage_installed_canisters(
        self,
        manage_installed_canister: Vec<InstalledLedgerSuite>,
    ) -> Self {
        self.upgrade_ledger_suite_orchestrator_expecting_ok(&OrchestratorArg::UpgradeArg(
            UpgradeArg {
                git_commit_hash: None,
                ledger_compressed_wasm_hash: None,
                index_compressed_wasm_hash: None,
                archive_compressed_wasm_hash: None,
                cycles_management: None,
                manage_ledger_suites: Some(manage_installed_canister),
                ledger_upgrade_arg: None,
            },
        ))
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
                None,
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
            &self
                .env
                .update_call(
                    self.ledger_suite_orchestrator_id,
                    Principal::anonymous(),
                    "canister_ids",
                    Encode!(contract).unwrap()
                )
                .expect("failed to execute token transfer"),
            Option<ManagedCanisterIds>
        )
        .unwrap()
    }

    pub fn advance_time_for_periodic_tasks(&self) {
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
        self.env.tick();
    }

    pub fn canister_status_of(&self, controlled_canister_id: Principal) -> CanisterStatusResult {
        self.env
            .canister_status(
                controlled_canister_id,
                Some(self.ledger_suite_orchestrator_id),
            )
            .unwrap()
    }

    pub fn get_orchestrator_info(&self) -> OrchestratorInfo {
        Decode!(
            &self
                .env
                .query_call(
                    self.ledger_suite_orchestrator_id,
                    Principal::anonymous(),
                    "get_orchestrator_info",
                    Encode!().unwrap()
                )
                .unwrap(),
            OrchestratorInfo
        )
        .unwrap()
    }

    pub fn check_metrics(self) -> MetricsAssert<LedgerSuiteOrchestrator> {
        MetricsAssert::from_http_query(self)
    }

    pub fn wait_for<T, E, F>(&self, f: F) -> T
    where
        F: Fn() -> Result<T, E>,
        E: std::fmt::Debug,
    {
        let mut last_error = None;
        for _ in 0..MAX_TICKS {
            self.env.tick();
            match f() {
                Ok(t) => return t,
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }
        panic!("Failed to get result after {MAX_TICKS} ticks: {last_error:?}");
    }

    pub fn wait_for_canister_to_be_installed_and_running(&self, canister_id: Principal) {
        self.wait_for(|| {
            let ledger_status = self.canister_status_of(canister_id);
            if ledger_status.status == CanisterStatusType::Running
                && ledger_status.module_hash.is_some()
            {
                Ok(())
            } else {
                Err(format!(
                    "Canister {canister_id} is not ready {ledger_status:?}"
                ))
            }
        });
    }
}

impl PocketIcHttpQuery for LedgerSuiteOrchestrator {
    fn get_pocket_ic(&self) -> &PocketIc {
        &self.env
    }

    fn get_canister_id(&self) -> CanisterId {
        self.ledger_suite_orchestrator_id
    }
}

pub fn new_pocket_ic() -> PocketIc {
    PocketIcBuilder::new()
        .with_system_subnet()
        .with_icp_config(IcpConfig {
            canister_execution_rate_limiting: Some(IcpConfigFlag::Disabled),
            ..Default::default()
        })
        .build()
}

pub fn out_of_band_upgrade(
    env: &PocketIc,
    controller: Principal,
    target: Principal,
    wasm: Vec<u8>,
) -> Result<(), RejectResponse> {
    env.upgrade_canister(target, wasm, Encode!(&()).unwrap(), Some(controller))
}

pub fn stop_canister(env: &PocketIc, controller: Principal, target: Principal) {
    env.stop_canister(target, Some(controller))
        .expect("failed to stop canister");
    let status = env
        .canister_status(target, Some(controller))
        .expect("failed to query canister status");
    assert_eq!(status.status, CanisterStatusType::Stopped);
}
