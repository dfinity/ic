use crate::scheduler::Erc20Token;
use crate::state::{Canister, Canisters};
use candid::{CandidType, Deserialize, Nat, Principal};
use std::fmt::{Display, Formatter};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum OrchestratorArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
    AddErc20Arg(AddErc20Arg),
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct InitArg {
    pub more_controller_ids: Vec<Principal>,
    pub minter_id: Option<Principal>,
    pub cycles_management: Option<CyclesManagement>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct UpgradeArg {
    pub git_commit_hash: Option<String>,
    pub ledger_compressed_wasm_hash: Option<String>,
    pub index_compressed_wasm_hash: Option<String>,
    pub archive_compressed_wasm_hash: Option<String>,
    pub cycles_management: Option<UpdateCyclesManagement>,
    pub manage_ledger_suites: Option<Vec<InstalledLedgerSuite>>,
}

impl UpgradeArg {
    pub fn upgrade_icrc1_ledger_suite(&self) -> bool {
        self.ledger_compressed_wasm_hash.is_some()
            || self.index_compressed_wasm_hash.is_some()
            || self.archive_compressed_wasm_hash.is_some()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct AddErc20Arg {
    pub contract: Erc20Contract,
    pub ledger_init_arg: LedgerInitArg,
}

impl AddErc20Arg {
    pub fn token_name(&self) -> &str {
        &self.ledger_init_arg.token_name
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct Erc20Contract {
    pub chain_id: Nat,
    pub address: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, serde::Serialize)]
pub struct LedgerInitArg {
    pub transfer_fee: Nat,
    pub decimals: u8,
    pub token_name: String,
    pub token_symbol: String,
    pub token_logo: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ManagedCanisterIds {
    pub ledger: Option<Principal>,
    pub index: Option<Principal>,
    pub archives: Vec<Principal>,
}

impl From<Canisters> for ManagedCanisterIds {
    fn from(canisters: Canisters) -> Self {
        Self {
            ledger: canisters.ledger_canister_id().cloned(),
            index: canisters.index_canister_id().cloned(),
            archives: canisters.archive_canister_ids().to_vec(),
        }
    }
}

impl Display for ManagedCanisterIds {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedCanisterIds")
            .field(
                "ledger",
                &self
                    .ledger
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or("pending".to_string()),
            )
            .field(
                "index",
                &self
                    .index
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or("pending".to_string()),
            )
            .field(
                "archives",
                &self
                    .archives
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

// TODO XC-47: extract type to separate crate since used between ckETH minter and LSO
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct AddCkErc20Token {
    pub chain_id: Nat,
    pub address: String,
    pub ckerc20_token_symbol: String,
    pub ckerc20_ledger_id: Principal,
}

#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize, serde::Serialize,
)]
pub struct CyclesManagement {
    pub cycles_for_ledger_creation: Nat,
    pub cycles_for_archive_creation: Nat,
    pub cycles_for_index_creation: Nat,
    pub cycles_top_up_increment: Nat,
}

impl Default for CyclesManagement {
    fn default() -> Self {
        const TEN_TRILLIONS: u64 = 10_000_000_000_000;
        const HUNDRED_TRILLIONS: u64 = 100_000_000_000_000;

        Self {
            cycles_for_ledger_creation: Nat::from(2 * HUNDRED_TRILLIONS),
            cycles_for_archive_creation: Nat::from(HUNDRED_TRILLIONS),
            cycles_for_index_creation: Nat::from(HUNDRED_TRILLIONS),
            cycles_top_up_increment: Nat::from(TEN_TRILLIONS),
        }
    }
}

impl CyclesManagement {
    /// Minimum amount of cycles the orchestrator should always have and some slack.
    ///
    /// The chosen amount must ensure that the orchestrator is always able to spawn a new ICRC1 ledger suite.
    pub fn minimum_orchestrator_cycles(&self) -> Nat {
        self.cycles_for_ledger_creation.clone()
            + self.cycles_for_index_creation.clone()
            + 2_u8 * self.cycles_top_up_increment.clone()
    }

    /// Minimum amount of cycles all monitored canisters should always have and some slack.
    ///
    /// The chosen amount must ensure that the ledger should be able to spawn an archive canister at any time.
    pub fn minimum_monitored_canister_cycles(&self) -> Nat {
        self.cycles_for_archive_creation.clone() + 2_u8 * self.cycles_top_up_increment.clone()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum ManagedCanisterStatus {
    Created {
        canister_id: Principal,
    },
    Installed {
        canister_id: Principal,
        installed_wasm_hash: String,
    },
}

impl<T> From<&Canister<T>> for ManagedCanisterStatus {
    fn from(canister: &Canister<T>) -> Self {
        let canister_id = *canister.canister_id();
        match canister.installed_wasm_hash() {
            None => ManagedCanisterStatus::Created { canister_id },
            Some(installed_wasm_hash) => ManagedCanisterStatus::Installed {
                canister_id,
                installed_wasm_hash: installed_wasm_hash.to_string(),
            },
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct InstalledLedgerSuite {
    pub token_symbol: String,
    pub ledger: InstalledCanister,
    pub index: InstalledCanister,
    pub archives: Option<Vec<Principal>>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct InstalledCanister {
    pub canister_id: Principal,
    pub installed_wasm_hash: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ManagedCanisters {
    pub erc20_contract: Erc20Contract,
    pub ckerc20_token_symbol: String,
    pub ledger: Option<ManagedCanisterStatus>,
    pub index: Option<ManagedCanisterStatus>,
    pub archives: Vec<Principal>,
}

impl From<(Erc20Token, Canisters)> for ManagedCanisters {
    fn from((token, canisters): (Erc20Token, Canisters)) -> Self {
        ManagedCanisters {
            erc20_contract: Erc20Contract {
                chain_id: candid::Nat::from(*token.chain_id().as_ref()),
                address: token.address().to_string(),
            },
            ckerc20_token_symbol: canisters.metadata.token_symbol.to_string(),
            ledger: canisters.ledger.as_ref().map(ManagedCanisterStatus::from),
            index: canisters.index.as_ref().map(ManagedCanisterStatus::from),
            archives: canisters.archives.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ManagedOtherCanisters {
    pub token_symbol: String,
    pub ledger: Option<ManagedCanisterStatus>,
    pub index: Option<ManagedCanisterStatus>,
    pub archives: Vec<Principal>,
}

impl From<Canisters> for ManagedOtherCanisters {
    fn from(value: Canisters) -> Self {
        Self {
            token_symbol: value.metadata.token_symbol.to_string(),
            ledger: value.ledger.as_ref().map(ManagedCanisterStatus::from),
            index: value.index.as_ref().map(ManagedCanisterStatus::from),
            archives: value.archives.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct LedgerSuiteVersion {
    pub ledger_compressed_wasm_hash: String,
    pub index_compressed_wasm_hash: String,
    pub archive_compressed_wasm_hash: String,
}

impl From<crate::state::LedgerSuiteVersion> for LedgerSuiteVersion {
    fn from(value: crate::state::LedgerSuiteVersion) -> Self {
        Self {
            ledger_compressed_wasm_hash: value.ledger_compressed_wasm_hash.to_string(),
            index_compressed_wasm_hash: value.index_compressed_wasm_hash.to_string(),
            archive_compressed_wasm_hash: value.archive_compressed_wasm_hash.to_string(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct OrchestratorInfo {
    pub managed_canisters: Vec<ManagedCanisters>,
    pub cycles_management: CyclesManagement,
    pub more_controller_ids: Vec<Principal>,
    pub minter_id: Option<Principal>,
    pub ledger_suite_version: Option<LedgerSuiteVersion>,
    pub managed_other_canisters: Option<Vec<ManagedOtherCanisters>>,
}

#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default, CandidType, Deserialize, serde::Serialize,
)]
pub struct UpdateCyclesManagement {
    pub cycles_for_ledger_creation: Option<Nat>,
    pub cycles_for_archive_creation: Option<Nat>,
    pub cycles_for_index_creation: Option<Nat>,
    pub cycles_top_up_increment: Option<Nat>,
}

impl UpdateCyclesManagement {
    pub fn apply(self, old: &mut CyclesManagement) {
        if let Some(cycles_for_ledger_creation) = self.cycles_for_ledger_creation {
            old.cycles_for_ledger_creation = cycles_for_ledger_creation;
        }
        if let Some(cycles_for_archive_creation) = self.cycles_for_archive_creation {
            old.cycles_for_archive_creation = cycles_for_archive_creation;
        }
        if let Some(cycles_for_index_creation) = self.cycles_for_index_creation {
            old.cycles_for_index_creation = cycles_for_index_creation;
        }
        if let Some(cycles_top_up_increment) = self.cycles_top_up_increment {
            old.cycles_top_up_increment = cycles_top_up_increment;
        }
    }
}
