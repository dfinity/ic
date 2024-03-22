use crate::state::Canisters;
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_icrc1_ledger::FeatureFlags as LedgerFeatureFlags;
use icrc_ledger_types::icrc1::account::Account as LedgerAccount;
use std::fmt::{Display, Formatter};

#[allow(clippy::large_enum_variant)]
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum OrchestratorArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
    AddErc20Arg(AddErc20Arg),
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InitArg {
    pub more_controller_ids: Vec<Principal>,
    pub minter_id: Option<Principal>,
    pub cycles_management: Option<CyclesManagement>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeArg {
    pub git_commit_hash: Option<String>,
    pub ledger_compressed_wasm_hash: Option<String>,
    pub index_compressed_wasm_hash: Option<String>,
    pub archive_compressed_wasm_hash: Option<String>,
}

impl UpgradeArg {
    pub fn upgrade_icrc1_ledger_suite(&self) -> bool {
        self.ledger_compressed_wasm_hash.is_some()
            || self.index_compressed_wasm_hash.is_some()
            || self.archive_compressed_wasm_hash.is_some()
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddErc20Arg {
    pub contract: Erc20Contract,
    pub ledger_init_arg: LedgerInitArg,
    pub git_commit_hash: String,
    pub ledger_compressed_wasm_hash: String,
    pub index_compressed_wasm_hash: String,
}

impl AddErc20Arg {
    pub fn token_name(&self) -> &str {
        &self.ledger_init_arg.token_name
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Erc20Contract {
    pub chain_id: Nat,
    pub address: String,
}

#[derive(CandidType, Deserialize, serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub struct LedgerInitArg {
    pub minting_account: LedgerAccount,
    pub fee_collector_account: Option<LedgerAccount>,
    pub initial_balances: Vec<(LedgerAccount, Nat)>,
    pub transfer_fee: Nat,
    pub decimals: Option<u8>,
    pub token_name: String,
    pub token_symbol: String,
    pub token_logo: String,
    pub max_memo_length: Option<u16>,
    pub feature_flags: Option<LedgerFeatureFlags>,
    pub maximum_number_of_accounts: Option<u64>,
    pub accounts_overflow_trim_quantity: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
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
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct AddCkErc20Token {
    pub chain_id: Nat,
    pub address: String,
    pub ckerc20_token_symbol: String,
    pub ckerc20_ledger_id: Principal,
}

#[derive(
    CandidType, serde::Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd,
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
            cycles_for_ledger_creation: Nat::from(HUNDRED_TRILLIONS),
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
