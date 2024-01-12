use crate::state::Canisters;
use candid::{CandidType, Deserialize, Nat, Principal};
use std::fmt::{Display, Formatter};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum OrchestratorArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
    AddErc20Arg(AddErc20Arg),
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InitArg {
    pub ledger_wasm: Vec<u8>,
    pub index_wasm: Vec<u8>,
    pub archive_wasm: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeArg {}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddErc20Arg {
    pub contract: Erc20Contract,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Erc20Contract {
    pub chain_id: Nat,
    pub address: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedCanisterIds {
    pub ledger: Principal,
    pub index: Principal,
    pub archives: Vec<Principal>,
}

impl From<Canisters> for ManagedCanisterIds {
    fn from(canisters: Canisters) -> Self {
        Self {
            ledger: *canisters.ledger_canister_id(),
            index: *canisters.index_canister_id(),
            archives: canisters.archive_canister_ids().to_vec(),
        }
    }
}

impl Display for ManagedCanisterIds {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedCanisterIds")
            .field("ledger", &self.ledger.to_string())
            .field("index", &self.index.to_string())
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
