#[cfg(test)]
mod tests;

pub use askama::Template;
use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
use ic_ledger_suite_orchestrator::state::{Canisters, IndexCanister, LedgerCanister, State};
use std::collections::BTreeMap;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    managed_canisters: BTreeMap<Erc20Token, CanistersDashboardData>,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct CanistersDashboardData {
    pub canisters: Vec<CanisterDashboardData>,
    pub ckerc20_token_symbol: String,
}

impl<'a> IntoIterator for &'a CanistersDashboardData {
    type Item = &'a CanisterDashboardData;
    type IntoIter = std::slice::Iter<'a, CanisterDashboardData>;

    fn into_iter(self) -> Self::IntoIter {
        self.canisters.iter()
    }
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct CanisterDashboardData {
    pub canister_type: String,
    pub canister_id: String,
    pub installed_from: String,
}

impl CanisterDashboardData {
    pub fn from_canisters(canisters: &Canisters) -> Vec<Self> {
        let mut result = Vec::with_capacity(3);
        if let Some(ledger) = &canisters.ledger {
            result.push(Self::from(ledger));
        }
        if let Some(index) = &canisters.index {
            result.push(Self::from(index));
        }
        //TODO add archive canisters
        result
    }
}

impl From<&LedgerCanister> for CanisterDashboardData {
    fn from(canister: &LedgerCanister) -> Self {
        Self {
            canister_type: "Ledger".to_string(),
            canister_id: canister.canister_id().to_string(),
            installed_from: canister
                .installed_wasm_hash()
                .map(|hash| hash.to_string())
                .unwrap_or("not installed".to_string()),
        }
    }
}

impl From<&IndexCanister> for CanisterDashboardData {
    fn from(canister: &IndexCanister) -> Self {
        Self {
            canister_type: "Index".to_string(),
            canister_id: canister.canister_id().to_string(),
            installed_from: canister
                .installed_wasm_hash()
                .map(|hash| hash.to_string())
                .unwrap_or("not installed".to_string()),
        }
    }
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        Self {
            managed_canisters: state
                .managed_canisters_iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        CanistersDashboardData {
                            ckerc20_token_symbol: v.metadata.ckerc20_token_symbol.clone(),
                            canisters: CanisterDashboardData::from_canisters(v),
                        },
                    )
                })
                .collect(),
        }
    }
}
