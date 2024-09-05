#[cfg(test)]
mod tests;

pub use askama::Template;
use candid::Principal;
use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
use ic_ledger_suite_orchestrator::state::{
    Archive, Canisters, GitCommitHash, Index, IndexCanister, Ledger, LedgerCanister, State,
    TokenId, WasmHash,
};
use ic_ledger_suite_orchestrator::storage::{StorableWasm, StoredWasm, WasmStore};
use std::cmp::Reverse;
use std::collections::BTreeMap;

mod filters {
    pub fn timestamp_to_datetime<T: std::fmt::Display>(timestamp: T) -> askama::Result<String> {
        let input = timestamp.to_string();
        let ts: i128 = input
            .parse()
            .map_err(|e| askama::Error::Custom(Box::new(e)))?;
        let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(ts).unwrap();
        // 2020-12-09T17:25:40+00:00
        let format =
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
                .unwrap();
        Ok(dt_offset.format(&format).unwrap())
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    managed_canisters: BTreeMap<Erc20Token, CanistersDashboardData>,
    other_canisters: BTreeMap<String, Vec<CanisterDashboardData>>,
    wasm_store: Vec<DashboardStoredWasm>,
}

#[derive(Clone, PartialEq, Debug, Default)]
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

#[derive(Clone, PartialEq, Debug, Default)]
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
        for archive in &canisters.archives {
            result.push(Self::from_archive(archive));
        }
        result
    }

    pub fn from_archive(canister_id: &Principal) -> Self {
        Self {
            canister_type: "Archive".to_string(),
            canister_id: canister_id.to_string(),
            installed_from: "N/A".to_string(),
        }
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

struct DashboardStoredWasm {
    pub timestamp: u64,
    pub wasm_hash: WasmHash,
    pub wasm_type: String,
    pub git_commit: GitCommitHash,
}

impl DashboardStoredWasm {
    fn from_wasm(wasm_hash: WasmHash, wasm: &StoredWasm) -> Self {
        let wasm_type = match wasm.marker() {
            Ledger::MARKER => "Ledger",
            Index::MARKER => "Index",
            Archive::MARKER => "Archive",
            _ => "Unknown",
        }
        .to_string();
        DashboardStoredWasm {
            timestamp: wasm.timestamp(),
            wasm_hash,
            wasm_type,
            git_commit: wasm.git_commit().clone(),
        }
    }
}

impl DashboardTemplate {
    pub fn from_state(state: &State, store: &WasmStore) -> Self {
        let mut wasm_store: Vec<_> = store
            .iter()
            .map(|(k, v)| DashboardStoredWasm::from_wasm(k, &v))
            .collect();
        wasm_store.sort_unstable_by_key(|w| {
            Reverse((w.timestamp, w.git_commit.clone(), w.wasm_hash.clone()))
        });

        let (erc20_canisters, other_canisters): (Vec<_>, Vec<_>) = state
            .all_managed_canisters_iter()
            .partition(|(token_id, _canisters)| match token_id {
                TokenId::Erc20(_) => true,
                TokenId::Other(_) => false,
            });

        Self {
            managed_canisters: erc20_canisters
                .into_iter()
                .map(|(token_id, v)| {
                    (
                        token_id.into_erc20_unchecked().clone(),
                        CanistersDashboardData {
                            ckerc20_token_symbol: v.metadata.token_symbol.clone(),
                            canisters: CanisterDashboardData::from_canisters(v),
                        },
                    )
                })
                .collect(),
            other_canisters: other_canisters
                .into_iter()
                .map(|(token_id, canisters)| {
                    (
                        token_id.into_other_unchecked().to_string(),
                        CanisterDashboardData::from_canisters(canisters),
                    )
                })
                .collect(),
            wasm_store,
        }
    }
}

//TODO XC-189: add other canisters to dashboard
