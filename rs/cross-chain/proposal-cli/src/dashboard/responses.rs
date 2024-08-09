use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CanisterInfo {
    pub canister_id: String,
    pub controllers: Vec<String>,
    pub module_hash: String,
    pub subnet_id: String,
    pub upgrades: Option<Vec<CanisterUpgradeInfo>>,
}

impl CanisterInfo {
    pub fn list_upgrade_proposals(&self) -> BTreeSet<u64> {
        self.upgrades
            .as_ref()
            .map(|upgrades| {
                upgrades
                    .iter()
                    .map(CanisterUpgradeInfo::proposal_id)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CanisterUpgradeInfo {
    pub executed_timestamp_seconds: u64,
    pub module_hash: String,
    proposal_id: serde_json::Number,
}

impl CanisterUpgradeInfo {
    /// Returns the proposal id of the upgrade
    /// which for some reason is returned as a floating point type
    /// by the dashboard API, e.g., 131388.0 instead of 131388.
    pub fn proposal_id(&self) -> u64 {
        self.proposal_id
            .as_u64()
            .or_else(|| self.proposal_id.as_f64().map(|f| f as u64))
            .expect("Failed to parse proposal id into a u64")
    }
}
