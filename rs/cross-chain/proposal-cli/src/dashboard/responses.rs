use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CanisterInfo {
    pub canister_id: String,
    pub controllers: Vec<String>,
    pub module_hash: String,
    pub subnet_id: String,
    pub upgrades: Vec<CanisterUpgradeInfo>,
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
        self.proposal_id.as_u64().o
    }
}
