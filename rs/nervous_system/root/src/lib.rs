use candid::{CandidType, Deserialize};
use dfn_core::api::CanisterId;

pub mod canister_status;
pub mod change_canister;
pub mod change_canister_controllers;
pub mod management_canister_client;
pub mod update_settings;

pub const LOG_PREFIX: &str = "[Root Canister] ";

/// Copied from ic-types::ic_00::CanisterIdRecord.
#[derive(CandidType, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub struct CanisterIdRecord {
    canister_id: CanisterId,
}

impl CanisterIdRecord {
    pub fn get_canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl From<CanisterId> for CanisterIdRecord {
    fn from(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}
