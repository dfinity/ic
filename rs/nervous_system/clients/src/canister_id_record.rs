use candid::CandidType;
use ic_base_types::CanisterId;
use serde::Deserialize;

/// Copied from ic-types::ic_00::CanisterIdRecord.
#[derive(CandidType, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub struct CanisterIdRecord {
    pub canister_id: CanisterId,
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
