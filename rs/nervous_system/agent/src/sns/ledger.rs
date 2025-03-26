use ic_base_types::PrincipalId;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct LedgerCanister {
    pub canister_id: PrincipalId,
}

impl LedgerCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }
}
