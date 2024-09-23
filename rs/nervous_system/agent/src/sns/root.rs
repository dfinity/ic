use ic_base_types::PrincipalId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootCanister {
    pub canister_id: PrincipalId,
}
