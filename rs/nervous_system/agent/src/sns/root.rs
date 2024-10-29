use ic_base_types::PrincipalId;
use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use serde::{Deserialize, Serialize};

use crate::CallCanisters;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootCanister {
    pub canister_id: PrincipalId,
}

impl RootCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }

    pub async fn sns_canisters_summary<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetSnsCanistersSummaryResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                GetSnsCanistersSummaryRequest {
                    update_canister_list: None,
                },
            )
            .await
    }
}
