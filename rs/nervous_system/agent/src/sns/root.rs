use ic_base_types::PrincipalId;
use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use serde::{Deserialize, Serialize};

use crate::CallCanisters;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootCanister {
    pub canister_id: PrincipalId,
}

impl RootCanister {
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
