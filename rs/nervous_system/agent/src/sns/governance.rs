use crate::CallCanisters;
use ic_base_types::PrincipalId;
use ic_sns_governance::pb::v1::{GetMetadataRequest, GetMetadataResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GovernanceCanister {
    pub canister_id: PrincipalId,
}

impl GovernanceCanister {
    pub async fn metadata<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetMetadataResponse, C::Error> {
        agent.call(self.canister_id, GetMetadataRequest {}).await
    }
}
