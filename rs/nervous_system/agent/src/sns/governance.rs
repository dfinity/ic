use crate::{null_request::NullRequest, CallCanisters};
use ic_base_types::PrincipalId;
use ic_sns_governance::pb::v1::{
    GetMetadataRequest, GetMetadataResponse, GetMode, GetModeResponse, GetRunningSnsVersionRequest,
    GetRunningSnsVersionResponse, NervousSystemParameters,
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
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

    pub async fn version<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetRunningSnsVersionResponse, C::Error> {
        agent
            .call(self.canister_id, GetRunningSnsVersionRequest {})
            .await
    }

    pub async fn get_mode<C: CallCanisters>(&self, agent: &C) -> Result<GetModeResponse, C::Error> {
        agent.call(self.canister_id, GetMode {}).await
    }

    pub async fn get_nervous_system_parameters<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<NervousSystemParameters, C::Error> {
        let request = NullRequest::new("get_nervous_system_parameters", false);
        agent.call(self.canister_id, request).await
    }
}

impl GovernanceCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }
}
