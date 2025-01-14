use crate::{null_request::NullRequest, CallCanisters};
use ic_base_types::PrincipalId;
use ic_sns_governance::pb::v1::{
    manage_neuron, GetMetadataRequest, GetMetadataResponse, GetMode, GetModeResponse,
    GetRunningSnsVersionRequest, GetRunningSnsVersionResponse, ManageNeuron, ManageNeuronResponse,
    NervousSystemParameters, NeuronId,
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

    pub async fn manage_neuron<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        command: manage_neuron::Command,
    ) -> Result<ManageNeuronResponse, C::Error> {
        let subaccount = neuron_id
            .subaccount()
            .expect("Valid SNS neuron IDs should be ICRC1 sub-accounts.")
            .to_vec();
        let request = ManageNeuron {
            subaccount,
            command: Some(command),
        };
        agent.call(self.canister_id, request).await
    }
}

impl GovernanceCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }
}
