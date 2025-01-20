use crate::{null_request::NullRequest, CallCanisters};
use ic_base_types::PrincipalId;
use ic_sns_governance::pb::v1::{
    manage_neuron, manage_neuron_response, GetMetadataRequest, GetMetadataResponse, GetMode,
    GetModeResponse, GetRunningSnsVersionRequest, GetRunningSnsVersionResponse, GovernanceError,
    ManageNeuron, ManageNeuronResponse, NervousSystemParameters, NeuronId, Proposal, ProposalId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct GovernanceCanister {
    pub canister_id: PrincipalId,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitProposalError<C: Error> {
    #[error("Failed to call SNS Governance")]
    CallGovernanceError(#[source] C),
    #[error("SNS Governance returned an error")]
    GovernanceError(#[source] GovernanceError),
    #[error("SNS Governance did not confirm that the proposal was made: {0:?}")]
    ProposalNotMade(ManageNeuronResponse),
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

    pub async fn submit_proposal<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        proposal: Proposal,
    ) -> Result<ProposalId, SubmitProposalError<C::Error>> {
        let response = self
            .manage_neuron(
                agent,
                neuron_id,
                manage_neuron::Command::MakeProposal(proposal),
            )
            .await
            .map_err(SubmitProposalError::CallGovernanceError)?;

        match response.command {
            Some(manage_neuron_response::Command::MakeProposal(
                manage_neuron_response::MakeProposalResponse {
                    proposal_id: Some(proposal_id),
                },
            )) => Ok(proposal_id),
            Some(manage_neuron_response::Command::Error(e)) => {
                Err(SubmitProposalError::GovernanceError(e))
            }
            _ => Err(SubmitProposalError::ProposalNotMade(response)),
        }
    }
}

impl GovernanceCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }
}
