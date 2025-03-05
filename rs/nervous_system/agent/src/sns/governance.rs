use crate::{null_request::NullRequest, CallCanisters};
use ic_base_types::PrincipalId;
use ic_sns_governance_api::pb::v1::{
    manage_neuron, manage_neuron_response,
    topics::{ListTopicsRequest, ListTopicsResponse},
    GetMetadataRequest, GetMetadataResponse, GetMode, GetModeResponse, GetProposal,
    GetProposalResponse, GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
    GovernanceError, ManageNeuron, ManageNeuronResponse, NervousSystemParameters, NeuronId,
    Proposal, ProposalId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod requests;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct GovernanceCanister {
    pub canister_id: PrincipalId,
}

pub struct SubmittedProposal {
    pub proposal_id: ProposalId,
}

#[derive(Debug, Error)]
pub enum ProposalSubmissionError {
    #[error("SNS Governance returned an error: {0:?}")]
    GovernanceError(GovernanceError),
    #[error("SNS Governance did not confirm that the proposal was made.")]
    NoConfirmation,
}

impl TryFrom<ManageNeuronResponse> for SubmittedProposal {
    type Error = ProposalSubmissionError;

    fn try_from(response: ManageNeuronResponse) -> Result<Self, Self::Error> {
        let proposal_id = match response.command {
            Some(manage_neuron_response::Command::MakeProposal(
                manage_neuron_response::MakeProposalResponse {
                    proposal_id: Some(proposal_id),
                },
            )) => proposal_id,
            Some(manage_neuron_response::Command::Error(err)) => {
                return Err(ProposalSubmissionError::GovernanceError(err));
            }
            _ => {
                return Err(ProposalSubmissionError::NoConfirmation);
            }
        };

        Ok(Self { proposal_id })
    }
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
        let subaccount = neuron_id.id;
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
    ) -> Result<ManageNeuronResponse, C::Error> {
        let response = self
            .manage_neuron(
                agent,
                neuron_id,
                manage_neuron::Command::MakeProposal(proposal),
            )
            .await?;

        Ok(response)
    }

    pub async fn get_proposal<C: CallCanisters>(
        &self,
        agent: &C,
        proposal_id: ProposalId,
    ) -> Result<GetProposalResponse, C::Error> {
        let request = GetProposal {
            proposal_id: Some(proposal_id),
        };
        agent.call(self.canister_id, request).await
    }

    pub async fn list_topics<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<ListTopicsResponse, C::Error> {
        agent.call(self.canister_id, ListTopicsRequest {}).await
    }
}

impl GovernanceCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }
}
