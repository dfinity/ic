use crate::{CallCanisters, null_request::NullRequest};
use ic_base_types::PrincipalId;
use ic_sns_governance_api::pb::v1::{
    AdvanceTargetVersionRequest, AdvanceTargetVersionResponse, GetMetadataRequest,
    GetMetadataResponse, GetMode, GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal,
    GetProposalResponse, GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
    GetUpgradeJournalRequest, GetUpgradeJournalResponse, GovernanceError, ListNeurons,
    ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, NervousSystemParameters, NeuronId,
    Proposal, ProposalId,
    governance::Version,
    manage_neuron::{self, RegisterVote},
    manage_neuron_response,
    topics::{ListTopicsRequest, ListTopicsResponse},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod requests;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct GovernanceCanister {
    pub canister_id: PrincipalId,
}

#[derive(Debug)]
pub struct SubmittedProposal {
    pub proposal_id: ProposalId,
}

#[derive(Debug, Error, PartialEq)]
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

    pub async fn follow<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        follow: manage_neuron::Follow,
    ) -> Result<ManageNeuronResponse, C::Error> {
        self.manage_neuron(agent, neuron_id, manage_neuron::Command::Follow(follow))
            .await
    }

    pub async fn set_following<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        set_following: manage_neuron::SetFollowing,
    ) -> Result<ManageNeuronResponse, C::Error> {
        self.manage_neuron(
            agent,
            neuron_id,
            manage_neuron::Command::SetFollowing(set_following),
        )
        .await
    }

    pub async fn increase_dissolve_delay<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        additional_dissolve_delay_seconds: u32,
    ) -> Result<ManageNeuronResponse, C::Error> {
        let request = manage_neuron::Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::IncreaseDissolveDelay(
                manage_neuron::IncreaseDissolveDelay {
                    additional_dissolve_delay_seconds,
                },
            )),
        });
        self.manage_neuron(agent, neuron_id, request).await
    }

    pub async fn register_vote<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
        proposal: ProposalId,
        vote: i32,
    ) -> Result<ManageNeuronResponse, C::Error> {
        self.manage_neuron(
            agent,
            neuron_id,
            manage_neuron::Command::RegisterVote(RegisterVote {
                proposal: Some(proposal),
                vote,
            }),
        )
        .await
    }

    pub async fn get_proposal<C: CallCanisters>(
        &self,
        agent: &C,
        proposal_id: ProposalId,
    ) -> Result<GetProposalResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                GetProposal {
                    proposal_id: Some(proposal_id),
                },
            )
            .await
    }

    pub async fn list_neurons<C: CallCanisters>(
        &self,
        agent: &C,
        request: ListNeurons,
    ) -> Result<ListNeuronsResponse, C::Error> {
        agent.call(self.canister_id, request).await
    }

    pub async fn get_neuron<C: CallCanisters>(
        &self,
        agent: &C,
        neuron_id: NeuronId,
    ) -> Result<GetNeuronResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                GetNeuron {
                    neuron_id: Some(neuron_id),
                },
            )
            .await
    }

    pub async fn get_upgrade_journal<C: CallCanisters>(
        &self,
        agent: &C,
        request: GetUpgradeJournalRequest,
    ) -> Result<GetUpgradeJournalResponse, C::Error> {
        agent.call(self.canister_id, request).await
    }

    pub async fn advance_target_version<C: CallCanisters>(
        &self,
        agent: &C,
        target_version: Version,
    ) -> Result<AdvanceTargetVersionResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                AdvanceTargetVersionRequest {
                    target_version: Some(target_version),
                },
            )
            .await
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
