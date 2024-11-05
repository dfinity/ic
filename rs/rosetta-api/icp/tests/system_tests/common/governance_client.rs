use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_base_types::PrincipalId;
use ic_nns_common::{pb::v1::ProposalId, types::NeuronId};
use ic_nns_governance_api::{
    pb::v1::{
        manage_neuron_response, manage_neuron_response::MakeProposalResponse, MakeProposalRequest,
        ManageNeuronResponse, ProposalInfo,
    },
    proposal_submission_helpers::create_make_proposal_payload,
};
use ic_nns_governance_api::pb::v1::ProposalActionRequest;
use ic_nns_governance_api::pb::v1::Motion;

pub struct GovernanceClient {
    agent: Agent,
    governance_principal: Principal,
}

impl GovernanceClient {
    pub fn new(agent: Agent, governance_principal: Principal) -> GovernanceClient {
        GovernanceClient {
            agent: agent,
            governance_principal,
        }
    }

    pub async fn make_proposal(
        &self,
        neuron_id: NeuronId,
        neuron_controller: PrincipalId,
        proposal: &MakeProposalRequest,
    ) -> ProposalId {
        let manage_neuron = create_make_proposal_payload(proposal.clone(), &neuron_id);
        let arg = Encode!(&manage_neuron).expect("Error while encoding arg.");
        let res = self
            .agent
            .update(&self.governance_principal, "manage_neuron")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("Error while calling endpoint.");
        //Make sure that the one making the proposal is also the controller of the neuron
        assert_eq!(
            PrincipalId::from(self.agent.get_principal().unwrap()),
            neuron_controller
        );
        let manage_neuron_res =
            Decode!(res.as_slice(), ManageNeuronResponse).expect("Error while decoding response.");
        if let ManageNeuronResponse {
            command:
                Some(manage_neuron_response::Command::MakeProposal(MakeProposalResponse {
                    proposal_id,
                    ..
                })),
        } = manage_neuron_res
        {
            assert!(proposal_id.is_some());
            let arg = Encode!(&proposal_id.unwrap().id).expect("Error while encoding arg.");
            self
                .agent
                .query(&self.governance_principal, "get_proposal_info")
                .with_arg(arg)
                .call()
                .await
                .expect("Error while calling endpoint.");
            proposal_id.unwrap()
        } else {
            panic!(
                "Making Proposal was unsuccessful --> Response : {:?}",
                manage_neuron_res
            )
        }
    }

    pub async fn submit_proposal(self: &Self, principal: Principal, neuron_id: NeuronId, title: &str, summary: &str, motion_text: &str) -> ProposalId {
        let proposal = MakeProposalRequest {
            title: Some(title.to_string()),
            summary: summary.to_string(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: motion_text.to_string(),
            })),
            ..Default::default()
        };
    
        let proposal_id = self
            .make_proposal(neuron_id.into(), PrincipalId::from(principal), &proposal)
            .await;
    
        proposal_id
    }

    pub async fn get_pending_proposals(self: &Self) -> Vec<ProposalInfo> {
        let arg = Encode!(&"").expect("Error while encoding arg.");
        let res = self
            .agent
            .query(&self.governance_principal, "get_pending_proposals")
            .with_arg(arg)
            .call()
            .await
            .expect("Error while calling endpoint.");
        let pending_proposals = Decode!(res.as_slice(), Vec<ProposalInfo>)
            .expect("Error while decoding response.");
        pending_proposals
    }
}
