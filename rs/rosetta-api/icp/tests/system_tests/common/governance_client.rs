use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_base_types::PrincipalId;
use ic_nns_common::{pb::v1::ProposalId, types::NeuronId};
use ic_nns_governance_api::{
    MakeProposalRequest, ManageNeuronResponse, Motion, ProposalActionRequest, ProposalInfo,
    manage_neuron_response, manage_neuron_response::MakeProposalResponse,
    proposal_submission_helpers::create_make_proposal_payload,
};

pub struct GovernanceClient {
    agent: Agent,
    governance_principal: Principal,
}

impl GovernanceClient {
    pub fn new(agent: Agent, governance_principal: Principal) -> GovernanceClient {
        GovernanceClient {
            agent,
            governance_principal,
        }
    }

    pub async fn submit_proposal(
        &self,
        principal: Principal,
        neuron_id: NeuronId,
        title: &str,
        summary: &str,
        motion_text: &str,
    ) -> Result<ProposalId, String> {
        let proposal = MakeProposalRequest {
            title: Some(title.to_string()),
            summary: summary.to_string(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: motion_text.to_string(),
            })),
            ..Default::default()
        };

        let neuron_controller = PrincipalId::from(principal);

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
            self.agent
                .query(&self.governance_principal, "get_proposal_info")
                .with_arg(arg)
                .call()
                .await
                .expect("Error while calling endpoint.");
            Ok(proposal_id.unwrap())
        } else {
            Err(format!(
                "Making Proposal was unsuccessful --> Response : {manage_neuron_res:?}"
            ))
        }
    }

    pub async fn get_pending_proposals(&self) -> Vec<ProposalInfo> {
        let arg = Encode!(&"").expect("Error while encoding arg.");
        let res = self
            .agent
            .query(&self.governance_principal, "get_pending_proposals")
            .with_arg(arg)
            .call()
            .await
            .expect("Error while calling endpoint.");
        Decode!(res.as_slice(), Vec<ProposalInfo>).expect("Error while decoding response.")
    }

    pub async fn get_proposal_info(&self, proposal_id: ProposalId) -> Option<ProposalInfo> {
        let arg = Encode!(&proposal_id.id).expect("Error while encoding arg.");
        let res = self
            .agent
            .query(&self.governance_principal, "get_proposal_info")
            .with_arg(arg)
            .call()
            .await
            .expect("Error while calling endpoint.");
        Decode!(res.as_slice(), Option<ProposalInfo>).expect("Error while decoding response.")
    }
}
