use crate::utils::NeuronDetails;
use candid::{Decode, Encode, Principal};
use canister_test::PrincipalId;
use ic_agent::Agent;
use ic_nns_common::{pb::v1::ProposalId, types::NeuronId};
use ic_nns_governance_api::{
    MakeProposalRequest, ManageNeuronResponse, ProposalInfo, manage_neuron_response,
    manage_neuron_response::MakeProposalResponse,
    proposal_submission_helpers::create_make_proposal_payload,
};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on},
};
use slog::{Logger, debug};

pub struct GovernanceClient {
    agent: Agent,
    governance_principal: Principal,
    logger: Logger,
}

///  Create an agent to interact with the ledger.
fn create_agent(env: &TestEnv) -> Agent {
    block_on(async {
        let subnet_sys = super::setup::subnet_sys(env);
        let node = subnet_sys.nodes().next().expect("No node in sys subnet.");
        assert_create_agent(node.get_public_url().as_str()).await
    })
}

impl GovernanceClient {
    pub fn new(env: &TestEnv, governance_principal: Principal) -> GovernanceClient {
        let logger = env.logger();
        let agent = create_agent(env);
        GovernanceClient {
            agent,
            governance_principal,
            logger,
        }
    }

    pub fn get_principal(&self) -> Principal {
        self.governance_principal
    }

    pub async fn make_proposal(
        &self,
        neuron_details: &NeuronDetails,
        proposal: &MakeProposalRequest,
    ) -> ProposalId {
        debug!(&self.logger, "[governance_client] Making Proposal");
        let neuron_id: NeuronId = neuron_details.neuron.id.unwrap().into();
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
            neuron_details.neuron.controller.unwrap()
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
            debug!(
                &self.logger,
                "[governance_client] Making Proposal was successful proposal ID is {}",
                proposal_id.unwrap().id
            );
            let arg = Encode!(&proposal_id.unwrap().id).expect("Error while encoding arg.");
            let res = self
                .agent
                .query(&self.governance_principal, "get_proposal_info")
                .with_arg(arg)
                .call()
                .await
                .expect("Error while calling endpoint.");
            let proposal_info = Decode!(res.as_slice(), Option<ProposalInfo>)
                .expect("Error while decoding response.");
            debug!(
                &self.logger,
                "{}",
                format!(
                    "Proposal Info Response from Governance Canister is : {:?}",
                    proposal_info.unwrap().proposal
                )
            );
            proposal_id.unwrap()
        } else {
            panic!("Making Proposal was unsuccessful --> Response : {manage_neuron_res:?}")
        }
    }
}
