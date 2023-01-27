use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasPublicApiUrl, IcNodeContainer};
use crate::rosetta_tests::setup::subnet_sys;
use crate::util::{assert_create_agent, block_on, delay};
use candid::{Decode, Encode, Principal};
use canister_test::PrincipalId;
use ic_agent::Agent;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_common::types::NeuronId;
use ic_nns_governance::pb::v1::manage_neuron_response::MakeProposalResponse;
use ic_nns_governance::pb::v1::{
    manage_neuron_response, proposal, ManageNeuronResponse, Motion, Proposal,
};
use ic_nns_governance::proposal_submission::create_make_proposal_payload;
use slog::{debug, Logger};

use super::lib::NeuronDetails;

pub struct GovernanceClient {
    agent: Agent,
    governance_principal: Principal,
    logger: Logger,
}

///  Create an agent to interact with the ledger.
fn create_agent(env: &TestEnv) -> Agent {
    block_on(async {
        let subnet_sys = subnet_sys(env);
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

    pub async fn make_proposal(&self, neuron_details: &NeuronDetails) -> ProposalId {
        debug!(&self.logger, "[governance_client] Making Proposal");
        let proposal = Proposal {
            title: Some("dummy title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
            })),
            ..Default::default()
        };
        let neuron_id: NeuronId = neuron_details.neuron.id.clone().unwrap().into();
        let manage_neuron = create_make_proposal_payload(proposal, &neuron_id);
        let arg = &Encode!(&manage_neuron).expect("Error while encoding arg.");
        let res = self
            .agent
            .update(&self.governance_principal, "manage_neuron")
            .with_arg(arg)
            .call_and_wait(delay())
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
                })),
        } = manage_neuron_res
        {
            debug!(
                &self.logger,
                "[governance_client] Making Proposal was succesfull"
            );
            proposal_id.unwrap()
        } else {
            panic!(
                "Making Proposal was unsuccessful --> Response : {:?}",
                manage_neuron_res
            )
        }
    }
}
