use dfn_candid::{candid, candid_one};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_KEYPAIR, TEST_NEURON_3_OWNER_KEYPAIR,
};
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change,
    manage_neuron::{self, Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    AddOrRemoveNodeProvider, ManageNeuron, ManageNeuronResponse, NodeProvider, Proposal,
    ProposalInfo, Vote,
};
use ic_nns_test_utils::{
    ids::{TEST_NEURON_2_ID, TEST_NEURON_3_ID},
    itest_helpers::{NnsCanisters, NnsInitPayloadsBuilder},
};

#[test]
#[ignore]
fn test_deadline_is_extended_with_wait_for_quiet() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Submit a proposal to add a node provider, but submit with a neuron that
        // doesn't have enough voting power.
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_2_ID,
                        },
                    )),
                    id: None,
                    command: Some(Command::MakeProposal(Box::new(Proposal {
                        title: Some("Just want to add this NP.".to_string()),
                        summary: "".to_string(),
                        url: "".to_string(),
                        action: Some(Action::AddOrRemoveNodeProvider(AddOrRemoveNodeProvider {
                            change: Some(Change::ToAdd(NodeProvider {
                                id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                                reward_account: None,
                            })),
                        })),
                    }))),
                },
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result.expect("Error making proposal").command.unwrap() {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            some_error => panic!(
                "Cannot find proposal id in response. The response is: {:?}",
                some_error
            ),
        };

        let pi: Option<ProposalInfo> = nns_canisters
            .governance
            .query_("get_proposal_info", candid, (pid,))
            .await
            .unwrap();

        let initial_deadline = pi.unwrap().deadline_timestamp_seconds.unwrap();

        // Now vote against the proposal, the deadline should be extended.
        let _result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_3_ID,
                        },
                    )),
                    id: None,
                    command: Some(manage_neuron::Command::RegisterVote(
                        manage_neuron::RegisterVote {
                            proposal: Some(pid),
                            vote: Vote::No as i32,
                        },
                    )),
                },
                &Sender::from_keypair(&TEST_NEURON_3_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pi: Option<ProposalInfo> = nns_canisters
            .governance
            .query_("get_proposal_info", candid, (pid,))
            .await
            .unwrap();

        let final_deadline = pi.unwrap().deadline_timestamp_seconds.unwrap();

        assert!(final_deadline > initial_deadline);

        Ok(())
    });
}
