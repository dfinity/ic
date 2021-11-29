use dfn_candid::{candid, candid_one};

use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::ids::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change,
    manage_neuron::{Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    AddOrRemoveNodeProvider, ManageNeuron, ManageNeuronResponse, NnsFunction, NodeProvider,
    Proposal, ProposalStatus, Vote,
};
use ic_nns_test_utils::{
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
    registry::get_value,
};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use maplit::btreemap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;

/// Test that a new Node Operator record can be added to the registry via a call
/// to the Governance canister's "manage_neuron" method (and that the Node
/// Operator ID is added to the Node Operator list)
///
/// The Node Provider specified in the payload must already be registered.
#[test]
fn test_submit_and_accept_add_node_operator_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Add a node provider
        //
        // No need to vote since the neuron votes automatically and this neuron
        // has enough votes for a majority.
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_1_ID,
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
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result.expect("Error making proposal").command.unwrap() {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            _ => panic!("Invalid response"),
        };

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                .await
                .status(),
            ProposalStatus::Executed
        );

        let rewardable_nodes = btreemap! { "default".to_string() => 10 };

        let proposal_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            dc_id: "AN1".into(),
            rewardable_nodes: rewardable_nodes.clone(),
        };

        let node_operator_record_key =
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).into_bytes();

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            NnsFunction::AssignNoid,
            proposal_payload.clone(),
            "<proposal created by test_submit_and_accept_add_node_operator_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Should have 1 pending proposals
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 1);

        // Cast votes.
        let input = (TEST_NEURON_1_ID, proposal_id, Vote::Yes);
        let _result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "forward_vote",
                candid,
                input,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Vote failed");

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        // Assert that the executed proposal had the expected result
        let fetched_node_operator_record: NodeOperatorRecord =
            get_value(&nns_canisters.registry, &node_operator_record_key).await;

        assert_eq!(
            proposal_payload
                .node_operator_principal_id
                .unwrap()
                .to_vec(),
            fetched_node_operator_record.node_operator_principal_id
        );
        assert_eq!(
            proposal_payload.node_allowance,
            fetched_node_operator_record.node_allowance
        );
        assert_eq!(proposal_payload.dc_id, fetched_node_operator_record.dc_id);
        assert_eq!(proposal_payload.rewardable_nodes, rewardable_nodes);

        Ok(())
    });
}
