use dfn_candid::candid_one;
use ic_base_types::NodeId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::pb::v1::{
    add_or_remove_node_provider::Change, manage_neuron::NeuronIdOrSubaccount,
    manage_neuron_response::Command as CommandResponse, AddOrRemoveNodeProvider,
    MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse,
    NnsFunction, NodeProvider, ProposalActionRequest, ProposalStatus,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
    registry::{get_value, get_value_or_panic, prepare_add_node_payload},
};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_keys::make_node_record_key;
use registry_canister::mutations::{
    do_add_node_operator::AddNodeOperatorPayload,
    node_management::do_remove_nodes::RemoveNodesPayload,
};
use std::collections::BTreeMap;

/// Test that nodes can be added and removed from the Registry correctly via
/// Governance's `manage_neuron` method. The test first adds a node provider and
/// a node operator as the setup step. A node belonging to the aforementioned
/// operator is then added and subsequently removed.
#[test]
fn test_add_and_remove_nodes_from_registry() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Add a node provider
        //
        // No need to vote explicitly since the neuron votes automatically and this
        // neuron has enough votes for a majority
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_1_ID,
                        },
                    )),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Just want to add this NP.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(
                                AddOrRemoveNodeProvider {
                                    change: Some(Change::ToAdd(NodeProvider {
                                        id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                                        reward_account: None,
                                    })),
                                },
                            )),
                        },
                    ))),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            some_error => panic!(
                "Cannot find proposal id in response. The response is: {:?}",
                some_error
            ),
        };

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                .await
                .status(),
            ProposalStatus::Executed
        );

        let proposal_payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: 5,
            node_provider_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            dc_id: "an1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: Some("0:0:0:0:0:0:0:0".into()),
        };

        submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AssignNoid,
            proposal_payload,
            "<This proposal was added via `test_add_and_remove_nodes_from_registry`>".to_string(),
            "".to_string(),
        )
        .await;

        let (payload, _) = prepare_add_node_payload(1);
        let node_id: NodeId = nns_canisters
            .registry
            .update_from_sender(
                "add_node",
                candid_one,
                payload,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let node_record = get_value_or_panic::<NodeRecord>(
            &nns_canisters.registry,
            make_node_record_key(node_id).as_bytes(),
        )
        .await;
        // Check if some fields are present
        assert!(
            node_record.http.is_some(),
            "node_record : {:?}",
            node_record
        );

        let proposal_payload = RemoveNodesPayload {
            node_ids: vec![node_id],
        };
        let prop_id = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::RemoveNodes,
            proposal_payload,
            "<This proposal was added via `test_add_and_remove_nodes_from_registry`>".to_string(),
            "".to_string(),
        )
        .await;
        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, prop_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        let node_record = get_value::<NodeRecord>(
            &nns_canisters.registry,
            make_node_record_key(node_id).as_bytes(),
        )
        .await;
        // Check if record is removed
        assert!(node_record.is_none(), "node_record : {:?}", node_record);

        Ok(())
    });
}
