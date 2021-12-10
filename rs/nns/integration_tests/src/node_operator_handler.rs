use assert_matches::assert_matches;
use dfn_candid::candid_one;

use ic_base_types::NodeId;
use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::ids::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change,
    manage_neuron::{Command, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    proposal::Action,
    AddOrRemoveNodeProvider, ManageNeuron, ManageNeuronResponse, NnsFunction, NodeProvider,
    Proposal, ProposalStatus,
};
use ic_nns_test_utils::registry::prepare_add_node_payload;
use ic_nns_test_utils::{
    governance::{submit_external_update_proposal, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
    registry::get_value,
};
use ic_protobuf::registry::node_operator::v1::{NodeOperatorRecord, RemoveNodeOperatorsPayload};
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::Error::KeyNotPresent;
use ic_registry_transport::{deserialize_get_value_response, serialize_get_value_request};
use ic_types::PrincipalId;
use maplit::btreemap;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;

/// Test that new Node Operator records can be added and removed to/from the
/// Registry
///
/// The Node Provider specified in the payload must already be registered.
#[test]
fn test_node_operator_records_can_be_added_and_removed() {
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

        add_node_operator(&nns_canisters, &*TEST_NEURON_1_OWNER_PRINCIPAL).await;
        add_node_operator(&nns_canisters, &*TEST_NEURON_2_OWNER_PRINCIPAL).await;

        // Assert that a Node Operator with no nodes can be removed
        let (payload, _, _) = prepare_add_node_payload();
        let _node_id: NodeId = nns_canisters
            .registry
            .update_from_sender(
                "add_node",
                candid_one,
                payload,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let node_operator_id_1: Vec<u8> = (*TEST_NEURON_1_OWNER_PRINCIPAL.into_vec()).to_vec();
        let node_operator_id_2: Vec<u8> = (*TEST_NEURON_2_OWNER_PRINCIPAL.into_vec()).to_vec();
        let proposal_payload = RemoveNodeOperatorsPayload {
            node_operators_to_remove: vec![node_operator_id_1, node_operator_id_2],
        };

        let node_operator_record_key_1 =
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).into_bytes();
        let node_operator_record_key_2 =
            make_node_operator_record_key(*TEST_NEURON_2_OWNER_PRINCIPAL).into_bytes();

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::RemoveNodeOperators,
            proposal_payload.clone(),
            "<proposal created by test_submit_and_accept_add_node_operator_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        // Node Operator 1 is not removed because it has associated node records
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &nns_canisters.registry,
            node_operator_record_key_1.as_slice(),
        )
        .await;

        assert_eq!(node_operator_record.dc_id, "DC");

        // Node Operator 2 is removed because it doesn't have associated node records
        let get_value_result = deserialize_get_value_response(
            nns_canisters
                .registry
                .query_(
                    "get_value",
                    on_wire::bytes,
                    serialize_get_value_request(node_operator_record_key_2.to_vec().clone(), None)
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .unwrap_err();

        assert_matches!(get_value_result, KeyNotPresent(_));

        Ok(())
    });
}

async fn add_node_operator(nns_canisters: &NnsCanisters<'_>, node_operator_id: &PrincipalId) {
    let rewardable_nodes = btreemap! { "default".to_string() => 10 };

    let proposal_payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(*node_operator_id),
        node_allowance: 5,
        node_provider_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        dc_id: "DC".into(),
        rewardable_nodes: rewardable_nodes.clone(),
    };

    let node_operator_record_key = make_node_operator_record_key(*node_operator_id).into_bytes();

    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns_canisters.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::AssignNoid,
        proposal_payload.clone(),
        "<proposal created by test_submit_and_accept_add_node_operator_proposal>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    // Assert that the executed proposal had the expected result
    let fetched_node_operator_record: NodeOperatorRecord =
        get_value(&nns_canisters.registry, &node_operator_record_key).await;

    let expected_node_operator_record: NodeOperatorRecord = proposal_payload.into();

    assert_eq!(fetched_node_operator_record, expected_node_operator_record);
}
