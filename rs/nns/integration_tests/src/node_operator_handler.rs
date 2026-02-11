use assert_matches::assert_matches;
use canister_test::Runtime;
use dfn_candid::candid_one;
use ic_base_types::NodeId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, NnsFunction, NodeProvider, ProposalActionRequest, ProposalStatus,
    add_or_remove_node_provider::Change, manage_neuron::NeuronIdOrSubaccount,
    manage_neuron_response::Command as CommandResponse,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    registry::{get_value_or_panic, prepare_add_node_payload},
};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::{
    Error::KeyNotPresent, deserialize_get_value_response, serialize_get_value_request,
};
use ic_types::PrincipalId;
use maplit::btreemap;
use registry_canister::mutations::{
    do_add_node_operator::AddNodeOperatorPayload,
    do_remove_node_operators::RemoveNodeOperatorsPayload,
};
use std::time::Duration;

/// Test that new Node Operator records can be added and removed to/from the
/// Registry
///
/// The Node Provider specified in the payload must already be registered.
#[test]
fn test_node_operator_records_can_be_added_and_removed() {
    state_machine_test_on_nns_subnet(|runtime| async move {
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
            _ => panic!("Invalid response"),
        };

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                .await
                .status,
            ProposalStatus::Executed as i32
        );

        add_node_operator(&nns_canisters, &TEST_NEURON_1_OWNER_PRINCIPAL).await;
        add_node_operator(&nns_canisters, &TEST_NEURON_2_OWNER_PRINCIPAL).await;

        // Assert that a Node Operator with no nodes can be removed
        let (payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);

        // To fix occasional flakiness similar to this error:
        // invalid TLS certificate: notBefore date (=ASN1Time(2024-12-12 13:17:08.0 +00:00:00)) \
        //      is in the future compared to current time (=ASN1Time(2024-12-12 13:16:39.0 +00:00:00))\"
        // we advance time on the state machine by 5 minutes.
        // The theory is that resource contention is causing the system time to advance while the time
        // set for the state machine does not, causing the key's time to be in the future.
        if let Runtime::StateMachine(sm) = &runtime {
            sm.advance_time(Duration::from_secs(300));
            sm.tick();
        };
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

        let proposal_payload = RemoveNodeOperatorsPayload::new(vec![
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            *TEST_NEURON_2_OWNER_PRINCIPAL,
        ]);

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
                .status,
            ProposalStatus::Executed as i32
        );

        // Node Operator 1 is not removed because it has associated node records
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &nns_canisters.registry,
            node_operator_record_key_1.as_slice(),
        )
        .await;

        assert_eq!(node_operator_record.dc_id, "dc"); // DC is forced to be lowercase

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
        node_allowance: 0,
        node_provider_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        dc_id: "DC".into(),
        rewardable_nodes: rewardable_nodes.clone(),
        ipv6: Some("0:0:0:0:0:0:0:0".into()),
        max_rewardable_nodes: Some(btreemap! {
            NodeRewardType::Type1.to_string() => 5
        }),
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
            .status,
        ProposalStatus::Executed as i32
    );

    // Assert that the executed proposal had the expected result
    let fetched_node_operator_record: NodeOperatorRecord =
        get_value_or_panic(&nns_canisters.registry, &node_operator_record_key).await;

    let expected_node_operator_record: NodeOperatorRecord = proposal_payload.into();

    assert_eq!(fetched_node_operator_record, expected_node_operator_record);
}
