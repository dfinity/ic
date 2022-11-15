use candid::CandidType;
use canister_test::Canister;
use dfn_candid::candid;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_version_key;
use registry_canister::mutations::{
    do_bless_replica_version::BlessReplicaVersionPayload,
    do_retire_replica_version::RetireReplicaVersionPayload,
    do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload,
};

async fn submit(
    governance: &Canister<'_>,
    function: NnsFunction,
    payload: impl CandidType,
) -> ProposalId {
    submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_2_ID),
        function,
        payload,
        "<proposal created by test_submit_and_accept_bless_retire_replica_version_proposal>"
            .to_string(),
        "".to_string(),
    )
    .await
}

#[test]
fn test_submit_and_accept_bless_retire_replica_version_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;
        let gov = &nns_canisters.governance;

        let version_42 = "version_42";
        let test_unassigned_version = "test_unassigned_version";
        let test_replica_version1 = "test_replica_version1";
        let test_replica_version2 = "test_replica_version2";
        let test_replica_version3 = "test_replica_version3";
        let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        let bless_version_payload = |version_id: &str| BlessReplicaVersionPayload {
            replica_version_id: version_id.to_string(),
            binary_url: "".into(),
            sha256_hex: "".into(),
            node_manager_binary_url: "".into(),
            node_manager_sha256_hex: "".into(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
            release_package_urls: Some(vec!["".to_string()]),
        };
        let retire_version_payload = |ids: Vec<&str>| RetireReplicaVersionPayload {
            replica_version_ids: ids.iter().map(|id| id.to_string()).collect(),
        };
        let cast_votes = |id| {
            let input = (TEST_NEURON_1_ID, id, Vote::Yes);
            gov.update_from_sender("forward_vote", candid, input, &sender)
        };

        let proposal_payload = bless_version_payload(test_replica_version1);
        let proposal_id = submit(gov, NnsFunction::BlessReplicaVersion, proposal_payload).await;

        // Should have 1 pending proposals
        let pending_proposals = get_pending_proposals(gov).await;
        assert_eq!(pending_proposals.len(), 1);

        // Cast votes.
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");

        // Wait until proposal is executed.
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(gov).await;
        assert_eq!(pending_proposals, vec![]);

        // bless second version
        let payload = bless_version_payload(test_replica_version2);
        let proposal_id = submit(gov, NnsFunction::BlessReplicaVersion, payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        // bless unassigned version
        let payload = bless_version_payload(test_unassigned_version);
        let proposal_id = submit(gov, NnsFunction::BlessReplicaVersion, payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &nns_canisters.registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![
                    version_42.to_string(),
                    test_replica_version1.to_string(),
                    test_replica_version2.to_string(),
                    test_unassigned_version.to_string(),
                ]
            }
        );

        // update unassigned version
        let update_unassigned_payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: Some(test_unassigned_version.to_string()),
        };
        let proposal_id = submit(
            gov,
            NnsFunction::UpdateUnassignedNodesConfig,
            update_unassigned_payload,
        )
        .await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        // retire versions
        let empty_payload = retire_version_payload(vec![]);
        let invalid_payload =
            retire_version_payload(vec![test_replica_version2, test_replica_version3]);
        let in_use_payload = retire_version_payload(vec![test_replica_version1, version_42]);
        let unassigned_payload =
            retire_version_payload(vec![test_replica_version1, test_unassigned_version]);
        let valid_payload =
            retire_version_payload(vec![test_replica_version1, test_replica_version2]);

        let proposal_id = submit(gov, NnsFunction::RetireReplicaVersion, empty_payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        // Proposal should fail (empty payload).
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Failed
        );

        let proposal_id = submit(gov, NnsFunction::RetireReplicaVersion, invalid_payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        // Proposal should fail (unknown version).
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Failed
        );

        let proposal_id = submit(gov, NnsFunction::RetireReplicaVersion, in_use_payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        // Proposal should fail (version used by subnet).
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Failed
        );

        let proposal_id = submit(gov, NnsFunction::RetireReplicaVersion, unassigned_payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        // Proposal should fail (version used by unassigned nodes).
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Failed
        );

        let proposal_id = submit(gov, NnsFunction::RetireReplicaVersion, valid_payload).await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        // Proposal should succeed.
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &nns_canisters.registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![
                    version_42.to_string(),
                    test_unassigned_version.to_string()
                ]
            }
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(gov).await;
        assert_eq!(pending_proposals, vec![]);

        Ok(())
    });
}
