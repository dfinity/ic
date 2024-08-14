use assert_matches::assert_matches;
use candid::CandidType;
use canister_test::Canister;
use dfn_candid::candid;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_versions_key;
use ic_types::ReplicaVersion;
use registry_canister::mutations::{
    do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
    do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
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
        "<proposal created by upgrades_handler test>".to_string(),
        "".to_string(),
    )
    .await
}

async fn assert_failed_with_reason(gov: &Canister<'_>, proposal_id: ProposalId, reason: &str) {
    let info = wait_for_final_state(gov, proposal_id).await;
    assert_eq!(info.status(), ProposalStatus::Failed);
    assert_matches!(
        info.failure_reason,
        Some(error) if error.error_message.contains(reason)
    );
}

#[test]
fn test_submit_and_accept_update_elected_replica_versions_proposal() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;
        let gov = &nns_canisters.governance;
        let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        let update_versions_payload =
            |elect: Option<String>, unelect: Vec<&str>| ReviseElectedGuestosVersionsPayload {
                release_package_sha256_hex: elect.as_ref().map(|_| {
                    "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D".into()
                }),
                release_package_urls: elect
                    .as_ref()
                    .map(|_| vec!["http://release_package.tar.zst".to_string()])
                    .unwrap_or_default(),
                replica_version_to_elect: elect,
                guest_launch_measurement_sha256_hex: None,
                replica_versions_to_unelect: unelect.iter().map(|s| s.to_string()).collect(),
            };
        let bless_version_payload = |version_id: &str| -> ReviseElectedGuestosVersionsPayload {
            update_versions_payload(Some(version_id.into()), vec![])
        };
        let retire_version_payload = |ids: Vec<&str>| -> ReviseElectedGuestosVersionsPayload {
            update_versions_payload(None, ids)
        };
        let cast_votes = |id| {
            let input = (TEST_NEURON_1_ID, id, Vote::Yes);
            gov.update_from_sender("forward_vote", candid, input, &sender)
        };

        let default_version = &ReplicaVersion::default().to_string();
        let unassigned_nodes_version = "unassigned_nodes_version";
        let version_to_elect_and_unelect1 = "version_to_elect_and_unelect1";
        let version_to_elect_and_unelect2 = "version_to_elect_and_unelect2";
        let version_to_elect = "version_to_elect";

        // bless three versions
        let setup = vec![
            bless_version_payload(version_to_elect_and_unelect1),
            bless_version_payload(version_to_elect_and_unelect2),
            bless_version_payload(unassigned_nodes_version),
        ];

        for payload in setup {
            let proposal_id = submit(gov, NnsFunction::ReviseElectedGuestosVersions, payload).await;
            let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
            assert_eq!(
                wait_for_final_state(gov, proposal_id).await.status(),
                ProposalStatus::Executed
            );
        }

        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &nns_canisters.registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![
                    default_version.to_string(),
                    version_to_elect_and_unelect1.to_string(),
                    version_to_elect_and_unelect2.to_string(),
                    unassigned_nodes_version.to_string(),
                ]
            }
        );

        // update unassigned version
        let deploy_unassigned_payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: unassigned_nodes_version.to_string(),
        };
        let proposal_id = submit(
            gov,
            NnsFunction::DeployGuestosToAllUnassignedNodes,
            deploy_unassigned_payload,
        )
        .await;
        let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
        assert_eq!(
            wait_for_final_state(gov, proposal_id).await.status(),
            ProposalStatus::Executed
        );

        let test_cases = vec![
            (
                retire_version_payload(vec![]),
                Some("At least one version has to be elected or unelected"),
            ),
            (
                retire_version_payload(vec![version_to_elect_and_unelect2, version_to_elect]),
                Some("Key not present"),
            ),
            (
                retire_version_payload(vec![version_to_elect_and_unelect1, default_version]),
                Some("currently deployed to a subnet"),
            ),
            (
                update_versions_payload(
                    Some(version_to_elect.into()),
                    vec![version_to_elect_and_unelect1, unassigned_nodes_version],
                ),
                Some("currently deployed to unassigned nodes"),
            ),
            (
                ReviseElectedGuestosVersionsPayload {
                    replica_version_to_elect: Some("version_with_missing_hash".into()),
                    ..Default::default()
                },
                Some("All parameters to elect a version have to be either set or unset"),
            ),
            (
                bless_version_payload(""),
                Some("Blessed an empty version ID"),
            ),
            (
                update_versions_payload(
                    Some(version_to_elect.into()),
                    vec![version_to_elect_and_unelect1, version_to_elect_and_unelect2],
                ),
                None,
            ),
            (
                update_versions_payload(Some(version_to_elect.into()), vec![]),
                Some("Key already present"),
            ),
            (
                update_versions_payload(Some(version_to_elect.into()), vec![version_to_elect]),
                Some("cannot elect and unelect the same version"),
            ),
        ];

        for (payload, expected_failure) in test_cases {
            let proposal_id = submit(gov, NnsFunction::ReviseElectedGuestosVersions, payload).await;
            let _result: ManageNeuronResponse = cast_votes(proposal_id).await.expect("Vote failed");
            if let Some(reason) = expected_failure {
                assert_failed_with_reason(gov, proposal_id, reason).await;
            } else {
                assert_eq!(
                    wait_for_final_state(gov, proposal_id).await.status(),
                    ProposalStatus::Executed
                );
            }
        }

        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &nns_canisters.registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![
                    default_version.to_string(),
                    unassigned_nodes_version.to_string(),
                    version_to_elect.to_string()
                ]
            }
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(gov).await;
        assert_eq!(pending_proposals, vec![]);

        Ok(())
    });
}
