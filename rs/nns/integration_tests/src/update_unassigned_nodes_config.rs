use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::{
    registry::MAX_NUM_SSH_KEYS,
    types::{NeuronId, ProposalId},
};
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use ic_types::ReplicaVersion;
use registry_canister::mutations::{
    do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
    do_update_ssh_readonly_access_for_all_unassigned_nodes::UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
};

#[test]
fn test_submit_update_ssh_readonly_access_for_all_unassigned_nodes() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // first we need to make sure that the unassigned nodes config contains a blessed replica version
        let replica_version = ReplicaVersion::default().to_string();
        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: replica_version.clone(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::DeployGuestosToAllUnassignedNodes,
            payload,
            "<proposal created by test_submit_update_ssh_readonly_access_for_all_unassigned_nodes>"
                .to_string(),
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

        let ssh_keys = vec!["key0".to_string(), "key1".to_string()];
        // A registry invariant guards against exceeding the max number of keys.
        let ssh_keys_invalid = vec!["key_invalid".to_string(); MAX_NUM_SSH_KEYS + 1];

        let payload = UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
            ssh_readonly_keys: ssh_keys.clone(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes,
            payload,
            "<proposal created by test_submit_update_ssh_readonly_access_for_all_unassigned_nodes>"
                .to_string(),
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

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let unassigned_nodes_config = get_value_or_panic::<UnassignedNodesConfigRecord>(
            &nns_canisters.registry,
            make_unassigned_nodes_config_record_key().as_bytes(),
        )
        .await;

        assert_eq!(unassigned_nodes_config.ssh_readonly_access, ssh_keys);

        let payload = UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
            ssh_readonly_keys: ssh_keys_invalid.clone(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes,
            payload.clone(),
            "<proposal created by test_submit_update_ssh_readonly_access_for_all_unassigned_nodes>"
                .to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status,
            ProposalStatus::Failed as i32
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let unassigned_nodes_config = get_value_or_panic::<UnassignedNodesConfigRecord>(
            &nns_canisters.registry,
            make_unassigned_nodes_config_record_key().as_bytes(),
        )
        .await;

        assert_eq!(unassigned_nodes_config.ssh_readonly_access, ssh_keys);

        Ok(())
    })
}

#[test]
fn test_submit_deploy_guestos_to_all_unassigned_nodes_proposal() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let replica_version = ReplicaVersion::default().to_string();

        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: replica_version.clone(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::DeployGuestosToAllUnassignedNodes,
            payload,
            "<proposal created by test_submit_deploy_guestos_to_all_unassigned_nodes_proposal>"
                .to_string(),
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

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let unassigned_nodes_config = get_value_or_panic::<UnassignedNodesConfigRecord>(
            &nns_canisters.registry,
            make_unassigned_nodes_config_record_key().as_bytes(),
        )
        .await;

        assert_eq!(unassigned_nodes_config.replica_version, replica_version);

        Ok(())
    })
}
