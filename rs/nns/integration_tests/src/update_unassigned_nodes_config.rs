use ic_canister_client::Sender;
use ic_nns_common::{
    registry::MAX_NUM_SSH_KEYS,
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::registry::get_value;
use ic_nns_test_utils::{
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
};
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use registry_canister::mutations::do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload;

#[test]
fn test_submit_update_unassigned_nodes_config_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let ssh_keys = Some(vec!["key0".to_string(), "key1".to_string()]);
        // A registry invariant guards against exceeding the max number of keys.
        let ssh_keys_invalid = Some(vec!["key_invalid".to_string(); MAX_NUM_SSH_KEYS + 1]);
        let replica_version = Some("version_42".to_string());

        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: ssh_keys.clone(),
            replica_version: replica_version.clone(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UpdateUnassignedNodesConfig,
            payload,
            "<proposal created by test_submit_update_unassigned_nodes_proposal>".to_string(),
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

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let unassigned_nodes_config = get_value::<UnassignedNodesConfigRecord>(
            &nns_canisters.registry,
            make_unassigned_nodes_config_record_key().as_bytes(),
        )
        .await;

        assert_eq!(
            &unassigned_nodes_config.ssh_readonly_access,
            ssh_keys.as_ref().unwrap()
        );
        assert_eq!(
            &unassigned_nodes_config.replica_version,
            replica_version.as_ref().unwrap()
        );

        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: ssh_keys_invalid.clone(),
            replica_version: None,
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UpdateUnassignedNodesConfig,
            payload.clone(),
            "<proposal created by test_submit_update_unassigned_nodes_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Failed
        );

        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: None,
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::UpdateUnassignedNodesConfig,
            payload.clone(),
            "<proposal created by test_submit_update_unassigned_nodes_proposal>".to_string(),
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

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let unassigned_nodes_config = get_value::<UnassignedNodesConfigRecord>(
            &nns_canisters.registry,
            make_unassigned_nodes_config_record_key().as_bytes(),
        )
        .await;

        assert_eq!(
            unassigned_nodes_config.ssh_readonly_access,
            ssh_keys.unwrap()
        );
        assert_eq!(
            unassigned_nodes_config.replica_version,
            replica_version.unwrap()
        );

        Ok(())
    })
}
