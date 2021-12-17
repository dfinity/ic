use dfn_candid::candid;

use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR};
use ic_nns_governance::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::ids::TEST_NEURON_2_ID;
use ic_nns_test_utils::{
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
};
use registry_canister::mutations::do_bless_replica_version::BlessReplicaVersionPayload;

#[test]
fn test_submit_and_accept_bless_replica_version_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let proposal_payload = BlessReplicaVersionPayload {
            replica_version_id: "test_replica_version".to_string(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            NnsFunction::BlessReplicaVersion,
            proposal_payload,
            "<proposal created by test_submit_and_accept_bless_replica_version_proposal>"
                .to_string(),
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

        Ok(())
    });
}
