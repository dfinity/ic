use canister_test::{Canister, Project};
use ic_base_types::{CanisterInstallMode, PrincipalId};
use ic_canister_client::Sender;
use ic_nns_constants::{
    ids::{
        TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR,
        TEST_USER2_PRINCIPAL, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR, TEST_USER5_KEYPAIR,
        TEST_USER6_KEYPAIR,
    },
    GOVERNANCE_CANISTER_ID,
};
use ic_nns_handler_root::{
    common::{CanisterIdRecord, CanisterStatusResult, ChangeNnsCanisterProposalPayload},
    root_proposals::{GovernanceUpgradeRootProposal, RootProposalBallot},
};
use ic_nns_test_utils::{
    itest_helpers::{NnsCanisters, NnsInitPayloadsBuilder},
    registry::initial_mutations_for_a_multinode_nns_subnet,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;

async fn get_pending_root_proposals(
    root_canister: &Canister<'_>,
) -> Vec<GovernanceUpgradeRootProposal> {
    let response: Vec<GovernanceUpgradeRootProposal> = root_canister
        .update_(
            "get_pending_root_proposals_to_upgrade_governance_canister",
            dfn_candid::candid_one,
            (),
        )
        .await
        .expect("Error getting pending root proposals (Generic error)");
    response
}

async fn vote_on_root_proposal(
    voter: &Sender,
    proposer: &PrincipalId,
    proposal_wasm_sha: &[u8],
    root: &Canister<'_>,
    ballot: RootProposalBallot,
) -> Result<(), String> {
    let response: Result<(), String> = root
        .update_from_sender(
            "vote_on_root_proposal_to_upgrade_governance_canister",
            dfn_candid::candid,
            (proposer, proposal_wasm_sha, ballot),
            voter,
        )
        .await
        .expect("Error voting on root proposal (Generic error)");
    response
}

async fn vote_on_root_proposal_from_multiple_voters(
    voters: &[Sender],
    proposer: &PrincipalId,
    proposal_wasm_sha: &[u8],
    root: &Canister<'_>,
    ballot: RootProposalBallot,
) -> Result<(), String> {
    for voter in voters {
        vote_on_root_proposal(voter, proposer, proposal_wasm_sha, root, ballot.clone()).await?;
    }
    Ok(())
}

fn governance_canister_sha() -> [u8; 32] {
    let governance_canister_wasm_bytes = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/governance",
        "governance-canister",
        &["test"],
    )
    .bytes();
    ic_crypto_sha::Sha256::hash(&governance_canister_wasm_bytes)
}

#[test]
fn test_upgrade_governance_through_root_proposal() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: initial_mutations_for_a_multinode_nns_subnet(),
                preconditions: vec![],
            }])
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Make the NO of the first node the sender of the proposal.
        let proposer = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let proposer_pid = *TEST_USER1_PRINCIPAL;

        // Build and submit a root proposal
        let root_proposal = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        // Note that we upgrade the governance canister to the universal
        // canister (effectively breaking governance). This is needed so
        // that we can be sure that the upgrade actually went through.
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let empty_wasm_sha =
            &ic_crypto_sha::Sha256::hash(ic_test_utilities::empty_wasm::EMPTY_WASM);

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (governance_canister_sha(), root_proposal),
                &proposer,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        response.expect("Error submitting root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 1);
        assert_eq!((&proposals)[0].proposed_wasm_sha, empty_wasm_sha);

        // Now vote for the root proposal from one of the other nodes.
        // Since we have 7 nodes, we can tolerate 2 faults, meaning we need
        // 5 votes for the proposal to be accepted, i.e. this vote won't
        // be enough.
        let voter = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        vote_on_root_proposal(
            &voter,
            &proposer_pid,
            &empty_wasm_sha.to_vec(),
            &nns_canisters.root,
            RootProposalBallot::Yes,
        )
        .await
        .expect("Error voting on root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 1);
        assert_eq!((&proposals)[0].proposed_wasm_sha, empty_wasm_sha);

        // Vote again, from 3 other voters this should take us over the threshold and
        // make the proposal execute.
        vote_on_root_proposal_from_multiple_voters(
            &[
                Sender::from_keypair(&TEST_USER3_KEYPAIR),
                Sender::from_keypair(&TEST_USER4_KEYPAIR),
                Sender::from_keypair(&TEST_USER5_KEYPAIR),
            ],
            &proposer_pid,
            &empty_wasm_sha.to_vec(),
            &nns_canisters.root,
            RootProposalBallot::Yes,
        )
        .await
        .expect("Error voting on root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 0);

        // Make sure the proposal executed by checking the sha of the wasm, which
        // should have changed.
        let status: CanisterStatusResult = nns_canisters
            .root
            .update_(
                "canister_status",
                dfn_candid::candid_one,
                CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
            )
            .await
            .unwrap();
        assert_eq!(status.module_hash.unwrap(), empty_wasm_sha);

        Ok(())
    })
}

// Test that a user that is not among the node operators of the NNS subnet can't
// submit a root proposal.
#[test]
fn test_unauthorized_user_cant_submit_on_root_proposals() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: initial_mutations_for_a_multinode_nns_subnet(),
                preconditions: vec![],
            }])
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Try and submit a proposal from a user that isn't an NO of the nns subnet.
        let proposer = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        // Build and submit a root proposal
        let root_proposal = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (governance_canister_sha(), root_proposal),
                &proposer,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        assert!(response.is_err());
        assert!(response
            .err()
            .unwrap()
            .contains("must be among the node operators of the nns subnet"));
        Ok(())
    })
}

#[test]
fn test_cant_submit_root_proposal_with_wrong_sha() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: initial_mutations_for_a_multinode_nns_subnet(),
                preconditions: vec![],
            }])
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;
        let proposer = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        // Build and submit a root proposal
        let root_proposal = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let empty_wasm_sha =
            &ic_crypto_sha::Sha256::hash(ic_test_utilities::empty_wasm::EMPTY_WASM);

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (empty_wasm_sha, root_proposal),
                &proposer,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        assert!(response.is_err());
        assert!(response
            .err()
            .unwrap()
            .contains("Expected governance wasm sha must match"));
        Ok(())
    })
}

#[test]
fn test_enough_no_votes_rejects_the_proposal() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: initial_mutations_for_a_multinode_nns_subnet(),
                preconditions: vec![],
            }])
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Make the NO of the first node the sender of the proposal.
        let proposer = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let proposer_pid = *TEST_USER1_PRINCIPAL;

        // Build and submit a root proposal
        let root_proposal = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        // Note that we upgrade the governance canister to the universal
        // canister (effectively breaking governance). This is needed so
        // that we can be sure that the upgrade actually went through.
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let empty_wasm_sha =
            &ic_crypto_sha::Sha256::hash(ic_test_utilities::empty_wasm::EMPTY_WASM);

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (governance_canister_sha(), root_proposal),
                &proposer,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        response.expect("Error submitting root proposal (Canister error)");

        // Vote No from 3 voters, this should cause the proposal to be rejected.
        vote_on_root_proposal_from_multiple_voters(
            &[
                Sender::from_keypair(&TEST_USER2_KEYPAIR),
                Sender::from_keypair(&TEST_USER3_KEYPAIR),
                Sender::from_keypair(&TEST_USER4_KEYPAIR),
            ],
            &proposer_pid,
            &empty_wasm_sha.to_vec(),
            &nns_canisters.root,
            RootProposalBallot::No,
        )
        .await
        .expect("Error voting on root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 0);

        // Make sure the proposal was rejected by checking the sha of the wasm, which
        // shouldn't have changed.
        let status: CanisterStatusResult = nns_canisters
            .root
            .update_(
                "canister_status",
                dfn_candid::candid_one,
                CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
            )
            .await
            .unwrap();
        assert_eq!(status.module_hash.unwrap(), governance_canister_sha());

        Ok(())
    })
}

// In this test we submit two proposals 1 and 2, but we vote on and execute 2
// first which should cause 1 to be invalid.
#[test]
fn test_changing_the_sha_invalidates_the_proposal() {
    ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: initial_mutations_for_a_multinode_nns_subnet(),
                preconditions: vec![],
            }])
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Make the NO of the first node the sender of the proposal.
        let proposer1 = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let proposer1_pid = *TEST_USER1_PRINCIPAL;

        // Build and submit a root proposal
        let root_proposal1 = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        // Note that we upgrade the governance canister to the empty
        // canister (effectively breaking governance). This is needed so
        // that we can be sure that the upgrade actually went through.
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let empty_wasm_sha =
            &ic_crypto_sha::Sha256::hash(ic_test_utilities::empty_wasm::EMPTY_WASM);

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (governance_canister_sha(), root_proposal1),
                &proposer1,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        response.expect("Error submitting root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 1);
        assert_eq!((&proposals)[0].proposed_wasm_sha, empty_wasm_sha);

        // Submit another proposal
        let proposer2 = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let proposer2_pid = *TEST_USER2_PRINCIPAL;

        // Build and submit a second root proposal
        let root_proposal2 = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        .with_wasm(ic_test_utilities::empty_wasm::EMPTY_WASM.to_vec());

        let response: Result<(), String> = nns_canisters
            .root
            .update_from_sender(
                "submit_root_proposal_to_upgrade_governance_canister",
                dfn_candid::candid,
                (governance_canister_sha(), root_proposal2),
                &proposer2,
            )
            .await
            .expect("Error submitting root proposal (Generic error)");
        response.expect("Error submitting root proposal (Canister error)");

        let proposals = get_pending_root_proposals(&nns_canisters.root).await;
        assert_eq!(proposals.len(), 2);
        assert_eq!((&proposals)[0].proposed_wasm_sha, empty_wasm_sha);
        assert_eq!((&proposals)[1].proposed_wasm_sha, empty_wasm_sha);

        // Vote to execute proposal 2 before proposal 1.
        vote_on_root_proposal_from_multiple_voters(
            &[
                Sender::from_keypair(&TEST_USER3_KEYPAIR),
                Sender::from_keypair(&TEST_USER4_KEYPAIR),
                Sender::from_keypair(&TEST_USER5_KEYPAIR),
                Sender::from_keypair(&TEST_USER6_KEYPAIR),
            ],
            &proposer2_pid,
            &empty_wasm_sha.to_vec(),
            &nns_canisters.root,
            RootProposalBallot::Yes,
        )
        .await
        .expect("Error voting on root proposal (Canister error)");

        // Vote on proposal 1 now, it should fail since proposal
        // 2 went through and changed the wasm.
        vote_on_root_proposal_from_multiple_voters(
            &[
                Sender::from_keypair(&TEST_USER2_KEYPAIR),
                Sender::from_keypair(&TEST_USER3_KEYPAIR),
                Sender::from_keypair(&TEST_USER4_KEYPAIR),
                Sender::from_keypair(&TEST_USER5_KEYPAIR),
            ],
            &proposer1_pid,
            &empty_wasm_sha.to_vec(),
            &nns_canisters.root,
            RootProposalBallot::Yes,
        )
        .await
        .expect_err("Should have returned an eror")
        .contains("Expected governance wasm sha must match");

        Ok(())
    })
}
