use ic_base_types::CanisterId;
use ic_management_canister_types_private::{CanisterSnapshotResponse, ListCanisterSnapshotArgs};
use ic_nns_constants::{LEDGER_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::pb::v1::ProposalStatus;
use ic_nns_governance_api::{
    MakeProposalRequest, ProposalActionRequest, TakeCanisterSnapshot,
    manage_neuron_response::Command,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        nns_governance_get_proposal_info_as_anonymous, nns_governance_make_proposal,
        nns_wait_for_proposal_execution, setup_nns_canisters, state_machine_builder_for_nns_tests,
        update_with_sender,
    },
};
use std::time::{Duration, SystemTime};

#[test]
fn test_canister_snapshot() {
    // Step 1: Prepare the world: Set up the NNS canisters with a super powerful neuron.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Basic facts.
    let neuron = get_neuron_1();
    let target_canister_id = LEDGER_CANISTER_ID;

    // Scenario A: The most basic thing: take a snapshot.

    // Step 2(A): Run the code under test: Take a snapshot via proposal.

    // Step 2(A).1: Assemble MakeProposalRequest.
    let take_snapshot = TakeCanisterSnapshot {
        canister_id: Some(target_canister_id.get()),
        replace_snapshot: None,
    };
    let action = ProposalActionRequest::TakeCanisterSnapshot(take_snapshot);
    let make_proposal_request = MakeProposalRequest {
        title: Some("Take a Snapshot of the Ledger Canister".to_string()),
        summary: "Do what the title says.".to_string(),
        url: "https://forum.dfinity.org/discuss-take-canister-snapshot".to_string(),
        action: Some(action),
    };

    // Step 2A.2: Submit the proposal.
    let make_proposal_response = nns_governance_make_proposal(
        &state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &make_proposal_request,
    );
    let first_proposal_id = match make_proposal_response.command.as_ref().unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("{make_proposal_response:#?}"),
    };

    // Step 2A.3: Wait for execution.
    nns_wait_for_proposal_execution(&state_machine, first_proposal_id.id);

    // Step 3A. Verify results.

    // Step 3A.1: Proposal marked success.
    let first_proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, first_proposal_id.id);
    assert_eq!(
        ProposalStatus::try_from(first_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{first_proposal_info:#?}",
    );

    // Step 3A.2: Verify that a snapshot was created, by calling
    // list_canister_snapshots.
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "list_canister_snapshots",
        ListCanisterSnapshotArgs::new(target_canister_id),
        // Must call as the Root canister, because only controllers are allowed
        // to list snapshots (and Root is a controller of Ledger, the target
        // canister, the canister being snapshotted).
        ROOT_CANISTER_ID.get(),
    )
    .expect("Failed to list snapshots");

    assert_eq!(
        list_canister_snapshots_response.len(),
        1,
        "{list_canister_snapshots_response:#?}"
    );

    let first_snapshot = &list_canister_snapshots_response[0];
    #[track_caller]
    fn assert_snapshot_seems_reasonable(snapshot: &CanisterSnapshotResponse) {
        let CanisterSnapshotResponse {
            id,
            total_size,
            taken_at_timestamp,
        } = snapshot.clone();

        // Snapshot belongs to the Ledger canister.
        assert_eq!(
            id.get_canister_id(),
            LEDGER_CANISTER_ID,
            "Snapshot target is not Ledger: {snapshot:#?}"
        );

        // Size is "reasonable".
        assert!(
            total_size > 10_000_000,
            "Snapshot is too small: {snapshot:#?}"
        );
        assert!(
            total_size < 100_000_000,
            "Snapshot is too large: {snapshot:#?}"
        );

        // Is recent.
        let taken_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_nanos(taken_at_timestamp))
            .unwrap();
        let age = SystemTime::now().duration_since(taken_at).unwrap();
        assert!(
            age < Duration::from_secs(5 * 60),
            "Snapshot is more than 5 min. old: {snapshot:#?}"
        );
    }
    assert_snapshot_seems_reasonable(first_snapshot);

    // Scenario B: Replace an existing snapshot.

    // Step 2(B): Run code under test.

    // Make a proposal, like in scenario A, but this time, set the
    // replace_snapshot field to the ID of the first snapshot (from scenario A).
    let take_snapshot_replace = TakeCanisterSnapshot {
        canister_id: Some(target_canister_id.get()),
        replace_snapshot: Some(first_snapshot.snapshot_id().to_vec()),
    };
    let action = ProposalActionRequest::TakeCanisterSnapshot(take_snapshot_replace);
    let make_proposal_request = MakeProposalRequest {
        title: Some("Take ANOTHER Snapshot and clobber the first".to_string()),
        summary: "Delete old, make new.".to_string(),
        url: "https://forum.dfinity.org/clobber-snapshot".to_string(),
        action: Some(action),
    };
    let propose_replace_response = nns_governance_make_proposal(
        &state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &make_proposal_request,
    );
    let replace_proposal_id = match propose_replace_response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose replace didn't return MakeProposal"),
    };

    assert_ne!(replace_proposal_id, first_proposal_id);
    nns_wait_for_proposal_execution(&state_machine, replace_proposal_id.id);

    let replace_proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, replace_proposal_id.id);
    assert_eq!(
        ProposalStatus::try_from(replace_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{replace_proposal_info:#?}",
    );

    // Step 3(B): Verify results.

    // Fetch (new) snapshots.
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "list_canister_snapshots",
        ListCanisterSnapshotArgs::new(target_canister_id),
        ROOT_CANISTER_ID.get(),
    )
    .expect("Failed to list snapshots after replace");

    // There should only be 1 snapshot, because even though we have a new
    // (second) snapshot, the existing (first) one is supposed to be replaced by
    // the new one.
    assert_eq!(
        list_canister_snapshots_response.len(),
        1,
        "{list_canister_snapshots_response:#?}"
    );

    // More interestingly, the one snapshot should NOT be the first one. The
    // first one should be CLOBBERED, blown away, replaced by the new one.
    let second_snapshot = &list_canister_snapshots_response[0];
    assert_ne!(
        second_snapshot.snapshot_id(),
        first_snapshot.snapshot_id(),
        "Snapshot ID should have changed"
    );

    // Generic checks of the second snapshot.
    assert_snapshot_seems_reasonable(second_snapshot);
}
