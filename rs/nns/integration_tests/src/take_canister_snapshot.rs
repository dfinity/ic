use candid::{CandidType, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{CanisterSnapshotResponse, ListCanisterSnapshotArgs};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::pb::v1::ProposalStatus;
use ic_nns_governance_api::{
    ExecuteNnsFunction, MakeProposalRequest, NnsFunction, ProposalActionRequest,
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
use serde::Deserialize;
use std::time::{Duration, SystemTime};

// Defined in ic_nns_handler_root_interface, but redefined here to avoid extra dependencies
// for the test target if not already present.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotRequest {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option<Vec<u8>>,
}

#[test]
fn test_take_canister_snapshot() {
    // Step 1: Prepare the world: Set up the NNS canisters and get the neuron.

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();

    // As of Jan, 2025, TakeCanisterSnapshot proposals are only enabled in
    // feature = "test", but setup_nns_canisters enables that.
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let neuron = get_neuron_1();

    // Target Governance canister for snapshot. Root is the controller of Governance.
    let target_canister_id = GOVERNANCE_CANISTER_ID;

    // Step 2A: Run the code under test: Take a snapshot via proposal.

    // Step 2A.1: Create a TakeCanisterSnapshot proposal.

    // Step 2A.1: Assemble proposal action.
    let snapshot_request = TakeCanisterSnapshotRequest {
        canister_id: target_canister_id.get(),
        replace_snapshot: None,
    };
    let nns_function = NnsFunction::TakeCanisterSnapshot;
    let payload = Encode!(&snapshot_request).expect("Failed to encode payload");
    let action = ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
        nns_function: nns_function as i32,
        payload,
    });
    let make_proposal_request = MakeProposalRequest {
        title: Some("Take a Snapshot of the Governance Canister".to_string()),
        summary: "Do what the title says.".to_string(),
        url: "https://forum.dfinity.org/discuss-take-canister-snapshot".to_string(),
        action: Some(action),
    };

    // Step 2A.2: Submit the proposal. It passes immediately, because the
    // proposer neuron is hyper powerful (i.e. has more than half the voting
    // power).
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

    // Step 2A.3: Wait.
    nns_wait_for_proposal_execution(&state_machine, first_proposal_id.id);

    // Step 3A. Verify results.

    // Step 3A.1: Proposal execution status is success. This is a rather
    // superficial check, but is a basic condition of correctness.
    let first_proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, first_proposal_id.id);
    assert_eq!(
        ProposalStatus::try_from(first_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{first_proposal_info:#?}",
    );

    // Step 3A.2: Fetch the current set of snapshots (of the Governance
    // canister).
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> = update_with_sender(
        &state_machine,
        CanisterId::ic_00(), // management "canister".
        "list_canister_snapshots",
        ListCanisterSnapshotArgs::new(target_canister_id),
        // Caller. Must call as the Root canister, because only controllers are
        // allowed to list snapshots of a canister (and Root is the controller
        // of Governance).
        ROOT_CANISTER_ID.get(), // caller
    )
    .expect("Failed to list snapshots");

    // Step 3A.3: Inspect the snapshots.
    #[track_caller]
    fn assert_snapshot_checks_out(snapshots: &[CanisterSnapshotResponse]) {
        assert_eq!(
            snapshots.len(),
            1,
            "{snapshots:#?}"
        );

        let snapshot = &snapshots[0];
        let CanisterSnapshotResponse {
            id,
            taken_at_timestamp,
            total_size,
        } = snapshot.clone();

        assert_eq!(
            id.get_canister_id(),
            GOVERNANCE_CANISTER_ID,
            "{snapshot:#?}"
        );

        let taken_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_nanos(taken_at_timestamp))
            .unwrap();
        let age = SystemTime::now().duration_since(taken_at).unwrap();
        assert!(age < Duration::from_secs(5 * 60), "{snapshot:#?}");

        assert!(total_size > 100_000_000, "{snapshot:#?}");
    }
    assert_snapshot_checks_out(&list_canister_snapshots_response);
    let first_snapshot = &list_canister_snapshots_response[0];

    // Step 2B: Run the code under test (again). This time, instead of JUST
    // taking a snapshot, replace an existing one.
    let payload = Encode!(&TakeCanisterSnapshotRequest {
        canister_id: target_canister_id.get(),
        replace_snapshot: Some(first_snapshot.snapshot_id().to_vec()),
    })
    .unwrap();
    let action = ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
        nns_function: nns_function as i32,
        payload,
    });
    let make_proposal_request = MakeProposalRequest {
        title: Some("Take ANOTHER Governance Canister Snapshot...".to_string()),
        summary: "... And blow away the first one.".to_string(),
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

    // Step 3B: Verify results.

    // Similar to case A, the first time we took a snapshot. The more
    // interesting assert comes after this...
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "list_canister_snapshots",
        ListCanisterSnapshotArgs::new(target_canister_id),
        ROOT_CANISTER_ID.get(),
    )
    .expect("Failed to list snapshots after replace");
    assert_snapshot_checks_out(&list_canister_snapshots_response);
    let second_snapshot = &list_canister_snapshots_response[0];

    // Here is the interesting verification in case B: Here, it is asserted that
    // the first snapshot got CLOBBERED by the second.
    assert_ne!(
        second_snapshot.snapshot_id(),
        first_snapshot.snapshot_id(),
        "{second_snapshot:#?}\n\nvs.\n\n{first_snapshot:#?}"
    );
}
