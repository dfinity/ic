use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{CanisterSnapshotResponse, ListCanisterSnapshotArgs};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::pb::v1::ProposalStatus;
use ic_nns_governance_api::{
    ExecuteNnsFunction, MakeProposalRequest, Motion, NnsFunction, ProposalActionRequest,
    ProposalInfo, manage_neuron_response::Command,
};
use ic_nns_handler_root_interface::{LoadCanisterSnapshotRequest, TakeCanisterSnapshotRequest};
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
fn test_take_and_load_canister_snapshot() {
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
        assert_eq!(snapshots.len(), 1, "{snapshots:#?}");

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

    // Step 1C: Prepare the world for LoadCanisterSnapshot. This consists of
    // submitting a "marker" (Motion) proposal. It will get blown away by the
    // LoadCanisterSnapshot proposal, because it is being created after the
    // snapshot loaded by the LoadCanisterSnapshot proposal.
    let make_marker_response = nns_governance_make_proposal(
        &state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &MakeProposalRequest {
            title: Some("Marker Proposal".to_string()),
            summary: "This is a marker proposal.".to_string(),
            url: "https://forum.dfinity.org/marker-proposal".to_string(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: "This proposal should disappear after snapshot load".to_string(),
            })),
        },
    );
    let marker_proposal_id = match make_marker_response.command.as_ref().unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("{make_marker_response:#?}"),
    };
    nns_wait_for_proposal_execution(&state_machine, marker_proposal_id.id);

    // Verify marker exists. After loading the snapshot, this won't work anymore.
    let _marker_info: ProposalInfo =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, marker_proposal_id.id);

    // Step 2C: Run the code under test by passing a LoadCanisterSnapshot
    // proposal. (As is often the case in tests, the proposal passes right away
    // due to the proposal being made by a neuron with overwhelming voting
    // power.)

    // Step 2C.1: Assemble MakeProposalRequest.
    let payload = Encode!(&LoadCanisterSnapshotRequest {
        canister_id: target_canister_id.get(),
        // Remember, this snapshot (second_snapshot) was taken BEFORE the marker
        // proposal.
        snapshot_id: second_snapshot.snapshot_id().to_vec(),
    })
    .unwrap();
    let action = ProposalActionRequest::ExecuteNnsFunction(ExecuteNnsFunction {
        nns_function: NnsFunction::LoadCanisterSnapshot as i32,
        payload,
    });
    let make_proposal_request = MakeProposalRequest {
        title: Some("Restore Governance Canister to Snapshot 2".to_string()),
        summary: r#"This will clobber the "marker" motion proposal."#.to_string(),
        url: "https://forum.dfinity.org/restore-governance-canister-to-snapshot-2".to_string(),
        action: Some(action),
    };

    // Step 2C.2: Submit the proposal.
    let make_proposal_response = nns_governance_make_proposal(
        &state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &make_proposal_request,
    );
    let load_proposal_id = match make_proposal_response.command.as_ref().unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("{make_proposal_response:#?}"),
    };

    // Step 3C: Verify LoadCanisterSnapshot execution.

    // Step 3C.1: Poll until the LoadCanisterSnapshot proposal vanishes (or it
    // is marked as fail). If LoadCanisterSnapshot proposals work correctly,
    // then the LoadCanisterSnapshot proposal itself would disappear, because
    // that proposal itself is not in the (Governance canister) snapshot.
    let mut done = false;
    for _ in 0..50 {
        // Fetch the LoadCanisterSnapshot proposal.
        let response_bytes = state_machine
            .execute_ingress_as(
                PrincipalId::new_anonymous(),
                GOVERNANCE_CANISTER_ID,
                "get_proposal_info",
                Encode!(&load_proposal_id.id).unwrap(),
            )
            .unwrap();
        let result = match response_bytes {
            ic_types::ingress::WasmResult::Reply(bytes) => bytes,
            ic_types::ingress::WasmResult::Reject(reason) => {
                panic!("get_proposal_info rejected: {reason}")
            }
        };
        let proposal_info: Option<ProposalInfo> =
            candid::Decode!(&result, Option<ProposalInfo>).unwrap();

        // If the proposal is suddenly missing, that's actually a sign that it
        // worked. In any case, it means we can now proceed with the rest of
        // verification.
        if proposal_info.is_none() {
            println!(
                "As expected, the LoadCanisterSnapshot proposal vanished \
                 (as a result of its own execution!).",
            );
            done = true;
            break;
        }

        // Exit early if proposal execution failed, since this is a terminal
        // state. This is "just" an optimization in that this whole test would
        // fail even if we deleted this chunk.
        let status = ProposalStatus::try_from(proposal_info.unwrap().status);
        if status == Ok(ProposalStatus::Failed) {
            panic!("Load Snapshot Proposal failed execution!");
        }

        // Sleep before polling again.
        state_machine.advance_time(Duration::from_secs(10));
        state_machine.tick();
    }
    assert!(
        done,
        "Timeout waiting for Load Snapshot Proposal to vanish \
         (as a result of correct execution).",
    );

    // Step 3C.2: Verify that the MARKER (motion) proposal has (also) been blown
    // away (not just the LoadCanisterSnapshot proposal).
    let response_bytes = state_machine
        .execute_ingress_as(
            PrincipalId::new_anonymous(),
            GOVERNANCE_CANISTER_ID,
            "get_proposal_info",
            Encode!(&marker_proposal_id.id).unwrap(),
        )
        .unwrap();
    let result = match response_bytes {
        ic_types::ingress::WasmResult::Reply(bytes) => bytes,
        ic_types::ingress::WasmResult::Reject(reason) => {
            panic!("get_proposal_info rejected: {reason}")
        }
    };
    let final_marker_proposal_status: Option<ProposalInfo> =
        candid::Decode!(&result, Option<ProposalInfo>).unwrap();
    assert_eq!(
        final_marker_proposal_status, None,
        "Marker proposal {} should have been wiped out by snapshot load, \
         but it still exists: {:#?}",
        marker_proposal_id.id, final_marker_proposal_status
    );

    // Step 3C.3: Verify that the first proposal is still there (albeit moot,
    // since the second proposal clobbered the snapshot created by the first
    // proposal.)
    let first_proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, first_proposal_id.id);
    assert_eq!(
        ProposalStatus::try_from(first_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "First proposal should still exist and be executed: {first_proposal_info:#?}",
    );
}
