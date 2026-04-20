use candid::{Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_management_canister_types_private::{CanisterSnapshotResponse, ListCanisterSnapshotArgs};
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    LoadCanisterSnapshot, MakeProposalRequest, Motion, ProposalActionRequest, TakeCanisterSnapshot,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        icrc1_balance, icrc1_transfer, nns_execute_proposal, nns_get_proposal_info,
        nns_governance_make_proposal, setup_nns_canisters, state_machine_builder_for_nns_tests,
        update_with_sender,
    },
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE, Tokens};
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use std::time::{Duration, SystemTime};

fn default_account_identifier(principal_id: PrincipalId) -> AccountIdentifier {
    AccountIdentifier::new(principal_id, None)
}

#[test]
fn test_canister_snapshot() {
    // Step 1: Prepare the world: Set up the NNS canisters with a super powerful neuron.
    let state_machine = state_machine_builder_for_nns_tests().build();

    let icp_token_sender = PrincipalId::new_user_test_id(298_993_015);
    let icp_token_receiver = PrincipalId::new_user_test_id(836_602_313);
    let stable_balance_principal = PrincipalId::new_user_test_id(724_822_448);

    let initial_balance = Tokens::from_e8s(10 * E8);

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(
            default_account_identifier(icp_token_sender),
            initial_balance,
        )
        .with_ledger_account(
            default_account_identifier(icp_token_receiver),
            initial_balance,
        )
        .with_ledger_account(
            default_account_identifier(stable_balance_principal),
            initial_balance,
        )
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);

    let target_canister_id = LEDGER_CANISTER_ID;

    // Scenario A: The most basic thing: take a snapshot.

    // Step 2(A): Run the code under test: Take a snapshot via proposal.
    let first_proposal_id = nns_execute_proposal(
        &state_machine,
        ProposalActionRequest::TakeCanisterSnapshot(TakeCanisterSnapshot {
            canister_id: Some(target_canister_id.get()),
            replace_snapshot: None,
        }),
    );

    // Step 3A: Verify that a snapshot was created, by calling
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
    let replace_proposal_id = nns_execute_proposal(
        &state_machine,
        ProposalActionRequest::TakeCanisterSnapshot(TakeCanisterSnapshot {
            canister_id: Some(target_canister_id.get()),
            replace_snapshot: Some(first_snapshot.snapshot_id().to_vec()),
        }),
    );

    assert_ne!(replace_proposal_id, first_proposal_id);

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

    // Scenario C: Load the second snapshot, but first, icp_token_sender sends
    // some ICP tokens to icp_token_recevier. That way, when the snapshot is
    // loaded, we can observe whether the expected effect takes place (i.e. the
    // ICP transfer from icp_token_sender to icp_token_receiver is rolled back).

    // Step 1(C): Prepare the world for LoadCanisterSnapshot.

    #[track_caller]
    fn assert_balance(state_machine: &StateMachine, owner: PrincipalId, expected_balance: Tokens) {
        let owner = Principal::from(owner);

        let account = Account {
            owner,
            subaccount: None,
        };

        let observed_balance = icrc1_balance(state_machine, LEDGER_CANISTER_ID, account);

        assert_eq!(observed_balance, expected_balance);
    }

    // Verify initial balances. This just makes sure that we configured this
    // test correctly; this is not to confirm that the code under test itself is
    // correct.
    assert_balance(&state_machine, icp_token_sender, initial_balance);
    assert_balance(&state_machine, icp_token_receiver, initial_balance);
    assert_balance(&state_machine, stable_balance_principal, initial_balance);

    // Tranfer ICP (from icp_token_sender to icp_token_receiver).
    let transfer_amount = Tokens::from_tokens(1).unwrap();
    icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        icp_token_sender,
        TransferArg {
            to: Account {
                owner: Principal::from(icp_token_receiver),
                subaccount: None,
            },
            amount: Nat::from(transfer_amount.get_e8s()),
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),

            from_subaccount: None,
            memo: None,
            created_at_time: None,
        },
    )
    .unwrap();

    // Verify balances AFTER transfer
    assert_balance(
        &state_machine,
        icp_token_sender,
        initial_balance
            .checked_sub(&transfer_amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
    );
    assert_balance(
        &state_machine,
        icp_token_receiver,
        initial_balance.checked_add(&transfer_amount).unwrap(),
    );
    assert_balance(&state_machine, stable_balance_principal, initial_balance);

    // Step 2(C): Run the code under test by making, adopting, and executing a
    // LoadCanisterSnapshot proposal. This should revert the Ledger canister to
    // `second_snapshot`, which was taken BEFORE the transfer (which took place
    // in Step 1(C)).

    nns_execute_proposal(
        &state_machine,
        ProposalActionRequest::LoadCanisterSnapshot(LoadCanisterSnapshot {
            canister_id: Some(target_canister_id.get()),
            snapshot_id: Some(second_snapshot.snapshot_id().to_vec()),
        }),
    );

    // Step 3(C): Verify results.

    // Balanaces are back to what they were.
    assert_balance(&state_machine, icp_token_sender, initial_balance);
    assert_balance(&state_machine, icp_token_receiver, initial_balance);
    assert_balance(&state_machine, stable_balance_principal, initial_balance);
}

/// Similar to previous test with the main difference being that Governance
/// is the guinea pig.
///
/// The reason for this additional test is that when the target canister is
/// Governance, there is special behavior: Root is supposed to do the operation
/// in the background. Without this, proposal execution would deadlock.
///
/// Minor difference: To verify that LoadCanisterSnapshot actually rolled
/// back Governance's state, we create a Motion proposal after the snapshot
/// and confirm it disappears after loading the snapshot.
#[test]
fn test_governance_canister_snapshot() {
    // Step 1: Prepare the world.

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let target_canister_id = GOVERNANCE_CANISTER_ID;

    // Create a Motion proposal BEFORE taking a snapshot. This one should survive
    // loading the snapshot near the end.
    let pre_snapshot_motion_proposal_id = nns_execute_proposal(
        &state_machine,
        ProposalActionRequest::Motion(Motion {
            motion_text: "This one survives.".to_string(),
        }),
    );

    // Take a snapshot of Governance (via proposal).
    //
    // Cannot use nns_execute_proposal for the same reason as LoadCanisterSnapshot
    // below: Root stops/restarts Governance in the background, racing with the poll.
    nns_governance_make_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId {
            id: TEST_NEURON_1_ID,
        },
        &MakeProposalRequest {
            title: Some("TakeCanisterSnapshot".to_string()),
            summary: String::new(),
            url: String::new(),
            action: Some(ProposalActionRequest::TakeCanisterSnapshot(
                TakeCanisterSnapshot {
                    canister_id: Some(target_canister_id.get()),
                    replace_snapshot: None,
                },
            )),
        },
    );
    // Let the background work (stop → take snapshot → start Governance) complete.
    for _ in 0..50 {
        state_machine.tick();
    }

    // Verify that the proposal had the desired effect: a new snapshot of
    // the Governance canister.
    let snapshots: Vec<CanisterSnapshotResponse> = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "list_canister_snapshots",
        ListCanisterSnapshotArgs::new(target_canister_id),
        ROOT_CANISTER_ID.get(),
    )
    .unwrap();
    assert_eq!(snapshots.len(), 1, "{snapshots:#?}");
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.id.get_canister_id(), GOVERNANCE_CANISTER_ID,);

    // Change Governance's state by creating ANOTHER (Motion) proposal.
    // This will get blown away at the end when we load the snapshot,
    // because the snapshot was taken before this proposal.
    let doomed_motion_proposal_id = nns_execute_proposal(
        &state_machine,
        ProposalActionRequest::Motion(Motion {
            motion_text: "This one gets rolled back.".to_string(),
        }),
    );
    // Verify the second/doommed Motion proposal exists. This is so that
    // when we find it absent after loading the canister snapshot, we are
    // seeing a CHANGE, not just the final state.
    let doomed_motion_proposal_info_before_load =
        nns_get_proposal_info(&state_machine, doomed_motion_proposal_id.id);
    assert_ne!(doomed_motion_proposal_info_before_load, None,);

    // Step 2: Execute the code under test: Load the snapshot (via proposal).
    //
    // We cannot use nns_execute_proposal here: when targeting Governance,
    // the proposal is marked Executed immediately (to avoid deadlock), then
    // Root stops/restores/starts Governance in the background, at which point
    // the proposal itself is gone (rolled back with the snapshot). Polling for
    // Executed status would race with the stop or never find the proposal.
    nns_governance_make_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId {
            id: TEST_NEURON_1_ID,
        },
        &MakeProposalRequest {
            title: Some("LoadCanisterSnapshot".to_string()),
            summary: String::new(),
            url: String::new(),
            action: Some(ProposalActionRequest::LoadCanisterSnapshot(
                LoadCanisterSnapshot {
                    canister_id: Some(target_canister_id.get()),
                    snapshot_id: Some(snapshot.snapshot_id().to_vec()),
                },
            )),
        },
    );

    // Let the background work (stop → load snapshot → start Governance) complete.
    for _ in 0..50 {
        state_machine.tick();
    }

    // Step 3: Verify results.

    // The pre-snapshot Motion proposal should still exist (it was part of the
    // snapshot).
    let pre_snapshot_motion_info_after =
        nns_get_proposal_info(&state_machine, pre_snapshot_motion_proposal_id.id);
    assert_ne!(
        pre_snapshot_motion_info_after, None,
        "Pre-snapshot Motion proposal should still exist: {pre_snapshot_motion_info_after:#?}",
    );

    // The post-snapshot Motion proposal should be gone, because it was not in
    // the snapshot.
    //
    // (As a side effect, the load proposal itself also disappears, but we use
    // this Motion proposal as the primary indicator since it is less confusing.)
    let doomed_motion_info_after_load =
        nns_get_proposal_info(&state_machine, doomed_motion_proposal_id.id);
    assert_eq!(doomed_motion_info_after_load, None,);
}
