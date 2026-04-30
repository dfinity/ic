use candid::{Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_management_canister_types_private::CanisterSnapshotResponse;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    NnsInstaller, management,
    nns::{self, ledger::icrc1_balance_of},
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::pb::v1::ProposalStatus;
use ic_nns_governance_api::{
    MakeProposalRequest, Motion, ProposalActionRequest, SuccessfulProposalExecutionValue,
    TakeCanisterSnapshotOk,
};
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE, Tokens};
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use std::{
    env,
    io::Write,
    process::Command,
    str::FromStr,
    time::{Duration, SystemTime},
};
use tempfile::NamedTempFile;

fn default_account_identifier(principal_id: PrincipalId) -> AccountIdentifier {
    AccountIdentifier::new(principal_id, None)
}

fn create_neuron_1_pem_file() -> NamedTempFile {
    let contents: String = TEST_NEURON_1_OWNER_KEYPAIR.to_pem();
    let mut pem_file = NamedTempFile::new().unwrap();
    pem_file.write_all(contents.as_bytes()).unwrap();
    pem_file
}

fn run_ic_admin(nns_url: &str, extra_args: Vec<String>) -> String {
    let ic_admin_path = env::var("IC_ADMIN_PATH").expect("IC_ADMIN_PATH not set");
    let pem_file = create_neuron_1_pem_file();
    let pem_file_path = pem_file.path().to_str().unwrap().to_string();
    let output = Command::new(ic_admin_path)
        .args(["--nns-url", nns_url, "--secret-key-pem", &pem_file_path])
        .args(&extra_args)
        .output()
        .expect("Failed to run ic-admin");
    let mut all_output = String::from_utf8(output.stdout).unwrap();
    all_output.push_str(&String::from_utf8(output.stderr).unwrap());
    assert_eq!(
        output.status.code().unwrap(),
        0,
        "ic-admin exited with non-zero status:\n{all_output}",
    );
    all_output
}

#[tokio::test]
async fn test_canister_snapshot() {
    // Step 1: Prepare the world: Set up the NNS canisters with a super powerful neuron.
    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    let icp_token_sender = PrincipalId::new_user_test_id(298_993_015);
    let icp_token_receiver = PrincipalId::new_user_test_id(836_602_313);
    let stable_balance_principal = PrincipalId::new_user_test_id(724_822_448);

    let initial_balance = Tokens::from_e8s(10 * E8);

    let mut nns_installer = NnsInstaller::default();
    nns_installer
        .with_current_nns_canister_versions()
        .with_ledger_balances(vec![
            (
                default_account_identifier(icp_token_sender),
                initial_balance,
            ),
            (
                default_account_identifier(icp_token_receiver),
                initial_balance,
            ),
            (
                default_account_identifier(stable_balance_principal),
                initial_balance,
            ),
        ]);
    nns_installer.install(&pocket_ic).await;

    let endpoint = pocket_ic.make_live(None).await;
    let nns_url = endpoint.as_ref();
    let neuron_id = TEST_NEURON_1_ID.to_string();

    let target_canister_id = LEDGER_CANISTER_ID;

    // Scenario A: The most basic thing: take a snapshot.

    // Step 2(A): Run the code under test: Take a snapshot via proposal.

    // Step 2(A).1: Submit proposal (via ic-admin).
    let ic_admin_output = run_ic_admin(
        nns_url,
        vec![
            "propose-to-take-canister-snapshot".to_string(),
            "--proposer".to_string(),
            neuron_id.clone(),
            "--canister-id".to_string(),
            target_canister_id.to_string(),
            "--summary".to_string(),
            "Take a snapshot of the Ledger canister.".to_string(),
        ],
    );
    let first_proposal_id = extract_proposal_id(&ic_admin_output);

    // Step 2A.2: Wait for execution.
    let first_proposal_info =
        nns::governance::wait_for_proposal_execution(&pocket_ic, first_proposal_id)
            .await
            .unwrap();

    // Step 3A. Verify results.

    // Step 3A.1: Proposal marked success.
    assert_eq!(
        ProposalStatus::try_from(first_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{first_proposal_info:#?}",
    );

    // Step 3A: Verify that a snapshot was created, by calling
    // list_canister_snapshots.
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> =
        management::list_canister_snapshots(
            &pocket_ic,
            target_canister_id,
            PrincipalId::from(ROOT_CANISTER_ID),
        )
        .await;

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

    // Step 3A.2: Verify that the snapshot ID is recorded in success_value.
    let snapshot_id_from_proposal = match &first_proposal_info.success_value {
        Some(SuccessfulProposalExecutionValue::TakeCanisterSnapshot(ok)) => ok.snapshot_id.clone(),
        other => panic!("Expected TakeCanisterSnapshot success value, got: {other:#?}"),
    };
    assert_eq!(
        snapshot_id_from_proposal,
        first_snapshot.snapshot_id().as_slice(),
    );

    // Scenario B: Replace an existing snapshot.

    // Step 2(B): Run code under test.

    // Make a proposal, like in scenario A, but this time, set the
    // replace_snapshot field to the ID of the first snapshot (from scenario A).
    let stderr = run_ic_admin(
        nns_url,
        vec![
            "propose-to-take-canister-snapshot".to_string(),
            "--proposer".to_string(),
            neuron_id.clone(),
            "--canister-id".to_string(),
            target_canister_id.to_string(),
            "--replace-snapshot".to_string(),
            hex::encode(first_snapshot.snapshot_id().as_slice()),
            "--summary".to_string(),
            "Take another snapshot and replace the first.".to_string(),
        ],
    );
    let replace_proposal_id = extract_proposal_id(&stderr);

    assert_ne!(replace_proposal_id, first_proposal_id);
    let replace_proposal_info =
        nns::governance::wait_for_proposal_execution(&pocket_ic, replace_proposal_id)
            .await
            .unwrap();

    // Step 3(B): Verify results.

    assert_eq!(
        ProposalStatus::try_from(replace_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{replace_proposal_info:#?}",
    );

    // List snapshots (again). Again, there should be 1, because the first
    // one got kicked out by the new one.
    let list_canister_snapshots_response: Vec<CanisterSnapshotResponse> =
        management::list_canister_snapshots(
            &pocket_ic,
            target_canister_id,
            PrincipalId::from(ROOT_CANISTER_ID),
        )
        .await;
    assert_eq!(
        list_canister_snapshots_response.len(),
        1,
        "{list_canister_snapshots_response:#?}"
    );

    // More interestingly, the one snapshot should NOT be the first one. The
    // first one should be CLOBBERED, blown away, replaced by the new one.
    let second_snapshot = &list_canister_snapshots_response[0];
    assert_ne!(second_snapshot.snapshot_id(), first_snapshot.snapshot_id());

    // Also verify that the replace proposal's success_value records the new snapshot ID.
    let snapshot_id_from_replace_proposal = match &replace_proposal_info.success_value {
        Some(SuccessfulProposalExecutionValue::TakeCanisterSnapshot(ok)) => ok.snapshot_id.clone(),
        other => panic!("Expected TakeCanisterSnapshot success value, got: {other:#?}"),
    };
    assert_eq!(
        snapshot_id_from_replace_proposal,
        second_snapshot.snapshot_id().as_slice(),
    );

    // Generic checks of the second snapshot.
    assert_snapshot_seems_reasonable(second_snapshot);

    // Scenario C: Load the second snapshot, but first, icp_token_sender sends
    // some ICP tokens to icp_token_recevier. That way, when the snapshot is
    // loaded, we can observe whether the expected effect takes place (i.e. the
    // ICP transfer from icp_token_sender to icp_token_receiver is rolled back).

    // Step 1(C): Prepare the world for LoadCanisterSnapshot.

    async fn assert_balance(
        pocket_ic: &PocketIc,
        owner: PrincipalId,
        expected_balance: Tokens,
        phase: &str,
    ) {
        let account = Account {
            owner: Principal::from(owner),
            subaccount: None,
        };
        let observed_balance = icrc1_balance_of(pocket_ic, account).await;
        assert_eq!(
            Tokens::from_e8s(u64::try_from(observed_balance.0).unwrap()),
            expected_balance,
            "Balance mismatch for {owner} during phase: {phase}",
        );
    }

    // The initial balances have not changed, but the code that set the initial
    // balances is a little bitfar away, so this is just to remind the reader
    // what the starting point is: everyone has the same initial_balance
    //(10 ICP).
    assert_balance(&pocket_ic, icp_token_sender, initial_balance, "initial").await;
    assert_balance(&pocket_ic, icp_token_receiver, initial_balance, "initial").await;
    assert_balance(
        &pocket_ic,
        stable_balance_principal,
        initial_balance,
        "initial",
    )
    .await;

    // Sender sends ICP to receiver.
    let transfer_amount = Tokens::from_tokens(1).unwrap();
    nns::ledger::icrc1_transfer(
        &pocket_ic,
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
    .await
    .unwrap();

    // Verify balances AFTER ICP is sent.
    assert_balance(
        &pocket_ic,
        icp_token_sender,
        initial_balance
            .checked_sub(&transfer_amount)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
        "after transfer",
    )
    .await;
    assert_balance(
        &pocket_ic,
        icp_token_receiver,
        initial_balance.checked_add(&transfer_amount).unwrap(),
        "after transfer",
    )
    .await;
    assert_balance(
        &pocket_ic,
        stable_balance_principal,
        initial_balance,
        "after transfer",
    )
    .await;

    // Step 2(C): Run the code under test by (making, adopting, and) executing a
    // LoadCanisterSnapshot proposal. This should revert the Ledger canister to
    // `second_snapshot`, which was taken BEFORE the transfer (which took place
    // in Step 1(C)).

    let stderr = run_ic_admin(
        nns_url,
        vec![
            "propose-to-load-canister-snapshot".to_string(),
            "--proposer".to_string(),
            neuron_id,
            "--canister-id".to_string(),
            target_canister_id.to_string(),
            "--snapshot-id".to_string(),
            hex::encode(second_snapshot.snapshot_id().as_slice()),
            "--summary".to_string(),
            "Restore the Ledger canister to snapshot 2, rolling back the ICP transfer.".to_string(),
        ],
    );
    let load_canister_snapshot_proposal_id = extract_proposal_id(&stderr);

    // Step 3C: Verify LoadCanisterSnapshot execution.

    let load_proposal_info = nns::governance::wait_for_proposal_execution(
        &pocket_ic,
        load_canister_snapshot_proposal_id,
    )
    .await
    .unwrap();
    assert_eq!(
        ProposalStatus::try_from(load_proposal_info.status),
        Ok(ProposalStatus::Executed),
        "{load_proposal_info:#?}",
    );

    // Balanaces are back to what they were.
    assert_balance(
        &pocket_ic,
        icp_token_sender,
        initial_balance,
        "after load snapshot",
    )
    .await;
    assert_balance(
        &pocket_ic,
        icp_token_receiver,
        initial_balance,
        "after load snapshot",
    )
    .await;
    assert_balance(
        &pocket_ic,
        stable_balance_principal,
        initial_balance,
        "after load snapshot",
    )
    .await;
}

/// Similar to previous test with the main difference being that Governance
/// is the guinea pig.
///
/// The reason for this additional test is that when the target canister is
/// Governance, there is special behavior: Root is supposed to do the operation
/// in the background. Without this special background behavior, proposal
/// execution would deadlock.
///
/// Minor difference: To verify that LoadCanisterSnapshot actually rolled
/// back Governance's state, we create a Motion proposal after the snapshot
/// (instead of sending ICP) and confirm it disappears after loading the
/// snapshot.
#[tokio::test]
async fn test_governance_canister_snapshot() {
    // Step 1: Prepare the world.

    // Create IC.
    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    // Install NNS.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    let endpoint = pocket_ic.make_live(None).await;
    let nns_url = endpoint.as_ref();
    let neuron_id = TEST_NEURON_1_ID.to_string();

    let target_canister_id = GOVERNANCE_CANISTER_ID;

    // Create a Motion proposal BEFORE taking a snapshot. This one should
    // survive loading the snapshot near the end.
    let pre_snapshot_motion_info = nns::governance::propose_and_wait(
        &pocket_ic,
        MakeProposalRequest {
            title: Some("Pre-snapshot Motion".to_string()),
            summary: String::new(),
            url: String::new(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: "This one survives.".to_string(),
            })),
        },
    )
    .await
    .unwrap();
    let pre_snapshot_motion_proposal_id = pre_snapshot_motion_info.id.unwrap().id;

    // Take a snapshot of Governance (via ic-admin).
    let output = run_ic_admin(
        nns_url,
        vec![
            "propose-to-take-canister-snapshot".to_string(),
            "--proposer".to_string(),
            neuron_id.clone(),
            "--canister-id".to_string(),
            target_canister_id.to_string(),
            "--summary".to_string(),
            "Take a snapshot of the Governance canister.".to_string(),
        ],
    );
    let take_canister_snapshot_proposal_id = extract_proposal_id(&output);

    // Wait for the effect of the proposal happen. This cannot be done in
    // the normal way (i.e. wait for the proposal status to become Executed,
    // as is done in the previous test), because when the target of a
    // snapshot proposal is Governance itself, it gets marked as successful
    // early. Instead, we just let pocket_ic advance by a "reasonable"
    // amount.
    for _ in 0..50 {
        pocket_ic.tick().await;
    }

    // Verify that the proposal had the desired effect: a new snapshot of
    // the Governance canister.
    let snapshots: Vec<CanisterSnapshotResponse> = management::list_canister_snapshots(
        &pocket_ic,
        target_canister_id,
        PrincipalId::from(ROOT_CANISTER_ID),
    )
    .await;
    assert_eq!(snapshots.len(), 1, "{snapshots:#?}");
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.id.get_canister_id(), GOVERNANCE_CANISTER_ID);

    // Verify that success_value is populated. When the target is Governance,
    // Root returns a placeholder/optimistic response to avoid a deadlock
    // (it cannot stop Governance while Governance is waiting for it). The
    // snapshot ID in that placeholder is zeroed.
    let take_canister_snapshot_proposal_info =
        nns::governance::get_proposal_info(&pocket_ic, take_canister_snapshot_proposal_id)
            .await
            .unwrap();
    let optimistic_snapshot_id = SnapshotId::from((CanisterId::from_u64(0), 0_u64)).to_vec();
    assert_eq!(
        take_canister_snapshot_proposal_info.success_value.unwrap(),
        SuccessfulProposalExecutionValue::from(TakeCanisterSnapshotOk {
            snapshot_id: optimistic_snapshot_id,
        }),
    );

    // Change Governance's state by creating ANOTHER (Motion) proposal.
    // This will get blown away at the end when we load the snapshot,
    // because the snapshot was taken before this proposal.
    let doomed_motion_info = nns::governance::propose_and_wait(
        &pocket_ic,
        MakeProposalRequest {
            title: Some("Doomed Motion".to_string()),
            summary: String::new(),
            url: String::new(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: "This one gets rolled back.".to_string(),
            })),
        },
    )
    .await
    .unwrap();
    let doomed_motion_proposal_id = doomed_motion_info.id.unwrap().id;

    // Verify the doomed proposal exists before loading the snapshot, so that
    // its absence afterward is a meaningful signal of change.
    assert_ne!(
        nns::governance::get_proposal_info(&pocket_ic, doomed_motion_proposal_id).await,
        None,
    );

    // Step 2: Execute the code under test: Load the snapshot (via ic-admin).
    let output = run_ic_admin(
        nns_url,
        vec![
            "propose-to-load-canister-snapshot".to_string(),
            "--proposer".to_string(),
            neuron_id,
            "--canister-id".to_string(),
            target_canister_id.to_string(),
            "--snapshot-id".to_string(),
            hex::encode(snapshot.snapshot_id().as_slice()),
            "--summary".to_string(),
            "Load the Governance snapshot, rolling back state.".to_string(),
        ],
    );
    let _load_proposal_id = extract_proposal_id(&output);
    // As with taking the snapshot, we cannot use Executed status to know
    // that the effect of the proposal has taken place.
    for _ in 0..50 {
        pocket_ic.tick().await;
    }

    // Step 3: Verify results.

    // The pre-snapshot Motion proposal should still exist (it was part of
    // the snapshot).
    assert_ne!(
        nns::governance::get_proposal_info(&pocket_ic, pre_snapshot_motion_proposal_id).await,
        None,
    );

    // The post-snapshot Motion proposal should be gone, because it was not in
    // the snapshot.
    //
    // (As a side effect, the load proposal itself also disappears, but we use
    // this Motion proposal as the primary indicator since it is less confusing.)
    assert_eq!(
        nns::governance::get_proposal_info(&pocket_ic, doomed_motion_proposal_id).await,
        None,
    );
}

/// Parses the proposal ID from ic-admin's stderr output, which looks like
/// "response: Ok(proposal 3)".
fn extract_proposal_id(ic_admin_output: &str) -> u64 {
    let re = regex::Regex::new(r"proposal (\d+)").unwrap();
    let captures = re.captures(ic_admin_output).unwrap_or_else(|| {
        panic!("Expected proposal response in ic-admin output:\n{ic_admin_output}")
    });
    u64::from_str(&captures[1]).unwrap()
}
