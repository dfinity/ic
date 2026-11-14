use super::*;
use crate::{
    governance::test_helpers::{DoNothingLedger, basic_governance_proto, execute_proposal},
    pb::sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
    types::test_helpers::NativeEnvironment,
};
use ic_base_types::SnapshotId;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::{
    E8, ONE_DAY_SECONDS, ledger::compute_neuron_staking_subaccount_bytes,
};
use ic_nervous_system_root::load_canister_snapshot::{
    LoadCanisterSnapshotError, LoadCanisterSnapshotOk,
};

const PROPOSAL_ID: u64 = 42;
const NOW: u64 = NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS;

fn root_canister_id() -> CanisterId {
    CanisterId::from_u64(1000)
}

fn dapp_canister_id() -> CanisterId {
    CanisterId::from_u64(2000)
}

/// The snapshot (of dapp_canister_id) that the proposal loads.
fn snapshot_id() -> SnapshotId {
    SnapshotId::from((dapp_canister_id(), 3))
}

/// A NativeEnvironment where Root says that the registered dapp canisters are `dapps`.
///
/// Calls that are not explicitly expected (by the caller of this function) fail.
fn new_env(dapps: Vec<CanisterId>) -> NativeEnvironment {
    let mut env = NativeEnvironment::default();
    env.default_canister_call_response = Err((Some(1), "Unexpected call!".to_string()));
    env.set_call_canister_response(
        root_canister_id(),
        "list_sns_canisters",
        Encode!(&ListSnsCanistersRequest {}).unwrap(),
        Ok(Encode!(&ListSnsCanistersResponse {
            dapps: dapps.into_iter().map(CanisterId::get).collect(),
            ..Default::default()
        })
        .unwrap()),
    );
    env
}

/// An adopted (but not yet executed) LoadCanisterSnapshot proposal, voted on by one neuron.
fn load_canister_snapshot_proposal_data() -> ProposalData {
    let action = Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(dapp_canister_id().get()),
        snapshot_id: Some(snapshot_id().to_vec()),
    });

    let neuron_id = NeuronId::from(compute_neuron_staking_subaccount_bytes(
        PrincipalId::new_user_test_id(1),
        /* nonce = */ 0,
    ));
    let voting_period_seconds = 4 * ONE_DAY_SECONDS;
    let proposal_creation_timestamp_seconds = NOW - voting_period_seconds - 60;

    ProposalData {
        action: u64::from(&action),
        id: Some(ProposalId { id: PROPOSAL_ID }),
        proposer: Some(neuron_id.clone()),
        proposal_creation_timestamp_seconds,
        initial_voting_period_seconds: voting_period_seconds,
        wait_for_quiet_deadline_increase_seconds: ONE_DAY_SECONDS,
        ballots: btreemap! {
            neuron_id.to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 1_234 * E8,
                cast_timestamp_seconds: proposal_creation_timestamp_seconds + 3_600,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_creation_timestamp_seconds
                + voting_period_seconds,
        }),
        proposal: Some(Proposal {
            title: "Roll back the dapp to before yesterday's faulty upgrade".to_string(),
            summary: "Yesterday's upgrade corrupted the dapp's state. This loads the snapshot \
                      that was taken right before that upgrade."
                .to_string(),
            url: "https://forum.example.com/t/roll-back-the-dapp/123".to_string(),
            action: Some(action),
        }),
        ..Default::default()
    }
}

/// Executes the proposal with ID PROPOSAL_ID in `env`. Besides that proposal, the SNS has the
/// proposals in `other_proposals`.
fn execute_load_canister_snapshot(
    env: NativeEnvironment,
    other_proposals: BTreeMap<u64, ProposalData>,
) -> ProposalData {
    let mut proposals = other_proposals;
    proposals.insert(PROPOSAL_ID, load_canister_snapshot_proposal_data());

    let mut governance = Governance::new(
        GovernanceProto {
            proposals,
            root_canister_id: Some(root_canister_id().get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    execute_proposal(&mut governance, PROPOSAL_ID)
}

#[test]
fn test_load_canister_snapshot_calls_root() {
    // Step 1: Prepare the world.
    let mut env = new_env(vec![dapp_canister_id()]);
    // When env is dropped, it asserts that Governance called Root's load_canister_snapshot
    // method, with exactly this request.
    env.require_call_canister_invocation(
        root_canister_id(),
        "load_canister_snapshot",
        Encode!(&LoadCanisterSnapshotRequest {
            canister_id: dapp_canister_id().get(),
            snapshot_id: snapshot_id().to_vec(),
        })
        .unwrap(),
        Some(Ok(Encode!(&LoadCanisterSnapshotResponse::Ok(
            LoadCanisterSnapshotOk {}
        ))
        .unwrap())),
    );

    // Step 2: Run the code under test.
    let proposal_data = execute_load_canister_snapshot(env, btreemap! {});

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.executed_timestamp_seconds, NOW);
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert_eq!(proposal_data.failure_reason, None);
}

#[test]
fn test_load_canister_snapshot_fails_when_root_fails() {
    // Step 1: Prepare the world.
    let mut env = new_env(vec![dapp_canister_id()]);
    env.require_call_canister_invocation(
        root_canister_id(),
        "load_canister_snapshot",
        Encode!(&LoadCanisterSnapshotRequest {
            canister_id: dapp_canister_id().get(),
            snapshot_id: snapshot_id().to_vec(),
        })
        .unwrap(),
        Some(Ok(Encode!(&LoadCanisterSnapshotResponse::Err(
            LoadCanisterSnapshotError {
                code: Some(3),
                description: "Could not find the snapshot ID.".to_string(),
            }
        ))
        .unwrap())),
    );

    // Step 2: Run the code under test.
    let proposal_data = execute_load_canister_snapshot(env, btreemap! {});

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Failed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);
    let failure_reason = proposal_data.failure_reason.unwrap();
    assert_eq!(failure_reason.error_type, ErrorType::External as i32);
    // The cause is the error from Root (prepared in step 1), for this canister.
    let message = &failure_reason.error_message;
    assert!(
        message.contains("Could not find the snapshot ID"),
        "{message}"
    );
    assert!(
        message.contains(&dapp_canister_id().to_string()),
        "{message}"
    );
}

/// The target is checked again when the proposal is executed, because the dapp canister might
/// have been deregistered since the proposal was submitted.
#[test]
fn test_load_canister_snapshot_fails_when_target_is_no_longer_a_dapp() {
    // Step 1: Prepare the world. Root no longer lists the target as a dapp canister. Governance
    // must not even try to call Root's load_canister_snapshot method (new_env makes any such
    // call fail, but the error below shows that it was not made).
    let env = new_env(vec![]);

    // Step 2: Run the code under test.
    let proposal_data = execute_load_canister_snapshot(env, btreemap! {});

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Failed,
        "{proposal_data:#?}"
    );
    let failure_reason = proposal_data.failure_reason.unwrap();
    assert_eq!(failure_reason.error_type, ErrorType::InvalidProposal as i32);
    // The cause is that the target is no longer registered.
    let message = &failure_reason.error_message;
    assert!(message.contains("registered"), "{message}");
    assert!(
        message.contains(&dapp_canister_id().to_string()),
        "{message}"
    );
}

/// An adopted UpgradeSnsControlledCanister proposal that is being executed.
fn upgrade_in_progress() -> ProposalData {
    ProposalData {
        action: u64::from(&Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister::default(),
        )),
        id: Some(ProposalId { id: 7 }),
        decided_timestamp_seconds: NOW - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: NOW - 10,
        }),
        ..Default::default()
    }
}

/// Like other upgrades, a LoadCanisterSnapshot proposal is not executed while an upgrade is in
/// progress: its execution fails (it is not retried later).
#[test]
fn test_load_canister_snapshot_aborts_when_an_upgrade_is_in_progress() {
    // Step 1: Prepare the world. Governance must not call Root's load_canister_snapshot method
    // (new_env makes any such call fail, but the error below shows that it was not made).
    let env = new_env(vec![dapp_canister_id()]);
    let upgrade_in_progress = upgrade_in_progress();
    assert_eq!(
        upgrade_in_progress.status(),
        ProposalDecisionStatus::Adopted
    );

    // Step 2: Run the code under test.
    let proposal_data = execute_load_canister_snapshot(env, btreemap! { 7 => upgrade_in_progress });

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Failed,
        "{proposal_data:#?}"
    );
    let failure_reason = proposal_data.failure_reason.unwrap();
    assert_eq!(
        failure_reason.error_type,
        ErrorType::ResourceExhausted as i32
    );
    assert!(
        failure_reason.error_message.contains(&format!(
            "Another upgrade is currently in progress (proposal IDs 7, {PROPOSAL_ID})"
        )),
        "{failure_reason:?}"
    );
}

/// Conversely, while a LoadCanisterSnapshot proposal is being executed, no upgrade (e.g. an
/// UpgradeSnsControlledCanister proposal) is executed.
#[test]
fn test_load_canister_snapshot_in_progress_blocks_upgrades() {
    // Step 1: Prepare the world.
    let load_canister_snapshot_in_progress = ProposalData {
        decided_timestamp_seconds: NOW - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: NOW - 10,
        }),
        ..load_canister_snapshot_proposal_data()
    };
    assert_eq!(
        load_canister_snapshot_in_progress.status(),
        ProposalDecisionStatus::Adopted
    );
    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                PROPOSAL_ID => load_canister_snapshot_in_progress,
                7 => upgrade_in_progress(),
            },
            root_canister_id: Some(root_canister_id().get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(new_env(vec![dapp_canister_id()])),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run the code under test. This is what executing the upgrade proposal (7) does
    // first.
    let result = governance.check_no_upgrades_in_progress(Some(7));

    // Step 3: Inspect results.
    let err = result.unwrap_err();
    assert_eq!(err.error_type, ErrorType::ResourceExhausted as i32);
    assert!(
        err.error_message.contains(&format!(
            "Another upgrade is currently in progress (proposal IDs 7, {PROPOSAL_ID})"
        )),
        "{err:?}"
    );
}
