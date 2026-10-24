//! Tests for executing TakeCanisterSnapshot and LoadCanisterSnapshot proposals, and
//! UpgradeSnsControlledCanister proposals with take_canister_snapshot set.

use super::*;
use crate::{
    governance::test_helpers::{
        DoNothingLedger, TEST_ARCHIVES_CANISTER_IDS, TEST_GOVERNANCE_CANISTER_ID,
        TEST_INDEX_CANISTER_ID, TEST_LEDGER_CANISTER_ID, TEST_ROOT_CANISTER_ID,
        TEST_SWAP_CANISTER_ID, basic_governance_proto, execute_proposal,
    },
    pb::{
        sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
        v1::upgrade_sns_controlled_canister::TakeSnapshotBeforeUpgrade,
    },
    sns_upgrade::{CanisterSummary, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse},
    types::test_helpers::NativeEnvironment,
};
use async_trait::async_trait;
use ic_base_types::SnapshotId;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_root::{
    load_canister_snapshot::{LoadCanisterSnapshotError, LoadCanisterSnapshotOk},
    take_canister_snapshot::{TakeCanisterSnapshotError, TakeCanisterSnapshotOk as RootTakeOk},
};
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_test_utilities_types::ids::canister_test_id;
use pretty_assertions::assert_eq;
use std::sync::{Arc, Mutex};

const PROPOSAL_ID: u64 = 1;

lazy_static! {
    static ref DAPP_CANISTER_ID: CanisterId = canister_test_id(600);
    static ref OTHER_DAPP_CANISTER_ID: CanisterId = canister_test_id(601);
    static ref NEW_WASM: Vec<u8> = vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];
}

type CanisterCallResult = Result<Vec<u8>, (Option<i32>, String)>;
type Call = (CanisterId, String, Vec<u8>);

/// Replies to canister calls based only on the name of the method, and records all calls, so
/// that tests can inspect which calls were made, in which order, and with which arguments.
///
/// Calls to methods without a scripted reply are rejected the way that the replica rejects
/// calls to methods that do not exist (e.g. because the callee is an older version).
struct RecordingEnvironment {
    replies: BTreeMap<String, CanisterCallResult>,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl RecordingEnvironment {
    fn new(replies: Vec<(&str, CanisterCallResult)>) -> (Self, Arc<Mutex<Vec<Call>>>) {
        let calls = Arc::new(Mutex::new(vec![]));
        let env = Self {
            replies: replies
                .into_iter()
                .map(|(method_name, reply)| (method_name.to_string(), reply))
                .collect(),
            calls: Arc::clone(&calls),
        };
        (env, calls)
    }
}

#[async_trait]
impl Environment for RecordingEnvironment {
    fn now(&self) -> u64 {
        NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS
    }

    fn insecure_random_u64(&mut self) -> u64 {
        4 // Chosen by fair dice roll.
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> CanisterCallResult {
        self.calls
            .lock()
            .unwrap()
            .push((canister_id, method_name.to_string(), arg));

        self.replies.get(method_name).cloned().unwrap_or_else(|| {
            Err((
                Some(3), // CanisterReject
                format!(
                    "Error from Canister {canister_id}: Canister has no update method \
                     '{method_name}'."
                ),
            ))
        })
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }

    fn canister_id(&self) -> CanisterId {
        *TEST_GOVERNANCE_CANISTER_ID
    }

    fn canister_version(&self) -> Option<u64> {
        None
    }
}

fn snapshot_id(canister_id: CanisterId, local_id: u64) -> Vec<u8> {
    SnapshotId::from((canister_id, local_id)).to_vec()
}

fn summary(canister_id: CanisterId) -> CanisterSummary {
    CanisterSummary {
        canister_id: Some(canister_id.get()),
        status: None,
    }
}

/// What Root's get_sns_canisters_summary replies (used by the UpgradeSnsControlledCanister path).
fn get_sns_canisters_summary_reply() -> CanisterCallResult {
    Ok(Encode!(&GetSnsCanistersSummaryResponse {
        root: Some(summary(*TEST_ROOT_CANISTER_ID)),
        governance: Some(summary(*TEST_GOVERNANCE_CANISTER_ID)),
        ledger: Some(summary(*TEST_LEDGER_CANISTER_ID)),
        swap: Some(summary(*TEST_SWAP_CANISTER_ID)),
        dapps: vec![summary(*DAPP_CANISTER_ID), summary(*OTHER_DAPP_CANISTER_ID)],
        archives: TEST_ARCHIVES_CANISTER_IDS
            .iter()
            .copied()
            .map(summary)
            .collect(),
        index: Some(summary(*TEST_INDEX_CANISTER_ID)),
    })
    .unwrap())
}

/// What Root's list_sns_canisters replies (used by the snapshot proposals).
fn list_sns_canisters_reply() -> CanisterCallResult {
    Ok(Encode!(&ListSnsCanistersResponse {
        root: Some(TEST_ROOT_CANISTER_ID.get()),
        governance: Some(TEST_GOVERNANCE_CANISTER_ID.get()),
        ledger: Some(TEST_LEDGER_CANISTER_ID.get()),
        swap: Some(TEST_SWAP_CANISTER_ID.get()),
        dapps: vec![DAPP_CANISTER_ID.get(), OTHER_DAPP_CANISTER_ID.get()],
        archives: TEST_ARCHIVES_CANISTER_IDS
            .iter()
            .map(|id| id.get())
            .collect(),
        index: Some(TEST_INDEX_CANISTER_ID.get()),
        extensions: None,
    })
    .unwrap())
}

fn root_take_ok(local_id: u64) -> RootTakeOk {
    RootTakeOk {
        id: snapshot_id(*DAPP_CANISTER_ID, local_id),
        taken_at_timestamp: 1_700_000_000_000_000_000,
        total_size: 42_000,
    }
}

fn take_canister_snapshot_reply_ok(local_id: u64) -> CanisterCallResult {
    Ok(Encode!(&TakeCanisterSnapshotResponse::Ok(root_take_ok(local_id))).unwrap())
}

fn expected_success_value(local_id: u64) -> Option<SuccessfulProposalExecutionValue> {
    let RootTakeOk {
        id,
        taken_at_timestamp,
        total_size,
    } = root_take_ok(local_id);

    Some(SuccessfulProposalExecutionValue {
        proposal_type: Some(
            successful_proposal_execution_value::ProposalType::TakeCanisterSnapshot(
                TakeCanisterSnapshotOk {
                    snapshot_id: id,
                    taken_at_timestamp,
                    total_size,
                },
            ),
        ),
    })
}

fn ready_to_execute(action: Action) -> ProposalData {
    ProposalData {
        action: u64::from(&action),
        id: Some(ProposalId { id: PROPOSAL_ID }),
        ballots: btreemap! {
            "neuron 1".to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 9001,
                cast_timestamp_seconds: 1,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        proposal: Some(Proposal {
            title: "A proposal about snapshots".to_string(),
            action: Some(action),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn new_governance(
    proposals: BTreeMap<u64, ProposalData>,
    env: impl Environment + 'static,
) -> Governance {
    Governance::new(
        GovernanceProto {
            proposals,
            root_canister_id: Some(TEST_ROOT_CANISTER_ID.get()),
            ledger_canister_id: Some(TEST_LEDGER_CANISTER_ID.get()),
            swap_canister_id: Some(TEST_SWAP_CANISTER_ID.get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    )
}

fn upgrade_action(take_canister_snapshot: Option<TakeSnapshotBeforeUpgrade>) -> Action {
    Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        new_canister_wasm: NEW_WASM.clone(),
        canister_upgrade_arg: None,
        mode: Some(CanisterInstallModeProto::Upgrade.into()),
        chunked_canister_wasm: None,
        canister_upgrade_options: None,
        take_canister_snapshot,
    })
}

fn expected_change_canister_arg() -> Vec<u8> {
    let mode = CanisterInstallModeV2::Upgrade(None);
    let request = ChangeCanisterRequest::new(
        true, // stop_before_installing
        mode,
        *DAPP_CANISTER_ID,
    )
    .with_arg(Encode!().unwrap())
    .with_mode(mode)
    .with_wasm(NEW_WASM.clone());
    Encode!(&request).unwrap()
}

fn expected_take_canister_snapshot_arg(replace_snapshot: Option<Vec<u8>>) -> Vec<u8> {
    Encode!(&TakeCanisterSnapshotRequest {
        canister_id: DAPP_CANISTER_ID.get(),
        replace_snapshot,
    })
    .unwrap()
}

fn method_names(calls: &Arc<Mutex<Vec<Call>>>) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .map(|(canister_id, method_name, _arg)| {
            assert_eq!(*canister_id, *TEST_ROOT_CANISTER_ID, "{method_name}");
            method_name.clone()
        })
        .collect()
}

fn arg_of(calls: &Arc<Mutex<Vec<Call>>>, method_name: &str) -> Vec<u8> {
    let calls = calls.lock().unwrap();
    let matches = calls
        .iter()
        .filter(|(_canister_id, name, _arg)| name == method_name)
        .map(|(_canister_id, _name, arg)| arg.clone())
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{method_name} calls: {matches:?}");
    matches[0].clone()
}

#[track_caller]
fn assert_failed_with(proposal_data: &ProposalData, error_type: ErrorType, substrings: &[&str]) {
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Failed,
        "{proposal_data:#?}"
    );
    let failure_reason = proposal_data.failure_reason.as_ref().unwrap();
    assert_eq!(
        failure_reason.error_type, error_type as i32,
        "{failure_reason:#?}"
    );
    for substring in substrings {
        assert!(
            failure_reason.error_message.contains(substring),
            "Expected {substring:?} in: {}",
            failure_reason.error_message
        );
    }
}

// ---------------------------------------------------------------------------
// UpgradeSnsControlledCanister with take_canister_snapshot
// ---------------------------------------------------------------------------

#[test]
fn test_upgrade_with_snapshot_takes_snapshot_then_upgrades() {
    // Step 1: Prepare the world.
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(3)),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.success_value, expected_success_value(3));

    // The snapshot is taken before the upgrade, both via Root.
    assert_eq!(
        method_names(&calls),
        vec![
            "get_sns_canisters_summary",
            "take_canister_snapshot",
            "change_canister",
        ],
    );
    assert_eq!(
        arg_of(&calls, "get_sns_canisters_summary"),
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
    );
    assert_eq!(
        arg_of(&calls, "take_canister_snapshot"),
        expected_take_canister_snapshot_arg(None),
    );
    // The upgrade itself is exactly the same as without a snapshot.
    assert_eq!(
        arg_of(&calls, "change_canister"),
        expected_change_canister_arg()
    );
}

/// The snapshot is recorded before change_canister is called: even if change_canister then
/// fails, the proposal's success_value says which snapshot was taken (so that the DAO knows
/// what to load).
#[test]
fn test_upgrade_with_snapshot_records_snapshot_before_change_canister() {
    // Step 1: Prepare the world.
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(4)),
        (
            "change_canister",
            Err((Some(5), "Root is having a bad day.".to_string())),
        ),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &["Root is having a bad day."],
    );
    assert_eq!(proposal_data.success_value, expected_success_value(4));
    assert_eq!(
        method_names(&calls),
        vec![
            "get_sns_canisters_summary",
            "take_canister_snapshot",
            "change_canister",
        ],
    );
}

#[test]
fn test_upgrade_with_snapshot_does_not_upgrade_when_snapshot_fails() {
    // Step 1: Prepare the world. Root replies to take_canister_snapshot with an error, the
    // way it does when the canister already has the maximum number of snapshots.
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        (
            "take_canister_snapshot",
            Ok(Encode!(&TakeCanisterSnapshotResponse::Err(
                TakeCanisterSnapshotError {
                    code: Some(5),
                    description: "Canister has reached the maximum number of snapshots allowed."
                        .to_string(),
                }
            ))
            .unwrap()),
        ),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &[
            &format!(
                "Canister {} was not upgraded, because taking a snapshot of it beforehand failed",
                *DAPP_CANISTER_ID
            ),
            "(error code Some(5))",
            "Canister has reached the maximum number of snapshots allowed.",
        ],
    );
    assert_eq!(proposal_data.success_value, None);
    // Most importantly, change_canister was NOT called.
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "take_canister_snapshot"],
    );
}

/// An old Root does not have take_canister_snapshot. In that case, the upgrade must not
/// happen (rather than happen without a snapshot).
#[test]
fn test_upgrade_with_snapshot_fails_closed_when_root_lacks_take_canister_snapshot() {
    // Step 1: Prepare the world. There is no scripted reply for take_canister_snapshot, so
    // RecordingEnvironment rejects it like the replica would ("has no update method").
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &[
            "was not upgraded",
            "Root.take_canister_snapshot failed",
            "has no update method 'take_canister_snapshot'",
        ],
    );
    assert_eq!(proposal_data.success_value, None);
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "take_canister_snapshot"],
    );
}

#[test]
fn test_upgrade_with_snapshot_fails_closed_when_root_reply_is_garbage() {
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("take_canister_snapshot", Ok(Encode!().unwrap())),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &[
            "was not upgraded",
            "Could not decode the reply from Root.take_canister_snapshot",
        ],
    );
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "take_canister_snapshot"],
    );
}

#[test]
fn test_upgrade_with_snapshot_passes_replace_snapshot_through() {
    // Step 1: Prepare the world.
    let replace_snapshot = snapshot_id(*DAPP_CANISTER_ID, 1);
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        (
            "take_canister_snapshot",
            take_canister_snapshot_reply_ok(11),
        ),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(replace_snapshot.clone()),
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.success_value, expected_success_value(11));
    assert_eq!(
        arg_of(&calls, "take_canister_snapshot"),
        expected_take_canister_snapshot_arg(Some(replace_snapshot)),
    );
}

/// Validation already prevents this, but execution checks again, right before acting.
#[test]
fn test_upgrade_with_snapshot_refuses_replace_snapshot_of_other_canister() {
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        (
            "take_canister_snapshot",
            take_canister_snapshot_reply_ok(11),
        ),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(snapshot_id(*OTHER_DAPP_CANISTER_ID, 1)),
    }));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::InvalidProposal,
        &["was not upgraded", "not of the target canister"],
    );
    assert_eq!(method_names(&calls), vec!["get_sns_canisters_summary"]);
}

/// Without take_canister_snapshot, the upgrade works exactly as before: no snapshot calls, the
/// same change_canister call, and no success_value.
#[test]
fn test_upgrade_without_snapshot_is_unchanged() {
    // Step 1: Prepare the world. Even though Root could take a snapshot, it must not be asked.
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(3)),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = upgrade_action(None);
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.success_value, None);
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "change_canister"],
    );
    assert_eq!(
        arg_of(&calls, "change_canister"),
        expected_change_canister_arg()
    );
}

/// The snapshot is only taken after the existing checks pass, e.g. not for core canisters.
#[test]
fn test_upgrade_with_snapshot_of_non_dapp_takes_no_snapshot() {
    let (env, calls) = RecordingEnvironment::new(vec![
        (
            "get_sns_canisters_summary",
            get_sns_canisters_summary_reply(),
        ),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(3)),
        ("change_canister", Ok(Encode!().unwrap())),
    ]);
    let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        canister_id: Some(TEST_LEDGER_CANISTER_ID.get()),
        new_canister_wasm: NEW_WASM.clone(),
        canister_upgrade_arg: None,
        mode: Some(CanisterInstallModeProto::Upgrade.into()),
        chunked_canister_wasm: None,
        canister_upgrade_options: None,
        take_canister_snapshot: Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: None,
        }),
    });
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::InvalidCommand,
        &["can only upgrade dapp canisters"],
    );
    assert_eq!(method_names(&calls), vec!["get_sns_canisters_summary"]);
}

// ---------------------------------------------------------------------------
// TakeCanisterSnapshot
// ---------------------------------------------------------------------------

fn take_action(canister_id: CanisterId, replace_snapshot: Option<Vec<u8>>) -> Action {
    Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
        canister_id: Some(canister_id.get()),
        replace_snapshot,
    })
}

#[test]
fn test_take_canister_snapshot_records_snapshot() {
    let replace_snapshot = snapshot_id(*DAPP_CANISTER_ID, 2);
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(8)),
    ]);
    let action = take_action(*DAPP_CANISTER_ID, Some(replace_snapshot.clone()));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.success_value, expected_success_value(8));
    assert_eq!(
        method_names(&calls),
        vec!["list_sns_canisters", "take_canister_snapshot"],
    );
    assert_eq!(
        arg_of(&calls, "list_sns_canisters"),
        Encode!(&ListSnsCanistersRequest {}).unwrap(),
    );
    assert_eq!(
        arg_of(&calls, "take_canister_snapshot"),
        expected_take_canister_snapshot_arg(Some(replace_snapshot)),
    );

    // success_value is also visible to clients.
    let api_proposal_data = ic_sns_governance_api::pb::v1::ProposalData::from(proposal_data);
    assert_eq!(
        api_proposal_data.success_value,
        Some(
            ic_sns_governance_api::pb::v1::SuccessfulProposalExecutionValue::TakeCanisterSnapshot(
                ic_sns_governance_api::pb::v1::TakeCanisterSnapshotOk {
                    snapshot_id: snapshot_id(*DAPP_CANISTER_ID, 8),
                    taken_at_timestamp: 1_700_000_000_000_000_000,
                    total_size: 42_000,
                }
            )
        ),
    );
}

#[test]
fn test_take_canister_snapshot_fails_with_roots_error() {
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        (
            "take_canister_snapshot",
            Ok(Encode!(&TakeCanisterSnapshotResponse::Err(
                TakeCanisterSnapshotError {
                    code: None,
                    description: "Another operation is currently in progress.".to_string(),
                }
            ))
            .unwrap()),
        ),
    ]);
    let action = take_action(*DAPP_CANISTER_ID, None);
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &[
            &format!(
                "Failed to take a snapshot of canister {}",
                *DAPP_CANISTER_ID
            ),
            "Another operation is currently in progress.",
        ],
    );
    assert_eq!(proposal_data.success_value, None);
    assert_eq!(
        method_names(&calls),
        vec!["list_sns_canisters", "take_canister_snapshot"],
    );
}

/// The canister might have been deregistered since the proposal was made.
#[test]
fn test_take_canister_snapshot_rechecks_target_at_execution() {
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(8)),
    ]);
    let action = take_action(canister_test_id(999), None);
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::InvalidCommand,
        &[
            "TakeCanisterSnapshot cannot target canister",
            "not registered",
        ],
    );
    assert_eq!(method_names(&calls), vec!["list_sns_canisters"]);
}

#[test]
fn test_take_canister_snapshot_waits_for_other_upgrades() {
    // Step 1: Prepare the world: another upgrade proposal has been adopted, but has not
    // finished executing yet.
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        ("take_canister_snapshot", take_canister_snapshot_reply_ok(8)),
    ]);
    let other_upgrade_proposal_id = 2;
    let other_upgrade_proposal = ProposalData {
        id: Some(ProposalId {
            id: other_upgrade_proposal_id,
        }),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..ready_to_execute(upgrade_action(None))
    };
    assert_eq!(
        other_upgrade_proposal.status(),
        ProposalDecisionStatus::Adopted
    );
    let action = take_action(*DAPP_CANISTER_ID, None);
    let mut governance = new_governance(
        btreemap! {
            PROPOSAL_ID => ready_to_execute(action),
            other_upgrade_proposal_id => other_upgrade_proposal,
        },
        env,
    );

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    // Step 3: Inspect results.
    assert_failed_with(
        &proposal_data,
        ErrorType::ResourceExhausted,
        &["Another upgrade is currently in progress"],
    );
    assert_eq!(method_names(&calls), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// LoadCanisterSnapshot
// ---------------------------------------------------------------------------

fn load_action(canister_id: CanisterId, snapshot_id: Vec<u8>) -> Action {
    Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(canister_id.get()),
        snapshot_id: Some(snapshot_id),
    })
}

#[test]
fn test_load_canister_snapshot_calls_root() {
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        (
            "load_canister_snapshot",
            Ok(Encode!(&LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {})).unwrap()),
        ),
    ]);
    let action = load_action(*DAPP_CANISTER_ID, snapshot_id(*DAPP_CANISTER_ID, 3));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
    assert_eq!(proposal_data.success_value, None);
    assert_eq!(
        method_names(&calls),
        vec!["list_sns_canisters", "load_canister_snapshot"],
    );
    assert_eq!(
        arg_of(&calls, "load_canister_snapshot"),
        Encode!(&LoadCanisterSnapshotRequest {
            canister_id: DAPP_CANISTER_ID.get(),
            snapshot_id: snapshot_id(*DAPP_CANISTER_ID, 3),
        })
        .unwrap(),
    );
}

#[test]
fn test_load_canister_snapshot_fails_with_roots_error() {
    let (env, _calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        (
            "load_canister_snapshot",
            Ok(Encode!(&LoadCanisterSnapshotResponse::Err(
                LoadCanisterSnapshotError {
                    code: Some(3),
                    description: "Could not find the snapshot ID.".to_string(),
                }
            ))
            .unwrap()),
        ),
    ]);
    let action = load_action(*DAPP_CANISTER_ID, snapshot_id(*DAPP_CANISTER_ID, 3));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &[
            &format!(
                "Failed to load a snapshot into canister {}",
                *DAPP_CANISTER_ID
            ),
            "Could not find the snapshot ID.",
        ],
    );
}

#[test]
fn test_load_canister_snapshot_fails_closed_when_root_lacks_the_method() {
    let (env, calls) =
        RecordingEnvironment::new(vec![("list_sns_canisters", list_sns_canisters_reply())]);
    let action = load_action(*DAPP_CANISTER_ID, snapshot_id(*DAPP_CANISTER_ID, 3));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::External,
        &["Root.load_canister_snapshot failed", "has no update method"],
    );
    assert_eq!(
        method_names(&calls),
        vec!["list_sns_canisters", "load_canister_snapshot"],
    );
}

/// Validation already prevents this, but execution checks again, right before acting.
#[test]
fn test_load_canister_snapshot_refuses_snapshot_of_other_canister() {
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        (
            "load_canister_snapshot",
            Ok(Encode!(&LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {})).unwrap()),
        ),
    ]);
    let action = load_action(*DAPP_CANISTER_ID, snapshot_id(*OTHER_DAPP_CANISTER_ID, 3));
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::InvalidProposal,
        &["not of the target canister"],
    );
    assert_eq!(method_names(&calls), vec!["list_sns_canisters"]);
}

#[test]
fn test_load_canister_snapshot_refuses_non_dapp_target() {
    let (env, calls) = RecordingEnvironment::new(vec![
        ("list_sns_canisters", list_sns_canisters_reply()),
        (
            "load_canister_snapshot",
            Ok(Encode!(&LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {})).unwrap()),
        ),
    ]);
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let action = load_action(
        governance_canister_id,
        snapshot_id(governance_canister_id, 0),
    );
    let mut governance = new_governance(btreemap! { PROPOSAL_ID => ready_to_execute(action) }, env);

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);

    assert_failed_with(
        &proposal_data,
        ErrorType::InvalidCommand,
        &["is the SNS Governance canister"],
    );
    assert_eq!(method_names(&calls), vec!["list_sns_canisters"]);
}
