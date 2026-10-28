//! Tests for executing UpgradeSnsControlledCanister proposals with take_canister_snapshot.

use super::*;
use crate::{
    governance::test_helpers::{
        DoNothingLedger, TEST_DAPP_CANISTER_IDS, TEST_GOVERNANCE_CANISTER_ID,
        TEST_ROOT_CANISTER_ID, basic_governance_proto, execute_proposal,
    },
    pb::v1::upgrade_sns_controlled_canister::TakeSnapshotBeforeUpgrade,
    sns_upgrade::{CanisterSummary, GetSnsCanistersSummaryResponse},
    types::test_helpers::NativeEnvironment,
};
use async_trait::async_trait;
use ic_base_types::SnapshotId;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_root::take_canister_snapshot::{
    TakeCanisterSnapshotError, TakeCanisterSnapshotOk as RootTakeCanisterSnapshotOk,
};
use std::sync::{Arc, Mutex};

const PROPOSAL_ID: u64 = 1;

type CanisterCallResult = Result<Vec<u8>, (Option<i32>, String)>;
type Calls = Vec<(String, Vec<u8>)>;

/// Replies to calls to Root based only on the name of the method, and records which methods were
/// called (in order), and with what arguments. Calls to methods without a scripted reply are
/// rejected the way the replica rejects calls to methods that do not exist.
struct RecordingEnvironment {
    replies: BTreeMap<&'static str, CanisterCallResult>,
    calls: Arc<Mutex<Calls>>,
}

#[async_trait]
impl Environment for RecordingEnvironment {
    fn now(&self) -> u64 {
        NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS
    }

    fn insecure_random_u64(&mut self) -> u64 {
        4
    }

    async fn call_canister(
        &self,
        _canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> CanisterCallResult {
        self.calls
            .lock()
            .unwrap()
            .push((method_name.to_string(), arg));
        self.replies.get(method_name).cloned().unwrap_or_else(|| {
            Err((
                Some(3),
                format!("Canister has no update method '{method_name}'."),
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

fn snapshot_id(local_id: u64) -> Vec<u8> {
    SnapshotId::from((TEST_DAPP_CANISTER_IDS[0], local_id)).to_vec()
}

/// Executes an UpgradeSnsControlledCanister proposal (for a registered dapp canister) with the
/// given take_canister_snapshot. Root replies to take_canister_snapshot with
/// `take_canister_snapshot_reply` (or, if None, it does not have such a method).
///
/// Returns the proposal, and the (names and arguments of) the methods of Root that were called.
fn execute_upgrade(
    take_canister_snapshot: Option<TakeSnapshotBeforeUpgrade>,
    take_canister_snapshot_reply: Option<TakeCanisterSnapshotResponse>,
) -> (ProposalData, Calls) {
    let dapp_summary = CanisterSummary {
        canister_id: Some(TEST_DAPP_CANISTER_IDS[0].get()),
        status: None,
    };
    let mut replies = btreemap! {
        "get_sns_canisters_summary" => Ok(Encode!(&GetSnsCanistersSummaryResponse {
            root: None,
            governance: None,
            ledger: None,
            swap: None,
            dapps: vec![dapp_summary],
            archives: vec![],
            index: None,
        })
        .unwrap()),
        "change_canister" => Ok(Encode!().unwrap()),
    };
    if let Some(reply) = take_canister_snapshot_reply {
        replies.insert("take_canister_snapshot", Ok(Encode!(&reply).unwrap()));
    }
    let calls = Arc::new(Mutex::new(vec![]));
    let env = RecordingEnvironment {
        replies,
        calls: Arc::clone(&calls),
    };

    let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        canister_id: Some(TEST_DAPP_CANISTER_IDS[0].get()),
        new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_upgrade_arg: None,
        mode: None,
        chunked_canister_wasm: None,
        canister_upgrade_options: None,
        take_canister_snapshot,
    });
    let proposal_data = ProposalData {
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
            title: "Upgrade the dapp".to_string(),
            action: Some(action),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! { PROPOSAL_ID => proposal_data },
            root_canister_id: Some(TEST_ROOT_CANISTER_ID.get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let proposal_data = execute_proposal(&mut governance, PROPOSAL_ID);
    let calls = calls.lock().unwrap().clone();
    (proposal_data, calls)
}

fn method_names(calls: &[(String, Vec<u8>)]) -> Vec<&str> {
    calls.iter().map(|(name, _arg)| name.as_str()).collect()
}

#[test]
fn test_upgrade_without_take_canister_snapshot_is_unchanged() {
    let (proposal_data, calls) = execute_upgrade(None, None);

    assert_eq!(proposal_data.status(), ProposalDecisionStatus::Executed);
    assert_eq!(proposal_data.success_value, None);
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "change_canister"]
    );
}

#[test]
fn test_upgrade_takes_snapshot_then_upgrades() {
    let replace_snapshot = snapshot_id(1);
    let reply = TakeCanisterSnapshotResponse::Ok(RootTakeCanisterSnapshotOk {
        id: snapshot_id(2),
        taken_at_timestamp: 123,
        total_size: 456,
    });

    let (proposal_data, calls) = execute_upgrade(
        Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: Some(replace_snapshot.clone()),
        }),
        Some(reply),
    );

    assert_eq!(proposal_data.status(), ProposalDecisionStatus::Executed);
    assert_eq!(
        method_names(&calls),
        vec![
            "get_sns_canisters_summary",
            "take_canister_snapshot",
            "change_canister"
        ]
    );
    // replace_snapshot is passed through to Root.
    assert_eq!(
        calls[1].1,
        Encode!(&TakeCanisterSnapshotRequest {
            canister_id: TEST_DAPP_CANISTER_IDS[0].get(),
            replace_snapshot: Some(replace_snapshot),
        })
        .unwrap()
    );
    // The new snapshot is recorded.
    assert_eq!(
        proposal_data.success_value,
        Some(SuccessfulProposalExecutionValue {
            proposal_type: Some(
                successful_proposal_execution_value::ProposalType::TakeCanisterSnapshot(
                    TakeCanisterSnapshotOk {
                        snapshot_id: snapshot_id(2),
                        taken_at_timestamp: 123,
                        total_size: 456,
                    }
                )
            ),
        })
    );
}

#[test]
fn test_upgrade_does_not_happen_when_taking_snapshot_fails() {
    let reply = TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
        code: Some(5),
        description: "Canister has reached the maximum number of snapshots.".to_string(),
    });

    let (proposal_data, calls) = execute_upgrade(
        Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: None,
        }),
        Some(reply),
    );

    assert_eq!(proposal_data.status(), ProposalDecisionStatus::Failed);
    let error_message = proposal_data.failure_reason.unwrap().error_message;
    assert!(
        error_message.contains("was not upgraded"),
        "{error_message}"
    );
    assert!(
        error_message.contains("maximum number of snapshots"),
        "{error_message}"
    );
    assert_eq!(proposal_data.success_value, None);
    // Most importantly, change_canister was NOT called.
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "take_canister_snapshot"]
    );
}

/// E.g. a new Governance with an old Root.
#[test]
fn test_upgrade_does_not_happen_when_root_cannot_take_snapshots() {
    let (proposal_data, calls) = execute_upgrade(
        Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: None,
        }),
        None,
    );

    assert_eq!(proposal_data.status(), ProposalDecisionStatus::Failed);
    let error_message = proposal_data.failure_reason.unwrap().error_message;
    assert!(
        error_message.contains("has no update method 'take_canister_snapshot'"),
        "{error_message}"
    );
    assert_eq!(
        method_names(&calls),
        vec!["get_sns_canisters_summary", "take_canister_snapshot"]
    );
}
