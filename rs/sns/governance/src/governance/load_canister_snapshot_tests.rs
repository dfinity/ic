use super::*;
use crate::{
    governance::test_helpers::{
        DoNothingLedger, TEST_DAPP_CANISTER_IDS, TEST_ROOT_CANISTER_ID, basic_governance_proto,
        execute_proposal,
    },
    pb::sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
    types::test_helpers::NativeEnvironment,
};
use ic_base_types::SnapshotId;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_root::load_canister_snapshot::{
    LoadCanisterSnapshotError, LoadCanisterSnapshotOk,
};

const PROPOSAL_ID: u64 = 1;

fn load_canister_snapshot_request() -> Vec<u8> {
    let dapp_canister_id = TEST_DAPP_CANISTER_IDS[0];
    Encode!(&LoadCanisterSnapshotRequest {
        canister_id: dapp_canister_id.get(),
        snapshot_id: SnapshotId::from((dapp_canister_id, 3)).to_vec(),
    })
    .unwrap()
}

/// Executes a LoadCanisterSnapshot proposal, where Root replies to load_canister_snapshot with
/// `load_canister_snapshot_reply`.
fn execute_load_canister_snapshot(
    load_canister_snapshot_reply: Result<Vec<u8>, (Option<i32>, String)>,
) -> ProposalData {
    let dapp_canister_id = TEST_DAPP_CANISTER_IDS[0];

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        *TEST_ROOT_CANISTER_ID,
        "list_sns_canisters",
        Encode!(&ListSnsCanistersRequest {}).unwrap(),
        Ok(Encode!(&ListSnsCanistersResponse {
            dapps: vec![dapp_canister_id.get()],
            ..Default::default()
        })
        .unwrap()),
    );
    env.require_call_canister_invocation(
        *TEST_ROOT_CANISTER_ID,
        "load_canister_snapshot",
        load_canister_snapshot_request(),
        Some(load_canister_snapshot_reply),
    );

    let action = Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(dapp_canister_id.get()),
        snapshot_id: Some(SnapshotId::from((dapp_canister_id, 3)).to_vec()),
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
            title: "Roll back the dapp".to_string(),
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

    execute_proposal(&mut governance, PROPOSAL_ID)
}

#[test]
fn test_load_canister_snapshot_calls_root() {
    let reply = Encode!(&LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {})).unwrap();

    let proposal_data = execute_load_canister_snapshot(Ok(reply));

    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::Executed,
        "{proposal_data:#?}"
    );
}

#[test]
fn test_load_canister_snapshot_fails_when_root_fails() {
    let reply = Encode!(&LoadCanisterSnapshotResponse::Err(
        LoadCanisterSnapshotError {
            code: Some(3),
            description: "Could not find the snapshot ID.".to_string(),
        }
    ))
    .unwrap();

    let proposal_data = execute_load_canister_snapshot(Ok(reply));

    assert_eq!(proposal_data.status(), ProposalDecisionStatus::Failed);
    let error_message = proposal_data.failure_reason.unwrap().error_message;
    assert!(
        error_message.contains("Could not find the snapshot ID."),
        "{error_message}"
    );
}
