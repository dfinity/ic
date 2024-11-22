use super::assorted_governance_tests::{
    basic_governance_proto, DoNothingLedger, TEST_GOVERNANCE_CANISTER_ID, TEST_ROOT_CANISTER_ID,
};
use super::*;
use crate::{
    pb::v1::{ProposalData, Tally, UpgradeSnsToNextVersion},
    sns_upgrade::{ListUpgradeStep, ListUpgradeStepsRequest, ListUpgradeStepsResponse, SnsVersion},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_common::cmc::FakeCmc;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use maplit::btreemap;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_initiate_upgrade_blocked_by_upgrade_proposal() {
    // Step 1: Prepare the world.
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

    let mut env = NativeEnvironment::new(Some(governance_canister_id));

    let current_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let target_version = {
        let mut version = current_version.clone();
        version.governance_wasm_hash = vec![9, 9, 9];
        version
    };

    // Set up environment to return upgrade steps that would allow an upgrade
    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "list_upgrade_steps",
        Encode!(&ListUpgradeStepsRequest {
            starting_at: Some(current_version.clone()),
            sns_governance_canister_id: Some(governance_canister_id.into()),
            limit: 0,
        })
        .unwrap(),
        Ok(Encode!(&ListUpgradeStepsResponse {
            steps: vec![
                ListUpgradeStep {
                    version: Some(current_version.clone())
                },
                ListUpgradeStep {
                    version: Some(target_version.clone())
                },
            ]
        })
        .unwrap()),
    );

    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let proposal = ProposalData {
        action: (&action).into(),
        id: Some(proposal_id.into()),
        decided_timestamp_seconds: 1,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            target_version: Some(target_version.clone().into()),
            // Add an upgrade proposal that is adopted but not executed
            proposals: btreemap! {
                proposal_id => proposal
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    assert_eq!(governance.proto.cached_upgrade_steps, None);
    governance.temporarily_lock_refresh_cached_upgrade_steps();
    governance.refresh_cached_upgrade_steps().await;
    assert_eq!(
        governance
            .proto
            .cached_upgrade_steps
            .clone()
            .unwrap()
            .upgrade_steps
            .unwrap()
            .versions
            .len(),
        2
    );

    governance
        .initiate_upgrade_if_sns_behind_target_version()
        .await;

    // Step 3: Inspect results.
    // The pending_version should remain None since we had an upgrade proposal in progress
    assert_eq!(governance.proto.pending_version, None);

    // The deployed version should remain unchanged
    assert_eq!(
        governance.proto.deployed_version,
        Some(Version::from(current_version))
    );

    // The target version should remain unchanged
    assert_eq!(
        governance.proto.target_version,
        Some(Version::from(target_version))
    );
}

#[tokio::test]
async fn test_initiate_upgrade_blocked_by_pending_upgrade() {
    // Step 1: Prepare the world.
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

    let mut env = NativeEnvironment::new(Some(governance_canister_id));

    let current_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let target_version = {
        let mut version = current_version.clone();
        version.governance_wasm_hash = vec![9, 9, 9];
        version
    };

    // Set up environment to return upgrade steps that would allow an upgrade
    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "list_upgrade_steps",
        Encode!(&ListUpgradeStepsRequest {
            starting_at: Some(current_version.clone()),
            sns_governance_canister_id: Some(governance_canister_id.into()),
            limit: 0,
        })
        .unwrap(),
        Ok(Encode!(&ListUpgradeStepsResponse {
            steps: vec![
                ListUpgradeStep {
                    version: Some(current_version.clone())
                },
                ListUpgradeStep {
                    version: Some(target_version.clone())
                },
            ]
        })
        .unwrap()),
    );

    let pending_version = Version {
        root_wasm_hash: vec![8, 8, 8],
        governance_wasm_hash: vec![8, 8, 8],
        ledger_wasm_hash: vec![8, 8, 8],
        swap_wasm_hash: vec![8, 8, 8],
        archive_wasm_hash: vec![8, 8, 8],
        index_wasm_hash: vec![8, 8, 8],
    };
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(Version::from(current_version.clone())),
            target_version: Some(Version::from(target_version.clone())),
            // There's already an upgrade pending
            pending_version: Some(PendingVersion {
                target_version: Some(pending_version.clone()),
                mark_failed_at_seconds: 123,
                checking_upgrade_lock: 0,
                proposal_id: Some(42),
            }),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    assert_eq!(governance.proto.cached_upgrade_steps, None);
    governance.temporarily_lock_refresh_cached_upgrade_steps();
    governance.refresh_cached_upgrade_steps().await;
    assert_eq!(
        governance
            .proto
            .cached_upgrade_steps
            .clone()
            .unwrap()
            .upgrade_steps
            .unwrap()
            .versions
            .len(),
        2
    );

    governance
        .initiate_upgrade_if_sns_behind_target_version()
        .await;

    // Step 3: Inspect results.
    // The pending_version should remain unchanged since we had an upgrade in progress
    assert_eq!(
        governance.proto.pending_version,
        Some(PendingVersion {
            target_version: Some(pending_version),
            mark_failed_at_seconds: 123,
            checking_upgrade_lock: 0,
            proposal_id: Some(42),
        })
    );

    // The deployed version should remain unchanged
    assert_eq!(
        governance.proto.deployed_version,
        Some(Version::from(current_version))
    );

    // The target version should remain unchanged
    assert_eq!(
        governance.proto.target_version,
        Some(Version::from(target_version))
    );
}
