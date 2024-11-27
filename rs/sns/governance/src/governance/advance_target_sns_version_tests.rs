use super::test_helpers::{
    basic_governance_proto, canister_status_for_test,
    canister_status_from_management_canister_for_test, DoNothingLedger, TEST_ARCHIVES_CANISTER_IDS,
    TEST_GOVERNANCE_CANISTER_ID, TEST_INDEX_CANISTER_ID, TEST_LEDGER_CANISTER_ID,
    TEST_ROOT_CANISTER_ID, TEST_SWAP_CANISTER_ID,
};
use super::*;
use crate::sns_upgrade::CanisterSummary;
use crate::sns_upgrade::GetWasmRequest;
use crate::sns_upgrade::GetWasmResponse;
use crate::sns_upgrade::SnsWasm;
use crate::sns_upgrade::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use crate::{
    pb::v1::{ProposalData, Tally, UpgradeSnsToNextVersion},
    sns_upgrade::{ListUpgradeStep, ListUpgradeStepsRequest, ListUpgradeStepsResponse, SnsVersion},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusType,
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
            deployed_version: Some(Version::from(current_version.clone())),
            target_version: Some(Version::from(target_version.clone())),
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
async fn test_automatic_upgrade_when_behind_target_version_for_root() {
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

    let intermediate_version = {
        let mut version = current_version.clone();
        version.root_wasm_hash = vec![4, 4, 4];
        version
    };

    let target_version = {
        let mut version = intermediate_version.clone();
        version.root_wasm_hash = vec![9, 9, 9];
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
                    version: Some(intermediate_version.clone())
                },
                ListUpgradeStep {
                    version: Some(target_version.clone())
                },
            ]
        })
        .unwrap()),
    );

    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(Version::from(current_version.clone())),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Update the cached upgrade steps
    assert_eq!(governance.proto.cached_upgrade_steps, None);
    governance.run_periodic_tasks().await;
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
        3
    );

    // Step 3: Set target version to latest version
    governance.proto.target_version = Some(Version::from(target_version.clone()));

    // Step 4: Run periodic tasks and observe upgrades

    {
        // The first periodic task initiates the upgrade
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_calls_for_initiate_upgrade(
            &mut env,
            vec![4, 4, 4],
            SnsCanisterType::Root,
            current_version.clone(),
        );
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }
    {
        // The second periodic task marks the upgrade as completed, and starts the next one
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_get_sns_canisters_summary_call(&mut env, intermediate_version.clone());
        add_environment_mock_calls_for_initiate_upgrade(
            &mut env,
            vec![9, 9, 9],
            SnsCanisterType::Root,
            intermediate_version.clone(),
        );
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }

    // Should now be at intermediate version
    assert_eq!(
        governance.proto.deployed_version,
        Some(Version::from(intermediate_version.clone()))
    );

    {
        // The third periodic task marks the upgrade as completed
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_get_sns_canisters_summary_call(&mut env, target_version.clone());
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }

    // Should now be at target version
    assert_eq!(
        governance.proto.deployed_version,
        Some(Version::from(target_version))
    );
}

#[tokio::test]
async fn test_automatic_upgrade_when_behind_target_version_for_governance() {
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

    let intermediate_version = {
        let mut version = current_version.clone();
        version.governance_wasm_hash = vec![4, 4, 4];
        version
    };

    let target_version = {
        let mut version = intermediate_version.clone();
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
                    version: Some(intermediate_version.clone())
                },
                ListUpgradeStep {
                    version: Some(target_version.clone())
                },
            ]
        })
        .unwrap()),
    );

    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Update the cached upgrade steps
    assert_eq!(governance.proto.cached_upgrade_steps, None);
    governance.run_periodic_tasks().await;
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
        3
    );

    // Step 3: Set target version to latest version
    governance.proto.target_version = Some(Version::from(target_version.clone()));

    // Step 4: Run periodic tasks and observe upgrades
    {
        // The first periodic task initiates the upgrade
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_calls_for_initiate_upgrade(
            &mut env,
            vec![4, 4, 4],
            SnsCanisterType::Governance,
            current_version.clone(),
        );
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }
    {
        // The second periodic task marks the upgrade as completed, and starts the next one
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_get_sns_canisters_summary_call(&mut env, intermediate_version.clone());
        add_environment_mock_calls_for_initiate_upgrade(
            &mut env,
            vec![9, 9, 9],
            SnsCanisterType::Governance,
            intermediate_version.clone(),
        );
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }

    // Should now be at intermediate version
    assert_eq!(
        governance.proto.deployed_version,
        Some(Version::from(intermediate_version))
    );

    {
        // The third periodic task marks the upgrade as completed
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        add_environment_mock_get_sns_canisters_summary_call(&mut env, target_version.clone());
        governance.env = Box::new(env);
        governance.run_periodic_tasks().await;
    }

    // Should now be at target version
    assert_eq!(
        governance.proto.deployed_version,
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

#[test]
fn test_perform_advance_target_version() {
    let deployed_version = Version {
        root_wasm_hash: vec![1, 0, 1],
        governance_wasm_hash: vec![1, 0, 2],
        swap_wasm_hash: vec![1, 0, 3],
        index_wasm_hash: vec![1, 0, 4],
        ledger_wasm_hash: vec![1, 0, 5],
        archive_wasm_hash: vec![1, 0, 6],
    };
    let next_version = Version {
        root_wasm_hash: vec![2, 0, 1],
        ..deployed_version.clone()
    };
    let next_next_version = Version {
        index_wasm_hash: vec![2, 0, 4],
        ..deployed_version.clone()
    };
    // Smoke check: Make sure all versions are different
    let versions = vec![
        deployed_version.clone(),
        next_version.clone(),
        next_next_version.clone(),
    ];
    assert!(
        versions.iter().collect::<HashSet::<_>>().len() == versions.len(),
        "Duplicates!"
    );

    let make_governance = |versions: Vec<Version>, current_target| {
        let mut governance_proto = basic_governance_proto();
        governance_proto.deployed_version = versions.first().cloned();
        governance_proto.target_version = current_target;
        governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
            upgrade_steps: Some(Versions { versions }),
            ..Default::default()
        });
        let env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));
        let mut governance = crate::governance::Governance::new(
            governance_proto.try_into().unwrap(),
            Box::new(env),
            Box::new(DoNothingLedger {}),
            Box::new(DoNothingLedger {}),
            Box::new(FakeCmc::new()),
        );
        // TODO[NNS1-3365]: Enable the AdvanceSnsTargetVersionFeature.
        governance.test_features_enabled = true;
        governance
    };

    for (label, current_target, new_target, expected_result) in [
        (
            "Scenario A. Cannot advance SNS target to deployed version.",
            None,
            deployed_version,
            Err(
                "InvalidProposal: new_target_version must differ from the current version."
                    .to_string(),
            ),
        ),
        (
            "Scenario B. Can advance SNS target to next version.",
            None,
            next_version.clone(),
            Ok(()),
        ),
        (
            "Scenario C. Can advance SNS target to next next version (current target is not set).",
            None,
            next_next_version.clone(),
            Ok(()),
        ),
        (
            "Scenario D. Can advance SNS target to next next version (current target is set).",
            Some(next_version.clone()),
            next_next_version.clone(),
            Ok(()),
        ),
        (
            "Scenario E. Cannot advance SNS target to next version since current target is ahead.",
            Some(next_next_version),
            next_version.clone(),
            Err("InvalidProposal: SNS target already set to SnsVersion { \
                    root:010001, \
                    governance:010002, \
                    swap:010003, \
                    index:020004, \
                    ledger:010005, \
                    archive:010006 \
                }."
            .to_string()),
        ),
    ] {
        let mut governance = make_governance(versions.clone(), current_target);
        let result = governance
            .perform_advance_target_version(new_target)
            .map_err(|err| err.to_string());
        assert_eq!(result, expected_result, "{}", label);
    }
}

#[test]
fn test_upgrade_periodic_task_lock_times_out() {
    let env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));
    let mut gov = Governance::new(
        basic_governance_proto().try_into().unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert!(gov.acquire_upgrade_periodic_task_lock());
    assert!(!gov.acquire_upgrade_periodic_task_lock());
    assert!(gov.upgrade_periodic_task_lock.is_some());

    // advance time
    gov.env.set_time_warp(TimeWarp {
        delta_s: UPGRADE_PERIODIC_TASK_LOCK_TIMEOUT_SECONDS as i64 + 1,
    });
    assert!(gov.acquire_upgrade_periodic_task_lock()); // The lock should successfully be acquired, since the previous one timed out
    assert!(!gov.acquire_upgrade_periodic_task_lock());
}

#[test]
fn test_upgrade_periodic_task_lock_doesnt_get_stuck_during_overflow() {
    let env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));
    let mut gov = Governance::new(
        basic_governance_proto().try_into().unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    gov.upgrade_periodic_task_lock = Some(u64::MAX);
    assert!(gov.acquire_upgrade_periodic_task_lock());
}

fn add_environment_mock_calls_for_initiate_upgrade(
    env: &mut NativeEnvironment,
    expected_wasm_hash_requested: Vec<u8>,
    expected_canister_to_be_upgraded: SnsCanisterType,
    starting_version: SnsVersion,
) {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
    let index_canister_id = *TEST_INDEX_CANISTER_ID;

    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "get_wasm",
        Encode!(&GetWasmRequest {
            hash: expected_wasm_hash_requested
        })
        .unwrap(),
        Ok(Encode!(&GetWasmResponse {
            wasm: Some(SnsWasm {
                wasm: vec![9, 8, 7, 6, 5, 4, 3, 2],
                canister_type: expected_canister_to_be_upgraded.into(), // Governance
                proposal_id: None,
            })
        })
        .unwrap()),
    );

    let canisters_to_be_upgraded = match expected_canister_to_be_upgraded {
        SnsCanisterType::Unspecified => {
            panic!("Cannot be unspecified")
        }
        SnsCanisterType::Root => vec![root_canister_id],
        SnsCanisterType::Governance => vec![governance_canister_id],
        SnsCanisterType::Ledger => vec![ledger_canister_id],
        SnsCanisterType::Archive => ledger_archive_ids,
        SnsCanisterType::Swap => {
            panic!("Swap upgrade not supported via SNS (ownership)")
        }
        SnsCanisterType::Index => vec![index_canister_id],
    };

    assert!(!canisters_to_be_upgraded.is_empty());

    if expected_canister_to_be_upgraded != SnsCanisterType::Root {
        add_environment_mock_get_sns_canisters_summary_call(&mut *env, starting_version);
        for canister_id in canisters_to_be_upgraded {
            env.require_call_canister_invocation(
                root_canister_id,
                "change_canister",
                Encode!(&ChangeCanisterRequest::new(
                    true,
                    CanisterInstallMode::Upgrade,
                    canister_id
                )
                .with_wasm(vec![9, 8, 7, 6, 5, 4, 3, 2])
                .with_arg(Encode!().unwrap()))
                .unwrap(),
                // We don't actually look at the response from this call anywhere
                Some(Ok(Encode!().unwrap())),
            );
        }
    } else {
        for canister_id in canisters_to_be_upgraded {
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "stop_canister",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(vec![]),
            );
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "canister_status",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(Encode!(&canister_status_from_management_canister_for_test(
                    vec![],
                    CanisterStatusType::Stopped,
                ))
                .unwrap()),
            );
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "start_canister",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(vec![]),
            );
            // For root canister, this is the required call that ensures our wiring was correct.
            env.require_call_canister_invocation(
                CanisterId::ic_00(),
                "install_code",
                Encode!(&ic_management_canister_types::InstallCodeArgs {
                    mode: ic_management_canister_types::CanisterInstallMode::Upgrade,
                    canister_id: canister_id.get(),
                    wasm_module: vec![9, 8, 7, 6, 5, 4, 3, 2],
                    arg: Encode!().unwrap(),
                    compute_allocation: None,
                    memory_allocation: None,
                    sender_canister_version: None,
                })
                .unwrap(),
                Some(Ok(vec![])),
            );
        }
    }
}

fn add_environment_mock_get_sns_canisters_summary_call(
    env: &mut NativeEnvironment,
    version: SnsVersion,
) {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
    let index_canister_id = *TEST_INDEX_CANISTER_ID;
    let swap_canister_id = *TEST_SWAP_CANISTER_ID;

    env.set_call_canister_response(
        *TEST_ROOT_CANISTER_ID,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&GetSnsCanistersSummaryResponse {
            governance: Some(CanisterSummary {
                canister_id: Some(PrincipalId::from(governance_canister_id)),
                status: Some(canister_status_for_test(
                    version.governance_wasm_hash,
                    CanisterStatusType::Running,
                ))
            }),
            swap: Some(CanisterSummary {
                canister_id: Some(PrincipalId::from(swap_canister_id)),
                status: Some(canister_status_for_test(
                    version.swap_wasm_hash,
                    CanisterStatusType::Running,
                )),
            }),
            root: Some(CanisterSummary {
                canister_id: Some(PrincipalId::from(root_canister_id)),
                status: Some(canister_status_for_test(
                    version.root_wasm_hash,
                    CanisterStatusType::Running,
                )),
            }),
            ledger: Some(CanisterSummary {
                canister_id: Some(PrincipalId::from(ledger_canister_id)),
                status: Some(canister_status_for_test(
                    version.ledger_wasm_hash,
                    CanisterStatusType::Running,
                )),
            }),
            index: Some(CanisterSummary {
                canister_id: Some(PrincipalId::from(index_canister_id)),
                status: Some(canister_status_for_test(
                    version.index_wasm_hash,
                    CanisterStatusType::Running,
                )),
            }),
            archives: ledger_archive_ids
                .iter()
                .map(|id| CanisterSummary {
                    canister_id: Some(PrincipalId::from(*id)),
                    status: Some(canister_status_for_test(
                        version.archive_wasm_hash.clone(),
                        CanisterStatusType::Running,
                    )),
                })
                .collect(),
            dapps: vec![],
        })
        .unwrap()),
    );
}
