use super::*;
use crate::governance::{Governance, ValidGovernanceProto};
use crate::pb::v1::Governance as GovernancePb;
use crate::pb::v1::governance::Versions;
use crate::pb::v1::governance::{CachedUpgradeSteps as CachedUpgradeStepsPb, Mode as ModePb};
use crate::types::test_helpers::NativeEnvironment;
use futures::FutureExt;
use ic_nervous_system_canisters::{cmc::MockCMC, ledger::MockICRC1Ledger};
use ic_test_utilities_types::ids::canister_test_id;
use pretty_assertions::assert_eq;

fn sns_version_for_tests() -> Version {
    Version {
        root_wasm_hash: vec![
            73, 94, 49, 55, 11, 20, 250, 97, 199, 107, 209, 72, 60, 159, 155, 166, 103, 51, 121,
            62, 226, 150, 62, 142, 68, 162, 49, 67, 106, 96, 188, 198,
        ],
        governance_wasm_hash: vec![
            63, 235, 143, 247, 180, 127, 83, 218, 131, 35, 94, 76, 104, 103, 107, 182, 219, 84,
            223, 30, 98, 223, 54, 129, 222, 148, 37, 173, 92, 244, 59, 229,
        ],
        swap_wasm_hash: vec![
            59, 180, 144, 209, 151, 184, 207, 46, 125, 153, 72, 188, 181, 209, 252, 70, 116, 122,
            131, 82, 148, 179, 255, 228, 123, 136, 45, 191, 165, 132, 85, 95,
        ],
        index_wasm_hash: vec![
            8, 174, 80, 66, 200, 228, 19, 113, 109, 4, 160, 141, 184, 134, 184, 198, 176, 27, 182,
            16, 184, 25, 124, 219, 224, 82, 197, 149, 56, 185, 36, 240,
        ],
        ledger_wasm_hash: vec![
            232, 148, 47, 86, 249, 67, 155, 137, 177, 59, 216, 3, 127, 53, 113, 38, 226, 79, 30,
            121, 50, 207, 3, 1, 130, 67, 52, 117, 5, 149, 159, 212,
        ],
        archive_wasm_hash: vec![
            92, 89, 92, 42, 220, 127, 109, 153, 113, 41, 143, 238, 47, 166, 102, 146, 151, 17, 231,
            51, 65, 25, 42, 183, 8, 4, 199, 131, 160, 238, 224, 63,
        ],
    }
}

fn standard_governance_proto_for_tests(deployed_version: Option<Version>) -> GovernancePb {
    GovernancePb {
        root_canister_id: Some(PrincipalId::from(canister_test_id(500))),
        ledger_canister_id: Some(PrincipalId::from(canister_test_id(502))),
        swap_canister_id: Some(PrincipalId::from(canister_test_id(503))),

        sns_metadata: Some(SnsMetadata {
            logo: None,
            url: Some("https://example.com".to_string()),
            name: Some("Example".to_string()),
            description: Some("Very descriptive description".to_string()),
        }),
        sns_initialization_parameters: "".to_string(),
        parameters: Some(NervousSystemParameters::with_default_values()),
        id_to_nervous_system_functions: BTreeMap::new(),

        neurons: Default::default(),
        proposals: Default::default(),

        latest_reward_event: None,
        in_flight_commands: Default::default(),
        genesis_timestamp_seconds: 0,
        metrics: None,
        mode: ModePb::Normal.into(),
        deployed_version,
        pending_version: None,
        is_finalizing_disburse_maturity: None,
        maturity_modulation: None,
        target_version: None,
        timers: None,
        upgrade_journal: None,
        cached_upgrade_steps: None,
    }
}

fn governance_for_tests(governance_proto: GovernancePb) -> Governance {
    Governance::new(
        ValidGovernanceProto::try_from(governance_proto)
            .expect("Failed validating governance proto"),
        Box::new(NativeEnvironment::new(Some(canister_test_id(501)))),
        Box::new(MockICRC1Ledger::default()),
        Box::new(MockICRC1Ledger::default()),
        Box::new(MockCMC::default()),
    )
}

#[test]
fn test_validate_and_render_advance_target_version_action() {
    // Prepare the world.
    let pre_deployed_version = sns_version_for_tests();
    let deployed_version = Version {
        root_wasm_hash: vec![
            67, 28, 179, 51, 254, 179, 247, 98, 247, 66, 176, 222, 165, 135, 69, 99, 58, 42, 44,
            164, 16, 117, 233, 147, 49, 131, 216, 80, 180, 221, 178, 89,
        ],
        ..pre_deployed_version.clone()
    };
    let intermediate_version = Version {
        governance_wasm_hash: vec![
            131, 31, 108, 253, 195, 85, 209, 50, 78, 217, 59, 177, 168, 212, 177, 246, 163, 237,
            165, 7, 14, 89, 228, 112, 205, 253, 15, 45, 53, 222, 138, 136,
        ],
        ..deployed_version.clone()
    };
    let expected_target_version = Version {
        swap_wasm_hash: vec![
            131, 19, 172, 34, 210, 239, 10, 12, 18, 144, 168, 91, 71, 242, 53, 207, 162, 76, 162,
            201, 109, 9, 91, 141, 190, 213, 80, 36, 131, 185, 205, 24,
        ],
        ..intermediate_version.clone()
    };

    // Smoke check: Make sure all versions are different
    let versions = vec![
        pre_deployed_version,
        deployed_version.clone(),
        intermediate_version.clone(),
        expected_target_version.clone(),
    ];
    assert!(
        versions.iter().collect::<HashSet::<_>>().len() == versions.len(),
        "Duplicates!"
    );

    let mut governance_proto = standard_governance_proto_for_tests(Some(deployed_version));
    governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions { versions }),
        ..Default::default()
    });

    // Run code under test.
    {
        // Experiment A: Advance the target to the intermediate version.
        let action = Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(intermediate_version.clone())),
        });

        let governance = governance_for_tests(governance_proto.clone());

        let (_, action_auxiliary) = validate_and_render_action(&Some(action), &governance, vec![])
            .now_or_never()
            .unwrap()
            .unwrap();

        // Inspect the observed results.
        assert_eq!(
            action_auxiliary,
            ActionAuxiliary::AdvanceSnsTargetVersion(intermediate_version)
        );
    }

    // Experiments B, C: Advance the target to the latest available version (either implicitly
    //  or explicitly).
    for action in [
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion { new_target: None }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(expected_target_version.clone())),
        }),
    ] {
        let expected_target_version = expected_target_version.clone();

        let governance = governance_for_tests(governance_proto.clone());

        let (actual_text, action_auxiliary) =
            validate_and_render_action(&Some(action), &governance, vec![])
                .now_or_never()
                .unwrap()
                .unwrap();

        // Inspect the observed results.
        assert_eq!(
            action_auxiliary,
            ActionAuxiliary::AdvanceSnsTargetVersion(expected_target_version)
        );
        // Notice that there are only 3 expected upgrade steps (pre_deployed_version is gone).
        assert_eq!(
            actual_text,
            r#"# Proposal to advance SNS target version

| Canister   | Current version's module hash                                    | New target version's module hash                                 |
|------------|------------------------------------------------------------------|------------------------------------------------------------------|
| Root       | 431cb333feb3f762f742b0dea58745633a2a2ca41075e9933183d850b4ddb259 | 431cb333feb3f762f742b0dea58745633a2a2ca41075e9933183d850b4ddb259 |
| Governance | 3feb8ff7b47f53da83235e4c68676bb6db54df1e62df3681de9425ad5cf43be5 | 831f6cfdc355d1324ed93bb1a8d4b1f6a3eda5070e59e470cdfd0f2d35de8a88 |
| Swap       | 3bb490d197b8cf2e7d9948bcb5d1fc46747a835294b3ffe47b882dbfa584555f | 8313ac22d2ef0a0c1290a85b47f235cfa24ca2c96d095b8dbed5502483b9cd18 |
| Index      | 08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0 | 08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0 |
| Ledger     | e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4 | e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4 |
| Archive    | 5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f | 5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f |

### Upgrade steps

| Step | Root | Governance | Swap | Index | Ledger | Archive | Changes |
|------|------|------------|------|-------|--------|---------|---------|
|    0 | 431cb3 | 3feb8f | 3bb490 | 08ae50 | e8942f | 5c595c | Current version |
|    1 | 431cb3 | 831f6c | 3bb490 | 08ae50 | e8942f | 5c595c | Governance @ 831f6cfdc355d1324ed93bb1a8d4b1f6a3eda5070e59e470cdfd0f2d35de8a88 |
|    2 | 431cb3 | 831f6c | 8313ac | 08ae50 | e8942f | 5c595c | Swap @ 8313ac22d2ef0a0c1290a85b47f235cfa24ca2c96d095b8dbed5502483b9cd18 |


### Monitoring the upgrade process

Please note: the upgrade steps mentioned above (valid around 1970-01-01 00:00:00 UTC) might change during this proposal's voting period.

The **upgrade journal** provides up-to-date information on this SNS's upgrade process:

https://qys37-7yaaa-aaaaa-aah2q-cai.raw.icp0.io/journal/json"#,
        );
    }
}

#[test]
fn test_no_pending_upgrades() {
    // Prepare the world.
    let pre_deployed_version = sns_version_for_tests();
    let deployed_version = Version {
        root_wasm_hash: vec![
            67, 28, 179, 51, 254, 179, 247, 98, 247, 66, 176, 222, 165, 135, 69, 99, 58, 42, 44,
            164, 16, 117, 233, 147, 49, 131, 216, 80, 180, 221, 178, 89,
        ],
        ..pre_deployed_version.clone()
    };
    let non_existent_version = Version {
        root_wasm_hash: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ],
        ..deployed_version.clone()
    };

    // Smoke check: Make sure all versions are different
    let versions = vec![pre_deployed_version.clone(), deployed_version.clone()];
    assert!(
        versions.iter().collect::<HashSet::<_>>().len() == versions.len(),
        "Duplicates!"
    );

    let mut governance_proto = standard_governance_proto_for_tests(Some(deployed_version.clone()));
    governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions { versions }),
        ..Default::default()
    });

    // Run code under test.
    for action in [
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion { new_target: None }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(deployed_version)),
        }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(pre_deployed_version)),
        }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(non_existent_version)),
        }),
    ] {
        let governance = governance_for_tests(governance_proto.clone());

        let err = validate_and_render_action(&Some(action), &governance, vec![])
            .now_or_never()
            .unwrap()
            .unwrap_err();

        // Inspect the observed results.
        assert_eq!(
            err,
            "Currently, the SNS does not have pending upgrades. You may need to wait for \
             the upgrade steps to be refreshed. This shouldn't take more than 3600 seconds.",
        );
    }
}

#[test]
fn test_deployed_version_not_in_cached_upgrade_steps() {
    // Prepare the world.
    let pre_deployed_version = sns_version_for_tests();
    let deployed_version = Version {
        root_wasm_hash: vec![
            67, 28, 179, 51, 254, 179, 247, 98, 247, 66, 176, 222, 165, 135, 69, 99, 58, 42, 44,
            164, 16, 117, 233, 147, 49, 131, 216, 80, 180, 221, 178, 89,
        ],
        ..pre_deployed_version.clone()
    };
    let non_existent_version = Version {
        root_wasm_hash: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ],
        ..deployed_version.clone()
    };

    // Smoke check: Make sure all versions are different
    let versions = vec![pre_deployed_version.clone(), non_existent_version.clone()];
    assert!(
        versions.iter().collect::<HashSet::<_>>().len() == versions.len(),
        "Duplicates!"
    );

    let mut governance_proto = standard_governance_proto_for_tests(Some(deployed_version.clone()));
    governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions { versions }),
        ..Default::default()
    });

    // Run code under test.
    for action in [
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion { new_target: None }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(deployed_version)),
        }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(pre_deployed_version)),
        }),
        Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
            new_target: Some(SnsVersion::from(non_existent_version)),
        }),
    ] {
        let governance = governance_for_tests(governance_proto.clone());

        let err = validate_and_render_action(&Some(action), &governance, vec![])
            .now_or_never()
            .unwrap()
            .unwrap_err();

        // Inspect the observed results.
        assert_eq!(
            err,
            "Currently, the SNS does not have pending upgrades. You may need to wait for \
             the upgrade steps to be refreshed. This shouldn't take more than 3600 seconds.",
        );
    }
}

#[test]
fn test_invalid_new_targets() {
    // Prepare the world.
    let deployed_version = sns_version_for_tests();
    let next_version = Version {
        root_wasm_hash: vec![
            67, 28, 179, 51, 254, 179, 247, 98, 247, 66, 176, 222, 165, 135, 69, 99, 58, 42, 44,
            164, 16, 117, 233, 147, 49, 131, 216, 80, 180, 221, 178, 89,
        ],
        ..deployed_version.clone()
    };
    let next_next_version = Version {
        index_wasm_hash: vec![
            103, 181, 240, 191, 18, 142, 128, 26, 223, 74, 149, 158, 162, 108, 60, 156, 160, 205,
            57, 153, 64, 225, 105, 162, 106, 46, 178, 55, 137, 154, 148, 221,
        ],
        ..deployed_version.clone()
    };
    let non_existent_version = Version {
        root_wasm_hash: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ],
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

    // Run code under test.

    for (label, current_target_version, action, expected_result) in [
        (
            "Scenario A: `new_target` is equal to `deployed_version`.",
            None,
            Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
                new_target: Some(SnsVersion::from(deployed_version.clone())),
            }),
            Err("new_target_version must differ from the current version.".to_string()),
        ),
        (
            "Scenario B: `new_target` is not a known version.",
            None,
            Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
                new_target: Some(SnsVersion::from(non_existent_version)),
            }),
            Err("new_target_version must be among the upgrade steps.".to_string()),
        ),
        (
            "Scenario C: `new_target` is equal to `current_target_version`.",
            Some(next_version.clone()),
            Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
                new_target: Some(SnsVersion::from(next_version.clone())),
            }),
            Err(format!("SNS target already set to {next_version}.")),
        ),
        (
            "Scenario D: `new_target` is behind `current_target_version`.",
            Some(next_next_version.clone()),
            Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
                new_target: Some(SnsVersion::from(next_version.clone())),
            }),
            Err(format!("SNS target already set to {next_next_version}.")),
        ),
        (
            "Scenario E: `new_target` is ahead of `current_target_version`.",
            Some(next_version),
            Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion {
                new_target: Some(SnsVersion::from(next_next_version.clone())),
            }),
            Ok(ActionAuxiliary::AdvanceSnsTargetVersion(next_next_version)),
        ),
    ] {
        let mut governance_proto =
            standard_governance_proto_for_tests(Some(deployed_version.clone()));
        governance_proto.target_version = current_target_version;
        governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
            upgrade_steps: Some(Versions {
                versions: versions.clone(),
            }),
            ..Default::default()
        });

        let governance = governance_for_tests(governance_proto.clone());

        let result = validate_and_render_action(&Some(action), &governance, vec![])
            .now_or_never()
            .unwrap()
            .map(|(_, action_auxiliary)| action_auxiliary);

        // Inspect the observed results.
        assert_eq!(result, expected_result, "{}", label);
    }
}
