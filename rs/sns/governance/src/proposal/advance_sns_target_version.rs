use super::*;
use crate::pb::v1::governance::Versions;
use crate::pb::v1::governance::{CachedUpgradeSteps as CachedUpgradeStepsPb, Mode as ModePb};
use crate::pb::v1::Governance as GovernancePb;
use crate::types::test_helpers::NativeEnvironment;
use futures::FutureExt;
use ic_test_utilities_types::ids::canister_test_id;

fn standard_governance_proto_for_tests(deployed_version: Option<Version>) -> GovernancePb {
    GovernancePb {
        root_canister_id: Some(PrincipalId::from(canister_test_id(500))),
        ledger_canister_id: Some(PrincipalId::from(canister_test_id(502))),
        swap_canister_id: Some(PrincipalId::from(canister_test_id(503))),

        sns_metadata: None,
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

#[test]
fn test_can_be_submitted_without_args() {
    // Prepare the world.
    let governance_canister_id = canister_test_id(501);

    let deployed_version = Version {
        archive_wasm_hash: vec![
            92, 89, 92, 42, 220, 127, 109, 153, 113, 41, 143, 238, 47, 166, 102, 146, 151, 17, 231,
            51, 65, 25, 42, 183, 8, 4, 199, 131, 160, 238, 224, 63,
        ],
        governance_wasm_hash: vec![
            63, 235, 143, 247, 180, 127, 83, 218, 131, 35, 94, 76, 104, 103, 107, 182, 219, 84,
            223, 30, 98, 223, 54, 129, 222, 148, 37, 173, 92, 244, 59, 229,
        ],
        index_wasm_hash: vec![
            8, 174, 80, 66, 200, 228, 19, 113, 109, 4, 160, 141, 184, 134, 184, 198, 176, 27, 182,
            16, 184, 25, 124, 219, 224, 82, 197, 149, 56, 185, 36, 240,
        ],
        ledger_wasm_hash: vec![
            232, 148, 47, 86, 249, 67, 155, 137, 177, 59, 216, 3, 127, 53, 113, 38, 226, 79, 30,
            121, 50, 207, 3, 1, 130, 67, 52, 117, 5, 149, 159, 212,
        ],
        root_wasm_hash: vec![
            73, 94, 49, 55, 11, 20, 250, 97, 199, 107, 209, 72, 60, 159, 155, 166, 103, 51, 121,
            62, 226, 150, 62, 142, 68, 162, 49, 67, 106, 96, 188, 198,
        ],
        swap_wasm_hash: vec![
            59, 180, 144, 209, 151, 184, 207, 46, 125, 153, 72, 188, 181, 209, 252, 70, 116, 122,
            131, 82, 148, 179, 255, 228, 123, 136, 45, 191, 165, 132, 85, 95,
        ],
    };
    let expected_target_version = deployed_version.clone();

    let mut governance_proto = standard_governance_proto_for_tests(Some(deployed_version.clone()));
    governance_proto.cached_upgrade_steps = Some(CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions {
            versions: vec![deployed_version],
        }),
        response_timestamp_seconds: Some(0),
        requested_timestamp_seconds: Some(0),
    });
    let env = NativeEnvironment::new(Some(governance_canister_id));

    // Run code under test.
    let action = Action::AdvanceSnsTargetVersion(AdvanceSnsTargetVersion { new_target: None });

    let (actual_text, action_auxiliary) =
        validate_and_render_action(&Some(action), &env, &governance_proto, vec![])
            .now_or_never()
            .unwrap()
            .unwrap();

    // Inspect the observed results.
    assert_eq!(
        action_auxiliary,
        ActionAuxiliary::AdvanceSnsTargetVersion(expected_target_version)
    );
    assert_eq!(
        actual_text,
        r#"# Proposal to advance SNS target version

| Canister   | Current version's module hash                                    | New target version's module hash                                 |
|------------|------------------------------------------------------------------|------------------------------------------------------------------|
| Root       | 495e31370b14fa61c76bd1483c9f9ba66733793ee2963e8e44a231436a60bcc6 | 495e31370b14fa61c76bd1483c9f9ba66733793ee2963e8e44a231436a60bcc6 |
| Governance | 3feb8ff7b47f53da83235e4c68676bb6db54df1e62df3681de9425ad5cf43be5 | 3feb8ff7b47f53da83235e4c68676bb6db54df1e62df3681de9425ad5cf43be5 |
| Swap       | 3bb490d197b8cf2e7d9948bcb5d1fc46747a835294b3ffe47b882dbfa584555f | 3bb490d197b8cf2e7d9948bcb5d1fc46747a835294b3ffe47b882dbfa584555f |
| Index      | 08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0 | 08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0 |
| Ledger     | e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4 | e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4 |
| Archive    | 5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f | 5c595c2adc7f6d9971298fee2fa666929711e73341192ab70804c783a0eee03f |

### Upgrade steps

| Step | Root | Governance | Swap | Index | Ledger | Archive | Changes |
|------|------|------------|------|-------|--------|---------|---------|
|    0 | 495e31 | 3feb8f | 3bb490 | 08ae50 | e8942f | 5c595c | Current version |


### Monitoring the upgrade process

Please note: the upgrade steps above (valid around timestamp 0 seconds) might change during this proposal's voting period. Such changes are unlikely and are subject to NNS community's approval.

The **upgrade journal** provides up-to-date information on this SNS's upgrade process:

https://qys37-7yaaa-aaaaa-aah2q-cai.raw.icp0.io/journal/json"#,
    );
}
