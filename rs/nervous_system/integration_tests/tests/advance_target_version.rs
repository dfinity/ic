use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, add_wasms_to_sns_wasm, install_nns_canisters, nns,
    },
};
use ic_nns_test_utils::sns_wasm::create_modified_sns_wasm;
use ic_sns_governance::{
    governance::UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS, pb::v1 as sns_pb,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;
use pocket_ic::PocketIcBuilder;
use std::time::Duration;

const TICKS_PER_TASK: u64 = 2;

#[test]
fn test_get_upgrade_journal() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let wait_for_next_periodic_task = |sleep_duration_seconds| {
        let now = pocket_ic.get_time();
        pocket_ic.advance_time(Duration::from_secs(sleep_duration_seconds));
        for _ in 0..TICKS_PER_TASK {
            pocket_ic.tick();
        }
        assert_eq!(
            pocket_ic.get_time(),
            now + Duration::from_secs(sleep_duration_seconds)
                + Duration::from_nanos(TICKS_PER_TASK)
        );
    };

    // Install the (master) NNS canisters.
    let with_mainnet_nns_canisters = false;
    install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, None, vec![]);

    // Publish (master) SNS Wasms to SNS-W.
    let with_mainnet_sns_wasms = false;
    let deployed_sns_starting_info =
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_wasms).unwrap();
    let initial_sns_version = nns::sns_wasm::get_lastest_sns_version(&pocket_ic);

    // Deploy an SNS instance via proposal.
    let sns = {
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .clone()
            .unwrap();

        let sns_instance_label = "1";
        let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
            &pocket_ic,
            create_service_nervous_system,
            sns_instance_label,
        );

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open).unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        );
        sns
    };

    // State A: right after SNS creation.
    let response_timestamp_seconds = {
        let sns_pb::GetUpgradeJournalResponse {
            upgrade_steps,
            response_timestamp_seconds,
        } = sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id);
        let upgrade_steps = upgrade_steps
            .expect("upgrade_steps should be Some")
            .versions;
        assert_eq!(upgrade_steps, vec![initial_sns_version.clone()]);
        assert_eq!(response_timestamp_seconds, Some(1620501459));
        response_timestamp_seconds.unwrap()
    };

    wait_for_next_periodic_task(UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS);

    // State B: after the first periodic task's completion. No changes expected yet.
    {
        let sns_pb::GetUpgradeJournalResponse {
            upgrade_steps,
            response_timestamp_seconds,
        } =
            sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id);
        let upgrade_steps = upgrade_steps
            .expect("upgrade_steps should be Some")
            .versions;
        assert_eq!(upgrade_steps, vec![initial_sns_version.clone()]);

        // bazel test //rs/nervous_system/integration_tests/... --test_arg=test_get_upgrade_journal
        // ...
        // assertion `left == right` failed
        // left: Some(1620505063)
        // right: Some(1620505059)
        assert_eq!(response_timestamp_seconds, Some(response_timestamp_seconds + UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS));
    }
}
