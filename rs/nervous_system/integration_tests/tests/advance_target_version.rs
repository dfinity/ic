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
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
            .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
            .with_one_developer_neuron(
                PrincipalId::new_user_test_id(830947),
                ONE_MONTH_SECONDS * 6,
                756575,
                0,
            )
            .build();
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
    {
        let sns_pb::GetUpgradeJournalResponse {
            upgrade_steps,
            response_timestamp_seconds,
        } = sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id);
        let upgrade_steps = upgrade_steps
            .expect("upgrade_steps should be Some")
            .versions;
        assert_eq!(upgrade_steps, vec![initial_sns_version.clone()]);
        assert_eq!(response_timestamp_seconds, Some(1620501459));
    }

    wait_for_next_periodic_task(UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS);

    // State B: after the first periodic task's completion. No changes expected yet.
    {
        let sns_pb::GetUpgradeJournalResponse { upgrade_steps, .. } =
            sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id);
        let upgrade_steps = upgrade_steps
            .expect("upgrade_steps should be Some")
            .versions;
        assert_eq!(upgrade_steps, vec![initial_sns_version.clone()]);
    }

    // Publish a new SNS version.
    let (new_sns_version_1, new_sns_version_2) = {
        let (_, original_ledger_wasm) = deployed_sns_starting_info
            .get(&SnsCanisterType::Ledger)
            .unwrap();

        let new_sns_version_1 = {
            let ledger_wasm = create_modified_sns_wasm(original_ledger_wasm, Some(1));
            add_wasm_via_nns_proposal(&pocket_ic, ledger_wasm.clone()).unwrap();
            let ledger_wasm_hash = ledger_wasm.sha256_hash().to_vec();
            sns_pb::governance::Version {
                ledger_wasm_hash,
                ..initial_sns_version.clone()
            }
        };

        let new_sns_version_2 = {
            let ledger_wasm = create_modified_sns_wasm(original_ledger_wasm, Some(2));
            add_wasm_via_nns_proposal(&pocket_ic, ledger_wasm.clone()).unwrap();
            let ledger_wasm_hash = ledger_wasm.sha256_hash().to_vec();
            sns_pb::governance::Version {
                ledger_wasm_hash,
                ..new_sns_version_1.clone()
            }
        };

        let sns_version = nns::sns_wasm::get_lastest_sns_version(&pocket_ic);
        assert_ne!(sns_version, initial_sns_version);

        (new_sns_version_1, new_sns_version_2)
    };

    wait_for_next_periodic_task(UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS);

    // State C: after the second periodic task's completion.
    {
        let sns_pb::GetUpgradeJournalResponse { upgrade_steps, .. } =
            sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id);
        let upgrade_steps = upgrade_steps.expect("cached_upgrade_steps should be Some");

        assert_eq!(
            upgrade_steps.versions,
            vec![initial_sns_version, new_sns_version_1, new_sns_version_2,]
        );
    }
}
