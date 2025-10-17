use ic_nervous_system_agent::helpers::await_with_timeout;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasms_to_sns_wasm, hash_sns_wasms, nns,
        sns::{
            self,
            governance::{
                EXPECTED_UPGRADE_DURATION_MAX_SECONDS, EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
                set_automatically_advance_target_version_flag,
            },
        },
    },
};
use ic_sns_governance::governance::UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS;
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;
use pocket_ic::PocketIcBuilder;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_advance_target_version_upgrades_all_canisters_auto() {
    let automatically_advance_target_version = true;
    test_advance_target_version_upgrades_all_canisters(automatically_advance_target_version).await
}

#[tokio::test]
async fn test_advance_target_version_upgrades_all_canisters_no_auto() {
    let automatically_advance_target_version = false;
    test_advance_target_version_upgrades_all_canisters(automatically_advance_target_version).await
}

async fn test_advance_target_version_upgrades_all_canisters(
    automatically_advance_target_version: bool,
) {
    eprintln!("Step 0: Setup the test environment ...");
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    eprintln!("Install the (master) NNS canisters ...");
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    eprintln!("Step 0.1: Publish (master) SNS Wasms to SNS-W ...");
    let with_mainnet_sns_canisters = false;
    let initial_sns_version = {
        let deployed_sns_starting_info =
            add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
                .await
                .unwrap();
        deployed_sns_starting_info
            .into_iter()
            .map(|(canister_type, (_, wasm))| (canister_type, wasm))
            .collect::<BTreeMap<_, _>>()
    };

    eprintln!("Step 0.2: Deploy an SNS instance via proposal ...");
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
        )
        .await;

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
            .await
            .unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        )
        .await;
        sns
    };

    eprintln!("Step 0.3: Ensure an archive canister is spawned ...");
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns.governance.canister_id,
        sns.ledger.canister_id,
    )
    .await;

    eprintln!("Step 0.4: Ensure the value of automatically_advance_target_version is correct ...");
    set_automatically_advance_target_version_flag(
        &pocket_ic,
        sns.governance.canister_id,
        automatically_advance_target_version,
    )
    .await
    .unwrap();

    eprintln!("Step 2: Publish new SNS versions ...");
    let latest_sns_version = {
        let canister_types = vec![
            SnsCanisterType::Governance,
            SnsCanisterType::Root,
            SnsCanisterType::Swap,
            SnsCanisterType::Ledger,
            SnsCanisterType::Index,
            SnsCanisterType::Archive,
        ];

        let mut latest_version = initial_sns_version;

        for canister_type in canister_types {
            eprintln!("modify_and_add_wasm for {canister_type:?} ...");
            latest_version =
                nns::sns_wasm::modify_and_add_wasm(&pocket_ic, latest_version, canister_type, 1)
                    .await;
        }

        latest_version
    };

    eprintln!("Step 3: Wait for the upgrade steps to be refreshed ...");
    await_with_timeout(
        &pocket_ic,
        UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS..EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::try_get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .ok()
                .and_then(|journal| journal.upgrade_steps)
                .map(|upgrade_steps| upgrade_steps.versions)
                .map(|versions| versions.len())
        },
        // Hopefully there are 7 upgrade steps - 1 initial version, then another for each of the 6 canisters.
        &Some(7usize),
    )
    .await
    .unwrap();

    eprintln!("Step 4: advance the target version to the latest version. ...");
    let latest_sns_version_hash = hash_sns_wasms(&latest_sns_version);

    if !automatically_advance_target_version {
        sns::governance::advance_target_version(
            &pocket_ic,
            sns.governance.canister_id,
            latest_sns_version_hash.clone(),
        )
        .await;
    }

    eprintln!("Step 5: Wait for the upgrade to happen ...");
    await_with_timeout(
        &pocket_ic,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |pocket_ic| async {
            let journal =
                sns::governance::try_get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                    .await;
            journal.ok().and_then(|journal| journal.deployed_version)
        },
        &Some(latest_sns_version_hash),
    )
    .await
    .unwrap();
}
