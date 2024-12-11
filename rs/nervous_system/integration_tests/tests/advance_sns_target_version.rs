use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    await_with_timeout, sns,
    sns::governance::{
        EXPECTED_UPGRADE_DURATION_MAX_SECONDS, EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
    },
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, add_wasms_to_sns_wasm, install_nns_canisters, nns,
    },
};
use ic_nns_test_utils::sns_wasm::create_modified_sns_wasm;
use ic_sns_governance::pb::v1::upgrade_journal_entry::UpgradeStepsReset;
use ic_sns_governance::{
    governance::UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS,
    pb::v1 as sns_pb,
    pb::v1::upgrade_journal_entry::{Event, TargetVersionSet, UpgradeStepsRefreshed},
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_get_upgrade_journal() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    // Step 0: Install the (master) NNS canisters.
    let with_mainnet_nns_canisters = false;
    install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, None, vec![]).await;

    // Step 0.1: Publish (master) SNS Wasms to SNS-W.
    let with_mainnet_sns_canisters = false;
    let deployed_sns_starting_info = add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();
    let initial_sns_version = nns::sns_wasm::get_latest_sns_version(&pocket_ic).await;

    // Step 0.2: Deploy an SNS instance via proposal.
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

    // Step 1: Check that the upgrade journal contains the initial version right after SNS creation.
    let mut expected_upgrade_journal_entries = vec![];
    {
        expected_upgrade_journal_entries.push(Event::UpgradeStepsReset(UpgradeStepsReset::new(
            "this message will be redacted to keep the test spec more abstract".to_string(),
            vec![initial_sns_version.clone()],
        )));

        sns::governance::assert_upgrade_journal(
            &pocket_ic,
            sns.governance.canister_id,
            &expected_upgrade_journal_entries,
        )
        .await;
    }

    // Step 1.1: wait for the upgrade steps to be refreshed.
    await_with_timeout(
        &pocket_ic,
        UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS..EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .upgrade_steps
                .unwrap()
                .versions
        },
        &vec![initial_sns_version.clone()],
    )
    .await
    .unwrap();

    // Step 2: Publish new SNS versions.
    let (new_sns_version_1, new_sns_version_2) = {
        let (_, original_root_wasm) = deployed_sns_starting_info
            .get(&SnsCanisterType::Root)
            .unwrap();

        let new_sns_version_1 = {
            let root_wasm = create_modified_sns_wasm(original_root_wasm, Some(1));
            add_wasm_via_nns_proposal(&pocket_ic, root_wasm.clone())
                .await
                .unwrap();
            let root_wasm_hash = root_wasm.sha256_hash().to_vec();
            sns_pb::governance::Version {
                root_wasm_hash,
                ..initial_sns_version.clone()
            }
        };

        let new_sns_version_2 = {
            let root_wasm = create_modified_sns_wasm(original_root_wasm, Some(2));
            add_wasm_via_nns_proposal(&pocket_ic, root_wasm.clone())
                .await
                .unwrap();
            let root_wasm_hash = root_wasm.sha256_hash().to_vec();
            sns_pb::governance::Version {
                root_wasm_hash,
                ..new_sns_version_1.clone()
            }
        };

        let sns_version = nns::sns_wasm::get_latest_sns_version(&pocket_ic).await;
        assert_ne!(sns_version, initial_sns_version.clone());

        (new_sns_version_1, new_sns_version_2)
    };

    // Step 2.1: wait for the upgrade steps to be refreshed.
    await_with_timeout(
        &pocket_ic,
        UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS..EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .upgrade_steps
                .unwrap()
                .versions
        },
        &vec![
            initial_sns_version.clone(),
            new_sns_version_1.clone(),
            new_sns_version_2.clone(),
        ],
    )
    .await
    .unwrap();

    {
        expected_upgrade_journal_entries.push(Event::UpgradeStepsRefreshed(
            UpgradeStepsRefreshed::new(vec![
                initial_sns_version.clone(),
                new_sns_version_1.clone(),
                new_sns_version_2.clone(),
            ]),
        ));

        sns::governance::assert_upgrade_journal(
            &pocket_ic,
            sns.governance.canister_id,
            &expected_upgrade_journal_entries,
        )
        .await;
    }

    // State 3: Advance the target version via proposal.
    sns::governance::propose_to_advance_sns_target_version(&pocket_ic, sns.governance.canister_id)
        .await
        .unwrap();

    expected_upgrade_journal_entries.push(Event::TargetVersionSet(TargetVersionSet::new(
        None,
        Some(new_sns_version_2.clone()),
    )));

    sns::governance::assert_upgrade_journal(
        &pocket_ic,
        sns.governance.canister_id,
        &expected_upgrade_journal_entries,
    )
    .await;

    // Check that the target version is set to the new version.
    {
        let sns_pb::GetUpgradeJournalResponse { target_version, .. } =
            sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id).await;

        assert_eq!(target_version, Some(new_sns_version_2.clone()));
    }

    await_with_timeout(
        &pocket_ic,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .deployed_version
        },
        &Some(new_sns_version_2.clone()),
    )
    .await
    .unwrap();

    // Check that the deployed version is now set to the new version.
    {
        let sns_pb::GetUpgradeJournalResponse {
            deployed_version, ..
        } = sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id).await;

        assert_eq!(deployed_version, Some(new_sns_version_2.clone()));
    }

    // Check that the upgrade journal contains the correct entries.
    {
        expected_upgrade_journal_entries.push(
            sns_pb::upgrade_journal_entry::Event::UpgradeStarted(
                sns_pb::upgrade_journal_entry::UpgradeStarted::from_behind_target(
                    initial_sns_version.clone(),
                    new_sns_version_1.clone(),
                ),
            ),
        );

        expected_upgrade_journal_entries.push(
            sns_pb::upgrade_journal_entry::Event::UpgradeOutcome(
                sns_pb::upgrade_journal_entry::UpgradeOutcome::success(
                    "this message will be redacted to keep the test spec more abstract".to_string(),
                ),
            ),
        );

        expected_upgrade_journal_entries.push(
            sns_pb::upgrade_journal_entry::Event::UpgradeStarted(
                sns_pb::upgrade_journal_entry::UpgradeStarted::from_behind_target(
                    new_sns_version_1.clone(),
                    new_sns_version_2.clone(),
                ),
            ),
        );

        expected_upgrade_journal_entries.push(
            sns_pb::upgrade_journal_entry::Event::UpgradeOutcome(
                sns_pb::upgrade_journal_entry::UpgradeOutcome::success(
                    "this message will be redacted to keep the test spec more abstract".to_string(),
                ),
            ),
        );

        sns::governance::assert_upgrade_journal(
            &pocket_ic,
            sns.governance.canister_id,
            &expected_upgrade_journal_entries,
        )
        .await;
    }
}
