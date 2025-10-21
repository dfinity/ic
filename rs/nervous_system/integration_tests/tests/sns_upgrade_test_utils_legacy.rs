use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        self, add_wasm_via_nns_proposal, nns,
        sns::{self, governance::set_automatically_advance_target_version_flag},
    },
};
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_governance_sns_wasm, build_index_ng_sns_wasm,
    build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm, create_modified_sns_wasm,
    ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;

/// Tests upgrading SNS canisters to the master version, using the legacy UpgradeSnsToNextVersion proposals
pub async fn test_sns_upgrade_legacy(sns_canisters_to_upgrade: Vec<SnsCanisterType>) {
    let (pocket_ic, _initial_sns_version) =
        pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions().await;

    eprintln!("Creating SNS ...");
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

    eprintln!("Deploying an SNS instance via proposal ...");
    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    eprintln!("Await the swap lifecycle ...");
    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();

    eprintln!("smoke_test_participate_and_finalize ...");
    sns::swap::smoke_test_participate_and_finalize(
        &pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    eprintln!(
        "Disabling automatic upgrades to have full control over when an upgrade is triggered ..."
    );
    let automatically_advance_target_version = false;
    set_automatically_advance_target_version_flag(
        &pocket_ic,
        sns.governance.canister_id,
        automatically_advance_target_version,
    )
    .await
    .unwrap();

    eprintln!("Adding all WASMs ...");
    for canister_type in &sns_canisters_to_upgrade {
        let wasm = match canister_type {
            SnsCanisterType::Root => build_root_sns_wasm(),
            SnsCanisterType::Governance => build_governance_sns_wasm(),
            SnsCanisterType::Ledger => build_ledger_sns_wasm(),
            SnsCanisterType::Swap => build_swap_sns_wasm(),
            SnsCanisterType::Index => build_index_ng_sns_wasm(),
            SnsCanisterType::Unspecified => {
                panic!("Where did you get this canister type from?")
            }
            SnsCanisterType::Archive => build_archive_sns_wasm(),
        };

        let wasm = ensure_sns_wasm_gzipped(wasm);
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    eprintln!("Adding all WASMs with custom metadata ...");
    for canister_type in &sns_canisters_to_upgrade {
        let wasm = match canister_type {
            // Second upgrade with modified wasms
            SnsCanisterType::Root => create_modified_sns_wasm(&build_root_sns_wasm(), Some(42)),
            SnsCanisterType::Governance => {
                create_modified_sns_wasm(&build_governance_sns_wasm(), Some(42))
            }
            SnsCanisterType::Ledger => create_modified_sns_wasm(&build_ledger_sns_wasm(), Some(42)),
            SnsCanisterType::Swap => create_modified_sns_wasm(&build_swap_sns_wasm(), Some(42)),
            SnsCanisterType::Index => {
                create_modified_sns_wasm(&build_index_ng_sns_wasm(), Some(42))
            }
            SnsCanisterType::Unspecified => {
                panic!("Where did you get this canister type from?")
            }
            SnsCanisterType::Archive => {
                create_modified_sns_wasm(&build_archive_sns_wasm(), Some(42))
            }
        };

        let wasm = ensure_sns_wasm_gzipped(wasm);
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Only spawn an archive if we're testing it
    if sns_canisters_to_upgrade.contains(&SnsCanisterType::Archive) {
        eprintln!("Testing if the Archive canister is spawned ...");
        sns::ensure_archive_canister_is_spawned_or_panic(
            &pocket_ic,
            sns.governance.canister_id,
            sns.ledger.canister_id,
        )
        .await;
    }

    // Every canister we are testing has two upgrades.  We are just making sure the counts match
    for canister_type in &sns_canisters_to_upgrade {
        eprintln!("1st upgrade_sns_to_next_version_and_assert_change {canister_type:?} ...");
        sns::upgrade_sns_to_next_version_and_assert_change(&pocket_ic, &sns, *canister_type).await;
    }
    for canister_type in sns_canisters_to_upgrade {
        eprintln!("2nd upgrade_sns_to_next_version_and_assert_change {canister_type:?} ...");
        sns::upgrade_sns_to_next_version_and_assert_change(&pocket_ic, &sns, canister_type).await;
    }
}
