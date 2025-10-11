use ic_base_types::PrincipalId;
use ic_management_canister_types::CanisterStatusType;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        self, add_wasm_via_nns_proposal, insert_sns_wasm_upgrade_path_entries_via_nns_proposal,
        nns, sns, upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::sns_wasm::build_root_sns_wasm;
use ic_sns_governance_api::pb::v1::governance::Version;
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::{SnsCanisterType, SnsUpgrade, SnsVersion};
use std::time::Duration;

#[tokio::test]
async fn test_recover_from_deleted_index_canister() {
    let (pocket_ic, initial_sns_version) =
        pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions().await;

    // This is needed because the NNS Governance deserializes and serializes the add_wasm payload.
    // If the Governance cansiter lags behind, the `skip_update_latest_version` flag would be lost.
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID).await;

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

    // Deploy an SNS instance via proposal.
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        "1",
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

    sns::governance::set_automatically_advance_target_version_flag(
        &pocket_ic,
        sns.governance.canister_id,
        true,
    )
    .await
    .unwrap();

    // Uninstall the index canister and check that no wasm is on the canister.
    pocket_ic
        .uninstall_canister(sns.index.canister_id.0, Some(sns.root.canister_id.0))
        .await
        .unwrap();

    let index_canister_status = pocket_ic
        .canister_status(sns.index.canister_id.0, Some(sns.root.canister_id.0))
        .await
        .unwrap();
    assert_eq!(index_canister_status.module_hash, None);

    let mut sns_version = initial_sns_version.clone();
    for (canister_type, nonce) in [
        (SnsCanisterType::Index, 0),
        (SnsCanisterType::Ledger, 0),
        (SnsCanisterType::Archive, 0),
        (SnsCanisterType::Root, 0),
        (SnsCanisterType::Governance, 0),
        (SnsCanisterType::Swap, 0),
        (SnsCanisterType::Index, 1),
        (SnsCanisterType::Ledger, 1),
        (SnsCanisterType::Archive, 1),
        (SnsCanisterType::Root, 1),
        (SnsCanisterType::Governance, 1),
        (SnsCanisterType::Swap, 1),
    ] {
        sns_version =
            nns::sns_wasm::modify_and_add_wasm(&pocket_ic, sns_version, canister_type, nonce).await;
    }

    let hotfix_root_wasm = build_root_sns_wasm();
    add_wasm_via_nns_proposal(&pocket_ic, hotfix_root_wasm.clone(), true)
        .await
        .unwrap();
    let hotfix_root_wasm_hash = hotfix_root_wasm.sha256_hash().to_vec();

    pocket_ic.advance_time(Duration::from_secs(3600)).await;
    for _ in 0..100 {
        pocket_ic.advance_time(Duration::from_secs(10)).await;
        pocket_ic.tick().await;
    }

    let response =
        sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id).await;
    let current_version =
        to_sns_wasm_version(&response.upgrade_steps.as_ref().unwrap().versions[0]);
    let next_version = to_sns_wasm_version(&response.upgrade_steps.as_ref().unwrap().versions[1]);

    // Instead of (root1,index1)->(root1,index2), we reroute to
    // (root1,index1)->(root2,index1)->(root2,index2)->(root1,index2).
    let version_1 = SnsVersion {
        root_wasm_hash: hotfix_root_wasm_hash.clone(),
        ..current_version.clone()
    };
    let version_2 = SnsVersion {
        root_wasm_hash: hotfix_root_wasm_hash.clone(),
        ..next_version.clone()
    };
    let upgrade_path = vec![
        SnsUpgrade {
            current_version: Some(current_version.clone()),
            next_version: Some(version_1.clone()),
        },
        SnsUpgrade {
            current_version: Some(version_1.clone()),
            next_version: Some(version_2.clone()),
        },
        SnsUpgrade {
            current_version: Some(version_2.clone()),
            next_version: Some(next_version.clone()),
        },
    ];
    insert_sns_wasm_upgrade_path_entries_via_nns_proposal(
        &pocket_ic,
        upgrade_path,
        Some(sns.governance.canister_id),
        "https://forum.dfinity.org",
    )
    .await
    .unwrap();

    // Let the upgrade path refresh and tick enough so that necessary upgrades take place.
    pocket_ic.advance_time(Duration::from_secs(3600)).await;
    for _ in 0..300 {
        pocket_ic.advance_time(Duration::from_secs(10)).await;
        pocket_ic.tick().await;
    }

    // Let the upgrade steps refresh again.
    pocket_ic.advance_time(Duration::from_secs(3600)).await;
    for _ in 0..10 {
        pocket_ic.advance_time(Duration::from_secs(10)).await;
        pocket_ic.tick().await;
    }

    let response =
        sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id).await;
    // We expect that the upgrades are all finished.
    assert_eq!(response.upgrade_steps.unwrap().versions.len(), 1);
    assert_eq!(
        response.deployed_version.as_ref().unwrap(),
        response.target_version.as_ref().unwrap()
    );
    // We expect that the wasm hashes were the one we set.
    assert_eq!(
        response.deployed_version.as_ref().unwrap().root_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Root)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(
        response
            .deployed_version
            .as_ref()
            .unwrap()
            .governance_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Governance)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(
        response.deployed_version.as_ref().unwrap().swap_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Swap)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(
        response.deployed_version.as_ref().unwrap().index_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Index)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(
        response.deployed_version.as_ref().unwrap().ledger_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Ledger)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(
        response
            .deployed_version
            .as_ref()
            .unwrap()
            .archive_wasm_hash,
        sns_version
            .get(&SnsCanisterType::Archive)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );

    // We expect that the index canister was upgraded and running.
    let index_canister_status = pocket_ic
        .canister_status(sns.index.canister_id.0, Some(sns.root.canister_id.0))
        .await
        .unwrap();
    assert_eq!(
        index_canister_status.module_hash.as_ref().unwrap(),
        sns_version
            .get(&SnsCanisterType::Index)
            .unwrap()
            .sha256_hash()
            .as_slice()
    );
    assert_eq!(index_canister_status.status, CanisterStatusType::Running);
}

fn to_sns_wasm_version(version: &Version) -> SnsVersion {
    let Version {
        root_wasm_hash,
        governance_wasm_hash,
        ledger_wasm_hash,
        swap_wasm_hash,
        archive_wasm_hash,
        index_wasm_hash,
    } = version;
    SnsVersion {
        root_wasm_hash: root_wasm_hash.clone(),
        governance_wasm_hash: governance_wasm_hash.clone(),
        ledger_wasm_hash: ledger_wasm_hash.clone(),
        swap_wasm_hash: swap_wasm_hash.clone(),
        archive_wasm_hash: archive_wasm_hash.clone(),
        index_wasm_hash: index_wasm_hash.clone(),
    }
}
