use ic_base_types::PrincipalId;
use ic_management_canister_types::CanisterStatusType;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{self, add_wasm_via_nns_proposal, nns, sns},
};
use ic_nns_test_utils::sns_wasm::{build_root_sns_wasm, ensure_sns_wasm_gzipped};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;
use std::time::Duration;

/// Tests that the one-shot timer in SNS root upgrades the index canister to set
/// `retrieve_blocks_from_ledger_interval_seconds` to 5s.
///
/// The timer fires immediately after root's init/post_upgrade. It fetches the current
/// index WASM version from governance, then upgrades the index canister with
/// `UpgradeArg { retrieve_blocks_from_ledger_interval_seconds: Some(5) }`.
///
/// Since the interval is not directly queryable, we verify that the upgrade completes
/// successfully by checking the index canister remains running with the expected WASM.
#[tokio::test]
async fn test_upgrade_index_canister_to_5s_interval() {
    let (pocket_ic, sns_version) =
        pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions().await;

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

    // Use the tip-of-branch root wasm (contains the one-shot timer).
    let wasm = ensure_sns_wasm_gzipped(build_root_sns_wasm());
    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
    assert_eq!(proposal_info.failure_reason, None);

    // Deploy an SNS instance via proposal.
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        "1",
    )
    .await;

    // Complete the swap so the SNS is fully functional.
    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();
    sns::swap::smoke_test_participate_and_finalize(
        &pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    // Let the one-shot timer run (it fires with Duration::ZERO).
    for _ in 0..10 {
        pocket_ic.advance_time(Duration::from_secs(10)).await;
        pocket_ic.tick().await;
    }

    // Verify the index canister is still running after the upgrade.
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
            .as_slice(),
        "Index canister WASM hash should match the expected version after upgrade"
    );
    assert_eq!(
        index_canister_status.status,
        CanisterStatusType::Running,
        "Index canister should be running after the upgrade"
    );
}
