use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, install_canister, nns, sns,
        upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::{self, GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;

#[tokio::test]
async fn test_deploy_fresh_sns() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();

    let dapp_canister_ids: Vec<_> = create_service_nervous_system
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();

    eprintln!("1. Prepare the world (use mainnet WASMs for all NNS and SNS canisters) ...");
    let (pocket_ic, _initial_sns_version) =
        pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions().await;

    eprintln!("Install the test dapp ...");
    for dapp_canister_id in dapp_canister_ids.clone() {
        install_canister(
            &pocket_ic,
            "My Test Dapp",
            dapp_canister_id,
            vec![],
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
            None,
        )
        .await;
    }

    eprintln!("Step 1. Upgrade NNS Governance and SNS-W to the latest version ...");
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID).await;

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, SNS_WASM_CANISTER_ID).await;

    eprintln!("Test upgrading SNS Ledger via proposals. First, add all the WASMs to SNS-W ...");
    {
        let wasm = build_index_ng_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_ledger_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_archive_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // ---------------------------
    // --- Run code under test ---
    // ---------------------------

    eprintln!("Deploy an SNS instance via proposal ...");
    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    eprintln!("Testing the Archive canister requires that it can be spawned ...");
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns.governance.canister_id,
        sns.ledger.canister_id,
    )
    .await;
    // TODO eventually we need to test a swap
}
