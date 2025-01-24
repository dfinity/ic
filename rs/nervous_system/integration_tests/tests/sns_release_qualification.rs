use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, nns, sns, upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm, build_root_sns_wasm,
    build_swap_sns_wasm, ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;

mod sns_upgrade_test_utils;
use sns_upgrade_test_utils::test_sns_upgrade;

/// In order to ensure that creating an SNS still works, we need to test the following:
/// We test new SNS canisters with mainnet NNS canisters
/// We test mainnet SNS canisters with new NNS canisters
/// We test new SNS canisters with new NNS canisters
/// We test just swap in a deployment
/// We test just governance and root in an upgrade
///
/// For upgrades, we are concerned with ensuring that each canister is not by itself a terminal upgrade
/// so we test every canister's upgrade all in one test
/// We also are concerned with ensuring that root/governance do not need a particular order of upgrading
/// since there is sometimes a dependency between them, so we test them in both orders.
///
/// Note: FI canisters are considered fully tested elsewhere, and have stable APIs.
///
/// Deployment tests

#[tokio::test]
async fn test_deployment_all_upgrades() {
    test_sns_deployment(
        vec![GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID],
        vec![
            SnsCanisterType::Governance,
            SnsCanisterType::Ledger,
            SnsCanisterType::Root,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
        ],
    )
    .await;
}

#[tokio::test]
async fn test_deployment_with_only_nns_upgrades() {
    test_sns_deployment(vec![GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID], vec![]).await;
}

#[tokio::test]
async fn test_deployment_with_only_sns_upgrades() {
    test_sns_deployment(
        vec![],
        vec![
            SnsCanisterType::Root,
            SnsCanisterType::Governance,
            SnsCanisterType::Ledger,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
        ],
    )
    .await;
}

#[tokio::test]
async fn test_deployment_with_sns_root_and_governance_upgrade() {
    test_sns_deployment(
        vec![],
        vec![SnsCanisterType::Root, SnsCanisterType::Governance],
    )
    .await;
}

#[tokio::test]
async fn test_deployment_swap_upgrade() {
    test_sns_deployment(vec![], vec![SnsCanisterType::Swap]).await;
}

/// Upgrade Tests
#[tokio::test]
async fn test_upgrade_swap() {
    test_sns_upgrade(vec![SnsCanisterType::Swap]).await;
}

#[tokio::test]
async fn test_upgrade_sns_gov_root() {
    test_sns_upgrade(vec![SnsCanisterType::Root, SnsCanisterType::Governance]).await;
}

#[tokio::test]
async fn test_upgrade_upgrade_sns_gov_root() {
    test_sns_upgrade(vec![SnsCanisterType::Governance, SnsCanisterType::Root]).await;
}

/// Tests a deployment of the SNS.
/// Usually nns_canisters do not need to be upgraded, but sometimes they have to be due to dependencies
/// or API changes to init arguments
pub async fn test_sns_deployment(
    nns_canisters_to_upgrade: Vec<CanisterId>, // should use constants from nns/constants to make this easy to track
    sns_canisters_to_upgrade: Vec<SnsCanisterType>,
) {
    let (pocket_ic, _initial_sns_version) =
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

    for canister_id in nns_canisters_to_upgrade {
        upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, canister_id).await;
    }

    for canister_type in sns_canisters_to_upgrade {
        let wasm = match canister_type {
            SnsCanisterType::Unspecified => {
                panic!("Where did you get this canister type from?")
            }
            SnsCanisterType::Archive => {
                panic!("Archive is not part of the deployment.  Not supported yet.")
            }
            SnsCanisterType::Root => build_root_sns_wasm(),
            SnsCanisterType::Governance => build_governance_sns_wasm(),
            SnsCanisterType::Ledger => build_ledger_sns_wasm(),
            SnsCanisterType::Swap => build_swap_sns_wasm(),
            SnsCanisterType::Index => build_index_ng_sns_wasm(),
        };

        let wasm = ensure_sns_wasm_gzipped(wasm);
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Deploy an SNS instance via proposal.
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
}
