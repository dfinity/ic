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
    build_archive_sns_wasm, build_governance_sns_wasm, build_index_ng_sns_wasm,
    build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm, create_modified_sns_wasm,
    ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::{DeployedSns, SnsCanisterType};

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

/// Deployment tests
#[test]
fn test_deployment_all_upgrades() {
    test_sns_deployment(
        vec![GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID],
        vec![
            SnsCanisterType::Governance,
            SnsCanisterType::Ledger,
            SnsCanisterType::Root,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
        ],
    );
}

#[test]
fn test_deployment_with_only_nns_upgrades() {
    test_sns_deployment(vec![GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID], vec![]);
}

#[test]
fn test_deployment_with_only_sns_upgrades() {
    test_sns_deployment(
        vec![],
        vec![
            SnsCanisterType::Root,
            SnsCanisterType::Governance,
            SnsCanisterType::Ledger,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
        ],
    );
}

#[test]
fn test_deployment_with_sns_root_and_governance_upgrade() {
    test_sns_deployment(
        vec![],
        vec![SnsCanisterType::Root, SnsCanisterType::Governance],
    );
}

#[test]
fn test_deployment_swap_upgrade() {
    test_sns_deployment(vec![], vec![SnsCanisterType::Swap]);
}

/// Upgrade Tests
#[test]
fn test_upgrade_sns_gov_root() {
    test_sns_upgrade(vec![SnsCanisterType::Root, SnsCanisterType::Governance]);
}

#[test]
fn test_upgrade_upgrade_sns_gov_root() {
    test_sns_upgrade(vec![SnsCanisterType::Governance, SnsCanisterType::Root]);
}

#[test]
fn test_upgrade_everything() {
    test_sns_upgrade(vec![
        SnsCanisterType::Root,
        SnsCanisterType::Governance,
        SnsCanisterType::Swap,
        SnsCanisterType::Index,
        SnsCanisterType::Ledger,
        SnsCanisterType::Archive,
    ]);
}

/// Tests a deployment of the SNS.
/// Usually nns_canisters do not need to be upgraded, but sometimes they have to be due to dependencies
/// or API changes to init arguments
pub fn test_sns_deployment(
    nns_canisters_to_upgrade: Vec<CanisterId>, // should use constants from nns/constants to make this easy to track
    sns_canisters_to_upgrade: Vec<SnsCanisterType>,
) {
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

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
        upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, canister_id);
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
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Deploy an SNS instance via proposal.
    let sns_instance_label = "1";
    let (deployed_sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    );
    let DeployedSns {
        swap_canister_id: Some(swap_canister_id),
        ..
    } = deployed_sns
    else {
        panic!("Cannot find some SNS canister IDs in {:#?}", deployed_sns);
    };

    sns::swap::await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Open).unwrap();
    sns::swap::smoke_test_participate_and_finalize(&pocket_ic, swap_canister_id, swap_parameters);
}

fn test_sns_upgrade(sns_canisters_to_upgrade: Vec<SnsCanisterType>) {
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

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
    let sns_instance_label = "1";
    let (deployed_sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    );
    let DeployedSns {
        governance_canister_id: Some(sns_governance_canister_id),
        ledger_canister_id: Some(sns_ledger_canister_id),
        swap_canister_id: Some(swap_canister_id),
        ..
    } = deployed_sns
    else {
        panic!("Cannot find some SNS canister IDs in {:#?}", deployed_sns);
    };

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
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

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
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Only spawn an archive if we're testing it
    if sns_canisters_to_upgrade.contains(&SnsCanisterType::Archive) {
        // Testing the Archive canister requires that it can be spawned.
        sns::ensure_archive_canister_is_spawned_or_panic(
            &pocket_ic,
            sns_governance_canister_id,
            sns_ledger_canister_id,
        );
    }

    sns::swap::await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Open).unwrap();
    sns::swap::smoke_test_participate_and_finalize(&pocket_ic, swap_canister_id, swap_parameters);

    // Every canister we are testing has two upgrades.  We are just making sure the counts match
    for _ in sns_canisters_to_upgrade {
        sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
            &pocket_ic,
            sns_governance_canister_id,
        );
        sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
            &pocket_ic,
            sns_governance_canister_id,
        );
    }
}
