use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, nns, sns, upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::governance::ONE_MONTH_SECONDS;
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_governance_sns_wasm, build_index_ng_sns_wasm,
    build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm, create_modified_sns_wasm,
    ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::{DeployedSns, SnsCanisterType};

#[test]
fn test_tip_of_master_deployment() {
    test_sns_deployment(
        vec![
            GOVERNANCE_CANISTER_ID,
            SNS_WASM_CANISTER_ID,
            LEDGER_CANISTER_ID,
            ROOT_CANISTER_ID,
        ],
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
fn test_tip_of_master_upgrade_everything() {
    test_sns_upgrade(vec![
        SnsCanisterType::Root,
        SnsCanisterType::Governance,
        SnsCanisterType::Ledger,
        SnsCanisterType::Swap,
        SnsCanisterType::Index,
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
        governance_canister_id: Some(sns_governance_canister_id),
        ledger_canister_id: Some(sns_ledger_canister_id),
        swap_canister_id: Some(swap_canister_id),
        ..
    } = deployed_sns
    else {
        panic!("Cannot find some SNS caniser IDs in {:#?}", deployed_sns);
    };

    // Testing the Archive canister requires that it can be spawned.
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns_governance_canister_id,
        sns_ledger_canister_id,
    );

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
            SnsCanisterType::Root => create_modified_sns_wasm(&build_root_sns_wasm(), Some("foo")),
            SnsCanisterType::Governance => {
                create_modified_sns_wasm(&build_governance_sns_wasm(), Some("foo"))
            }
            SnsCanisterType::Ledger => {
                create_modified_sns_wasm(&build_ledger_sns_wasm(), Some("foo"))
            }
            SnsCanisterType::Swap => create_modified_sns_wasm(&build_swap_sns_wasm(), Some("foo")),
            SnsCanisterType::Index => {
                create_modified_sns_wasm(&build_index_ng_sns_wasm(), Some("foo"))
            }
            SnsCanisterType::Unspecified => {
                panic!("Where did you get this canister type from?")
            }
            SnsCanisterType::Archive => {
                create_modified_sns_wasm(&build_archive_sns_wasm(), Some("foo"))
            }
        };

        let wasm = ensure_sns_wasm_gzipped(wasm);
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Testing the Archive canister requires that it can be spawned.
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns_governance_canister_id,
        sns_ledger_canister_id,
    );

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
