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

#[test]
fn test_sns_upgrade() {
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .build();

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

    let original_neurons_fund_audit_info = nns::governance::get_neurons_fund_audit_info();
    assert_eq!(original_neurons_fund_audit_info, Some());

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID);

    let neurons_fund_audit_info = nns::governance::get_neurons_fund_audit_info();
    assert_eq!(original_neurons_fund_audit_info, neurons_fund_audit_info);
}
