use candid::Encode;
use canister_test::Project;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_ledger_sns_wasm, build_root_sns_wasm,
};
use ic_nns_test_utils::state_test_helpers::create_canister_with_cycles;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesResponse};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;

#[test]
fn list_deployed_snses_lists_created_sns_instances() {
    // We don't want the underlying warnings of the StateMachine
    let machine = StateMachine::new();
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );

    let subnet_ids = machine.get_subnet_ids();

    // TODO(NNS1-1444) Send the cycles in the request instead of creating the canister with sufficient
    // cycles for the test
    let sns_wasm_canister_id = create_canister_with_cycles(
        &machine,
        wasm,
        Some(
            Encode!(&SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![subnet_ids[0]]
            })
            .unwrap(),
        ),
        // 1000x cycles we currently are using per canister
        // TODO(NNS1-1444) start with no cycles
        Cycles::new(1_000_000_000_000),
        None,
    );

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    sns_wasm::add_wasm(&machine, sns_wasm_canister_id, root_wasm, &root_hash);

    let governance_wasm = build_governance_sns_wasm();
    let governance_hash = governance_wasm.sha256_hash();
    sns_wasm::add_wasm(
        &machine,
        sns_wasm_canister_id,
        governance_wasm,
        &governance_hash,
    );

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_hash = ledger_wasm.sha256_hash();
    sns_wasm::add_wasm(&machine, sns_wasm_canister_id, ledger_wasm, &ledger_hash);

    let root_1 = sns_wasm::deploy_new_sns(&machine, sns_wasm_canister_id)
        .canisters
        .unwrap()
        .root;
    let root_2 = sns_wasm::deploy_new_sns(&machine, sns_wasm_canister_id)
        .canisters
        .unwrap()
        .root;

    assert_ne!(root_1, root_2);

    let response = sns_wasm::list_deployed_snses(&machine, sns_wasm_canister_id);

    assert_eq!(
        response,
        ListDeployedSnsesResponse {
            instances: vec![
                DeployedSns {
                    root_canister_id: root_1,
                },
                DeployedSns {
                    root_canister_id: root_2,
                },
            ]
        }
    );
}
