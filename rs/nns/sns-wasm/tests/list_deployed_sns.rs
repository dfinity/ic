use candid::Encode;
use canister_test::Project;
use ic_nns_test_utils::state_test_helpers::{create_canister, set_up_universal_canister};
use ic_nns_test_utils::{sns_wasm, state_test_helpers};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesResponse};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;

#[test]
fn list_deployed_snses_lists_created_sns_instances() {
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );

    let subnet_ids = machine.get_subnet_ids();

    let sns_wasm_canister_id = create_canister(
        &machine,
        wasm.clone(),
        Some(
            Encode!(&SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![subnet_ids[0]]
            })
            .unwrap(),
        ),
        None,
    );

    // Enough cycles for 2 SNS deploys
    let wallet_canister =
        set_up_universal_canister(&machine, Some(Cycles::new(50_000_000_000_000 * 2)));

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine, sns_wasm_canister_id);

    let root_1 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        sns_wasm_canister_id,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap()
    .root;

    let root_2 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        sns_wasm_canister_id,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap()
    .root;

    assert_ne!(root_1, root_2);

    // Also check that deployed SNSes are persisted across upgrades
    machine
        .upgrade_canister(sns_wasm_canister_id, wasm.bytes(), vec![])
        .unwrap();

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
