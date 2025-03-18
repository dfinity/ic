use candid::{Decode, Encode};
use ic_nns_test_utils::common::{
    build_node_rewards_test_wasm, build_node_rewards_wasm, NnsInitPayloadsBuilder,
};
use ic_nns_test_utils::state_test_helpers::{
    query, setup_nns_canisters, state_machine_builder_for_nns_tests,
};
use ic_node_rewards_canister_api::lifecycle_args::InitArgs;
use ic_registry_keys::make_subnet_record_key;
use ic_state_machine_tests::StateMachine;
use ic_types::{PrincipalId, SubnetId};

#[test]
fn test_registry_value_syncing() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, init_payloads);

    let wasm = build_node_rewards_test_wasm();

    let canister_id = state_machine
        .install_canister(wasm.bytes(), Encode!(&InitArgs {}).unwrap(), None)
        .unwrap();

    // This is the value from invariant_compliant_mutation
    let test_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(999));
    let response = query(
        &state_machine,
        canister_id,
        "get_registry_value",
        Encode!(&make_subnet_record_key(test_subnet_id)).unwrap(),
    )
    .unwrap();

    let decoded = Decode!(&response, Result<Option<Vec<u8>>, String>).unwrap();

    assert_eq!(decoded, Ok(None));
}
