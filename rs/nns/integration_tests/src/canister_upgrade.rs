use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{install_code::CanisterInstallMode, proposal::Action};
use ic_nns_test_utils::common::{
    build_governance_wasm, build_lifeline_wasm, build_root_wasm, modify_wasm_bytes,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        nns_governance_get_proposal_info_as_anonymous, nns_propose_upgrade_nns_canister,
        setup_nns_canisters, state_machine_builder_for_nns_tests,
        wait_for_canister_upgrade_to_succeed,
    },
};

fn test_upgrade_canister(canister_id: CanisterId, canister_wasm: Wasm, use_proposal_action: bool) {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let n1 = get_neuron_1();

    let modified_wasm = modify_wasm_bytes(&canister_wasm.bytes(), 42);

    let proposal_id = nns_propose_upgrade_nns_canister(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        canister_id,
        modified_wasm.clone(),
        vec![],
        use_proposal_action,
    );

    let controller_canister_id = if canister_id == ROOT_CANISTER_ID {
        PrincipalId::from(LIFELINE_CANISTER_ID)
    } else {
        PrincipalId::from(ROOT_CANISTER_ID)
    };

    wait_for_canister_upgrade_to_succeed(
        &state_machine,
        canister_id,
        &Sha256::hash(&modified_wasm),
        controller_canister_id,
    );

    if use_proposal_action {
        let proposal_info =
            nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
        let action = proposal_info.proposal.unwrap().action.unwrap();
        if let Action::InstallCode(install_code) = action {
            assert_eq!(
                install_code.wasm_module_hash,
                Some(Sha256::hash(&modified_wasm).to_vec())
            );
            assert_eq!(install_code.arg_hash, Some(vec![]));
            assert_eq!(
                install_code.install_mode,
                Some(CanisterInstallMode::Upgrade as i32)
            );
            assert_eq!(install_code.canister_id, Some(canister_id.get()));
            assert_eq!(install_code.skip_stopping_before_installing, None);
        } else {
            panic!("Unexpected action: {:?}", action);
        }
    }
}

#[test]
fn upgrade_canisters_by_proposal() {
    test_upgrade_canister(GOVERNANCE_CANISTER_ID, build_governance_wasm(), true);
    test_upgrade_canister(GOVERNANCE_CANISTER_ID, build_governance_wasm(), false);
    test_upgrade_canister(ROOT_CANISTER_ID, build_root_wasm(), false);
    test_upgrade_canister(ROOT_CANISTER_ID, build_root_wasm(), true);
    test_upgrade_canister(LIFELINE_CANISTER_ID, build_lifeline_wasm(), true);
    test_upgrade_canister(LIFELINE_CANISTER_ID, build_lifeline_wasm(), false);
}
