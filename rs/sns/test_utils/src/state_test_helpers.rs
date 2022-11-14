use crate::itest_helpers::populate_canister_ids;
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::CanisterInstallMode;
use ic_nns_constants::ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID;
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_index_sns_wasm, build_ledger_sns_wasm, build_root_sns_wasm,
    build_swap_sns_wasm,
};
use ic_nns_test_utils::state_test_helpers::set_controllers;
use ic_sns_init::SnsCanisterInitPayloads;
use ic_state_machine_tests::StateMachine;

#[derive(Debug)]
pub struct SnsTestCanisterIds {
    pub root_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub ledger_canister_id: CanisterId,
    pub swap_canister_id: CanisterId,
    pub index_canister_id: CanisterId,
}

pub fn setup_sns_canisters(
    state_machine: &StateMachine,
    mut payloads: SnsCanisterInitPayloads,
) -> SnsTestCanisterIds {
    let create_canister = || state_machine.create_canister(/* settings= */ None);
    let install_canister = |canister_id, wasm, payload| {
        state_machine
            .install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, payload)
            .unwrap()
    };

    let root_canister_id = create_canister();
    let governance_canister_id = create_canister();
    let ledger_canister_id = create_canister();
    let swap_canister_id = create_canister();
    let index_canister_id = create_canister();

    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        root_canister_id,
        vec![governance_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        governance_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        ledger_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        swap_canister_id,
        vec![NNS_ROOT_CANISTER_ID.into(), swap_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        index_canister_id,
        vec![root_canister_id.into()],
    );

    populate_canister_ids(
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
        &mut payloads,
    );

    let SnsCanisterInitPayloads {
        governance,
        ledger,
        root,
        swap,
        index,
    } = payloads;

    install_canister(
        root_canister_id,
        build_root_sns_wasm().wasm,
        Encode!(&root).unwrap(),
    );
    install_canister(
        governance_canister_id,
        build_governance_sns_wasm().wasm,
        Encode!(&governance).unwrap(),
    );
    install_canister(
        ledger_canister_id,
        build_ledger_sns_wasm().wasm,
        Encode!(&ledger).unwrap(),
    );
    install_canister(
        swap_canister_id,
        build_swap_sns_wasm().wasm,
        Encode!(&swap).unwrap(),
    );
    install_canister(
        index_canister_id,
        build_index_sns_wasm().wasm,
        Encode!(&index).unwrap(),
    );

    SnsTestCanisterIds {
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
    }
}
