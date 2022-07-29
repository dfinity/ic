use candid::Encode;
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_nns_test_utils::common::{NnsInitPayloads, NnsInitPayloadsBuilder};
use ic_nns_test_utils::state_test_helpers::{self, create_canister, setup_nns_canisters};
use ic_state_machine_tests::StateMachine;

/// Create a `StateMachine` with NNS installed
pub fn set_up_state_machine_with_nns() -> StateMachine {
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    machine
}

pub fn install_sns_wasm(machine: &StateMachine, nns_init_payload: &NnsInitPayloads) -> CanisterId {
    let sns_wasm_bin =
        Project::cargo_bin_maybe_use_path_relative_to_rs("nns/sns-wasm", "sns-wasm-canister", &[]);

    create_canister(
        machine,
        sns_wasm_bin,
        Some(Encode!(&nns_init_payload.sns_wasms.clone()).unwrap()),
        None,
    )
}
