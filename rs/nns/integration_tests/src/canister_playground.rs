use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_nns_test_utils::state_test_helpers::{
    create_canister, state_machine_builder_for_nns_tests, update_with_sender,
};
use std::time::Duration;

#[test]
fn test_canister_playground() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let canister_playground_wasm =
        Project::cargo_bin_maybe_from_env("canister-playground-canister", &[]);

    let playground_id =
        create_canister(&state_machine, canister_playground_wasm, Some(vec![]), None);

    let _: () = update_with_sender(
        &state_machine,
        playground_id,
        "test",
        (),
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    // Up to 10 seconds of excitement
    for _ in 1..100 {
        state_machine.tick();
        state_machine.advance_time(Duration::from_millis(100))
    }
}
