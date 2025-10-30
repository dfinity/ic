use candid::{Decode, encode_args};
use canister_test::Project;
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;

#[test]
fn test_anonymous_http_request_validation() {
    let env = StateMachine::new();
    let canister_id = {
        let wasm =
            Project::cargo_bin_maybe_from_env("ic-validator-ingress-message-test-canister", &[]);

        env.install_canister(wasm.bytes(), /* args= */ vec![], None)
            .unwrap()
    };

    // Verify that an HTTP request with its ingress expiry set to genesis is valid at the
    // current time of the validator in the canister (when also set to genesis).
    let time_nanos_at_genesis = ic_types::time::GENESIS.as_nanos_since_unix_epoch();
    let args = encode_args((time_nanos_at_genesis, time_nanos_at_genesis)).unwrap();
    let result = env
        .query(
            canister_id,
            "create_and_validate_anonymous_http_with_ingress_expiry_time",
            args,
        )
        .unwrap();
    assert!(is_http_request_valid(result));

    // Verify that an HTTP request with its ingress expiry set to the UNIX epoch is invalid at the
    // current time of the canister (genesis).
    let args = encode_args((time_nanos_at_genesis, 0u64)).unwrap();
    let result = env
        .query(
            canister_id,
            "create_and_validate_anonymous_http_with_ingress_expiry_time",
            args,
        )
        .unwrap();
    assert!(!is_http_request_valid(result));
}

fn is_http_request_valid(result: WasmResult) -> bool {
    match result {
        WasmResult::Reply(reply) => Decode!(&reply, bool).unwrap(),
        WasmResult::Reject(reject) => panic!("Reject: {reject:?}"),
    }
}
