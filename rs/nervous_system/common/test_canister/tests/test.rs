use candid::Decode;
use canister_test::Project;
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;

#[test]
fn test_root() {
    // Step 1: Prepare.

    // Step 1.a: Make canister executor/supervisor/environment.
    let env = StateMachine::new();

    // Step 1.b: Build and install canister.
    let canister_id = {
        // Build canister (or use pre-built).
        let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "nervous_system/common/test_canister",
            "ic-nervous-system-common-test-canister",
            &[], // features
        );

        env.install_canister(wasm.bytes(), /* args= */ vec![], None)
            .unwrap()
    };

    // Step 2: Use canister.
    let get_build_metadata_args = candid::encode_args(()).unwrap();
    let build_metadata = env
        .query(canister_id, "get_build_metadata", get_build_metadata_args)
        .unwrap();

    // Step 3: Inspect results.
    let build_metadata = match build_metadata {
        WasmResult::Reply(reply) => Decode!(&reply, String).unwrap(),
        WasmResult::Reject(reject) => panic!("Reject: {:?}", reject),
    };
    assert!(
        build_metadata.contains("crate_name: ic-nervous-system-common-test-canister"),
        "build_metadata: {:?}",
        build_metadata
    );
}
