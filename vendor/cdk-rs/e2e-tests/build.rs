fn main() {
    // For the `macros` test
    prost_build::compile_protos(&["src/bin/macros/canister.proto"], &["src/"])
        .expect("Failed to compile protos");

    // For the `bindgen` test
    // Static Callee mode bindgen for the management_canister
    ic_cdk_bindgen::Config::new(
        "management_canister",
        "../ic-management-canister-types/tests/ic.did",
    )
    .set_type_selector_config("src/bin/bindgen_callee/management.toml")
    .static_callee(candid::Principal::management_canister())
    .generate();
    // Dynamic Callee mode bindgen for the bindgen_callee
    ic_cdk_bindgen::Config::new("bindgen_callee", "src/bin/bindgen_callee/callee.did")
        .dynamic_callee("ICP_CANISTER_ID:bindgen_callee")
        .generate();
}
