use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, UNIVERSAL_CANISTER_WASM_SHA256};

#[test]
fn check_hardcoded_sha256_is_up_to_date() {
    assert_eq!(
        UNIVERSAL_CANISTER_WASM_SHA256,
        ic_crypto_sha2::Sha256::hash(UNIVERSAL_CANISTER_WASM)
    );
}

#[test]
fn check_hardcoded_module_is_up_to_date() {
    let actual_module_path = std::env::var_os("UNIVERSAL_CANISTER_WASM").unwrap();
    let actual_module = std::fs::read(actual_module_path).unwrap();
    assert_eq!(actual_module, UNIVERSAL_CANISTER_WASM);
}
