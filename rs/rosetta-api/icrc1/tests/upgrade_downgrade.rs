#[test]
fn should_upgrade_and_downgrade_ledger_canister_suite() {
    let index_mainnet_wasm = index_mainnet_wasm();
    let index_wasm = index_wasm();
    assert_ne!(index_wasm, index_mainnet_wasm);
    let ledger_mainnet_wasm = ledger_mainnet_wasm();
    let ledger_wasm = ledger_wasm();
    assert_ne!(ledger_wasm, ledger_mainnet_wasm);
    assert_eq!(1, 3);
}

fn index_mainnet_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_INDEX_NG_DEPLOYED_VERSION_WASM_PATH")
}

fn index_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_INDEX_NG_WASM_PATH")
}

fn ledger_mainnet_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH")
}

fn ledger_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_LEDGER_WASM_PATH")
}

fn load_wasm_using_env_var(env_var: &str) -> Vec<u8> {
    let wasm_path = std::env::var(env_var).expect(&format!(
        "The wasm path must be set using the env variable {}",
        env_var
    ));
    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm file from path {} (env var {}): {}",
            wasm_path, env_var, e
        )
    })
}
