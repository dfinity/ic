pub fn ledger_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_LEDGER_WASM_PATH")
}

pub fn load_wasm_using_env_var(env_var: &str) -> Vec<u8> {
    let wasm_path = std::env::var(env_var).unwrap_or_else(|e| {
        panic!(
            "The wasm path must be set using the env variable {} ({})",
            env_var, e
        )
    });
    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm file from path {} (env var {}): {}",
            wasm_path, env_var, e
        )
    })
}
