fn main() {
    // Note that this build script is only used for `cargo clippy / build` and not for the bazel build.
    // It sets the UNIVERSAL_CANISTER_WASM_PATH environment variable to a fake value to let lib.rs compile.
    println!(
        "cargo:rustc-env=UNIVERSAL_CANISTER_WASM_PATH={}",
        std::env::var("UNIVERSAL_CANISTER_WASM_PATH").unwrap_or("lib.rs".to_string())
    );
}
