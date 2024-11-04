fn main() {
    // lib.rs depends on the environment variable UNIVERSAL_CANISTER_WASM_PATH which is set to the right value in BUILD.bazel.
    // To make cargo clippy / build work we set the variable to a fake value.
    println!(
        "cargo:rustc-env=UNIVERSAL_CANISTER_WASM_PATH={}",
        std::env::var("UNIVERSAL_CANISTER_WASM_PATH").unwrap_or("lib.rs".to_string())
    );
}
