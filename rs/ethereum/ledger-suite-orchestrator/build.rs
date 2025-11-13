use std::env::{self};
use std::path::PathBuf;

fn main() {
    let cargo_manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let compile_time_env_variables = [
        "LEDGER_CANISTER_WASM_PATH",
        "INDEX_CANISTER_WASM_PATH",
        "LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH",
    ];
    for env_var in compile_time_env_variables {
        let archive_path = match env::var_os(env_var) {
            Some(wasm_path) => PathBuf::from(wasm_path),
            None => cargo_manifest_dir
                // This is a hack.
                // Cargo is called on CI via ci/src/rust_lint/lint.sh.
                // The included WASMS binary for ledger, index and archive canisters are built by BAZEL tasks
                // which would need here to be somehow spawned by Cargo. To avoid this, we just use a wasm binary that
                // happens to be already checked-in in the repo.
                .join("../../ledger_suite/icrc1/wasm/ic-icrc1-archive.wasm.gz")
                .canonicalize()
                .expect("failed to canonicalize a path"),
        };

        println!("cargo:rerun-if-changed={}", archive_path.display());
        println!("cargo:rerun-if-env-changed={env_var}");
        println!("cargo:rustc-env={}={}", env_var, archive_path.display());
    }
}
