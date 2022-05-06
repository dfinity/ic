use std::env::{self, VarError};
use std::path::PathBuf;

fn main() {
    let archive_path = match env::var("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH") {
        Ok(wasm_path) => PathBuf::from(wasm_path),
        Err(VarError::NotPresent) => PathBuf::from("wasm/ledger-archive-node-canister.wasm")
            .canonicalize()
            .expect("failed to canonicalize a path"),
        Err(VarError::NotUnicode(path)) => panic!(
            "Ledger archive node Wasm path contains non-unicode characters: {:?}",
            path
        ),
    };

    println!("cargo:rerun-if-changed={}", archive_path.display());
    println!("cargo:rerun-if-env-changed=LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH");
    println!(
        "cargo:rustc-env=LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH={}",
        archive_path.display()
    );
}
