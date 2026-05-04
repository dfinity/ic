use std::env::{self};
use std::path::PathBuf;

fn main() {
    let cargo_manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let archive_path = match env::var_os("IC_ICRC1_ARCHIVE_WASM_PATH") {
        Some(wasm_path) => PathBuf::from(wasm_path),
        None => cargo_manifest_dir
            .join("../wasm/ic-icrc1-archive.wasm.gz")
            .canonicalize()
            .expect("failed to canonicalize a path"),
    };

    println!("cargo:rerun-if-changed={}", archive_path.display());
    println!("cargo:rerun-if-env-changed=IC_ICRC1_ARCHIVE_WASM_PATH");
    println!(
        "cargo:rustc-env=IC_ICRC1_ARCHIVE_WASM_PATH={}",
        archive_path.display()
    );
}
