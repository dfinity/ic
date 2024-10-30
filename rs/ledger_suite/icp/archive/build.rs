use std::path::PathBuf;

fn main() {
    let did_path = PathBuf::from("../ledger_archive.did")
        .canonicalize()
        .unwrap();

    println!("cargo:rerun-if-changed={}", did_path.display());
    println!(
        "cargo:rustc-env=LEDGER_ARCHIVE_DID_PATH={}",
        did_path.display()
    );
}
