fn main() {
    let did_path = std::path::PathBuf::from("archive.did")
        .canonicalize()
        .unwrap();

    println!("cargo:rustc-env=ARCHIVE_DID_PATH={}", did_path.display());
}
