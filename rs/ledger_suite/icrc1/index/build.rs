fn main() {
    let did_path = std::path::PathBuf::from("index.did")
        .canonicalize()
        .unwrap();

    println!("cargo:rustc-env=INDEX_DID_PATH={}", did_path.display());
}
