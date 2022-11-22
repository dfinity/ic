fn main() {
    let did_path = std::path::PathBuf::from("ckbtc_minter.did")
        .canonicalize()
        .unwrap();

    println!(
        "cargo:rustc-env=CKBTC_MINTER_DID_PATH={}",
        did_path.display()
    );
}
