use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=proto/attestation.proto");
    let manifest_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut config = prost_build::Config::new();
    // config.out_dir("src/gen");
    config.type_attribute(
        ".",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    config.compile_protos(
        &[manifest_path.join("proto/attestation.proto")],
        &[manifest_path],
    )?;
    Ok(())
}
