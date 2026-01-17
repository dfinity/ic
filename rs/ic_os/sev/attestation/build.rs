use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=proto/attestation.proto");
    let manifest_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut config = prost_build::Config::new();
    config.type_attribute(
        ".",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    config.compile_protos(
        &[manifest_path.join("proto/attestation.proto")],
        &[manifest_path],
    )?;

    // Run rustfmt on the generated file
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let generated_file = out_dir.join("attestation.rs");
    let rustfmt = std::env::var("RUSTFMT").unwrap_or_else(|_| "rustfmt".to_string());
    Command::new(rustfmt)
        .arg("--emit")
        .arg("files")
        .arg(&generated_file)
        .output()?;

    Ok(())
}
