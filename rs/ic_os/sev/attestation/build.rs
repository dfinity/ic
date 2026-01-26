use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=proto/attestation.proto");
    let manifest_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let mut config = prost_build::Config::new();
    config.type_attribute(
        ".",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    // Speed up deserialization of `opt blob`/`Option<Vec<u8>>` fields.
    config.field_attribute(
        "attestation.SevAttestationPackage.attestation_report",
        r#"#[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]"#,
    );
    config.compile_protos(
        &[manifest_path.join("proto/attestation.proto")],
        &[manifest_path],
    )?;

    ic_utils_rustfmt::rustfmt(&out_dir)?;

    Ok(())
}
