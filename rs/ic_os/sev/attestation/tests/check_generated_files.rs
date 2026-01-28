use ic_utils_rustfmt::rustfmt;
use std::path::PathBuf;

fn generate_prost_files(proto_dir: &std::path::Path, out_dir: &std::path::Path) {
    let mut config = prost_build::Config::new();
    config.out_dir(out_dir);
    config.type_attribute(
        ".",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    // Speed up deserialization of `opt blob`/`Option<Vec<u8>>` fields.
    config.field_attribute(
        "attestation.SevAttestationPackage.attestation_report",
        r#"#[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]"#,
    );
    config
        .compile_protos(&[proto_dir.join("attestation.proto")], &[proto_dir])
        .expect("Failed to compile protos");

    rustfmt(out_dir).expect("Failed to run rustfmt");
}

#[test]
fn check_generated_files() {
    let regenerate = std::env::var("REGENERATE").is_ok();

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let proto_dir = manifest_dir.join("proto");
    let committed_file = manifest_dir.join("src/proto_gen/attestation.rs");

    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    generate_prost_files(&proto_dir, out.path());
    let generated_file = out.path().join("attestation.rs");

    if regenerate {
        std::fs::copy(&generated_file, &committed_file).expect("Failed to copy generated file");
        println!("Regenerated {}", committed_file.display());
    } else {
        let committed_content =
            std::fs::read_to_string(&committed_file).expect("Failed to read committed file");
        let generated_content =
            std::fs::read_to_string(&generated_file).expect("Failed to read generated file");

        if committed_content != generated_content {
            panic!(
                "File {} is outdated, run:\nREGENERATE=1 cargo test -p attestation --test check_generated_files",
                committed_file.display()
            );
        }
    }
}
