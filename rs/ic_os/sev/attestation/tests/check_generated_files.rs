use ic_utils_rustfmt::rustfmt;
use std::path::PathBuf;

fn generate_prost_files(proto_dir: &std::path::Path, out_dir: &std::path::Path) {
    let mut config = prost_build::Config::new();
    config.out_dir(out_dir);
    config.type_attribute(
        ".",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
    );
    config
        .compile_protos(&[proto_dir.join("attestation.proto")], &[proto_dir])
        .expect("Failed to compile protos");

    // Format the generated files to match what build.rs produces
    rustfmt(out_dir).expect("Failed to run rustfmt");
}

#[test]
fn check_generated_files() {
    let cmd = "bazel build //rs/ic_os/sev/attestation:build_script && \
               cp bazel-bin/rs/ic_os/sev/attestation/build_script.out_dir/attestation.rs \
               rs/ic_os/sev/attestation/src/proto_gen/";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let proto_dir = manifest_dir.join("proto");
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    generate_prost_files(&proto_dir, out.path());

    let committed_file = manifest_dir.join("src/proto_gen/attestation.rs");
    let generated_file = out.path().join("attestation.rs");

    let committed_content =
        std::fs::read_to_string(&committed_file).expect("Failed to read committed file");
    let generated_content =
        std::fs::read_to_string(&generated_file).expect("Failed to read generated file");

    if committed_content != generated_content {
        panic!(
            "File {} is outdated, run:\n{}",
            committed_file.display(),
            cmd
        );
    }
}
