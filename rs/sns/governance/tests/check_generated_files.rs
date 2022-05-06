use ic_sns_governance_protobuf_generator::{generate_prost_files, ProtoPaths};
use ic_test_utilities_compare_dirs::{compare, CompareError};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let cmd = "cargo run --bin ic-sns-governance-protobuf-generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let governance_proto = manifest_dir.join("proto");
    let base_types_proto = manifest_dir.join("../../types/base_types/proto");
    let ledger_proto = manifest_dir.join("../../rosetta-api/ledger_canister/proto");
    generate_prost_files(
        ProtoPaths {
            governance: &governance_proto,
            base_types: &base_types_proto,
            ledger: &ledger_proto,
        },
        out.path(),
    );

    let gen = manifest_dir.join("gen");

    match compare(&gen, out.path()) {
        Ok(_) => (),
        Err(CompareError::PathsDiffer { .. }) => {
            panic!("Directory {} is outdated, run {}", gen.display(), cmd)
        }
        Err(CompareError::ContentDiffers { path }) => {
            panic!("Source file {} is outdated, run {}", path.display(), cmd)
        }
        Err(CompareError::IoError { path, cause }) => {
            panic!("I/O error on {}: {}", path.display(), cause)
        }
    }
}
