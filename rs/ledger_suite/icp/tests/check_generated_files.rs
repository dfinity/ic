use ic_test_utilities_compare_dirs::{CompareError, compare};
use ledger_canister_protobuf_generator::{ProtoPaths, generate_prost_files};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let cmd = "bazel run //rs/ledger_suite/icp/protobuf_generator:protobuf_generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let ledger_proto = manifest_dir.join("proto");
    let base_types_proto = manifest_dir.join("../../types/base_types/proto");
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    generate_prost_files(
        ProtoPaths {
            ledger: &ledger_proto,
            base_types: &base_types_proto,
        },
        out.path(),
    );

    let r#gen = manifest_dir.join("src/gen");

    match compare(&r#gen, out.path()) {
        Ok(_) => (),
        Err(CompareError::PathsDiffer { .. }) => {
            panic!("Directory {} is outdated, run {}", r#gen.display(), cmd)
        }
        Err(CompareError::ContentDiffers { path }) => {
            panic!("Source file {} is outdated, run {}", path.display(), cmd)
        }
        Err(CompareError::IoError { path, cause }) => {
            panic!("I/O error on {}: {}", path.display(), cause)
        }
    }
}
