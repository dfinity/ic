use ic_sns_swap_protobuf_generator::{ProtoPaths, generate_prost_files};
use ic_test_utilities_compare_dirs::{CompareError, compare};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let cmd = "bazel run //rs/sns/swap/protobuf_generator:protobuf_generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");

    let swap_proto = manifest_dir.join("proto");
    // TODO(NNS1-1589): Uncomment.
    // let sns_root_proto = manifest_dir.join("../root/proto");
    let base_types_proto = manifest_dir.join("../../types/base_types/proto");
    let ledger_proto = manifest_dir.join("../../ledger_suite/icp/proto");
    let nervous_system_proto = manifest_dir.join("../../nervous_system/proto/proto");

    generate_prost_files(
        ProtoPaths {
            swap: &swap_proto,
            // TODO(NNS1-1589): Uncomment.
            // sns_root: &sns_root_proto,
            base_types: &base_types_proto,
            ledger: &ledger_proto,
            nervous_system: &nervous_system_proto,
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
