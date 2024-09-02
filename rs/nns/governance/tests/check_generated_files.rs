use ic_nns_governance_protobuf_generator::{generate_prost_files, ProtoPaths};
use ic_test_utilities_compare_dirs::{compare, CompareError};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let command_to_regenerate =
        "bazel run //rs/nns/governance/protobuf_generator:protobuf_generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let governance_proto = manifest_dir.join("proto");

    let base_types_proto = manifest_dir.join("../../types/base_types/proto");
    let ledger_proto = manifest_dir.join("../../rosetta-api/icp_ledger/proto");
    let nervous_system_proto = manifest_dir.join("../../nervous_system/proto/proto");
    let nns_common_proto = manifest_dir.join("../common/proto");
    let sns_root_proto = manifest_dir.join("../../sns/root/proto");
    let sns_swap_proto = manifest_dir.join("../../sns/swap/proto");

    generate_prost_files(
        ProtoPaths {
            governance: &governance_proto,

            base_types: &base_types_proto,
            ledger: &ledger_proto,
            nervous_system: &nervous_system_proto,
            nns_common: &nns_common_proto,
            sns_root: &sns_root_proto,
            sns_swap: &sns_swap_proto,
        },
        out_dir.path(),
    );

    let gen = manifest_dir.join("src/gen");

    match compare(out_dir.path(), &gen) {
        Ok(_) => (),
        Err(CompareError::PathsDiffer { .. }) => {
            panic!(
                "Directory {} is outdated, run {}",
                gen.display(),
                command_to_regenerate
            )
        }
        Err(CompareError::ContentDiffers { path }) => {
            panic!(
                "Source file {} is outdated, run {}",
                path.display(),
                command_to_regenerate
            )
        }
        Err(CompareError::IoError { path, cause }) => {
            panic!("I/O error on {}: {}", path.display(), cause)
        }
    }
}
