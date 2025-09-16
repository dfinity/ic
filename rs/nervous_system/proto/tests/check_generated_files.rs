use ic_nervous_system_proto_protobuf_generator::{ProtoPaths, generate_prost_files};
use ic_test_utilities_compare_dirs::{CompareError, compare};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let command_to_regenerate =
        "bazel run //rs/nervous_system/proto/protobuf_generator:protobuf_generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let nervous_system_proto = manifest_dir.join("./proto");
    let base_types_proto = manifest_dir.join("../../types/base_types/proto");

    generate_prost_files(
        ProtoPaths {
            nervous_system: &nervous_system_proto,
            base_types: &base_types_proto,
        },
        out_dir.path(),
    );

    let r#gen = manifest_dir.join("src/gen");

    match compare(&r#gen, out_dir.path()) {
        Ok(_) => (),
        Err(CompareError::PathsDiffer { .. }) => {
            panic!(
                "Directory {} is outdated, run {}",
                r#gen.display(),
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
