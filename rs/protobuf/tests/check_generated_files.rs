use ic_protobuf_generator::generate_prost_files;
use ic_test_utilities_compare_dirs::{CompareError, compare};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let cmd = "bazel run //rs/protobuf/generator:generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let def = manifest_dir.join("def");
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    generate_prost_files(&def, out.path());

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
