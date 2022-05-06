use ic_base_types_protobuf_generator::generate_prost_files;
use ic_test_utilities_compare_dirs::{compare, CompareError};
use std::path::PathBuf;

#[test]
fn check_generated_files() {
    let cmd = "cargo run --bin ic-base-types-protobuf-generator";

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let def = manifest_dir.join("proto");
    let out = tempfile::TempDir::new().expect("failed to create a temporary directory");
    generate_prost_files(&def, out.path());

    let gen = manifest_dir.join("gen");
    match compare(&gen, out.path()) {
        Ok(_) => (),
        Err(CompareError::PathsDiffer { left, right }) => {
            panic!(
                "Directory {} is outdated ({:?} vs {:?}), run {}",
                gen.display(),
                left,
                right,
                cmd
            )
        }
        Err(CompareError::ContentDiffers { path }) => {
            panic!("Source file {} is outdated, run {}", path.display(), cmd)
        }
        Err(CompareError::IoError { path, cause }) => {
            panic!("I/O error on {}: {}", path.display(), cause)
        }
    }
}
