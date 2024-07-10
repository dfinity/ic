//! This a WIP upgrade/downgrade test for canister queues. The approach (following
//! the CUP compatibility tests):
//!
//! 1. At each commit to master, we create a binary that can serialize and
//!    deserialize queues according to the current logic (see
//!    binaries/publish/BUILD.bazel).
//!
//! 2. We add a test that uses:
//!
//!    a. the binary from the commit that matches the latest mainnet versions, as
//!    defined in mainnet_revisions.json, (the binary is downloaded from S3)
//!
//!    b. the binary from the current commit
//!
//!    and then checks that the artifacts serialized by one version can be deserialized
//!    by the other. As the today's special (free of charge), we also check that the
//!    current version can deserialize its own stuff.
//!
//! Currently this file is just a skeleton of the second step, as we haven't
//! committed the binary to master and published it to S3 yet.
//!
//! We also follow he approach from the CUP compatibility tests in that the binary
//! used is actually the binary produced by the rust_test, and not a separate
//! target. The second step then uses the fact that Rust test binaries can be passed
//! the name of the test as the argument, to perform the
//! serialization/deserialization. The convention is that there should be two test
//! functions called serialize and deserialize somewhere in the test suite. This is
//! a bit hacky, but gets around the annoying Rust test code visibility limitations,
//! allowing the test serializers/deserializers to use unit test code from
//! replicated_state.
//!
//! What's not adopted from CUP compatibility is the use of system tests, because
//! plain old Rust tests seem to do the trick just fine.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn data_dependency_file(dependency_path: &str) -> PathBuf {
    let runfiles_path: PathBuf = env::var("RUNFILES_DIR")
        .expect("RUNFILES_DIR not set; are you running this from Bazel?")
        .into();
    runfiles_path.join(dependency_path)
}

fn run_unit_test(binary: &Path, test_name: &str, current_dir: &Path) -> std::process::Output {
    let mut cmd = Command::new(binary);
    cmd.arg(test_name)
        .arg("--include-ignored")
        .arg("--nocapture")
        .current_dir(current_dir);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Could not execute unit test binary {binary:?}: {e:?}"));
    println!("Command output: {:?}", output);
    assert!(
        output.status.success(),
        "Command failed: with status {:?}",
        output.status
    );
    // If the given test doesn't actually exist, the test command will still pass.
    // We search the output for an indication that a test was actually executed.
    // Fragile, but better than nothing.
    assert!(
        std::str::from_utf8(&output.stdout).unwrap().contains("1 passed"),
        "Trying to execute {} from {:?}, but no test with such name was found.\nCheck that you don't have a typo in the name of the target module or test?",
        test_name,
        binary.file_name().unwrap(),
    );
    output
}

/// The test cases we want to execute; these are modules with tests called "serialize" and "deserialize".
/// The first element is the path to the test binary, which can be derived from the Bazel target.
/// The second element is the fully qualified name of the module implementing the test case.
const TESTS: &[(&str, &str)] = &[(
    "ic/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
    "canister_state::queues::tests::mainnet_compatibility_tests::basic_test",
)];

#[test]
fn compatibility_test() {
    // TODO: Add the actual up/downgrade tests once the basic test is merged to master
    for (binary_name, test_module) in TESTS {
        let binary = data_dependency_file(binary_name);
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_dir_path = tmp_dir.path();
        run_unit_test(
            &binary,
            &format!("{}::serialize", test_module),
            tmp_dir_path,
        );
        let nr_files = fs::read_dir(tmp_dir_path).unwrap().count();
        assert_eq!(nr_files, 1);
        run_unit_test(
            &binary,
            &format!("{}::deserialize", test_module),
            tmp_dir_path,
        );
    }
}
