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
//! We don't yet download the mainnet release version, since they don't have the
//! required binaries published. We just download some random previous version
//! that does.
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
//! Implemented as a system test since binary downloads from the CDN don't
//! work from plain Rust tests for some reason, and debugging/fixing this seems
//! neither fun nor profitable.

use anyhow::Result;
use slog::{info, Logger};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ic_recovery::file_sync_helper::download_binary;
use ic_system_test_driver::driver::{group::SystemTestGroup, test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::ReplicaVersion;

fn data_dependency_file(dependency_path: &str) -> PathBuf {
    let runfiles_path: PathBuf = env::var("RUNFILES_DIR")
        .expect("RUNFILES_DIR not set; are you running this from Bazel?")
        .into();
    runfiles_path.join(dependency_path)
}

fn run_unit_test(
    binary: &Path,
    test_name: &str,
    current_dir: &Path,
    logger: &Logger,
) -> std::process::Output {
    let mut cmd = Command::new(binary);
    cmd.arg(test_name)
        .arg("--include-ignored")
        .arg("--nocapture")
        .current_dir(current_dir);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Could not execute unit test binary {binary:?}: {e:?}"));
    info!(logger, "Command output: {:?}", output);
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

fn download_mainnet_binary(
    binary_name: &str,
    version: String,
    target_dir: &Path,
    log: &Logger,
) -> PathBuf {
    block_on(ic_system_test_driver::retry_with_msg_async!(
        "download mainnet binary",
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            download_binary(
                log,
                ReplicaVersion::try_from(version.clone()).unwrap(),
                binary_name.into(),
                target_dir,
            )
            .await
            .map_err(|e| e.into())
        }
    ))
    .expect("Failed to Download")
}

/// Check that the artifacts produced by the `test_module` of `from_binary` can be ingested by
/// the `test_module` of the `to_binary`
///
/// The from/to_binary are expected to be Rust test binaries, and the `test_module` is
/// expected to define `serialize` and `deserialize` functions.
fn test_one_direction(
    from_binary: &Path,
    to_binary: &Path,
    test_module: &str,
    tmp_dir: &Path,
    logger: &Logger,
) {
    run_unit_test(
        from_binary,
        &format!("{}::serialize", test_module),
        tmp_dir,
        logger,
    );

    // Sanity check that the serializer has created at least one file
    let nr_files = fs::read_dir(tmp_dir).unwrap().count();
    assert!(nr_files > 0);

    run_unit_test(
        to_binary,
        &format!("{}::deserialize", test_module),
        tmp_dir,
        logger,
    );
}

struct TestCase {
    published_binary: String,
    test_binary: String,
    test_module: String,
}

impl TestCase {
    fn new(published_binary: &str, test_binary: &str, test_module: &str) -> Self {
        Self {
            published_binary: published_binary.to_string(),
            test_binary: test_binary.to_string(),
            test_module: test_module.to_string(),
        }
    }

    pub fn bidirectional_test(&self, mainnet_version: String, logger: &Logger) {
        let download_dir = tempfile::tempdir().unwrap();
        let download_dir_path = download_dir.path();
        let published_binary = download_mainnet_binary(
            &self.published_binary,
            mainnet_version.clone(),
            download_dir_path,
            logger,
        );
        let test_binary = data_dependency_file(&self.test_binary);
        info!(
            logger,
            "Testing module {} with the mainnet commit {} and published binary {}",
            self.test_module,
            mainnet_version,
            self.published_binary
        );
        for (direction, from, to) in [
            ("upgrade", &published_binary, &test_binary),
            ("current self-compatibility", &test_binary, &test_binary),
            ("downgrade", &test_binary, &published_binary),
        ] {
            info!(logger, "Testing {}", direction);
            let tmp_dir = tempfile::tempdir().unwrap();
            let tmp_dir_path = tmp_dir.path();
            test_one_direction(from, to, &self.test_module, tmp_dir_path, logger);
        }
    }
}

fn test(env: TestEnv) {
    let logger = env.logger();

    let test_case = TestCase::new(
        "replicated-state-test",
        "ic/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
        "canister_state::queues::tests::mainnet_compatibility_tests::basic_test",
    );
    // TODO: read this from mainnet_revisions.json once the mainnet releases
    // have the fixture binaries published
    let mainnet_versions = vec!["38565ef90ef16d47f0d4646903bba61226f36d40".to_string()];
    info!(logger, "Mainnet versions: {:?}", mainnet_versions);

    for mainnet_version in mainnet_versions {
        test_case.bidirectional_test(mainnet_version, &logger)
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|_| ())
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
