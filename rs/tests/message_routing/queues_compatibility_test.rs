//! This is an upgrade/downgrade test for canister queues. The approach (following
//! the CUP compatibility tests):
//!
//! 1. At each commit to master, we create a binary that can serialize and
//!    deserialize queues according to the current logic (see
//!    binaries/publish/BUILD.bazel).
//!
//! 2. We add a test that uses:
//!
//!    a. the binary from the commit that matches the latest mainnet versions, as
//!    defined in mainnet-icos-revisions.json, (the binary is downloaded from S3)
//!
//!    b. the binary from the current commit
//!
//!    and then checks that the artifacts serialized by one version can be deserialized
//!    by the other. As the today's special (free of charge), we also check that the
//!    current version can deserialize its own stuff.
//!
//! We follow the approach from the CUP compatibility tests in that the binary
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
use slog::{Logger, info};
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
    info!(
        logger,
        "Command output stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "Command failed: with status {:?}",
        output.status
    );
    // If the given test doesn't actually exist, the test command will still pass.
    // We search the output for an indication that a test was actually executed.
    // Fragile, but better than nothing.
    assert!(
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .contains("1 passed"),
        "Trying to execute {} from {:?}, but no test with such name was found.\nCheck that you don't have a typo in the name of the target module or test, and that the test is availalable in the provided version?",
        test_name,
        binary.file_name().unwrap(),
    );
    output
}

fn download_mainnet_binary(
    binary_name: &str,
    version: &ReplicaVersion,
    target_dir: &Path,
    log: &Logger,
) -> PathBuf {
    block_on(ic_system_test_driver::retry_with_msg_async!(
        "download mainnet binary",
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            download_binary(log, version, binary_name.into(), target_dir)
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

enum TestType {
    #[allow(dead_code)]
    SelfTestOnly,
    Bidirectional {
        published_binary: String,
        mainnet_version: ReplicaVersion,
    },
}

struct TestCase {
    test_binary: String,
    test_module: String,
    test_type: TestType,
}

impl TestCase {
    fn new(test_type: TestType, test_binary: &str, test_module: &str) -> Self {
        Self {
            test_binary: test_binary.to_string(),
            test_module: test_module.to_string(),
            test_type,
        }
    }

    pub fn run(&self, logger: &Logger) {
        match &self.test_type {
            TestType::Bidirectional {
                published_binary,
                mainnet_version,
            } => {
                self.self_test(logger);
                self.bidirectional_test(mainnet_version, published_binary, logger)
            }
            TestType::SelfTestOnly => {
                self.self_test(logger);
            }
        }
    }

    fn self_test(&self, logger: &Logger) {
        let test_binary = data_dependency_file(&self.test_binary);
        info!(
            logger,
            "Testing self-compatibility of module {}", self.test_module
        );
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_dir_path = tmp_dir.path();
        test_one_direction(
            &test_binary,
            &test_binary,
            &self.test_module,
            tmp_dir_path,
            logger,
        );
    }

    fn bidirectional_test(
        &self,
        mainnet_version: &ReplicaVersion,
        published_binary_name: &str,
        logger: &Logger,
    ) {
        let download_dir = tempfile::tempdir().unwrap();
        let download_dir_path = download_dir.path();
        let published_binary = download_mainnet_binary(
            published_binary_name,
            mainnet_version,
            download_dir_path,
            logger,
        );
        let test_binary = data_dependency_file(&self.test_binary);
        info!(
            logger,
            "Testing module {} with the mainnet commit {} and published binary {}",
            self.test_module,
            mainnet_version,
            published_binary_name,
        );
        for (direction, from, to) in [
            ("upgrade", &published_binary, &test_binary),
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

    let mainnet_nns_version = get_mainnet_nns_revision().unwrap();
    let mainnet_application_subnet_version = get_mainnet_application_subnet_revision().unwrap();

    info!(
        logger,
        "Mainnet versions: \nNNS version: {:?}\nApplication subnet version: {:?}",
        mainnet_nns_version,
        mainnet_application_subnet_version
    );

    let mainnet_versions = [mainnet_nns_version, mainnet_application_subnet_version];

    let tests = mainnet_versions.iter().flat_map(|v| {
        [
            TestCase::new(
                TestType::Bidirectional {
                    published_binary: "replicated-state-test".to_string(),
                    mainnet_version: v.clone(),
                },
                "_main/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
                "canister_state::queues::tests::mainnet_compatibility_tests::basic_test",
            ),
            TestCase::new(
                TestType::Bidirectional {
                    published_binary: "replicated-state-test".to_string(),
                    mainnet_version: v.clone(),
                },
                "_main/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
                "canister_state::queues::tests::mainnet_compatibility_tests::best_effort_test",
            ),
            TestCase::new(
                TestType::Bidirectional {
                    published_binary: "replicated-state-test".to_string(),
                    mainnet_version: v.clone(),
                },
                "_main/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
                "canister_state::queues::tests::mainnet_compatibility_tests::input_order_test",
            ),
            TestCase::new(
                TestType::Bidirectional {
                    published_binary: "replicated-state-test".to_string(),
                    mainnet_version: v.clone(),
                },
                "_main/rs/replicated_state/replicated_state_test_binary/replicated_state_test_binary",
                "canister_state::queues::tests::mainnet_compatibility_tests::refunds_test",
            ),
        ]
    });

    for t in tests {
        t.run(&logger);
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|_| ())
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
