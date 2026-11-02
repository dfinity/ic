/* tag::catalog[]

Title:: Certification compatibility test

Goal::
Ensure that certification artifacts are backward/forward compatible wrt to mainnet and branch
replica versions. As the certification pool is kept across replica versions, a replica must be able
to read the certifications and certification shares persisted by the replica version it was
upgraded or downgraded from.

Runbook::
1. Generate and serialize a structurally exhaustive set of certification messages using the
   mainnet replica version, encoded as they are persisted in the certification pool.
2. Deserialize all messages using the branch version (= upgrade).
3. Generate and serialize a set of certification messages using the branch replica version.
4. Deserialize all messages using the mainnet version (= downgrade).

Success::
All certification messages serialized by one replica version can be deserialized by the other.

end::catalog[] */

use anyhow::Result;
use ic_system_test_driver::driver::test_env_api::{
    get_dependency_path_from_env, get_mainnet_application_subnet_revision, get_mainnet_nns_revision,
};
use ic_system_test_driver::driver::{group::SystemTestGroup, test_env::TestEnv};
use ic_system_test_driver::systest;
use slog::{Logger, info};
use std::fs;
use std::path::Path;
use std::process::Command;

/// The module of the `types-test` binary defining the `serialize` and `deserialize` unit tests.
const TEST_MODULE: &str = "consensus::certification::tests::mainnet_compatibility_tests";

/// The directory, relative to the working directory of the unit tests, which they serialize the
/// certification messages to.
const OUTPUT_DIR: &str = "certification_messages";

const SANITY_CHECK_MESSAGES_COUNT: usize = 7;

/// Whether both mainnet replica versions keep the certification pool across replica versions.
///
/// Older replica versions delete the certification pool when the replica version changes, so
/// there is nothing to be compatible with. Their `types-test` binaries also lack the unit tests
/// run here. Until both mainnet versions keep the certification pool, only the branch version is
/// checked against itself.
///
/// TODO: Remove once both mainnet versions keep the certification pool across replica versions,
/// and add `MAINNET_TYPES_TEST_RUNTIME_DEPS` to the `runtime_deps` of the test.
const MAINNET_VERSIONS_KEEP_CERTIFICATION_POOL: bool = false;

/// Run the ignored unit test `test_name` of the given test binary in `working_dir`.
fn run_unit_test(log: &Logger, binary: &Path, test_name: &str, working_dir: &Path) {
    let mut cmd = Command::new(binary);
    cmd.arg(test_name)
        .arg("--exact")
        .arg("--include-ignored")
        .arg("--nocapture")
        .current_dir(working_dir);

    info!(log, "{cmd:?} ...");
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Could not execute unit test because {e:?}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!(log, "Status: {}", output.status);
    info!(log, "stdout: {stdout}");
    info!(log, "stderr: {}", String::from_utf8_lossy(&output.stderr));

    assert!(output.status.success(), "Unit test execution failed.");
    // The test binary also succeeds when no test matches the given name.
    assert!(
        stdout.contains("1 passed"),
        "Unit test {test_name} was not found in {binary:?}."
    );
}

/// Check that the certification messages serialized by the `from` binary can be deserialized by
/// the `to` binary.
fn test_one_direction(env: &TestEnv, direction: &str, from: &Path, to: &Path) {
    let log = env.logger();
    let working_dir = env.get_path(format!("certification_compatibility_test/{direction}"));
    fs::create_dir_all(&working_dir).expect("Failed to create directory");

    info!(log, "Creating certification messages with {from:?}...");
    run_unit_test(
        &log,
        from,
        &format!("{TEST_MODULE}::serialize"),
        &working_dir,
    );

    let created_messages = fs::read_dir(working_dir.join(OUTPUT_DIR))
        .expect("Failed to read directory")
        .count();
    info!(log, "{created_messages} certification messages created.");
    assert!(
        created_messages >= SANITY_CHECK_MESSAGES_COUNT,
        "Not enough certification messages created. This is just a sanity check. \
        If it's expected that the number of messages decreases, \
        please adjust `SANITY_CHECK_MESSAGES_COUNT`."
    );

    info!(log, "Deserializing certification messages with {to:?}...");
    run_unit_test(
        &log,
        to,
        &format!("{TEST_MODULE}::deserialize"),
        &working_dir,
    );
}

fn test(env: TestEnv) {
    let log = env.logger();
    let branch_test = get_dependency_path_from_env("TYPES_TEST_PATH");

    test_one_direction(&env, "branch", &branch_test, &branch_test);

    if !MAINNET_VERSIONS_KEEP_CERTIFICATION_POOL {
        info!(
            log,
            "Skipping the mainnet versions, as they do not keep the certification pool across \
            replica versions."
        );
        return;
    }

    // `version` is only used for logging: which binary we get is determined by the bazel
    // dependency, not resolved from the version at runtime.
    for (subnet, version, mainnet_test_env_var) in [
        (
            "nns",
            get_mainnet_nns_revision().unwrap(),
            "MAINNET_NNS_TYPES_TEST_PATH",
        ),
        (
            "app",
            get_mainnet_application_subnet_revision().unwrap(),
            "MAINNET_APP_TYPES_TEST_PATH",
        ),
    ] {
        info!(log, "Continuing with mainnet {subnet} version {version}");
        let mainnet_test = get_dependency_path_from_env(mainnet_test_env_var);
        test_one_direction(
            &env,
            &format!("{subnet}_upgrade"),
            &mainnet_test,
            &branch_test,
        );
        test_one_direction(
            &env,
            &format!("{subnet}_downgrade"),
            &branch_test,
            &mainnet_test,
        );
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|_| ())
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
