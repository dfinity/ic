/* tag::catalog[]

Title:: CUP compatibility test

Goal::
Ensure that CUP artifacts are backward/forward compatible wrt to mainnet and branch replica versions.
This is essential in ensuring the compatibility of replica version upgrades.

Runbook::
1. Generate and serialize a structurally exhaustive set of CUP artifacts using the mainnet replica
   version.
2. Deserialize all artifacts using the branch version (= upgrade).
3. Remove all artifacts.
4. Generate and serialize a set of CUP artifacts using the branch replica version.
5. Deserialize all artifacts using the mainnet version (= downgrade).

Success::
All artifacts can be serialized and deserialized by the respective replica versions without errors
or violation of integrity.

end::catalog[] */

use anyhow::Result;
use ic_system_test_driver::driver::test_env_api::{
    get_dependency_path_from_env, get_mainnet_application_subnet_revision, get_mainnet_nns_revision,
};
use ic_system_test_driver::driver::{group::SystemTestGroup, test_env::TestEnv};
use ic_system_test_driver::systest;
use ic_types::ReplicaVersion;
use slog::{Logger, error, info};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SANITY_CHECK_ARTIFACTS_COUNT: usize = 46;

#[derive(PartialEq)]
enum Action {
    Serialize,
    Deserialize,
}

/// Call the exhaustive unit test binary at the given location.
fn call_unit_test(log: &Logger, binary: &PathBuf, action: Action) {
    let argument = format!(
        "exhaustive::tests::{}",
        match action {
            Action::Serialize => "serialize",
            Action::Deserialize => "deserialize",
        }
    );
    let mut cmd = Command::new(binary);
    cmd.arg(argument)
        .arg("--include-ignored")
        .arg("--nocapture");

    info!(log, "{cmd:?} ...");
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Could not execute unit test because {e:?}"));

    info!(log, "Status: {}", output.status);
    info!(log, "stdout: {}", String::from_utf8(output.stdout).unwrap());
    info!(log, "stderr: {}", String::from_utf8(output.stderr).unwrap());

    if !output.status.success() {
        if action == Action::Deserialize {
            error!(
                log,
                r#"
Deserialization of artifacts failed. Modifications to data types that may be part of the CUP
artifact usually need to be performed in three stages. Please ensure the following:

- If you tried to add a new enum variant, make sure that it cannot be used by the replica during
  the first rollout.
- If you tried to add a new struct field, make sure that it is declared as `Option`, and its `None`
  values are ignored by the struct's `Hash` implementation. The field has to be initialized with
  `None` during the first rollout. In the second rollout, the field may be set to `Some(_)` value.
  In the third rollout, the field may be made mandatory and the custom `Hash` implementation may
  be removed.
- If you tried to remove a struct field, make sure that it is declared as `Option`, and its `None`
  values are ignored by the struct's `Hash` implementation. The field has to be initialized with
  `Some(_)` value during the first rollout. In the second rollout, the field may be set to `None`.
  In the third rollout, the field may be removed.

Afterwards, adapt the `ExhaustiveSet` implementation of your modified data type such that it only
creates instances in line with the behavior described above. In your custom `ExhaustiveSet`
implementation, link the ticket tracking the next rollout step of your change.

For instance, when adding a field as `Option` (first rollout), your `ExhaustiveSet` implementation
should link to a ticket implementing the second step, during which the field is set to `Some(_)`
and the custom `ExhaustiveSet` implementation is removed at the same time.
"#
            );
        }
        panic!("Unit test execution failed.")
    }
}

fn nns_version_test(env: TestEnv) {
    test(
        env,
        &get_mainnet_nns_revision().unwrap(),
        "MAINNET_NNS_TYPES_TEST_PATH",
    )
}

fn application_subnet_version_test(env: TestEnv) {
    test(
        env,
        &get_mainnet_application_subnet_revision().unwrap(),
        "MAINNET_APP_TYPES_TEST_PATH",
    )
}

/// `mainnet_test_env_var` names the runtime dependency holding the `types-test`
/// binary built at `mainnet_version` (see `runtime_deps` in BUILD.bazel).
/// `mainnet_version` itself is only used for logging: which binary we get is
/// determined by the bazel dependency, not resolved from the version at runtime.
fn test(env: TestEnv, mainnet_version: &ReplicaVersion, mainnet_test_env_var: &str) {
    let log = env.logger();

    info!(log, "Continuing with mainnet version {mainnet_version}");

    let output_dir = PathBuf::from("cup_compatibility_test");
    if output_dir.exists() {
        // Remove potential left-overs from the other test runs
        fs::remove_dir_all(&output_dir)
            .expect("Should have all the permissions to remove the existing directory");
    }
    let branch_test = get_dependency_path_from_env("TYPES_TEST_PATH");
    let mainnet_test = get_dependency_path_from_env(mainnet_test_env_var);

    info!(log, "Creating artifacts with mainnet version...");
    call_unit_test(&log, &mainnet_test, Action::Serialize);

    let created_artifacts = fs::read_dir(&output_dir).unwrap().count();
    info!(log, "{created_artifacts} artifacts created.");
    assert!(
        created_artifacts >= SANITY_CHECK_ARTIFACTS_COUNT,
        "Not enough artifacts created. This is just a sanity check. \
        If it's expected that the number of artifacts decreases, \
        please adjust `SANITY_CHECK_ARTIFACTS_COUNT`."
    );
    info!(
        log,
        "Deserializing mainnet artifacts with branch version..."
    );
    call_unit_test(&log, &branch_test, Action::Deserialize);

    info!(log, "Removing artifacts...");
    fs::remove_dir_all(&output_dir).expect("Failed to remove directory");

    info!(log, "Creating artifacts with branch version...");
    call_unit_test(&log, &branch_test, Action::Serialize);

    let created_artifacts = fs::read_dir(output_dir).unwrap().count();
    info!(log, "{created_artifacts} artifacts created.");
    assert!(
        created_artifacts >= SANITY_CHECK_ARTIFACTS_COUNT,
        "Not enough artifacts created. This is just a sanity check. \
        If it's expected that the number of artifacts decreases, \
        please adjust `SANITY_CHECK_ARTIFACTS_COUNT`."
    );

    info!(
        log,
        "Deserializing branch artifacts with mainnet version..."
    );
    call_unit_test(&log, &mainnet_test, Action::Deserialize);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|_| ())
        .add_test(systest!(nns_version_test))
        .add_test(systest!(application_subnet_version_test))
        .execute_from_args()?;
    Ok(())
}
