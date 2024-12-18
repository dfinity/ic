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
use ic_recovery::file_sync_helper::download_binary;
use ic_system_test_driver::driver::{group::SystemTestGroup, test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::ReplicaVersion;
use slog::{error, info, Logger};
use std::fs;
use std::path::{Path, PathBuf};
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

/// TODO: Instead of downloading the mainnet binary, declare it as a bazel
/// dependency such that it is downloaded ahead of time. This should be done
/// once the following blockers are resolved:
/// 1. It is possible to declare a dependency that can download and extract
///    g-zipped archives, and make them executable.
/// 2. There is a way to automatically update the version of this dependency,
///    Ideally such that it is in sync with testnet/mainnet_revisions.json
fn download_mainnet_binary(version: String, log: &Logger, target_dir: &Path) -> PathBuf {
    block_on(ic_system_test_driver::retry_with_msg_async!(
        "download mainnet binary",
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            Ok(download_binary(
                log,
                ReplicaVersion::try_from(version.clone()).unwrap(),
                "types-test".into(),
                target_dir,
            )
            .await?)
        }
    ))
    .expect("Failed to Download")
}

fn test(env: TestEnv) {
    let log = env.logger();

    let mainnet_version =
        read_dependency_to_string("testnet/mainnet_nns_revision.txt").expect("mainnet IC version");
    info!(log, "Continuing with mainnet version {mainnet_version}");

    let output_dir = PathBuf::from("cup_compatibility_test");
    let branch_test = get_dependency_path("rs/tests/cup_compatibility/binaries/types_test");
    let tmp_dir = tempfile::tempdir().unwrap();
    let mainnet_test = download_mainnet_binary(mainnet_version, &log, tmp_dir.path());

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
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
