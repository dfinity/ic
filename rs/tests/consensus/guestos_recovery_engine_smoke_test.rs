/* tag::catalog[]

Title:: GuestOS recovery engine smoke test

Goal::
Verify that the guest OS recovery engine downloads the recovery artifacts, extracts
them, and places them in the correct locations.

Runbook::
. The CI will create dummy recovery artifacts and upload them to the expected URLs.
  The randomly generated content of these artifacts is passed as environment variables
  to the test.
. The test sets up an IC with a single system subnet with one node loaded with the
  recovery image.
. The test connects to the node via SSH and verifies that the recovery artifacts were
  downloaded, extracted, and placed in the correct locations.

Success::
. The recovery artifacts are extracted, placed in the correct locations, and their
  content matches the expected content (i.e. the content found in the upstreams).

end::catalog[] */

use anyhow::{anyhow, ensure, Result};
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{secs, HasTopologySnapshot, IcNodeContainer, SshSession},
    },
    retry_with_msg, systest,
};
use slog::info;
use ssh2::Session;

fn verify_content(
    ssh_session: &Session,
    actual_file_path: &str,
    expected_b64_path: &str,
) -> Result<()> {
    // Protobuf files are binary files, and since we deserialize them into UTF-8 strings,
    // we read their base64 encoding and compare those.
    let actual_b64 = execute_bash_command(
        ssh_session,
        format!("base64 {} | tr -d '\\n'", actual_file_path),
    )
    .map_err(|e| anyhow!(e))?;
    let expected_b64 = std::fs::read_to_string(expected_b64_path).map_err(|e| {
        anyhow!(
            "Failed to read expected content from {}: {}",
            expected_b64_path,
            e
        )
    })?;
    ensure!(
        actual_b64 == expected_b64,
        "Unexpected content in {}: (base-64 encoded) {}",
        actual_file_path,
        actual_b64,
    );
    Ok(())
}

/// Follows permissions defined in /ic/ic-os/components/ic/setup-permissions/setup-permissions.sh
fn verify_permissions_recursively(
    ssh_session: &Session,
    folder_path: &str,
    expected_owner: &str,
    expected_group: &str,
) -> Result<()> {
    let output = execute_bash_command(
        ssh_session,
        format!(
            // File type | Permissions | Owner | Group | File Name
            "find {} -exec stat -c '%F|%A|%U|%G|%n' {{}} \\;",
            folder_path
        ),
    )
    .map_err(|e| anyhow!(e))?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        ensure!(
            parts.len() == 5,
            "Unexpected output format from stat command: {}",
            line
        );

        let file_type = parts[0];
        let permissions = parts[1];
        let owner = parts[2];
        let group = parts[3];
        let file_name = parts[4];

        ensure!(
            owner == expected_owner,
            "Unexpected owner for {}. Actual: {}. Expected: {}.",
            file_name,
            owner,
            expected_owner
        );

        ensure!(
            group == expected_group,
            "Unexpected group for {}. Actual: {}. Expected: {}.",
            file_name,
            group,
            expected_group
        );

        if file_type == "directory" {
            ensure!(
                permissions == "drwxr-s---",
                "Unexpected permissions for directory {}. Actual: {}. Expected: drwxr-s---.",
                file_name,
                permissions
            );
        } else {
            ensure!(
                permissions == "-rw-r-----",
                "Unexpected permissions for file {}. Actual: {}. Expected: -rw-r-----.",
                file_name,
                permissions
            );
        }
    }

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .use_recovery_image()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Running recovery engine test...");

    let expected_cup_proto_path = std::env::var("RECOVERY_CUP_CONTENT_B64")
        .expect("RECOVERY_CUP_CONTENT_B64 environment variable not found");
    let expected_local_store_1_path = std::env::var("RECOVERY_STORE_CONTENT1_B64")
        .expect("RECOVERY_STORE_CONTENT1_B64 environment variable not found");
    let expected_local_store_2_path = std::env::var("RECOVERY_STORE_CONTENT2_B64")
        .expect("RECOVERY_STORE_CONTENT2_B64 environment variable not found");

    let node = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .next()
        .unwrap();

    let ssh_session = node.block_on_ssh_session().unwrap();

    //
    // Verify contents
    //

    // We retry multiple times the first time because the files being overwritten by the recovery
    // engine and this read are racing against each other.
    retry_with_msg!("verify CUP", log.clone(), secs(30), secs(5), || {
        verify_content(
            &ssh_session,
            "/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb",
            &expected_cup_proto_path,
        )
    })
    .unwrap();

    verify_content(
        &ssh_session,
        "/var/lib/ic/data/ic_registry_local_store/0001020304/05/06/07.pb",
        &expected_local_store_1_path,
    )
    .unwrap();

    verify_content(
        &ssh_session,
        "/var/lib/ic/data/ic_registry_local_store/08090a0b0c/0d/0e/0f.pb",
        &expected_local_store_2_path,
    )
    .unwrap();

    //
    // Verify permissions
    //

    verify_permissions_recursively(
        &ssh_session,
        "/var/lib/ic/data/cups",
        "ic-replica",
        "nonconfidential",
    )
    .unwrap();
    verify_permissions_recursively(
        &ssh_session,
        "/var/lib/ic/data/ic_registry_local_store",
        "ic-replica",
        "ic-registry-local-store",
    )
    .unwrap();
}

pub fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
