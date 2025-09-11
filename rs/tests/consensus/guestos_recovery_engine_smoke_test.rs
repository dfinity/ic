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

use anyhow::{anyhow, bail, ensure, Result};
use ic_consensus_system_test_utils::{
    impersonate_upstreams::{
        get_upstreams_uvm_ipv6, setup_upstreams_uvm, spoof_node_dns, uvm_serve_recovery_artifacts,
    },
    ssh_access::execute_bash_command,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, secs, HasTopologySnapshot, IcNodeContainer, SshSession,
        },
    },
    retry_with_msg, systest,
};
use slog::info;
use ssh2::Session;
use std::time::Duration;

fn read_env_var_path(env_var: &str) -> Vec<u8> {
    let dependency_path = get_dependency_path(
        std::env::var(env_var)
            .unwrap_or_else(|_| panic!("{} environment variable not found", env_var)),
    );
    std::fs::read(&dependency_path)
        .unwrap_or_else(|_| panic!("Failed to read content from {:?}", dependency_path))
}

fn read_env_var_path_to_string(env_var: &str) -> String {
    String::from_utf8(read_env_var_path(env_var))
        .unwrap_or_else(|_| panic!("Content of {} is not valid UTF-8", env_var))
}

fn verify_content(ssh_session: &Session, remote_file_path: &str, expected_b64: &str) -> Result<()> {
    // Protobuf files are binary files, and since we deserialize them into UTF-8 strings,
    // we read their base64 encoding and compare those.
    let actual_b64 = execute_bash_command(
        ssh_session,
        format!("base64 {} | tr -d '\\n'", remote_file_path),
    )
    .map_err(|e| anyhow!(e))?;
    ensure!(
        actual_b64 == expected_b64,
        "Unexpected content in {}: (base-64 encoded) {}",
        remote_file_path,
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
    setup_upstreams_uvm(&env);
    uvm_serve_recovery_artifacts(
        &env,
        read_env_var_path("RECOVERY_ARTIFACTS_PATH"),
        read_env_var_path_to_string("RECOVERY_HASH_PATH").trim(),
    )
    .unwrap();

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Running recovery engine test...");

    let expected_cup_b64 = read_env_var_path_to_string("RECOVERY_CUP_B64_PATH");
    let expected_local_store_1_b64 = read_env_var_path_to_string("RECOVERY_STORE_1_B64_PATH");
    let expected_local_store_2_b64 = read_env_var_path_to_string("RECOVERY_STORE_2_B64_PATH");
    let recovery_hash = read_env_var_path_to_string("RECOVERY_HASH_PATH");

    let node = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .next()
        .unwrap();

    let ssh_session = node.block_on_ssh_session().unwrap();

    let boot_id_pre_reboot = execute_bash_command(
        &ssh_session,
        "journalctl -q --list-boots | tail -n1 | awk '{print $2}'".to_string(),
    )
    .map_err(|e| anyhow!(e))
    .unwrap();
    info!(log, "Current boot ID: {}", boot_id_pre_reboot);

    info!(
        log,
        "Remounting /boot as read-write and updating boot_args file"
    );
    let boot_args_command = format!(
        "sudo mount -o remount,rw /boot && sudo sed -i 's/\\(BOOT_ARGS_A=\".*\\)\"/\\1 recovery-hash={}\"/' /boot/boot_args && sudo mount -o remount,ro /boot",
        recovery_hash
    );
    execute_bash_command(&ssh_session, boot_args_command)
        .map_err(|e| anyhow!(e))
        .unwrap();
    info!(log, "Boot_args file updated successfully.");

    info!(log, "Verifying boot_args file contents");
    let updated_boot_args = execute_bash_command(&ssh_session, "cat /boot/boot_args".to_string())
        .map_err(|e| anyhow!(e))
        .unwrap();
    info!(log, "Updated boot_args content:\n{}", updated_boot_args);

    info!(log, "Rebooting the host");
    execute_bash_command(&ssh_session, "sudo reboot".to_string())
        .map_err(|e| anyhow!(e))
        .unwrap();

    info!(log, "Waiting for host to reboot...");

    retry_with_msg!(
        format!(
            "Waiting until the host's boot ID changes from its pre reboot value of '{}'",
            boot_id_pre_reboot
        ),
        log.clone(),
        Duration::from_secs(2 * 60),
        Duration::from_secs(5),
        || {
            let new_ssh_session = node.block_on_ssh_session().unwrap();
            let boot_id = execute_bash_command(
                &new_ssh_session,
                "journalctl -q --list-boots | tail -n1 | awk '{print $2}'".to_string(),
            )
            .map_err(|e| anyhow!(e))
            .unwrap();
            if boot_id != boot_id_pre_reboot {
                info!(
                    log,
                    "Host boot ID changed from '{}' to '{}'", boot_id_pre_reboot, boot_id
                );
                Ok(())
            } else {
                bail!("Host boot ID is still '{}'", boot_id_pre_reboot)
            }
        }
    )
    .unwrap();

    let server_ipv6 = get_upstreams_uvm_ipv6(&env);
    spoof_node_dns(&node, &server_ipv6).unwrap();

    //
    // Verify contents
    //

    let ssh_session = node.block_on_ssh_session().unwrap();

    // We retry multiple times the first time because the files being overwritten by the recovery
    // engine and this read are racing against each other.
    retry_with_msg!("verify CUP", log.clone(), secs(30), secs(5), || {
        verify_content(
            &ssh_session,
            "/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb",
            &expected_cup_b64,
        )
    })
    .unwrap();

    verify_content(
        &ssh_session,
        "/var/lib/ic/data/ic_registry_local_store/0001020304/05/06/07.pb",
        &expected_local_store_1_b64,
    )
    .unwrap();

    verify_content(
        &ssh_session,
        "/var/lib/ic/data/ic_registry_local_store/08090a0b0c/0d/0e/0f.pb",
        &expected_local_store_2_b64,
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
