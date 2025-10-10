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

use anyhow::{Result, anyhow, ensure};
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
        ic::{InternetComputer, Node, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasTopologySnapshot, IcNodeContainer, SshSession, get_dependency_path_from_env,
            read_dependency_from_env_to_string, secs,
        },
    },
    retry_with_msg, systest,
};
use slog::info;
use ssh2::Session;

fn verify_content(ssh_session: &Session, remote_file_path: &str, expected_b64: &str) -> Result<()> {
    // Protobuf files are binary files, and since we deserialize them into UTF-8 strings,
    // we read their base64 encoding and compare those.
    let actual_b64 = execute_bash_command(
        ssh_session,
        format!("base64 {remote_file_path} | tr -d '\\n'"),
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
            "find {folder_path} -exec stat -c '%F|%A|%U|%G|%n' {{}} \\;"
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
    let recovery_hash = read_dependency_from_env_to_string("RECOVERY_HASH_PATH").unwrap();

    uvm_serve_recovery_artifacts(
        &env,
        &get_dependency_path_from_env("RECOVERY_ARTIFACTS_PATH"),
        &recovery_hash,
    )
    .unwrap();

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System).add_node(Node::new().with_recovery_hash(recovery_hash)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let node = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .next()
        .unwrap();

    let server_ipv6 = get_upstreams_uvm_ipv6(&env);
    spoof_node_dns(&node, &server_ipv6).unwrap();
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Running recovery engine test...");

    let expected_cup_b64 = read_dependency_from_env_to_string("RECOVERY_CUP_B64_PATH").unwrap();
    let expected_local_store_1_b64 =
        read_dependency_from_env_to_string("RECOVERY_STORE_1_B64_PATH").unwrap();
    let expected_local_store_2_b64 =
        read_dependency_from_env_to_string("RECOVERY_STORE_2_B64_PATH").unwrap();

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
