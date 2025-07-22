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

use std::net::Ipv6Addr;

use anyhow::{anyhow, ensure, Result};
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, secs, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            SshSession,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    retry_with_msg, systest,
};
use slog::info;
use ssh2::Session;

const UNIVERSAL_VM_NAME: &str = "upstream";

const UPSTREAMS: [&str; 2] = ["download.dfinity.systems", "download.dfinity.network"];

fn read_env_var_path_to_string(env_var: &str) -> String {
    let dependency_path = get_dependency_path(
        std::env::var(env_var)
            .unwrap_or_else(|_| panic!("{} environment variable not found", env_var)),
    );
    std::fs::read_to_string(&dependency_path)
        .unwrap_or_else(|_| panic!("Failed to read content from {:?}", dependency_path))
}

fn setup_upstream_uvm(env: &TestEnv) -> Ipv6Addr {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            std::env::var("GUESTOS_RECOVERY_ENGINE_UVM_CONFIG_PATH").unwrap_or_else(|_| {
                panic!("GUESTOS_RECOVERY_ENGINE_UVM_CONFIG_PATH environment variable not found")
            }),
        ))
        .start(env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let server_ipv6 = deployed_universal_vm.get_vm().unwrap().ipv6;

    let recovery_hash = read_env_var_path_to_string("RECOVERY_HASH_PATH");

    let logger = env.logger();
    info!(
        logger,
        "Setting up archive server UVM at {} with upstreams: {:?} and recovery hash: {}",
        server_ipv6,
        UPSTREAMS,
        recovery_hash
    );
    info!(
        logger,
        "{}",
        deployed_universal_vm
            .block_on_bash_script(
                &format!(
                    r#"
                        # Impersonate the upstreams where the recovery artifacts are normally stored.
                        DOMAINS="{}"
                        COMMON_NAME="{}"
                        RECOVERY_HASH="{}"

                        # Generate TLS certificates for the upstreams.
                        mkdir /tmp/certs
                        cd /tmp/certs
                        cp /config/minica.pem .
                        cp /config/minica-key.pem .
                        docker load -i /config/minica.tar
                        docker run -v "$(pwd)":/output minica:image --domains "$DOMAINS"
                        sudo mv $COMMON_NAME/cert.pem $COMMON_NAME/key.pem .
                        sudo chmod 644 cert.pem key.pem


                        # Serve the recovery artifacts with a static file server.
                        mkdir /tmp/web
                        cd /tmp/web
                        sudo mv /config/recovery.tar.zst .
                        docker load -i /config/static-file-server.tar
                        docker run -d \
                                   -p 443:8080 \
                                   -e TLS_CERT=/certs/cert.pem \
                                   -e TLS_KEY=/certs/key.pem \
                                   -e URL_PREFIX=/ic/$RECOVERY_HASH \
                                   -v /tmp/certs:/certs \
                                   -v "$(pwd)":/web \
                                   static-file-server:image
                    "#,
                    UPSTREAMS.join(","),
                    UPSTREAMS[0],
                    recovery_hash,
                )
            )
            .unwrap(),
    );

    server_ipv6
}

fn spoof_node_dns(env: &TestEnv, node: &IcNodeSnapshot, server_ipv6: &Ipv6Addr) {
    let logger = env.logger();
    info!(
        logger,
        "Spoofing node DNS to point to the archive server UVM..."
    );

    let ssh_session = node.block_on_ssh_session().unwrap();
    // File-system is read-only, so we modify /etc/hosts in a temporary file and replace the
    // original with a bind mount.
    let mut command = String::from(
        r#"
            sudo cp /etc/hosts /tmp/hosts
        "#,
    );
    for upstream in UPSTREAMS {
        command.push_str(&format!(
            r#"
                echo "{} {}" | sudo tee -a /tmp/hosts > /dev/null
            "#,
            server_ipv6, upstream
        ));
    }
    // Match the original /etc/hosts file permissions.
    command.push_str(
        r#"
            sudo chown --reference=/etc/hosts /tmp/hosts
            sudo chmod --reference=/etc/hosts /tmp/hosts

            sudo mount --bind /tmp/hosts /etc/hosts
        "#,
    );

    execute_bash_command(&ssh_session, command)
        .map_err(|e| anyhow!("Failed to spoof DNS for node {}: {}", node.node_id, e))
        .unwrap();
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
    let server_ipv6 = setup_upstream_uvm(&env);

    InternetComputer::new()
        .use_recovery_image()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let node = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .next()
        .unwrap();

    spoof_node_dns(&env, &node, &server_ipv6);
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Running recovery engine test...");

    let expected_cup_b64 = read_env_var_path_to_string("RECOVERY_CUP_B64_PATH");
    let expected_local_store_1_b64 = read_env_var_path_to_string("RECOVERY_STORE_1_B64_PATH");
    let expected_local_store_2_b64 = read_env_var_path_to_string("RECOVERY_STORE_2_B64_PATH");

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
