use std::net::Ipv6Addr;

use anyhow::{anyhow, Result};
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{get_dependency_path, IcNodeSnapshot, SshSession},
    universal_vm::{UniversalVm, UniversalVms},
};
use slog::info;

pub const UNIVERSAL_VM_NAME: &str = "upstream";
pub const UPSTREAMS: [&str; 2] = ["download.dfinity.systems", "download.dfinity.network"];

fn read_env_var_path_to_string(env_var: &str) -> String {
    let dependency_path = get_dependency_path(
        std::env::var(env_var)
            .unwrap_or_else(|_| panic!("{} environment variable not found", env_var)),
    );
    std::fs::read_to_string(&dependency_path)
        .unwrap_or_else(|_| panic!("Failed to read content from {:?}", dependency_path))
}

/// Sets up an upstream UVM that impersonates the download servers and serves recovery artifacts
pub fn setup_upstream_uvm(env: &TestEnv) -> Ipv6Addr {
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

/// Spoofs the node's DNS to point to the archive server UVM
pub fn spoof_node_dns(env: &TestEnv, node: &IcNodeSnapshot, server_ipv6: &Ipv6Addr) -> Result<()> {
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
        .map_err(|e| anyhow!("Failed to spoof DNS for node {}: {}", node.node_id, e))?;

    Ok(())
}
