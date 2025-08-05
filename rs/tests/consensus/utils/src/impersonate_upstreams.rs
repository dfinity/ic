use std::{io::Write, net::Ipv6Addr, path::PathBuf};

use anyhow::{anyhow, Result};
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{get_dependency_path, IcNodeSnapshot, SshSession},
    universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
};
use slog::info;

use crate::ssh_access::execute_bash_command;

const UNIVERSAL_VM_NAME: &str = "upstream";

const UPSTREAMS: [&str; 2] = ["download.dfinity.systems", "download.dfinity.network"];

pub fn get_upstreams_uvm(env: &TestEnv) -> DeployedUniversalVm {
    env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap()
}

pub fn get_upstreams_uvm_ipv6(env: &TestEnv) -> Ipv6Addr {
    get_upstreams_uvm(env).get_vm().unwrap().ipv6
}

pub fn setup_upstreams_uvm(env: &TestEnv) {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            std::env::var("IMPERSONATE_UPSTREAMS_UVM_CONFIG_PATH").unwrap_or_else(|_| {
                panic!("IMPERSONATE_UPSTREAMS_UVM_CONFIG_PATH environment variable not found")
            }),
        ))
        .start(env)
        .expect("failed to setup universal VM");
}

pub fn setup_upstreams_uvm_and_serve_recovery_artifacts(
    env: &TestEnv,
    artifacts: Vec<u8>,
    artifacts_hash: String,
) -> Result<()> {
    setup_upstreams_uvm(env);
    uvm_serve_recovery_artifacts(env, artifacts, artifacts_hash)
}

pub fn uvm_serve_recovery_artifacts(
    env: &TestEnv,
    artifacts: Vec<u8>,
    artifacts_hash: String,
) -> Result<()> {
    let logger = env.logger();

    info!(
        logger,
        "Setting up archive server UVM at {} with upstreams: {:?} and recovery hash: {}",
        get_upstreams_uvm_ipv6(env),
        UPSTREAMS,
        artifacts_hash,
    );

    let artifacts_path = PathBuf::from("/tmp/recovery.tar.zst");
    let session = get_upstreams_uvm(env).block_on_ssh_session()?;
    let mut remote_artifacts =
        session.scp_send(&artifacts_path, 0o644, artifacts.len() as u64, None)?;
    remote_artifacts.write_all(&artifacts)?;
    remote_artifacts.send_eof()?;
    remote_artifacts.wait_eof()?;
    remote_artifacts.close()?;
    remote_artifacts.wait_close()?;

    info!(
        logger,
        "{}",
        get_upstreams_uvm(env)
            .block_on_bash_script(
                &format!(
                    r#"
                        ## Impersonate the upstreams where the recovery artifacts are normally stored.

                        # Generate TLS certificates for the upstreams.
                        mkdir /tmp/certs
                        cd /tmp/certs
                        cp /config/minica.pem .
                        cp /config/minica-key.pem .
                        docker load -i /config/minica.tar
                        docker run -v "$(pwd)":/output minica:image --domains {domains}
                        sudo mv {common_name}/cert.pem {common_name}/key.pem .
                        sudo chmod 644 cert.pem key.pem

                        echo {artifacts_path}
                        ls -al {artifacts_path}

                        # Serve the recovery artifacts with a static file server.
                        mkdir /tmp/web
                        cd /tmp/web
                        sudo mv {artifacts_path} .
                        docker load -i /config/static-file-server.tar
                        docker run -d \
                                   -p 443:8080 \
                                   -e TLS_CERT=/certs/cert.pem \
                                   -e TLS_KEY=/certs/key.pem \
                                   -e URL_PREFIX=/ic/{artifacts_hash} \
                                   -v /tmp/certs:/certs \
                                   -v "$(pwd)":/web \
                                   static-file-server:image
                    "#,
                    domains = UPSTREAMS.join(","),
                    common_name = UPSTREAMS[0],
                    artifacts_path = artifacts_path.display(),
                    artifacts_hash = artifacts_hash.trim(),
                )
            )?,
    );

    Ok(())
}

pub fn spoof_node_dns(env: &TestEnv, node: &IcNodeSnapshot, server_ipv6: &Ipv6Addr) {
    let logger = env.logger();
    info!(
        logger,
        "Spoofing node DNS to point the upstreams to the UVM at {}", server_ipv6,
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
