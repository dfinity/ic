use std::{net::Ipv6Addr, path::Path};

use anyhow::Result;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{SshSession, get_dependency_path, scp_send_to},
    universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
};

const UNIVERSAL_VM_NAME: &str = "upstreams";

const UPSTREAMS: [&str; 2] = ["download.dfinity.systems", "download.dfinity.network"];

const CERTS_ROOT: &str = "/tmp/certs";
const WEB_ROOT: &str = "/tmp/web";

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

    get_upstreams_uvm(env)
        .block_on_bash_script(&format!(
            r#"
                # Generate TLS certificates for the upstreams.
                mkdir -p {CERTS_ROOT}
                cd {CERTS_ROOT}
                cp /config/minica.pem .
                cp /config/minica-key.pem .
                docker load -i /config/minica.tar
                docker run -v "$(pwd)":/output minica:image --domains {domains}
                sudo mv {common_name}/cert.pem {common_name}/key.pem .
                sudo chmod 644 cert.pem key.pem

                # Serve a static file server with the TLS certificates.
                mkdir -p {WEB_ROOT}
                cd {WEB_ROOT}
                docker load -i /config/static-file-server.tar
                docker run -d \
                       -p 443:8080 \
                       -e TLS_CERT=/certs/cert.pem \
                       -e TLS_KEY=/certs/key.pem \
                       -v {CERTS_ROOT}:/certs \
                       -v "$(pwd)":/web \
                       static-file-server:image
            "#,
            domains = UPSTREAMS.join(","),
            common_name = UPSTREAMS[0],
        ))
        .unwrap();
}

pub fn uvm_serve_recovery_image(
    env: &TestEnv,
    image_path: &Path,
    image_version: &str,
) -> Result<()> {
    uvm_serve_file(
        env,
        image_path,
        Path::new(&format!(
            "ic/{image_version}/guest-os/update-img-recovery/update-img.tar.zst"
        )),
    )
}

pub fn uvm_serve_recovery_artifacts(
    env: &TestEnv,
    artifacts_path: &Path,
    recovery_hash_prefix: &str,
) -> Result<()> {
    uvm_serve_file(
        env,
        artifacts_path,
        Path::new(&format!("recovery/{recovery_hash_prefix}/recovery.tar.zst")),
    )
}

fn uvm_serve_file(env: &TestEnv, local_path: &Path, uri: &Path) -> Result<()> {
    let uvm = get_upstreams_uvm(env);
    let session = uvm.block_on_ssh_session()?;

    // Create the web root directory and the uri subdirectories.
    let remote_path = Path::new(WEB_ROOT).join(uri);
    uvm.block_on_bash_script_from_session(
        &session,
        &format!("mkdir -p {}", remote_path.parent().unwrap().display(),),
    )?;

    // Send the file to the UVM.
    scp_send_to(env.logger(), &session, local_path, &remote_path, 0o644);

    // The static server is already running and will serve the file at the given URI.

    Ok(())
}

fn get_spoof_commands(server_ipv6: &Ipv6Addr) -> String {
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
                echo "{server_ipv6} {upstream}" | sudo tee -a /tmp/hosts > /dev/null
            "#
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

    command
}

pub fn spoof_node_dns<T>(node: &T, server_ipv6: &Ipv6Addr) -> Result<String>
where
    T: SshSession,
{
    node.block_on_bash_script(&get_spoof_commands(server_ipv6))
}

pub async fn spoof_node_dns_async<T>(node: &T, server_ipv6: &Ipv6Addr) -> Result<String>
where
    T: SshSession + Sync,
{
    node.block_on_bash_script_async(&get_spoof_commands(server_ipv6))
        .await
}
