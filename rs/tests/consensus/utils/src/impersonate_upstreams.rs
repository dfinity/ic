use std::{io::Write, net::Ipv6Addr, path::Path};

use anyhow::{anyhow, Result};
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{get_dependency_path, SshSession},
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

pub fn uvm_serve_guestos_image(env: &TestEnv, image: Vec<u8>, image_version: &str) -> Result<()> {
    uvm_serve_file(
        env,
        image,
        Path::new(&format!(
            "ic/{}/guest-os/update-img/update-img.tar.zst",
            image_version
        )),
    )
}

pub fn uvm_serve_recovery_artifacts(
    env: &TestEnv,
    artifacts: Vec<u8>,
    artifacts_hash: &str,
) -> Result<()> {
    uvm_serve_file(
        env,
        artifacts,
        Path::new(&format!("ic/{}/recovery.tar.zst", artifacts_hash)),
    )
}

fn uvm_serve_file(env: &TestEnv, file: Vec<u8>, uri: &Path) -> Result<()> {
    let uvm = get_upstreams_uvm(env);

    // Create the web root directory and the uri subdirectories.
    let file_path = Path::new(WEB_ROOT).join(uri);
    uvm.block_on_bash_script(&format!(
        "mkdir -p {}",
        file_path.parent().unwrap().display(),
    ))?;

    // Send the file to the UVM.
    let mut remote_artifacts =
        uvm.block_on_ssh_session()?
            .scp_send(&file_path, 0o644, file.len() as u64, None)?;
    remote_artifacts.write_all(&file)?;
    remote_artifacts.send_eof()?;
    remote_artifacts.wait_eof()?;
    remote_artifacts.close()?;
    remote_artifacts.wait_close()?;

    // The static server is already running and will serve the file at the given URI.

    Ok(())
}

pub fn spoof_node_dns<T>(node: &T, server_ipv6: &Ipv6Addr)
where
    T: SshSession,
{
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

    node.block_on_bash_script(&command)
        .map_err(|e| anyhow!("Failed to spoof DNS: {}", e))
        .unwrap();
}
