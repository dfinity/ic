use anyhow::Result;
use ssh2::Session;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Error type for bare metal deployment operations
#[derive(Debug, Error)]
pub enum DeploymentError {
    /// SSH authentication failed
    #[error("SSH authentication failed")]
    SshAuthFailed,
    /// SSH connection failed (host unreachable)
    #[error("SSH connection failed: {0}")]
    SshConnectionFailed(String),
    /// Other deployment error
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

// Defines RELOAD_ICOS_CMD, the tool to reload the IC-OS that is copied to the baremetal host.
include!(concat!(env!("OUT_DIR"), "/reload_icos_cmd.rs"));

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Source of an OS image
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// URL to download the image from
    Url(http::Uri),
    /// Local file path to copy via SCP
    File(PathBuf),
}

/// Configuration for bare metal deployment. At least one of hostos_image or guestos_image or
/// setupos_config_image must be specified.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// The HostOS upgrade image (.tar.zst)
    pub hostos_upgrade_image: Option<ImageSource>,
    /// The GuestOS image (.tar.zst)
    pub guestos_image: Option<ImageSource>,
    /// The SetupOS config image (created by build-setupos-config-image.sh)
    pub setupos_config_image: Option<ImageSource>,
}

/// Deploys images to the bare metal node given by `ip`.
pub fn deploy_to_bare_metal(
    config: &DeploymentConfig,
    ip: IpAddr,
    ssh_private_key_path: &Path,
) -> Result<(), DeploymentError> {
    if config.hostos_upgrade_image.is_none()
        && config.guestos_image.is_none()
        && config.setupos_config_image.is_none()
    {
        return Err(DeploymentError::Other(anyhow::anyhow!(
            "hostos_image, guestos_image or setupos_config_image must be specified"
        )));
    }

    println!("Starting bare metal deployment to {ip}");

    let ssh_session = establish_ssh_connection(ip, ssh_private_key_path)?;
    copy_via_scp(
        &ssh_session,
        RELOAD_ICOS_CMD,
        RELOAD_ICOS_CMD.len() as u64,
        Path::new("/tmp/reload_icos_cmd"),
        0o755,
    )?;

    let mut reload_icos_cmd = String::from("/tmp/reload_icos_cmd");

    let image_configs = [
        (
            &config.setupos_config_image,
            "SetupOS config",
            "--setupos-config-img",
        ),
        (
            &config.hostos_upgrade_image,
            "HostOS",
            "--hostos-upgrade-img",
        ),
        (&config.guestos_image, "GuestOS", "--guestos-img"),
    ];

    for (image, name, flag) in image_configs {
        if let Some(image) = image {
            let source = match image {
                ImageSource::Url(uri) => {
                    println!("Using {} URL: {}", name, uri);
                    uri.to_string()
                }
                ImageSource::File(path) => {
                    println!("Copying {} file...", name);
                    let epoch_secs = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let random: u32 = rand::random();
                    let remote_path = format!("/tmp/deploy-{}-{random:x}", epoch_secs);
                    copy_file_via_scp(&ssh_session, path, Path::new(&remote_path), 0o644)?;
                    remote_path
                }
            };
            reload_icos_cmd.push_str(&format!(" {}={}", flag, source));
        }
    }

    println!("Executing reload_icos...");
    execute_bash_script(&ssh_session, &reload_icos_cmd)?;

    println!("Deployment completed");
    Ok(())
}

pub fn establish_ssh_connection(
    host_ip: IpAddr,
    private_key_path: &Path,
) -> Result<Session, DeploymentError> {
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(host_ip, 22), SSH_CONNECT_TIMEOUT)
        .map_err(|e| DeploymentError::SshConnectionFailed(e.to_string()))?;

    let mut sess = Session::new().map_err(|e| DeploymentError::Other(e.into()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| DeploymentError::SshConnectionFailed(e.to_string()))?;

    sess.userauth_pubkey_file("admin", None, private_key_path, None)
        .map_err(|_| DeploymentError::SshAuthFailed)?;

    if !sess.authenticated() {
        return Err(DeploymentError::SshAuthFailed);
    }

    Ok(sess)
}

fn copy_via_scp<R: Read>(
    session: &Session,
    mut reader: R,
    size: u64,
    remote_path: &Path,
    mode: i32,
) -> Result<(), DeploymentError> {
    let mut remote_file = session
        .scp_send(remote_path, mode, size, None)
        .map_err(|e| DeploymentError::Other(e.into()))?;
    std::io::copy(&mut reader, &mut remote_file).map_err(|e| DeploymentError::Other(e.into()))?;
    remote_file
        .send_eof()
        .map_err(|e| DeploymentError::Other(e.into()))?;
    remote_file
        .wait_eof()
        .map_err(|e| DeploymentError::Other(e.into()))?;
    remote_file
        .wait_close()
        .map_err(|e| DeploymentError::Other(e.into()))?;
    Ok(())
}

fn copy_file_via_scp(
    session: &Session,
    local_path: &Path,
    remote_path: &Path,
    mode: i32,
) -> Result<(), DeploymentError> {
    let size = std::fs::metadata(local_path)
        .map_err(|e| DeploymentError::Other(e.into()))?
        .len();
    let file = std::fs::File::open(local_path).map_err(|e| DeploymentError::Other(e.into()))?;
    copy_via_scp(session, file, size, remote_path, mode)
}

fn execute_bash_script(session: &Session, script: &str) -> Result<(), DeploymentError> {
    let mut channel = session
        .channel_session()
        .map_err(|e| DeploymentError::Other(e.into()))?;
    channel
        .exec("bash")
        .map_err(|e| DeploymentError::Other(e.into()))?;
    channel
        .write_all(script.as_bytes())
        .map_err(|e| DeploymentError::Other(e.into()))?;
    channel
        .send_eof()
        .map_err(|e| DeploymentError::Other(e.into()))?;

    let mut out = String::new();
    channel
        .read_to_string(&mut out)
        .map_err(|e| DeploymentError::Other(e.into()))?;
    let mut err = String::new();
    channel
        .stderr()
        .read_to_string(&mut err)
        .map_err(|e| DeploymentError::Other(e.into()))?;

    if channel
        .exit_status()
        .map_err(|e| DeploymentError::Other(e.into()))?
        != 0
    {
        return Err(DeploymentError::Other(anyhow::anyhow!(
            "Script failed. Output: {out}\nError: {err}"
        )));
    }

    Ok(())
}
