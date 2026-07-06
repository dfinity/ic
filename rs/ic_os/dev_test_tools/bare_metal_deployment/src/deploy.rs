use anyhow::Result;
use grub::BootAlternative;
use ssh2::Session;
use std::fmt::Write as _;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// SSH authentication method
#[derive(Debug, Clone)]
pub enum SshAuthMethod {
    /// Use SSH agent (requires SSH_AUTH_SOCK to be set)
    Agent,
    /// Use a private key file
    KeyFile(PathBuf),
}

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

/// Source of an OS image.
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// URL to download the image from.
    Url(http::Uri),
    /// Local file path to copy via SCP.
    File(PathBuf),
}

/// Configuration for deploying GuestOS.
#[derive(Debug, Clone)]
pub struct GuestOsDeploymentConfig {
    /// The GuestOS image source.
    pub image: ImageSource,
    /// How the GuestOS image should be deployed.
    pub mode: GuestOsDeploymentMode,
}

impl GuestOsDeploymentConfig {
    pub fn full(image: ImageSource) -> Self {
        Self {
            image,
            mode: GuestOsDeploymentMode::Full,
        }
    }

    pub fn upgrade(
        image: ImageSource,
        target_boot_alternative: BootAlternative,
        wipe_var_partition: bool,
    ) -> Self {
        Self {
            image,
            mode: GuestOsDeploymentMode::Upgrade {
                target_boot_alternative,
                wipe_var_partition,
            },
        }
    }
}

/// Supported GuestOS deployment modes.
#[derive(Debug, Clone, Copy)]
pub enum GuestOsDeploymentMode {
    /// Replace the full GuestOS disk image.
    Full,
    /// Install a GuestOS upgrade image into a specific boot alternative.
    Upgrade {
        target_boot_alternative: BootAlternative,
        wipe_var_partition: bool,
    },
}

/// Configuration for bare metal deployment. At least one of hostos_upgrade_image or guestos or
/// setupos_config_image must be specified.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// The HostOS upgrade image (.tar.zst).
    pub hostos_upgrade_image: Option<ImageSource>,
    /// The GuestOS deployment configuration.
    pub guestos: Option<GuestOsDeploymentConfig>,
    /// The SetupOS config image (created by build-setupos-config-image.sh).
    pub setupos_config_image: Option<ImageSource>,
}

/// Deploys images to the bare metal node given by `ip`.
pub fn deploy_to_bare_metal(
    config: &DeploymentConfig,
    ip: IpAddr,
    ssh_auth_method: &SshAuthMethod,
) -> Result<(), DeploymentError> {
    if config.hostos_upgrade_image.is_none()
        && config.guestos.is_none()
        && config.setupos_config_image.is_none()
    {
        return Err(DeploymentError::Other(anyhow::anyhow!(
            "hostos_upgrade_image, guestos or setupos_config_image must be specified"
        )));
    }

    println!("Starting bare metal deployment to {ip}");

    let ssh_session = establish_ssh_connection(ip, ssh_auth_method)?;

    copy_via_scp(
        &ssh_session,
        RELOAD_ICOS_CMD,
        RELOAD_ICOS_CMD.len() as u64,
        Path::new("/tmp/reload_icos_cmd"),
        0o755,
    )?;

    let mut cmd = String::from("/tmp/reload_icos_cmd");
    if let Some(image) = &config.setupos_config_image {
        let source = prepare_image_source_for_reload_icos(&ssh_session, image, "SetupOS config")?;
        write!(cmd, " --setupos-config-img={source}").unwrap();
    }
    if let Some(image) = &config.hostos_upgrade_image {
        let source = prepare_image_source_for_reload_icos(&ssh_session, image, "HostOS")?;
        write!(cmd, " --hostos-upgrade-img={source}").unwrap();
    }

    if let Some(guestos) = &config.guestos {
        let source = prepare_image_source_for_reload_icos(&ssh_session, &guestos.image, "GuestOS")?;
        match guestos.mode {
            GuestOsDeploymentMode::Full => {
                write!(cmd, " --guestos-img={source}").unwrap();
            }
            GuestOsDeploymentMode::Upgrade {
                target_boot_alternative,
                wipe_var_partition,
            } => {
                write!(cmd, " --guestos-upgrade-img={source}").unwrap();
                write!(
                    cmd,
                    " --guestos-target-boot-alternative={target_boot_alternative}"
                )
                .unwrap();

                if wipe_var_partition {
                    write!(cmd, " --guestos-wipe-var-partition").unwrap();
                }
            }
        }
    }

    println!("Executing reload_icos...");
    execute_remote_command(&ssh_session, &cmd)?;

    println!("Deployment completed");
    Ok(())
}

fn prepare_image_source_for_reload_icos(
    session: &Session,
    image: &ImageSource,
    name: &str,
) -> Result<String, DeploymentError> {
    match image {
        ImageSource::Url(uri) => {
            println!("Using {name} URL: {uri}");
            Ok(uri.to_string())
        }
        ImageSource::File(path) => {
            println!("Copying {} file...", name);
            let epoch_secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let remote_path = format!("/tmp/deploy-{}-{:x}", epoch_secs, rand::random::<u32>());
            copy_file_via_scp(session, path, Path::new(&remote_path), 0o644)?;
            Ok(remote_path)
        }
    }
}

pub fn establish_ssh_connection(
    host_ip: IpAddr,
    auth_method: &SshAuthMethod,
) -> Result<Session, DeploymentError> {
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(host_ip, 22), SSH_CONNECT_TIMEOUT)
        .map_err(|e| DeploymentError::SshConnectionFailed(e.to_string()))?;

    let mut sess = Session::new().map_err(|e| DeploymentError::Other(e.into()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| DeploymentError::SshConnectionFailed(e.to_string()))?;

    match auth_method {
        SshAuthMethod::Agent => {
            let mut agent = sess.agent().map_err(|e| DeploymentError::Other(e.into()))?;
            agent.connect().map_err(|e| {
                DeploymentError::Other(anyhow::anyhow!(
                    "Failed to connect to SSH agent: {}. Is SSH_AUTH_SOCK set?",
                    e
                ))
            })?;
            agent
                .list_identities()
                .map_err(|e| DeploymentError::Other(e.into()))?;

            let identities = agent
                .identities()
                .map_err(|e| DeploymentError::Other(e.into()))?;

            if identities.is_empty() {
                return Err(DeploymentError::Other(anyhow::anyhow!(
                    "No identities found in SSH agent"
                )));
            }

            let authenticated = identities
                .iter()
                .any(|id| agent.userauth("admin", id).is_ok());

            if !authenticated {
                return Err(DeploymentError::SshAuthFailed);
            }
        }
        SshAuthMethod::KeyFile(private_key_path) => {
            sess.userauth_pubkey_file("admin", None, private_key_path, None)
                .map_err(|_| DeploymentError::SshAuthFailed)?;
        }
    }

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

fn execute_remote_command(session: &Session, command: &str) -> Result<(), DeploymentError> {
    let mut channel = session
        .channel_session()
        .map_err(|e| DeploymentError::Other(e.into()))?;
    channel
        .exec(command)
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
            "Command failed. Output: {out}\nError: {err}"
        )));
    }

    Ok(())
}
