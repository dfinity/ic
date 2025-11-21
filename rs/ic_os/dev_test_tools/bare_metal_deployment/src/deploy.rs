use anyhow::{Context, Result, bail, ensure};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

// The reload_hostos tool to be copied to the baremetal host, defines RELOAD_HOSTOS_CMD
include!(concat!(env!("OUT_DIR"), "/reload_hostos_cmd.rs"));

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
) -> Result<()> {
    if config.hostos_upgrade_image.is_none()
        && config.guestos_image.is_none()
        && config.setupos_config_image.is_none()
    {
        bail!("hostos_image, guestos_image or setupos_config_image must be specified");
    }

    println!("Starting bare metal deployment to {ip}");

    let ssh_session = establish_ssh_connection(ip, ssh_private_key_path)?;
    copy_via_scp(
        &ssh_session,
        RELOAD_HOSTOS_CMD,
        RELOAD_HOSTOS_CMD.len() as u64,
        Path::new("/tmp/reload_hostos_cmd"),
        0o755,
    )?;

    let mut reload_hostos_cmd = String::from("/tmp/reload_hostos_cmd");

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
            reload_hostos_cmd.push_str(&format!(" {}={}", flag, source));
        }
    }

    println!("Executing reload_hostos...");
    execute_bash_script(&ssh_session, &reload_hostos_cmd)?;

    println!("Deployment completed");
    Ok(())
}

fn establish_ssh_connection(host_ip: IpAddr, private_key_path: &Path) -> Result<Session> {
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(host_ip, 22), SSH_CONNECT_TIMEOUT)?;

    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;

    sess.userauth_pubkey_file("admin", None, private_key_path, None)
        .context("Auth failed")?;
    ensure!(sess.authenticated(), "Session not authenticated");

    Ok(sess)
}

fn copy_via_scp<R: Read>(
    session: &Session,
    mut reader: R,
    size: u64,
    remote_path: &Path,
    mode: i32,
) -> Result<()> {
    let mut remote_file = session.scp_send(remote_path, mode, size, None)?;
    std::io::copy(&mut reader, &mut remote_file)?;
    remote_file.send_eof()?;
    remote_file.wait_eof()?;
    remote_file.wait_close()?;
    Ok(())
}

fn copy_file_via_scp(
    session: &Session,
    local_path: &Path,
    remote_path: &Path,
    mode: i32,
) -> Result<()> {
    let size = std::fs::metadata(local_path)?.len();
    let file = std::fs::File::open(local_path)?;
    copy_via_scp(session, file, size, remote_path, mode)
}

fn execute_bash_script(session: &Session, script: &str) -> Result<()> {
    let mut channel = session.channel_session()?;
    channel.exec("bash")?;
    channel.write_all(script.as_bytes())?;
    channel.send_eof()?;

    let mut out = String::new();
    channel.read_to_string(&mut out)?;
    let mut err = String::new();
    channel.stderr().read_to_string(&mut err)?;

    if channel.exit_status()? != 0 {
        bail!("Script failed. Output: {out}\nError: {err}");
    }

    Ok(())
}
