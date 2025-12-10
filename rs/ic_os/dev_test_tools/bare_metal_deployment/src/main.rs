use anyhow::{Context, Result, bail, ensure};
use bare_metal_deployment::deploy::{
    DeploymentConfig, DeploymentError, ImageSource, deploy_to_bare_metal, establish_ssh_connection,
};
use bare_metal_deployment::{BareMetalIpmiSession, LoginInfo, parse_login_info_from_csv};
use clap::Parser;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

#[derive(Parser, Debug)]
#[command(
    about = "Deploy HostOS and GuestOS images to bare metal hosts. If no images are specified, checks SSH connection and injects key via IPMI if needed."
)]
struct Args {
    /// Path to CSV file with baremetal login info (host,username,password,guest_ipv6), e.g. zh2-dll01.csv.
    /// Ask the node team for access to this file.
    #[arg(long)]
    login_info: PathBuf,

    /// HostOS environment to build (e.g., "dev", "prod").
    /// If left empty, HostOS will not be deployed.
    #[arg(long)]
    hostos: Option<String>,

    /// GuestOS environment to build (e.g., "dev", "prod").
    /// If left empty, GuestOS will not be deployed.
    #[arg(long)]
    guestos: Option<String>,

    /// Skip building images with Bazel, use a previously built image.
    /// Fails if images are not found at expected paths.
    #[arg(long)]
    nobuild: bool,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum OsType {
    HostOs,
    GuestOs,
}

impl Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsType::HostOs => write!(f, "HostOS"),
            OsType::GuestOs => write!(f, "GuestOS"),
        }
    }
}

/// Attempts to find a default SSH key in the user's .ssh directory.
/// Returns (public_key, private_key_path)
fn get_default_ssh_keys() -> Result<(String, PathBuf)> {
    let home_dir = std::env::var("HOME").context("HOME environment variable not set")?;
    let home_path = Path::new(&home_dir);

    let key_paths = [
        home_path.join(".ssh/id_ed25519"),
        home_path.join(".ssh/id_rsa"),
        home_path.join(".ssh/id_ecdsa"),
    ];

    for private_key_path in &key_paths {
        if private_key_path.exists() {
            let public_key_path = private_key_path.with_extension("pub");
            let public_key = fs::read_to_string(&public_key_path).with_context(|| {
                format!("Failed to read SSH public key from {:?}", public_key_path)
            })?;
            return Ok((public_key, private_key_path.clone()));
        }
    }

    bail!(
        "No SSH private key found. Tried: {}",
        key_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn build_image(os_type: OsType, env: &str) -> Result<()> {
    let bazel_target = match os_type {
        OsType::HostOs => format!("//ic-os/hostos/envs/{env}:update-img.tar.zst"),
        OsType::GuestOs => format!("//ic-os/guestos/envs/{env}:disk-img.tar.zst"),
    };

    println!("Building {bazel_target}");

    let output = Command::new("bazel")
        .arg("build")
        .arg(&bazel_target)
        .status()
        .context("Failed to execute bazel build")?;

    ensure!(output.success(), "Bazel build failed for {bazel_target}");
    println!("Successfully built {bazel_target}");

    Ok(())
}

fn artifact_path(os_type: OsType, env: &str) -> PathBuf {
    match os_type {
        OsType::HostOs => PathBuf::from(format!(
            "bazel-bin/ic-os/hostos/envs/{env}/update-img.tar.zst",
        )),
        OsType::GuestOs => PathBuf::from(format!(
            "bazel-bin/ic-os/guestos/envs/{env}/disk-img.tar.zst",
        )),
    }
}

fn get_or_build_image(os_type: OsType, env: &str, build: bool) -> Result<PathBuf> {
    if build {
        build_image(os_type, env)?;
    } else {
        println!("Skipping {} build (--nobuild specified)", os_type);
    }
    let path = artifact_path(os_type, env);
    ensure!(
        path.exists(),
        "{os_type} image not found at {}.",
        path.display()
    );

    Ok(path)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(working_dir) = env::var_os("BUILD_WORKING_DIRECTORY") {
        env::set_current_dir(working_dir)?;
    }

    let config = DeploymentConfig {
        hostos_upgrade_image: args
            .hostos
            .map(|env| get_or_build_image(OsType::HostOs, &env, !args.nobuild))
            .transpose()?
            .map(ImageSource::File),
        guestos_image: args
            .guestos
            .map(|env| get_or_build_image(OsType::GuestOs, &env, !args.nobuild))
            .transpose()?
            .map(ImageSource::File),
        setupos_config_image: None,
    };

    println!("Loading SSH keys...");
    let (ssh_public_key, ssh_private_key_path) = get_default_ssh_keys()?;
    println!("Using SSH key: {:?}.pub", ssh_private_key_path);

    println!("Reading login info from {:?}", args.login_info);
    let login_csv = fs::read_to_string(&args.login_info)
        .with_context(|| format!("Failed to read login info from {:?}", args.login_info))?;
    let login_info = parse_login_info_from_csv(&login_csv)?;

    let host_ip = login_info.hostos_address();

    // Check if we need to deploy or just verify SSH connection
    let has_images = config.hostos_upgrade_image.is_some()
        || config.guestos_image.is_some()
        || config.setupos_config_image.is_some();

    let final_host_ip = if has_images {
        println!("Deploying to bare metal host at {host_ip}");
        let ip = execute_with_ssh_recovery(
            |ip| deploy_to_bare_metal(&config, ip.into(), &ssh_private_key_path),
            &login_info,
            &ssh_public_key,
        )?;
        println!("Deployment completed successfully");
        ip
    } else {
        println!("No images specified. Checking SSH connection to {host_ip}...");
        let ip = execute_with_ssh_recovery(
            |ip| establish_ssh_connection(ip.into(), &ssh_private_key_path).map(|_| ()),
            &login_info,
            &ssh_public_key,
        )?;
        println!("SSH connection successful");
        ip
    };
    if config.hostos_upgrade_image.is_some() {
        println!("You'll need to wait 1-2 minutes for the host to reboot.");
    }

    println!("You can SSH into the host using the following command:");
    println!("ssh admin@{final_host_ip}");

    Ok(())
}

/// Executes an SSH operation with automatic error recovery via IPMI:
/// If SSH connection or authentication fails: Connects via IPMI, injects SSH key, uses IPMI's
/// host IP, and retries.
/// Returns the final host IP address used (may differ from initial IP if recovery was needed).
fn execute_with_ssh_recovery<F>(
    mut operation: F,
    login_info: &LoginInfo,
    ssh_public_key: &str,
) -> Result<std::net::Ipv6Addr>
where
    F: FnMut(std::net::Ipv6Addr) -> Result<(), DeploymentError>,
{
    match operation(login_info.hostos_address()) {
        Ok(_) => Ok(login_info.hostos_address()),
        Err(DeploymentError::SshAuthFailed) | Err(DeploymentError::SshConnectionFailed(_)) => {
            println!("SSH failed. Connecting via IPMI to inject key and get current host IP...");
            let mut ipmi_session = BareMetalIpmiSession::start(login_info)?;
            ipmi_session.inject_ssh_key(ssh_public_key)?;
            let ipmi_host_ip = ipmi_session.hostos_address();
            println!("SSH key injected. Using host IP from IPMI: {ipmi_host_ip}");
            drop(ipmi_session);

            println!("Retrying...");
            operation(ipmi_host_ip)?;
            Ok(ipmi_host_ip)
        }
        Err(DeploymentError::Other(e)) => Err(e),
    }
}
