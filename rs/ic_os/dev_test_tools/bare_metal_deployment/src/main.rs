use anyhow::{Context, Result, bail, ensure};
use bare_metal_deployment::{
    BareMetalIpmiSession,
    parse_login_info_from_csv,
};
use clap::Parser;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};
use bare_metal_deployment::deploy::{deploy_to_bare_metal, DeploymentConfig, ImageSource};

#[derive(Parser, Debug)]
#[command(about = "Deploy HostOS and GuestOS images to bare metal hosts. If no images are specified, only injects SSH key via IPMI.")]
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
    // If running via bazel run, set the current directory to the "main" directory.
    if let Some(working_dir) = env::var_os("BUILD_WORKING_DIRECTORY") {
        env::set_current_dir(working_dir)?;
    }

    if args.hostos.is_none() && args.guestos.is_none() {
        println!("Neither --hostos nor --guestos specified; will only inject SSH key via IPMI.");
    }

    let hostos_image = args
        .hostos
        .map(|env| get_or_build_image(OsType::HostOs, &env, !args.nobuild))
        .transpose()?;
    let guestos_image = args
        .guestos
        .map(|env| get_or_build_image(OsType::GuestOs, &env, !args.nobuild))
        .transpose()?;

    let config = DeploymentConfig {
        hostos_upgrade_image: hostos_image.map(ImageSource::File),
        guestos_image: guestos_image.map(ImageSource::File),
        // TODO: Maybe in the future we could support injecting config via this tool.
        setupos_config_image: None,
    };

    // Read login info from CSV file
    println!("Reading login info from {:?}", args.login_info);
    let login_csv = fs::read_to_string(&args.login_info)
        .with_context(|| format!("Failed to read login info from {:?}", args.login_info))?;
    let login_info = parse_login_info_from_csv(&login_csv)?;

    // Get SSH keys
    println!("Loading SSH keys...");
    let (ssh_public_key, ssh_private_key_path) = get_default_ssh_keys()?;
    println!("Using SSH key: {:?}.pub", ssh_private_key_path);

    // Inject SSH key via IPMI
    println!("Connecting to bare metal host via IPMI...");
    let mut ipmi_session = BareMetalIpmiSession::start(&login_info)?;
    let host_ip = ipmi_session.host_address();
    println!("Connected to bare metal host. HostOS IP: {host_ip}");
    ipmi_session.inject_ssh_key(&ssh_public_key)?;
    println!("SSH key injected successfully");

    if config.guestos_image.is_some() || config.hostos_upgrade_image.is_some() {
        println!("Deploying to bare metal host at {host_ip}");
        deploy_to_bare_metal(&config, host_ip.into(), &ssh_private_key_path)?;
        if config.hostos_upgrade_image.is_some() {
            println!("You'll need to wait 1-2 minutes for the host to reboot.");
        }
    } else {
        println!("Skipping deployment (--hostos or --guestos not specified)");
    }

    println!("You can SSH into the host using the following command:");
    println!("ssh admin@{host_ip}");

    Ok(())
}
