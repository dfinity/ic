use std::{
    assert, fs,
    fs::File,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
};

use anyhow::{bail, Context, Error};
use clap::Args;
use tempfile::TempDir;
use url::Url;

use config::deployment_json::DeploymentSettings;
use partition_tools::{ext::ExtPartition, Partition};

#[derive(Args)]
pub struct ConfigIni {
    #[arg(long)]
    node_reward_type: Option<String>,

    #[arg(long)]
    ipv6_prefix: Option<String>,

    #[arg(long)]
    ipv6_gateway: Option<Ipv6Addr>,

    #[arg(long)]
    ipv4_address: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_gateway: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_prefix_length: Option<u8>,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long)]
    enable_trusted_execution_environment: Option<bool>,

    #[arg(long)]
    verbose: Option<String>,
}

#[derive(Args)]
pub struct DeploymentConfig {
    #[arg(long)]
    pub nns_url: Option<Url>,

    #[arg(long, allow_hyphen_values = true)]
    pub nns_public_key: Option<String>,

    #[arg(long)]
    pub memory_gb: Option<u32>,

    /// Can be "kvm" or "qemu". If None, is treated as "kvm".
    #[arg(long)]
    pub cpu: Option<String>,

    /// If None, is treated as 64.
    #[arg(long)]
    pub nr_of_vcpus: Option<u32>,

    #[arg(long)]
    pub mgmt_mac: Option<String>,

    #[arg(long)]
    pub deployment_environment: Option<String>,

    #[arg(long)]
    pub elasticsearch_hosts: Option<String>,

    #[arg(long)]
    pub elasticsearch_tags: Option<String>,

    #[arg(long)]
    pub hostos_recovery_upgrader_boot_parameter: Option<String>,
}

pub async fn write_config(path: &Path, cfg: &ConfigIni) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create config file")?;

    let ConfigIni {
        node_reward_type,
        ipv6_prefix,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        enable_trusted_execution_environment,
        domain,
        verbose,
    } = cfg;

    if let Some(node_reward_type) = node_reward_type {
        writeln!(&mut f, "node_reward_type={}", node_reward_type)?;
    }

    if let (Some(ipv6_prefix), Some(ipv6_gateway)) = (ipv6_prefix, ipv6_gateway) {
        // Always write 4 segments, even if our prefix is less.
        assert!(format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok());
        writeln!(&mut f, "ipv6_prefix={}", ipv6_prefix)?;
        writeln!(&mut f, "ipv6_gateway={}", ipv6_gateway)?;
    }

    if let (Some(ipv4_address), Some(ipv4_gateway), Some(ipv4_prefix_length), Some(domain)) =
        (ipv4_address, ipv4_gateway, ipv4_prefix_length, domain)
    {
        writeln!(&mut f, "ipv4_address={}", ipv4_address)?;
        writeln!(&mut f, "ipv4_gateway={}", ipv4_gateway)?;
        writeln!(&mut f, "ipv4_prefix_length={}", ipv4_prefix_length)?;
        writeln!(&mut f, "domain={}", domain)?;
    }

    if let Some(enable_trusted_execution_environment) = enable_trusted_execution_environment {
        writeln!(
            &mut f,
            "enable_trusted_execution_environment={}",
            enable_trusted_execution_environment
        )?;
    }

    if let Some(verbose) = verbose {
        writeln!(&mut f, "verbose={}", verbose)?;
    }

    Ok(())
}

pub async fn write_public_keys(path: &Path, ks: Vec<String>) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create public keys file")?;

    for k in ks {
        writeln!(&mut f, "{k}")?;
    }

    Ok(())
}

pub async fn update_deployment(path: &Path, cfg: &DeploymentConfig) -> Result<(), Error> {
    let mut deployment_json = {
        let f = File::open(path).context("failed to open deployment config file")?;
        let deployment_json: DeploymentSettings = serde_json::from_reader(f)?;

        deployment_json
    };

    if let Some(mgmt_mac) = &cfg.mgmt_mac {
        deployment_json.deployment.mgmt_mac = Some(mgmt_mac.to_owned());
    }

    if let Some(nns_url) = &cfg.nns_url {
        deployment_json.nns.url = vec![nns_url.clone()];
    }

    if let Some(memory) = cfg.memory_gb {
        deployment_json.resources.memory = memory;
    }

    if let Some(cpu) = &cfg.cpu {
        deployment_json.resources.cpu = Some(cpu.to_owned());
    }

    if let Some(nr_of_vcpus) = &cfg.nr_of_vcpus {
        deployment_json.resources.nr_of_vcpus = Some(nr_of_vcpus.to_owned());
    }

    if let Some(deployment_environment) = &cfg.deployment_environment {
        deployment_json.deployment.name = deployment_environment.to_owned();
    }

    if let Some(elasticsearch_hosts) = &cfg.elasticsearch_hosts {
        deployment_json.logging.hosts = elasticsearch_hosts.to_owned();
    }

    if let Some(elasticsearch_tags) = &cfg.elasticsearch_tags {
        deployment_json.logging.tags = Some(elasticsearch_tags.to_owned());
    }

    let mut f = File::create(path).context("failed to open deployment config file")?;
    let output = serde_json::to_string_pretty(&deployment_json)?;
    write!(&mut f, "{output}")?;

    Ok(())
}

pub async fn update_hostos_boot_args(
    setupos_image_path: &Path,
    boot_parameter: &str,
) -> Result<(), Error> {
    // Create temporary directory for extraction
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    // Step 1: Extract host-os.img.tar.zst from data partition
    println!("Extracting HostOS image from SetupOS data partition...");
    let mut data_partition = ExtPartition::open(setupos_image_path.to_owned(), Some(4)).await?;

    let hostos_compressed_path = work_dir.join("host-os.img.tar.zst");
    let hostos_compressed_content = data_partition
        .read_file(Path::new("/host-os.img.tar.zst"))
        .await
        .context("failed to read host-os.img.tar.zst from data partition")?;

    fs::write(&hostos_compressed_path, hostos_compressed_content)
        .context("failed to write host-os.img.tar.zst to temp directory")?;

    data_partition.close().await?;

    // Step 2: Decompress .zst file
    println!("Decompressing HostOS image...");
    let hostos_tar_path = work_dir.join("host-os.img.tar");
    let output = Command::new("zstd")
        .args([
            "-d",
            hostos_compressed_path.to_str().unwrap(),
            "-o",
            hostos_tar_path.to_str().unwrap(),
        ])
        .output()
        .context("failed to run zstd decompression")?;

    if !output.status.success() {
        bail!(
            "zstd decompression failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Step 3: Extract tar file
    println!("Extracting HostOS tar archive...");
    let hostos_img_path = work_dir.join("disk.img");
    let output = Command::new("tar")
        .args([
            "-xf",
            hostos_tar_path.to_str().unwrap(),
            "-C",
            work_dir.to_str().unwrap(),
        ])
        .output()
        .context("failed to extract tar file")?;

    if !output.status.success() {
        bail!(
            "tar extraction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Step 4: Set up loop device for HostOS image
    println!("Setting up loop device for HostOS image...");
    let loop_output = Command::new("losetup")
        .args(["-f", "--show", "-P", hostos_img_path.to_str().unwrap()])
        .output()
        .context("failed to set up loop device")?;

    if !loop_output.status.success() {
        bail!(
            "losetup failed: {}",
            String::from_utf8_lossy(&loop_output.stderr)
        );
    }

    let loop_device = String::from_utf8(loop_output.stdout)
        .context("invalid loop device output")?
        .trim()
        .to_string();

    println!("Using loop device: {}", loop_device);

    // Ensure we clean up the loop device
    let cleanup_loop = || {
        let _ = Command::new("losetup").args(["-d", &loop_device]).output();
    };

    // Step 5: Activate LVM
    println!("Activating LVM...");
    let lvm_output = Command::new("vgchange")
        .args(["-ay", "hostlvm"])
        .output()
        .context("failed to activate LVM")?;

    if !lvm_output.status.success() {
        cleanup_loop();
        bail!(
            "LVM activation failed: {}",
            String::from_utf8_lossy(&lvm_output.stderr)
        );
    }

    // Step 6: Mount and modify boot partitions
    let mount_point_a = work_dir.join("boot_a");
    let mount_point_b = work_dir.join("boot_b");
    fs::create_dir_all(&mount_point_a).context("failed to create mount point A")?;
    fs::create_dir_all(&mount_point_b).context("failed to create mount point B")?;

    // Mount boot partition A
    println!("Mounting boot partition A...");
    let mount_a_output = Command::new("mount")
        .args(["/dev/hostlvm/A_boot", mount_point_a.to_str().unwrap()])
        .output()
        .context("failed to mount boot partition A")?;

    if !mount_a_output.status.success() {
        cleanup_loop();
        bail!(
            "Failed to mount boot partition A: {}",
            String::from_utf8_lossy(&mount_a_output.stderr)
        );
    }

    // Mount boot partition B
    println!("Mounting boot partition B...");
    let mount_b_output = Command::new("mount")
        .args(["/dev/hostlvm/B_boot", mount_point_b.to_str().unwrap()])
        .output()
        .context("failed to mount boot partition B")?;

    if !mount_b_output.status.success() {
        let _ = Command::new("umount")
            .args([mount_point_a.to_str().unwrap()])
            .output();
        cleanup_loop();
        bail!(
            "Failed to mount boot partition B: {}",
            String::from_utf8_lossy(&mount_b_output.stderr)
        );
    }

    // Function to modify boot_args file
    let modify_boot_args = |boot_args_path: &Path| -> Result<(), Error> {
        let mut content =
            fs::read_to_string(boot_args_path).context("failed to read boot_args file")?;

        println!("Original boot_args content:\n{}", content);

        // Add hash parameter to both BOOT_ARGS_A and BOOT_ARGS_B lines
        let hash_param = format!(" hash={}", boot_parameter);

        // Process BOOT_ARGS_A line
        if let Some(start) = content.find("BOOT_ARGS_A=\"") {
            if let Some(end) = content[start..].find("\"\n").map(|i| start + i) {
                content.insert_str(end, &hash_param);
            }
        }

        // Process BOOT_ARGS_B line (need to search again after modification)
        if let Some(start) = content.find("BOOT_ARGS_B=\"") {
            if let Some(end) = content[start..].find("\"\n").map(|i| start + i) {
                content.insert_str(end, &hash_param);
            }
        }

        println!("Modified boot_args content:\n{}", content);

        fs::write(boot_args_path, content).context("failed to write modified boot_args file")?;

        Ok(())
    };

    // Modify boot_args in both partitions
    println!("Modifying boot_args in partition A...");
    let boot_args_a_path = mount_point_a.join("boot_args");
    modify_boot_args(&boot_args_a_path)?;

    println!("Modifying boot_args in partition B...");
    let boot_args_b_path = mount_point_b.join("boot_args");
    modify_boot_args(&boot_args_b_path)?;

    // Step 7: Unmount partitions
    println!("Unmounting boot partitions...");
    let _ = Command::new("umount")
        .args([mount_point_a.to_str().unwrap()])
        .output();
    let _ = Command::new("umount")
        .args([mount_point_b.to_str().unwrap()])
        .output();

    // Step 8: Deactivate LVM
    println!("Deactivating LVM...");
    let _ = Command::new("vgchange").args(["-an", "hostlvm"]).output();

    // Step 9: Clean up loop device
    cleanup_loop();

    // Step 10: Repackage the HostOS image
    println!("Repackaging HostOS image...");
    let repack_tar_output = Command::new("tar")
        .args([
            "-cf",
            hostos_tar_path.to_str().unwrap(),
            "-C",
            work_dir.to_str().unwrap(),
            "disk.img",
        ])
        .output()
        .context("failed to repackage tar file")?;

    if !repack_tar_output.status.success() {
        bail!(
            "tar repackaging failed: {}",
            String::from_utf8_lossy(&repack_tar_output.stderr)
        );
    }

    // Step 11: Compress the tar file
    println!("Compressing HostOS image...");
    let compress_output = Command::new("zstd")
        .args([
            hostos_tar_path.to_str().unwrap(),
            "-o",
            hostos_compressed_path.to_str().unwrap(),
            "--rm",
        ])
        .output()
        .context("failed to compress tar file")?;

    if !compress_output.status.success() {
        bail!(
            "zstd compression failed: {}",
            String::from_utf8_lossy(&compress_output.stderr)
        );
    }

    // Step 12: Write the modified HostOS image back to data partition
    println!("Writing modified HostOS image back to SetupOS...");
    let modified_content =
        fs::read(&hostos_compressed_path).context("failed to read modified host-os.img.tar.zst")?;

    let mut data_partition = ExtPartition::open(setupos_image_path.to_owned(), Some(4)).await?;

    // Write using a temporary file
    let temp_file = work_dir.join("temp_hostos.tar.zst");
    fs::write(&temp_file, &modified_content).context("failed to write temp file")?;

    data_partition
        .write_file(&temp_file, Path::new("/host-os.img.tar.zst"))
        .await
        .context("failed to write modified host-os.img.tar.zst back to data partition")?;

    data_partition.close().await?;

    println!("Successfully updated HostOS boot parameters!");
    Ok(())
}
