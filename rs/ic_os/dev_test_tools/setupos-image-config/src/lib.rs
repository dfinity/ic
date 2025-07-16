use std::{
    assert, fs,
    fs::File,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Error};
use clap::Args;
use tempfile::TempDir;
use url::Url;

use config::setupos::deployment_json::DeploymentSettings;
use config_types::DeploymentEnvironment;
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
    pub nns_urls: Option<Url>,

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
    pub deployment_environment: Option<DeploymentEnvironment>,

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

    if let Some(nns_urls) = &cfg.nns_urls {
        deployment_json.nns.urls = vec![nns_urls.clone()];
    }

    if let Some(memory) = cfg.memory_gb {
        deployment_json.vm_resources.memory = memory;
    }

    if let Some(cpu) = &cfg.cpu {
        deployment_json.vm_resources.cpu = cpu.to_owned();
    }

    if let Some(nr_of_vcpus) = &cfg.nr_of_vcpus {
        deployment_json.vm_resources.nr_of_vcpus = nr_of_vcpus.to_owned();
    }

    if let Some(deployment_environment) = &cfg.deployment_environment {
        deployment_json.deployment.deployment_environment = deployment_environment.to_owned();
    }

    if let Some(elasticsearch_hosts) = &cfg.elasticsearch_hosts {
        deployment_json.logging.elasticsearch_hosts = Some(elasticsearch_hosts.to_owned());
    }

    if let Some(elasticsearch_tags) = &cfg.elasticsearch_tags {
        deployment_json.logging.elasticsearch_tags = Some(elasticsearch_tags.to_owned());
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
    // Clean up any existing loop devices and LVM state
    println!("Cleaning up any existing loop devices and LVM state...");

    // Unmount any mounted hostlvm devices
    let mount_output = Command::new("mount").output();
    if let Ok(output) = mount_output {
        let mount_text = String::from_utf8_lossy(&output.stdout);
        for line in mount_text.lines() {
            if line.contains("/dev/mapper/hostlvm-") {
                if let Some(mount_point) = line.split_whitespace().nth(2) {
                    let _ = Command::new("sudo")
                        .args(["umount", "-f", mount_point])
                        .output();
                }
            }
        }
    }

    // Deactivate and remove hostlvm volume group
    let _ = Command::new("sudo")
        .args(["/usr/sbin/vgchange", "-an", "hostlvm"])
        .output();
    let _ = Command::new("sudo")
        .args(["/usr/sbin/vgremove", "--force", "hostlvm"])
        .output();

    // Clean up existing loop devices
    let losetup_output = Command::new("sudo")
        .args(["/usr/sbin/losetup", "-a"])
        .output();

    if let Ok(output) = losetup_output {
        let losetup_text = String::from_utf8_lossy(&output.stdout);
        for line in losetup_text.lines() {
            if let Some(device) = line.split(':').next() {
                let _ = Command::new("sudo")
                    .args(["/usr/sbin/losetup", "-d", device])
                    .output();
            }
        }
    }

    // Clear LVM cache
    let _ = Command::new("sudo")
        .args(["/usr/sbin/pvscan", "--cache"])
        .output();

    thread::sleep(Duration::from_secs(1));

    // Create temporary directory for extraction
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    // Extract host-os.img.tar.zst from data partition
    println!("Extracting HostOS image from SetupOS data partition...");
    let mut data_partition = ExtPartition::open(setupos_image_path.to_owned(), Some(4)).await?;

    let data_extract_dir = work_dir.join("data_partition");
    fs::create_dir_all(&data_extract_dir).context("failed to create data partition extract dir")?;
    data_partition
        .copy_files_to(&data_extract_dir)
        .await
        .context("failed to extract data partition contents")?;

    let hostos_compressed_path = work_dir.join("host-os.img.tar.zst");
    let source_hostos_path = data_extract_dir.join("host-os.img.tar.zst");

    fs::copy(&source_hostos_path, &hostos_compressed_path)
        .context("failed to copy host-os.img.tar.zst to work directory")?;

    data_partition.close().await?;

    // Decompress .zst file
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

    // Extract tar file
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

    // Verify disk image
    let metadata = fs::metadata(&hostos_img_path).context("failed to get disk image metadata")?;
    if metadata.len() == 0 {
        bail!("Disk image is empty");
    }

    // Set up loop device for HostOS image
    println!("Setting up loop device for HostOS image...");
    let loop_output = Command::new("sudo")
        .args([
            "/usr/sbin/losetup",
            "-f",
            "--show",
            "-P",
            hostos_img_path.to_str().unwrap(),
        ])
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

    // Cleanup guard for loop device
    struct LoopDeviceGuard {
        device_path: String,
    }

    impl Drop for LoopDeviceGuard {
        fn drop(&mut self) {
            let _ = Command::new("sudo")
                .args(["/usr/sbin/vgchange", "-an", "hostlvm"])
                .output();
            thread::sleep(Duration::from_millis(500));
            let _ = Command::new("sudo")
                .args(["/usr/sbin/losetup", "-d", &self.device_path])
                .output();
        }
    }

    let _loop_guard = LoopDeviceGuard {
        device_path: loop_device.clone(),
    };

    // Force partition table re-read
    let _ = Command::new("sudo")
        .args(["/usr/sbin/blockdev", "--rereadpt", &loop_device])
        .output();

    thread::sleep(Duration::from_secs(2));

    // Activate LVM
    println!("Activating LVM...");
    let pv_path = format!("{}p3", loop_device);

    // Wait for partition to appear
    let mut retry_count = 0;
    while retry_count < 5 && !Path::new(&pv_path).exists() {
        thread::sleep(Duration::from_millis(1000));
        retry_count += 1;
    }

    if !Path::new(&pv_path).exists() {
        bail!("LVM physical volume partition {} does not exist", pv_path);
    }

    let lvm_output = Command::new("sudo")
        .args(["/usr/sbin/vgchange", "-ay", "hostlvm"])
        .output()
        .context("failed to activate LVM")?;

    if !lvm_output.status.success() {
        bail!(
            "LVM activation failed: {}",
            String::from_utf8_lossy(&lvm_output.stderr)
        );
    }

    // Mount and modify boot partition A
    println!("Mounting and modifying boot partition...");
    let mount_point_a = work_dir.join("boot_a");
    fs::create_dir_all(&mount_point_a).context("failed to create mount point A")?;

    // Find A_boot device path
    let possible_a_boot_paths = vec![
        "/dev/hostlvm/A_boot",
        "/dev/mapper/hostlvm-A_boot",
        "/dev/mapper/hostlvm-A--boot",
    ];

    let mut a_boot_path = None;
    for path in &possible_a_boot_paths {
        if Path::new(path).exists() {
            a_boot_path = Some(path.to_string());
            break;
        }
    }

    let a_boot_path =
        a_boot_path.ok_or_else(|| anyhow::anyhow!("Could not find A_boot device node"))?;

    // Mount boot partition A
    let mount_a_output = Command::new("sudo")
        .args([
            "mount",
            "-o",
            "rw",
            &a_boot_path,
            mount_point_a.to_str().unwrap(),
        ])
        .output()
        .context("failed to mount boot partition A")?;

    if !mount_a_output.status.success() {
        bail!(
            "Failed to mount boot partition A: {}",
            String::from_utf8_lossy(&mount_a_output.stderr)
        );
    }

    // Modify boot_args file
    let boot_args_a_path = mount_point_a.join("boot_args");
    let mut content =
        fs::read_to_string(&boot_args_a_path).context("failed to read boot_args file")?;

    let hash_param = format!(" hash={}", boot_parameter);

    // Add hash parameter to both BOOT_ARGS_A and BOOT_ARGS_B lines
    if let Some(start) = content.find("BOOT_ARGS_A=\"") {
        if let Some(end) = content[start..].find("\"\n").map(|i| start + i) {
            content.insert_str(end, &hash_param);
        }
    }

    if let Some(start) = content.find("BOOT_ARGS_B=\"") {
        if let Some(end) = content[start..].find("\"\n").map(|i| start + i) {
            content.insert_str(end, &hash_param);
        }
    }

    // Write modified content using temporary file
    let temp_file_path = work_dir.join("boot_args_modified.tmp");
    fs::write(&temp_file_path, &content).context("failed to write temporary boot_args file")?;

    let cp_output = Command::new("sudo")
        .args([
            "cp",
            temp_file_path.to_str().unwrap(),
            boot_args_a_path.to_str().unwrap(),
        ])
        .output()
        .context("failed to copy modified boot_args file")?;

    if !cp_output.status.success() {
        bail!(
            "Failed to copy modified boot_args file: {}",
            String::from_utf8_lossy(&cp_output.stderr)
        );
    }

    let _ = fs::remove_file(&temp_file_path);

    // Unmount partition A
    let _ = Command::new("sudo")
        .args(["umount", mount_point_a.to_str().unwrap()])
        .output();

    // Repackage the HostOS image
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

    // Compress the tar file
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

    // Write the modified HostOS image back to data partition
    println!("Writing modified HostOS image back to SetupOS...");
    let modified_content =
        fs::read(&hostos_compressed_path).context("failed to read modified host-os.img.tar.zst")?;

    let mut data_partition = ExtPartition::open(setupos_image_path.to_owned(), Some(4)).await?;

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
