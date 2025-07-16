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
    // Preemptively deactivate any lingering LVM VGs to avoid conflicts.
    let _ = Command::new("sudo")
        .args(["/usr/sbin/vgchange", "-an", "hostlvm"])
        .output();
    let _ = Command::new("sudo")
        .args(["/usr/sbin/pvscan", "--cache"])
        .output();

    // Create temporary directory for extraction
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    // Step 1: Extract host-os.img.tar.zst from data partition
    println!("Extracting HostOS image from SetupOS data partition...");
    let mut data_partition = ExtPartition::open(setupos_image_path.to_owned(), Some(4)).await?;

    // Extract all files from data partition to temp directory
    let data_extract_dir = work_dir.join("data_partition");
    fs::create_dir_all(&data_extract_dir).context("failed to create data partition extract dir")?;
    data_partition
        .copy_files_to(&data_extract_dir)
        .await
        .context("failed to extract data partition contents")?;

    let hostos_compressed_path = work_dir.join("host-os.img.tar.zst");
    let source_hostos_path = data_extract_dir.join("host-os.img.tar.zst");

    // Copy the binary file directly
    fs::copy(&source_hostos_path, &hostos_compressed_path)
        .context("failed to copy host-os.img.tar.zst to work directory")?;

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

    // Step 4: Verify disk image before setting up loop device
    println!("Verifying disk image...");
    let metadata = fs::metadata(&hostos_img_path).context("failed to get disk image metadata")?;
    println!("Disk image size: {} bytes", metadata.len());

    if metadata.len() == 0 {
        bail!("Disk image is empty");
    }

    // Step 4: Set up loop device for HostOS image using sudo
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
    println!("Using loop device: {}", loop_device);

    // Ensure we clean up the loop device using a scope guard (RAII)
    struct LoopDeviceGuard {
        device_path: String,
    }

    impl Drop for LoopDeviceGuard {
        fn drop(&mut self) {
            println!("Cleaning up loop device {}...", &self.device_path);
            let _ = Command::new("sudo")
                .args(["/usr/sbin/vgchange", "-an", "hostlvm"])
                .output();
            let _ = Command::new("sudo")
                .args(["/usr/sbin/losetup", "-d", &self.device_path])
                .output();
            let _ = Command::new("sudo")
                .args(["/usr/sbin/pvscan", "--cache"])
                .output();
        }
    }

    let _loop_guard = LoopDeviceGuard {
        device_path: loop_device.clone(),
    };

    // Force kernel to re-read partition table
    println!("Forcing partition table re-read...");
    let reread_output = Command::new("sudo")
        .args(["/usr/sbin/blockdev", "--rereadpt", &loop_device])
        .output()
        .context("failed to run blockdev --rereadpt")?;

    if !reread_output.status.success() {
        println!(
            "blockdev --rereadpt warning: {}",
            String::from_utf8_lossy(&reread_output.stderr)
        );
        // Try alternative method using sfdisk
        println!("Trying alternative method with sfdisk...");
        let sfdisk_output = Command::new("sudo")
            .args(["/usr/sbin/sfdisk", "-R", &loop_device])
            .output()
            .context("failed to run sfdisk -R")?;

        if !sfdisk_output.status.success() {
            println!(
                "sfdisk -R warning: {}",
                String::from_utf8_lossy(&sfdisk_output.stderr)
            );
        }

        // Try kpartx as last resort
        println!("Trying kpartx to create partition mappings...");
        let kpartx_output = Command::new("sudo")
            .args(["kpartx", "-av", &loop_device])
            .output();

        if let Ok(output) = kpartx_output {
            if output.status.success() {
                println!("kpartx output: {}", String::from_utf8_lossy(&output.stdout));
            } else {
                println!(
                    "kpartx warning: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        } else {
            println!("kpartx not available");
        }
    }

    // Give kernel time to detect partitions and manually create device nodes
    thread::sleep(Duration::from_secs(2));

    // Since udev isn't available in this build environment, manually create device nodes
    println!("Manually creating partition device nodes...");

    // Parse lsblk output to get major:minor numbers for partitions
    let lsblk_output = Command::new("lsblk")
        .args(["-r", "-n", "-o", "NAME,MAJ:MIN", &loop_device])
        .output()
        .context("failed to run lsblk for device numbers")?;

    let lsblk_text = String::from_utf8_lossy(&lsblk_output.stdout);
    println!("lsblk device info:\n{}", lsblk_text);

    // Create device nodes for each partition
    for line in lsblk_text.lines() {
        if line.contains("part") || line.contains("p") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let maj_min = parts[1];

                if let Some((major, minor)) = maj_min.split_once(':') {
                    let device_path = format!("/dev/{}", name);

                    println!(
                        "Creating device node: {} ({}:{})",
                        device_path, major, minor
                    );

                    let mknod_output = Command::new("sudo")
                        .args(["mknod", &device_path, "b", major, minor])
                        .output()
                        .context("failed to create device node with mknod")?;

                    if !mknod_output.status.success() {
                        println!(
                            "mknod warning for {}: {}",
                            device_path,
                            String::from_utf8_lossy(&mknod_output.stderr)
                        );
                    } else {
                        println!("Successfully created: {}", device_path);
                    }
                }
            }
        }
    }

    // Give time for device nodes to be available
    thread::sleep(Duration::from_secs(1));

    // Debug: Check the disk image partition table
    println!("=== DEBUGGING DISK IMAGE PARTITION TABLE ===");
    let fdisk_output = Command::new("sudo")
        .args(["/usr/sbin/fdisk", "-l", &hostos_img_path.to_string_lossy()])
        .output()
        .context("failed to run fdisk on disk image")?;
    println!("fdisk -l output for disk image:");
    println!("{}", String::from_utf8_lossy(&fdisk_output.stdout));
    if !fdisk_output.stderr.is_empty() {
        println!("fdisk errors:");
        println!("{}", String::from_utf8_lossy(&fdisk_output.stderr));
    }

    let fdisk_loop_output = Command::new("sudo")
        .args(["/usr/sbin/fdisk", "-l", &loop_device])
        .output()
        .context("failed to run fdisk on loop device")?;
    println!("fdisk -l output for loop device:");
    println!("{}", String::from_utf8_lossy(&fdisk_loop_output.stdout));
    if !fdisk_loop_output.stderr.is_empty() {
        println!("fdisk errors for loop device:");
        println!("{}", String::from_utf8_lossy(&fdisk_loop_output.stderr));
    }

    // Debug: Check lsblk output for the loop device
    println!("=== DEBUGGING LSBLK OUTPUT ===");
    let lsblk_output = Command::new("lsblk")
        .args([&loop_device])
        .output()
        .context("failed to run lsblk")?;
    println!("lsblk output for {}:", loop_device);
    println!("{}", String::from_utf8_lossy(&lsblk_output.stdout));
    if !lsblk_output.stderr.is_empty() {
        println!("lsblk errors:");
        println!("{}", String::from_utf8_lossy(&lsblk_output.stderr));
    }

    // Debug: Check if partitions were created
    println!("=== DEBUGGING PARTITION CREATION ===");
    for i in 1..=10 {
        let partition_path = format!("{}p{}", loop_device, i);
        if Path::new(&partition_path).exists() {
            println!("Found partition: {}", partition_path);
            if let Ok(metadata) = fs::metadata(&partition_path) {
                println!(
                    "  Partition {} size/type: {:?}",
                    partition_path,
                    metadata.file_type()
                );
            }
        }
    }

    // Debug: Check what LVM can see
    println!("=== DEBUGGING LVM DETECTION ===");
    let pvscan_output = Command::new("sudo")
        .args(["/usr/sbin/pvscan"])
        .output()
        .context("failed to run pvscan")?;
    println!("pvscan output:");
    println!("{}", String::from_utf8_lossy(&pvscan_output.stdout));
    if !pvscan_output.stderr.is_empty() {
        println!("pvscan errors:");
        println!("{}", String::from_utf8_lossy(&pvscan_output.stderr));
    }

    let vgscan_output = Command::new("sudo")
        .args(["/usr/sbin/vgscan"])
        .output()
        .context("failed to run vgscan")?;
    println!("vgscan output:");
    println!("{}", String::from_utf8_lossy(&vgscan_output.stdout));
    if !vgscan_output.stderr.is_empty() {
        println!("vgscan errors:");
        println!("{}", String::from_utf8_lossy(&vgscan_output.stderr));
    }

    // Step 5: Activate LVM
    println!("Activating LVM...");

    // First, ensure LVM sees the physical volume using a simple retry loop
    let pv_path = format!("{}p3", loop_device);
    let mut retry_count = 0;
    let max_retries = 5;

    while retry_count < max_retries && !Path::new(&pv_path).exists() {
        println!(
            "Waiting for partition {} to appear (attempt {}/{})",
            pv_path,
            retry_count + 1,
            max_retries
        );
        thread::sleep(Duration::from_millis(1000));
        retry_count += 1;
    }

    if !Path::new(&pv_path).exists() {
        // Debug: List what's actually in /dev/
        println!("=== DEBUGGING /dev/ CONTENTS ===");
        if let Ok(output) = Command::new("ls").args(["-la", "/dev/loop*"]).output() {
            println!("ls -la /dev/loop*:");
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }

        bail!(
            "LVM physical volume partition {} does not exist after {} retries. Available partitions: {:?}",
            pv_path,
            max_retries,
            (1..=10)
                .map(|i| format!("{}p{}", loop_device, i))
                .filter(|p| Path::new(p).exists())
                .collect::<Vec<_>>()
        );
    }

    println!("Found partition: {}", pv_path);

    let lvm_output = Command::new("sudo")
        .args(["/usr/sbin/vgchange", "-ay", "hostlvm"])
        .output()
        .context("failed to activate LVM")?;

    if !lvm_output.status.success() {
        bail!(
            "LVM activation failed: {}\nAvailable partitions: {:?}",
            String::from_utf8_lossy(&lvm_output.stderr),
            (1..=10)
                .map(|i| format!("{}p{}", loop_device, i))
                .filter(|p| Path::new(p).exists())
                .collect::<Vec<_>>()
        );
    }

    // Debug: Check device mapper status and manually create device nodes if needed
    println!("=== DEBUGGING DEVICE MAPPER STATUS ===");
    let dmsetup_output = Command::new("sudo")
        .args(["dmsetup", "ls"])
        .output()
        .context("failed to run dmsetup ls")?;
    println!("dmsetup ls output:");
    println!("{}", String::from_utf8_lossy(&dmsetup_output.stdout));

    let dmsetup_info_output = Command::new("sudo")
        .args(["dmsetup", "info"])
        .output()
        .context("failed to run dmsetup info")?;
    println!("dmsetup info output:");
    println!("{}", String::from_utf8_lossy(&dmsetup_info_output.stdout));

    // Try to manually create device nodes for the logical volumes
    println!("=== MANUALLY CREATING DEVICE NODES ===");

    // Get the device mapper names and create device nodes
    let dm_devices = ["hostlvm-A_boot", "hostlvm-B_boot"];

    for dm_name in &dm_devices {
        // Get major:minor for this device
        let dmsetup_table_output = Command::new("sudo")
            .args(["dmsetup", "table", dm_name])
            .output();

        if let Ok(output) = dmsetup_table_output {
            if output.status.success() {
                println!("dmsetup table {} output:", dm_name);
                println!("{}", String::from_utf8_lossy(&output.stdout));

                // Get device info including major:minor
                let dmsetup_info_dev_output = Command::new("sudo")
                    .args(["dmsetup", "info", dm_name])
                    .output();

                if let Ok(info_output) = dmsetup_info_dev_output {
                    let info_text = String::from_utf8_lossy(&info_output.stdout);
                    println!("dmsetup info {} output:", dm_name);
                    println!("{}", info_text);

                    // Extract major:minor from the output
                    if let Some(major_line) =
                        info_text.lines().find(|l| l.contains("Major, minor:"))
                    {
                        if let Some(major_minor) = major_line.split(':').nth(1) {
                            let parts: Vec<&str> = major_minor.trim().split(',').collect();
                            if parts.len() == 2 {
                                if let (Ok(major), Ok(minor)) = (
                                    parts[0].trim().parse::<u32>(),
                                    parts[1].trim().parse::<u32>(),
                                ) {
                                    let device_path = format!("/dev/mapper/{}", dm_name);

                                    println!(
                                        "Creating device node: {} ({}:{})",
                                        device_path, major, minor
                                    );
                                    let mknod_output = Command::new("sudo")
                                        .args([
                                            "mknod",
                                            &device_path,
                                            "b",
                                            &major.to_string(),
                                            &minor.to_string(),
                                        ])
                                        .output();

                                    match mknod_output {
                                        Ok(output) => {
                                            if output.status.success() {
                                                println!(
                                                    "Successfully created device node: {}",
                                                    device_path
                                                );
                                            } else {
                                                println!(
                                                    "mknod failed for {}: {}",
                                                    device_path,
                                                    String::from_utf8_lossy(&output.stderr)
                                                );
                                            }
                                        }
                                        Err(err) => {
                                            println!(
                                                "Failed to run mknod for {}: {}",
                                                device_path, err
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                println!(
                    "dmsetup table failed for {}: {}",
                    dm_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    // Step 6: Mount and modify boot partitions
    let mount_point_a = work_dir.join("boot_a");
    let mount_point_b = work_dir.join("boot_b");
    fs::create_dir_all(&mount_point_a).context("failed to create mount point A")?;
    fs::create_dir_all(&mount_point_b).context("failed to create mount point B")?;

    // Debug: Check if LVM logical volumes exist and are accessible
    println!("=== DEBUGGING LVM LOGICAL VOLUMES ===");
    let lvs_output = Command::new("sudo")
        .args(["/usr/sbin/lvs", "hostlvm"])
        .output()
        .context("failed to run lvs")?;
    println!("lvs output:");
    println!("{}", String::from_utf8_lossy(&lvs_output.stdout));
    if !lvs_output.stderr.is_empty() {
        println!("lvs errors:");
        println!("{}", String::from_utf8_lossy(&lvs_output.stderr));
    }

    // Check what device nodes actually exist in /dev/mapper/ and /dev/hostlvm/
    println!("=== DEBUGGING DEVICE MAPPER NODES ===");

    // List /dev/mapper/ contents
    let mapper_output = Command::new("ls")
        .args(["-la", "/dev/mapper/"])
        .output()
        .context("failed to list /dev/mapper/")?;
    println!("ls -la /dev/mapper/:");
    println!("{}", String::from_utf8_lossy(&mapper_output.stdout));

    // List /dev/hostlvm/ contents if it exists
    if Path::new("/dev/hostlvm/").exists() {
        let hostlvm_output = Command::new("ls")
            .args(["-la", "/dev/hostlvm/"])
            .output()
            .context("failed to list /dev/hostlvm/")?;
        println!("ls -la /dev/hostlvm/:");
        println!("{}", String::from_utf8_lossy(&hostlvm_output.stdout));
    } else {
        println!("/dev/hostlvm/ directory does not exist");
    }

    // Try to find the actual device paths using different naming conventions
    let possible_a_boot_paths = vec![
        "/dev/hostlvm/A_boot",
        "/dev/mapper/hostlvm-A_boot",
        "/dev/mapper/hostlvm-A--boot",
    ];

    let possible_b_boot_paths = vec![
        "/dev/hostlvm/B_boot",
        "/dev/mapper/hostlvm-B_boot",
        "/dev/mapper/hostlvm-B--boot",
    ];

    println!("Checking possible device paths:");
    let mut a_boot_path = None;
    let mut b_boot_path = None;

    for path in &possible_a_boot_paths {
        println!("  {} exists: {}", path, Path::new(path).exists());
        if Path::new(path).exists() && a_boot_path.is_none() {
            a_boot_path = Some(path.to_string());
        }
    }

    for path in &possible_b_boot_paths {
        println!("  {} exists: {}", path, Path::new(path).exists());
        if Path::new(path).exists() && b_boot_path.is_none() {
            b_boot_path = Some(path.to_string());
        }
    }

    let a_boot_path = a_boot_path.ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find A_boot device node. Checked paths: {:?}",
            possible_a_boot_paths
        )
    })?;

    let b_boot_path = b_boot_path.ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find B_boot device node. Checked paths: {:?}",
            possible_b_boot_paths
        )
    })?;

    println!("Using device paths:");
    println!("  A_boot: {}", a_boot_path);
    println!("  B_boot: {}", b_boot_path);

    // Check what filesystem type is on the partitions
    let file_output = Command::new("sudo")
        .args(["file", "-s", &a_boot_path])
        .output()
        .context("failed to run file -s on A_boot")?;
    println!("file -s {} output:", a_boot_path);
    println!("{}", String::from_utf8_lossy(&file_output.stdout));

    // Try to determine filesystem type with blkid
    let blkid_output = Command::new("sudo")
        .args(["/usr/sbin/blkid", &a_boot_path])
        .output()
        .context("failed to run blkid on A_boot")?;
    println!("blkid {} output:", a_boot_path);
    println!("{}", String::from_utf8_lossy(&blkid_output.stdout));
    if !blkid_output.stderr.is_empty() {
        println!("blkid errors:");
        println!("{}", String::from_utf8_lossy(&blkid_output.stderr));
    }

    // Mount boot partition A using sudo mount
    println!("Mounting boot partition A...");
    let mount_a_output = Command::new("sudo")
        .args(["mount", &a_boot_path, mount_point_a.to_str().unwrap()])
        .output()
        .context("failed to run mount command for boot partition A")?;

    if !mount_a_output.status.success() {
        bail!(
            "Failed to mount boot partition A: {}",
            String::from_utf8_lossy(&mount_a_output.stderr)
        );
    }

    // Mount boot partition B using sudo mount
    println!("Mounting boot partition B...");
    let mount_b_output = Command::new("sudo")
        .args(["mount", &b_boot_path, mount_point_b.to_str().unwrap()])
        .output()
        .context("failed to run mount command for boot partition B")?;

    if !mount_b_output.status.success() {
        // Clean up mount A on failure
        let _ = Command::new("sudo")
            .args(["umount", mount_point_a.to_str().unwrap()])
            .output();
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

    // Step 7: Unmount partitions using sudo umount
    println!("Unmounting boot partitions...");
    let _ = Command::new("sudo")
        .args(["umount", mount_point_a.to_str().unwrap()])
        .output();
    let _ = Command::new("sudo")
        .args(["umount", mount_point_b.to_str().unwrap()])
        .output();

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
