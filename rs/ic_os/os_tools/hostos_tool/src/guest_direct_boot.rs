use crate::mount::TempMount;
use anyhow::Result;
use anyhow::{ensure, Context};
use config::guest_vm_config::DirectBootConfig;
use grub::{read_grubenv, BootAlternative};
use regex::Regex;
use std::fs::File;
use std::path::Path;
use sys_mount::Mount;

pub fn prepare_direct_boot(
    guestos_device: &Path,
    kernel_path: &Path,
    initrd_path: &Path,
) -> Result<DirectBootConfig> {
    let grub_partition = mount_guest_partition(guestos_device, "grub")?;
    let grubenv = read_grubenv(&grub_partition.target_path().join("grubenv"))?;
    drop(grub_partition);

    let boot_alternative = grubenv
        .boot_alternative
        .context("Failed to read boot_alternative from grubenv")?;

    let boot_partition_name = match boot_alternative {
        BootAlternative::A => "A_boot",
        BootAlternative::B => "B_boot",
    };

    let boot_args_var_name = match boot_alternative {
        BootAlternative::A => "BOOT_ARGS_A",
        BootAlternative::B => "BOOT_ARGS_B",
    };

    let boot_partition = mount_guest_partition(guestos_device, boot_partition_name)?;
    let boot_args = read_boot_args(
        &boot_partition.target_path().join("boot_args"),
        boot_args_var_name,
    )
    .context("Failed to read boot args")?;

    std::fs::copy(boot_partition.target_path().join("vmlinuz"), &kernel_path)?;
    std::fs::copy(
        boot_partition.target_path().join("initrd.img"),
        &initrd_path,
    )?;

    Ok(DirectBootConfig {
        kernel: kernel_path.to_path_buf(),
        initrd: initrd_path.to_path_buf(),
        kernel_cmdline: boot_args,
    })
}

fn read_boot_args(config: &Path, boot_args_var_name: &str) -> Result<String> {
    let boot_args_re = Regex::new(&format!("{boot_args_var_name}=\"?([^#\n\"]*)"))?;
    let config_contents = std::fs::read_to_string(config)?;
    let (_, [value]) = boot_args_re
        .captures(&config_contents)
        .with_context(|| format!("Variable {boot_args_var_name} not found"))?
        .extract();
    Ok(value.to_string())
}

fn mount_guest_partition(guestos_device: &Path, partition_name: &str) -> anyhow::Result<TempMount> {
    let guest_gpt = gptman::GPT::find_from(
        &mut File::open(guestos_device).context("Could not open GuestOS LVM")?,
    )
    .context("Could not read GPT of Guest LVM")?;
    let partition_count = guest_gpt.iter().count();
    ensure!(
        partition_count >= 9,
        "There must be at least 9 partitions but only found {partition_count}"
    );
    let partition_entry = guest_gpt
        .iter()
        .find(|partition| partition.1.partition_name.as_str() == "grub")
        .context("Could not find grub partition")?
        .1;

    TempMount::from_mount_builder(
        Mount::builder().loopback_offset(partition_entry.starting_lba * guest_gpt.sector_size),
        guestos_device,
    )
    .with_context(|| format!("Mounting {partition_name} failed"))
}
