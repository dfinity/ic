use crate::mount::{DeviceMount, DeviceMounter};
use anyhow::Result;
use anyhow::{ensure, Context};
use config::guest_vm_config::DirectBootConfig;
use grub::{BootAlternative, BootCycle, GrubEnv};
use partition_tools::ext::ExtPartition;
use regex::Regex;
use std::fs::File;
use std::path::Path;

pub async fn prepare_direct_boot(
    guestos_device: &Path,
    kernel_path: &Path,
    initrd_path: &Path,
    should_refresh_grubenv: bool,
    device_mounter: &dyn DeviceMounter,
) -> Result<DirectBootConfig> {
    let grub_partition = mount_guest_partition(guestos_device, "grub", device_mounter).await?;
    let grubenv_path = grub_partition.target_path().join("grubenv");
    let mut grubenv = GrubEnv::read_from(File::open(&grubenv_path)?)?;
    if should_refresh_grubenv && refresh_grubenv(&mut grubenv)? {
        grubenv
            .write_to_file(&grubenv_path)
            .context("Failed to upgrade grubenv")?;
    }
    drop(grub_partition);

    let boot_alternative = grubenv
        .boot_alternative
        .context("Failed to read boot_alternative from grubenv")?
        .context("Missing boot_alternative in grubenv")?;

    let boot_partition_name = match boot_alternative {
        BootAlternative::A => "A_boot",
        BootAlternative::B => "B_boot",
    };

    let boot_args_var_name = match boot_alternative {
        BootAlternative::A => "BOOT_ARGS_A",
        BootAlternative::B => "BOOT_ARGS_B",
    };

    let boot_partition =
        mount_guest_partition(guestos_device, boot_partition_name, device_mounter).await?;
    let boot_args = read_boot_args(
        &boot_partition.target_path().join("boot_args"),
        boot_args_var_name,
    )
    .context("Failed to read boot args")?;

    tokio::fs::copy(boot_partition.target_path().join("vmlinuz"), &kernel_path).await?;
    tokio::fs::copy(
        boot_partition.target_path().join("initrd.img"),
        &initrd_path,
    )
    .await?;

    Ok(DirectBootConfig {
        kernel: kernel_path.to_path_buf(),
        initrd: initrd_path.to_path_buf(),
        kernel_cmdline: boot_args,
    })
}

/// Refreshes the boot cycle and boot alternative in the grubenv.
/// Returns true if the grubenv was changed.
fn refresh_grubenv(grub_env: &mut GrubEnv) -> Result<bool> {
    let mut boot_alternative = grub_env
        .boot_alternative
        .clone()
        .context("Invalid boot_alternative")?
        .unwrap_or(BootAlternative::A);
    let mut boot_cycle = grub_env
        .boot_cycle
        .clone()
        .context("Invalid boot_cycle")?
        .unwrap_or(BootCycle::Stable);

    match boot_cycle {
        BootCycle::Stable => {}
        BootCycle::Install => boot_cycle = BootCycle::Stable,
        BootCycle::FirstBoot => boot_cycle = BootCycle::FailsafeCheck,
        BootCycle::FailsafeCheck => {
            boot_cycle = BootCycle::Stable;
            boot_alternative = boot_alternative.get_opposite();
        }
    };
    let changed = grub_env.boot_alternative != Ok(Some(boot_alternative))
        || grub_env.boot_cycle != Ok(Some(boot_cycle));

    grub_env.boot_alternative = Ok(Some(boot_alternative));
    grub_env.boot_cycle = Ok(Some(boot_cycle));
    Ok(changed)
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

async fn mount_guest_partition(
    guestos_device: &Path,
    partition_name: &str,
    device_mounter: &dyn DeviceMounter,
) -> Result<Box<dyn DeviceMount>> {
    let guest_gpt = gptman::GPT::find_from(
        &mut File::open(guestos_device).context("Could not open GuestOS device")?,
    )
    .context("Could not read GPT of Guest device")?;
    let partition_count = guest_gpt.iter().count();
    ensure!(
        partition_count >= 9,
        "There must be at least 9 partitions but only found {partition_count}"
    );
    let partition_entry = guest_gpt
        .iter()
        .find(|partition| partition.1.partition_name.as_str() == partition_name)
        .with_context(|| format!("Could not find {partition_name} partition"))?
        .1;

    device_mounter
        .mount(
            guestos_device.to_path_buf(),
            partition_entry.starting_lba * guest_gpt.sector_size,
            partition_entry
                .size()
                .context("Could not get partition size")?
                * guest_gpt.sector_size,
        )
        .await
        .with_context(|| format!("Mounting {partition_name} failed"))
}
