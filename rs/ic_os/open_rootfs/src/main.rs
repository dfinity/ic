mod partitions;
mod proposal;
mod recovery;
mod verity;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use command_runner::{CommandRunner, RealCommandRunner};
use ic_device::mount::PartitionProvider;
use linux_kernel_command_line::KernelCommandLine;
use recovery::extract_and_verify_recovery_rootfs_hash;
use sev_guest::firmware::SevGuestFirmware;
use std::path::Path;
use std::str::FromStr;
use verity::veritysetup;

/// Opens the root filesystem with dm-verity verification.
///
/// This tool is responsible for setting up the verified root filesystem during boot.
/// It first attempts to open the root device using the base root hash from the kernel
/// command line. If that fails, it falls back reading and verifying an alternative GuestOS
/// proposal which allows booting from a recovery root filesystem.
#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    // We should be very careful about erroring out before the run() call. We should not block
    // the regular (non-recovery) code path just because some dependency for the recovery
    // code path has failed.
    let root_device = std::env::var("ROOT").context("Missing ROOT environment variable")?;
    let kernel_command_line =
        KernelCommandLine::from_str(&std::fs::read_to_string("/proc/cmdline")?)
            .context("Failed to parse kernel command line")?;
    run(
        Path::new(&root_device),
        &kernel_command_line,
        || {
            sev::firmware::guest::Firmware::open()
                .context("Failed to open SEV firmware")
                .map(|firmware| Box::new(firmware) as _)
        },
        &RealCommandRunner,
        &ic_device::mount::UdevPartitionProvider,
    )
}

pub fn run(
    root_device: &Path,
    kernel_cmdline: &KernelCommandLine,
    sev_firmware_provider: impl Fn() -> Result<Box<dyn SevGuestFirmware>>,
    command_runner: &dyn CommandRunner,
    partition_provider: &dyn PartitionProvider,
) -> Result<()> {
    let base_root_hash = kernel_cmdline
        .get_argument("root_hash")
        .with_context(|| format!("Missing root_hash from kernel cmdline: {kernel_cmdline}"))?;

    // Try to get SEV Firmware handle
    let sev_firmware = sev_firmware_provider();

    eprintln!("Attempting to open root device with base root hash from kernel cmdline");
    match veritysetup(
        root_device,
        &base_root_hash,
        command_runner,
        sev_firmware.is_ok(),
    ) {
        Ok(_) => {
            eprintln!("Successfully opened root device with base root hash");
            return Ok(());
        }
        Err(e) => {
            eprintln!("Failed to open root device with base root hash: {e:?}");
        }
    }

    eprintln!("Trying alternative GuestOS proposal");

    let recovery_hash = extract_and_verify_recovery_rootfs_hash(
        root_device,
        sev_firmware.context("unable to get SEV Firmware")?.as_mut(),
        command_runner,
        partition_provider,
    )
    .context("Failed to extract/verify alternative GuestOS proposal")?;

    eprintln!(
        "Found and verified alternative GuestOS proposal, attempting to open with recovery root \
        hash"
    );
    veritysetup(root_device, &recovery_hash, command_runner, true)?;
    eprintln!("Successfully opened root device with recovery root hash");

    Ok(())
}
