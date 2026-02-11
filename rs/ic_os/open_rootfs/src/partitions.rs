use anyhow::{Context, Result, bail};
use command_runner::CommandRunner;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use uuid::Uuid;

// Defined in partitions.csv
pub const A_ROOT_UUID: Uuid = Uuid::from_u128(0x7C0A626E_E5EA_E543_B5C5_300EB8304DB7);
pub const B_ROOT_UUID: Uuid = Uuid::from_u128(0xA78BC3A8_376C_054A_96E7_3904B915D0C5);
pub const A_BOOT_UUID: Uuid = Uuid::from_u128(0xDDF618FE_7244_B446_A175_3296E6B9D02E);
pub const B_BOOT_UUID: Uuid = Uuid::from_u128(0xD5214E4F_F7B0_B945_9A9B_52B9188DF4C5);

/// Get the boot partition UUID corresponding to the given root device
pub fn get_boot_partition_uuid(
    root_device: &Path,
    command_runner: &dyn CommandRunner,
) -> Result<Uuid> {
    let root_uuid = get_partition_uuid(root_device, command_runner)
        .context("Failed to get partition UUID for root device")?;

    match root_uuid {
        A_ROOT_UUID => {
            eprintln!("Root partition is A, using A_BOOT partition");
            Ok(A_BOOT_UUID)
        }
        B_ROOT_UUID => {
            eprintln!("Root partition is B, using B_BOOT partition");
            Ok(B_BOOT_UUID)
        }
        uuid => bail!("Unexpected root partition UUID {uuid}"),
    }
}

/// Get the partition UUID (PARTUUID) of a block device using blkid
fn get_partition_uuid(device: &Path, command_runner: &dyn CommandRunner) -> Result<Uuid> {
    // Run blkid to get the PARTUUID
    let output = command_runner
        .output(
            Command::new("blkid")
                .arg("-s")
                .arg("PARTUUID")
                .arg("-o")
                .arg("value")
                .arg(device),
        )
        .with_context(|| format!("Failed to run blkid for {device:?}"))?;

    if !output.status.success() {
        bail!(
            "blkid failed for {device:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let partuuid_str = String::from_utf8(output.stdout)
        .with_context(|| format!("blkid output is not valid UTF-8 for {device:?}"))?;

    Uuid::from_str(partuuid_str.trim())
        .with_context(|| format!("Failed to parse PARTUUID '{partuuid_str}' as UUID"))
}
