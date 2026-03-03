use anyhow::{Context, Result};
use command_runner::RealCommandRunner;
use grub::BootCycle;
use ic_device::mount::{FileSystem, GptPartitionProvider, MountOptions, PartitionSelector};
use std::process::Command;
use uuid::Uuid;

const GUESTOS_DEVICE: &str = "/dev/hostlvm/guestos";
// TODO: replace if-else with unwrap() once it's const
const GRUB_PARTITION_UUID: Uuid =
    // This UUID is defined in ic-os/guestos/partitions.csv
    if let Ok(uuid) = Uuid::try_parse("6788E4CF-F456-104E-9A34-A2C58CFB0EE6") {
            uuid
        } else {
            panic!("Failed to parse GRUB partition UUID");
        };

/// Prints the current GuestOS boot alternative.
pub fn show_guestos_alternative() -> Result<()> {
    show_guestos_alternative_impl(&GptPartitionProvider::new(GUESTOS_DEVICE.into())?)
}

fn show_guestos_alternative_impl(
    partition_provider: &dyn ic_device::mount::PartitionProvider,
) -> Result<()> {
    let grub_partition = partition_provider
        .mount_partition(
            PartitionSelector::ByUuid(GRUB_PARTITION_UUID),
            MountOptions {
                file_system: FileSystem::Vfat,
                read_only: true, // GuestOS may be running, we must mount readonly
            },
        )
        .context("Could not mount grub partition")?;
    let grubenv_path = grub_partition.mount_point().join("grubenv");

    let grubenv_file = std::fs::File::open(&grubenv_path).context("Failed to open grubenv")?;
    let grubenv = grub::GrubEnv::read_from(grubenv_file).context("Failed to read grubenv")?;
    println!(
        "GuestOS Boot alternative: {}",
        grubenv
            .boot_alternative
            .map_or_else(|e| e.to_string(), |v| v.to_string())
    );
    println!(
        "GuestOS Boot cycle: {}",
        grubenv
            .boot_cycle
            .map_or_else(|e| e.to_string(), |v| v.to_string())
    );
    Ok(())
}

/// Changes the GuestOS boot alternative to `target` or toggles to the opposite if `None`.
pub fn swap_guestos_alternative(target: Option<grub::BootAlternative>) -> Result<()> {
    println!(
        "This will swap the GuestOS boot alternative. Only use this command if instructed during node recovery."
    );
    println!("Do you want to continue? (y/n)");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !["y", "yes"].contains(&input.trim().to_ascii_lowercase().as_str()) {
        println!("Operation cancelled.");
        return Ok(());
    }

    swap_guestos_alternative_impl(
        &GptPartitionProvider::new(GUESTOS_DEVICE.into())?,
        target,
        &RealCommandRunner,
    )
}

/// Mounts the GRUB partition, updates `boot_alternative` and `boot_cycle` in grubenv, then
/// unmounts. Returns the resolved boot alternative that was written.
fn update_grubenv(
    partition_provider: &dyn ic_device::mount::PartitionProvider,
    target_boot_alternative: Option<grub::BootAlternative>,
) -> Result<grub::BootAlternative> {
    let grub_partition = partition_provider
        .mount_partition(
            PartitionSelector::ByUuid(GRUB_PARTITION_UUID),
            MountOptions {
                file_system: FileSystem::Vfat,
                read_only: false, // Needs write access to update grubenv
            },
        )
        .context("Could not mount grub partition")?;
    let grubenv_path = grub_partition.mount_point().join("grubenv");

    let grubenv_file = std::fs::File::open(&grubenv_path).context("Failed to open grubenv")?;
    let mut grubenv = grub::GrubEnv::read_from(grubenv_file).context("Failed to read grubenv")?;

    const NO_BOOT_ALTERNATIVE_ERROR: &str = "Invalid/missing boot alternative in grubenv, please \
            specify an explicit boot alternative by running `guestos-alternative swap A` or \
            `guestos-alternative swap B`";
    let target_boot_alternative = match target_boot_alternative {
        Some(target) => target,
        None => grubenv
            .boot_alternative
            .context(NO_BOOT_ALTERNATIVE_ERROR)?
            .get_opposite(),
    };
    grubenv.boot_alternative = Ok(target_boot_alternative);
    grubenv.boot_cycle = Ok(BootCycle::FirstBoot);
    grubenv
        .write_to_file(&grubenv_path)
        .context("Failed to write grubenv")?;

    Ok(target_boot_alternative)
}

fn swap_guestos_alternative_impl(
    partition_provider: &dyn ic_device::mount::PartitionProvider,
    target_boot_alternative: Option<grub::BootAlternative>,
    command_runner: &dyn command_runner::CommandRunner,
) -> Result<()> {
    println!("Stopping GuestOS service...");
    command_runner
        .status(&mut Command::new("systemctl").args([
            "stop",
            "guestos.service",
            "upgrade-guestos.service",
        ]))
        .context("Failed to stop guestos.service and upgrade-guestos.service")?;

    println!("Swapping GuestOS boot alternative...");
    let target_boot_alternative = update_grubenv(partition_provider, target_boot_alternative);

    println!("Restarting GuestOS...");
    command_runner
        .status(&mut Command::new("systemctl").args(["start", "guestos.service"]))
        .context("Failed to restart guestos.service after swapping GuestOS boot alternative")?;

    match target_boot_alternative {
        Ok(alternative) => {
            println!("Successfully swapped GuestOS boot alternative to {alternative}")
        }
        Err(e) => return Err(e.context("Failed to swap GuestOS boot alternative")),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use command_runner::MockCommandRunner;
    use grub::GrubEnv;
    use ic_device::mount::testing::MockPartitionProvider;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Helper function to create a mock partition provider with a grubenv file
    fn create_mock_partition_provider(
        boot_alternative: Option<grub::BootAlternative>,
        boot_cycle: Option<BootCycle>,
    ) -> (MockPartitionProvider, Arc<TempDir>) {
        let grub_partition = Arc::new(TempDir::new().expect("Failed to create temp dir"));
        let grubenv_path = grub_partition.path().join("grubenv");

        let grubenv = GrubEnv {
            boot_alternative: boot_alternative.ok_or(grub::GrubEnvVariableError::Undefined),
            boot_cycle: boot_cycle.ok_or(grub::GrubEnvVariableError::Undefined),
            ..GrubEnv::default()
        };
        grubenv
            .write_to_file(&grubenv_path)
            .expect("Failed to write grubenv");

        let mut partitions = HashMap::new();
        partitions.insert(
            PartitionSelector::ByUuid(GRUB_PARTITION_UUID),
            grub_partition.clone(),
        );

        (MockPartitionProvider::new(partitions), grub_partition)
    }

    fn create_mock_command_runner(
        expect_stop_guestos: bool,
        expect_start_guestos: bool,
    ) -> MockCommandRunner {
        let mut mock_runner = MockCommandRunner::new();
        if expect_stop_guestos {
            mock_runner
                .expect_status()
                .withf(|cmd| {
                    format!("{cmd:?}")
                        == r#""systemctl" "stop" "guestos.service" "upgrade-guestos.service""#
                })
                .once()
                .return_once(|_| Ok(std::process::ExitStatus::default()));
        }
        if expect_start_guestos {
            mock_runner
                .expect_status()
                .withf(|cmd| format!("{cmd:?}") == r#""systemctl" "start" "guestos.service""#)
                .once()
                .return_once(|_| Ok(std::process::ExitStatus::default()));
        }

        mock_runner
    }

    #[test]
    fn test_show_guestos_alternative_impl() {
        let (provider, _temp_dir) =
            create_mock_partition_provider(Some(grub::BootAlternative::A), Some(BootCycle::Stable));

        let result = show_guestos_alternative_impl(&provider);
        assert!(result.is_ok());
    }

    #[test]
    fn test_swap_guestos_alternative_impl_with_explicit_target() {
        let (provider, grub_partition) =
            create_mock_partition_provider(Some(grub::BootAlternative::B), Some(BootCycle::Stable));

        let result = swap_guestos_alternative_impl(
            &provider,
            Some(grub::BootAlternative::A),
            &create_mock_command_runner(true, true),
        );
        assert!(result.is_ok());

        // Verify the grubenv was updated correctly
        let grubenv_path = grub_partition.path().join("grubenv");
        let grubenv_content = fs::read(&grubenv_path).expect("Failed to read grubenv");
        let grubenv =
            GrubEnv::read_from(grubenv_content.as_slice()).expect("Failed to parse grubenv");

        assert_eq!(grubenv.boot_alternative, Ok(grub::BootAlternative::A));
        assert_eq!(grubenv.boot_cycle, Ok(BootCycle::FirstBoot));
    }

    #[test]
    fn test_swap_guestos_alternative_impl_toggle() {
        let (provider, grub_partition) =
            create_mock_partition_provider(Some(grub::BootAlternative::A), Some(BootCycle::Stable));

        // No explicit target - should toggle to opposite
        let result =
            swap_guestos_alternative_impl(&provider, None, &create_mock_command_runner(true, true));
        assert!(result.is_ok());

        // Verify the grubenv was updated correctly
        let grubenv_path = grub_partition.path().join("grubenv");
        let grubenv_content = fs::read(&grubenv_path).expect("Failed to read grubenv");
        let grubenv =
            GrubEnv::read_from(grubenv_content.as_slice()).expect("Failed to parse grubenv");

        assert_eq!(grubenv.boot_alternative, Ok(grub::BootAlternative::B));
        assert_eq!(grubenv.boot_cycle, Ok(BootCycle::FirstBoot));
    }

    #[test]
    fn test_swap_guestos_alternative_impl_toggle_fails_with_undefined_boot_alternative() {
        let (provider, _grub_partition) = create_mock_partition_provider(
            None, // Undefined boot alternative
            Some(BootCycle::Stable),
        );

        // No explicit target and undefined boot alternative should fail
        let result =
            swap_guestos_alternative_impl(&provider, None, &create_mock_command_runner(true, true));
        assert!(result.is_err());
        assert!(
            format!("{:#}", result.unwrap_err())
                .contains("Invalid/missing boot alternative in grubenv")
        );
    }
}
