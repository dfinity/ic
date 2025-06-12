use crate::mount::PartitionProvider;
use anyhow::Context;
use anyhow::Result;
use config::guest_vm_config::DirectBootConfig;
use grub::{BootAlternative, BootCycle, GrubEnv};
use regex::Regex;
use std::fs::File;
use std::path::Path;
use tempfile::NamedTempFile;

/// Prepares a direct boot configuration by reading the GRUB environment and boot partition.
///
/// # Arguments
/// * `kernel_path` - Path where the kernel file should be copied to
/// * `initrd_path` - Path where the initrd file should be copied to
/// * `should_refresh_grubenv` - Whether to refresh the GRUB environment ot support reverting to
///   the previous boot alternative
/// * `partition_provider` - Provider for accessing partitions
///
/// # Returns
/// * `Ok(Some(DirectBootConfig))` - Configuration for direct booting if successful
/// * `Ok(None)` - If direct boot is not supported (old GuestOS)
/// * `Err` - If any error occurs during preparation
pub async fn prepare_direct_boot(
    should_refresh_grubenv: bool,
    partition_provider: &dyn PartitionProvider,
) -> Result<Option<DirectBootConfig>> {
    let grub_partition = partition_provider.mount_partition("grub").await?;
    let grubenv_path = grub_partition.mount_point().join("grubenv");
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

    let boot_partition = partition_provider
        .mount_partition(boot_partition_name)
        .await?;

    let boot_args_path = boot_partition.mount_point().join("boot_args");
    if !boot_args_path.exists() {
        // If boot_args file is missing, we can't do direct boot.
        // We have this option for backwards compatibility with older GuestOS releases.
        return Ok(None);
    }
    let boot_args =
        read_boot_args(&boot_args_path, boot_args_var_name).context("Failed to read boot args")?;

    let kernel = NamedTempFile::new()?;
    let initrd = NamedTempFile::new()?;

    tokio::fs::copy(boot_partition.mount_point().join("vmlinuz"), &kernel).await?;
    tokio::fs::copy(boot_partition.mount_point().join("initrd.img"), &initrd).await?;

    Ok(Some(DirectBootConfig {
        kernel,
        initrd,
        kernel_cmdline: boot_args,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::testing::MockPartitionProvider;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_grub_partition(
        boot_alternative: BootAlternative,
        boot_cycle: BootCycle,
    ) -> Arc<TempDir> {
        let grub_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));
        let grubenv_path = grub_dir.path().join("grubenv");

        let mut grubenv = GrubEnv::default();
        grubenv.boot_alternative = Ok(Some(boot_alternative));
        grubenv.boot_cycle = Ok(Some(boot_cycle));
        grubenv
            .write_to_file(&grubenv_path)
            .expect("Failed to write grubenv");

        grub_dir
    }

    fn create_test_boot_partition(boot_args_a: &str, boot_args_b: &str) -> Arc<TempDir> {
        let boot_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));

        // Create boot_args file
        let boot_args_file = File::create(boot_dir.path().join("boot_args")).unwrap();
        writeln!(boot_args_file, "BOOT_ARGS_A=\"{boot_args_a}\"").unwrap();
        writeln!(boot_args_file, "BOOT_ARGS_B=\"{boot_args_b}\"").unwrap();

        // Create dummy kernel and initrd files
        fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").expect("Failed to write kernel");
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd")
            .expect("Failed to write initrd");

        boot_dir
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_alternative_a() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::Stable);
        let boot_partition = create_test_boot_partition("favorite_letter=a", "favorite_letter=b");

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("A_boot".to_string(), boot_partition);

        let config = prepare_direct_boot(false, &MockPartitionProvider::new(partitions))
            .await
            .expect("Failed to prepare direct boot")
            .expect("Expected direct boot to be supported");

        assert_eq!(config.kernel_cmdline, "favorite_letter=a");

        // Verify files were copied
        assert_eq!(fs::read(&config.kernel).unwrap(), b"fake kernel");
        assert_eq!(fs::read(&config.initrd).unwrap(), b"fake initrd");
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_alternative_b() {
        let grub_partition = create_test_grub_partition(BootAlternative::B, BootCycle::Stable);
        let boot_partition = create_test_boot_partition(
            "favorite_letter=a",
            "favorite_letter=b other_favorite_letter=B",
        );

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("B_boot".to_string(), boot_partition);

        let config = prepare_direct_boot(false, &MockPartitionProvider::new(partitions))
            .await
            .expect("Failed to prepare direct boot")
            .expect("Expected direct boot to be supported");

        assert_eq!(
            config.kernel_cmdline,
            "favorite_letter=b other_favorite_letter=B"
        );
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_with_grubenv_refresh() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::FirstBoot);
        let boot_partition = create_test_boot_partition("favorite_letter=a", "favorite_letter=b");

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition.clone());
        partitions.insert("A_boot".to_string(), boot_partition);

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let kernel_path = temp_dir.path().join("kernel");
        let initrd_path = temp_dir.path().join("initrd");

        let config = prepare_direct_boot(true, &MockPartitionProvider::new(partitions))
            .await
            .expect("Failed to prepare direct boot")
            .expect("Expected direct boot to be supported");

        // Verify grubenv was updated
        let grubenv_path = grub_partition.path().join("grubenv");
        let updated_grubenv = GrubEnv::read_from(File::open(&grubenv_path).unwrap()).unwrap();
        assert_eq!(
            updated_grubenv.boot_cycle.unwrap(),
            Some(BootCycle::FailsafeCheck)
        );
        assert_eq!(
            updated_grubenv.boot_alternative.unwrap(),
            Some(BootAlternative::A)
        );
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_no_grubenv_refresh() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::FirstBoot);
        let boot_partition = create_test_boot_partition("favorite_letter=a", "favorite_letter=b");

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition.clone());
        partitions.insert("A_boot".to_string(), boot_partition);

        let config = prepare_direct_boot(false, &MockPartitionProvider::new(partitions))
            .await
            .expect("Failed to prepare direct boot")
            .expect("Expected direct boot to be supported");

        // Verify grubenv was NOT updated
        let grubenv_path = grub_partition.path().join("grubenv");
        let grubenv = GrubEnv::read_from(File::open(&grubenv_path).unwrap()).unwrap();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::FirstBoot));
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_missing_grub_partition() {
        // Intentionally not adding grub partition
        let provider = MockPartitionProvider::new(HashMap::new());

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result
            .expect_err("Expected error when missing grub partition")
            .to_string()
            .contains("Could not find partition"));
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_missing_boot_partition() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::Stable);

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        // Intentionally not adding A_boot partition

        let result = prepare_direct_boot(false, &MockPartitionProvider::new(partitions)).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Could not find partition"));
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_invalid_grubenv() {
        let grub_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));
        // Create invalid grubenv file
        fs::write(grub_dir.path().join("grubenv"), b"invalid content").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_dir);

        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_missing_boot_args_file() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::Stable);
        let boot_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));
        // Don't create boot_args file
        fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").unwrap();
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("A_boot".to_string(), boot_dir);

        let result = prepare_direct_boot(false, &MockPartitionProvider::new(partitions))
            .await
            .expect("Expected no error");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_missing_kernel_file() {
        let grub_partition = create_test_grub_partition(BootAlternative::A, BootCycle::Stable);
        let boot_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));

        // Create boot_args and initrd but not vmlinuz
        fs::write(boot_dir.path().join("boot_args"), "BOOT_ARGS_A=\"test\"").unwrap();
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("A_boot".to_string(), boot_dir);

        let result = prepare_direct_boot(false, &MockPartitionProvider::new(partitions))
            .await
            .expect_err("Expected error because of missing kernel file");
    }

    #[tokio::test]
    async fn test_prepare_direct_boot_boot_args_without_quotes() {
        let grub_partition =
            create_test_grub_partition(BootAlternative::B, BootCycle::Stable).await?;
        let boot_dir = Arc::new(TempDir::new()?);

        // Create boot_args without quotes
        let boot_args_content = "BOOT_ARGS_B=quiet splash\n";
        fs::write(boot_dir.path().join("boot_args"), boot_args_content).await?;
        fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").await?;
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").await?;

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("B_boot".to_string(), boot_dir);

        let provider = MockPartitionProvider::new(partitions);

        let temp_dir = TempDir::new()?;
        let kernel_path = temp_dir.path().join("kernel");
        let initrd_path = temp_dir.path().join("initrd");

        let config = prepare_direct_boot(false, &provider)
            .await
            .expect("Failed to prepare direct boot")
            .expect("Expected direct boot to be supported");

        assert_eq!(config.kernel_cmdline, "quiet splash");
    }
}
