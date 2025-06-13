use crate::mount::{MountOptions, PartitionProvider};
use anyhow::Context;
use anyhow::Result;
use config::guest_vm_config::DirectBootConfig;
use grub::{BootAlternative, BootCycle, GrubEnv};
use regex::Regex;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[derive(Debug)]
pub struct DirectBoot {
    /// The kernel file
    pub kernel: NamedTempFile,
    /// The initrd file
    pub initrd: NamedTempFile,
    /// Kernel command line parameters
    pub kernel_cmdline: String,
}

impl DirectBoot {
    pub fn to_config(&self) -> DirectBootConfig {
        DirectBootConfig {
            kernel: self.kernel.path().to_path_buf(),
            initrd: self.initrd.path().to_path_buf(),
            kernel_cmdline: self.kernel_cmdline.clone(),
        }
    }
}

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
) -> Result<Option<DirectBoot>> {
    let grub_partition = partition_provider
        .mount_partition(
            "grub",
            MountOptions {
                readonly: !should_refresh_grubenv,
            },
        )
        .await?;
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
        .mount_partition(boot_partition_name, MountOptions { readonly: true })
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

    Ok(Some(DirectBoot {
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

    /// Test helper to create a complete test setup with GRUB and boot partitions
    struct TestSetup {
        provider: MockPartitionProvider,
        grub_partition: Arc<TempDir>,
    }

    impl TestSetup {
        fn new(
            boot_alternative: BootAlternative,
            boot_cycle: BootCycle,
            boot_args_a: &str,
            boot_args_b: &str,
        ) -> Self {
            let grub_partition = Self::create_grub_partition(boot_alternative, boot_cycle);
            let a_boot_partition = Self::create_boot_partition(boot_args_a, "SHOULD NOT BE USED");
            let b_boot_partition = Self::create_boot_partition("SHOULD NOT BE USED", boot_args_b);

            let mut partitions = HashMap::new();
            partitions.insert("grub".to_string(), grub_partition.clone());
            partitions.insert("A_boot".to_string(), a_boot_partition);
            partitions.insert("B_boot".to_string(), b_boot_partition);

            Self {
                provider: MockPartitionProvider::new(partitions),
                grub_partition,
            }
        }

        fn create_grub_partition(
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

        fn create_boot_partition(boot_args_a: &str, boot_args_b: &str) -> Arc<TempDir> {
            let boot_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));

            let mut boot_args_file = File::create(boot_dir.path().join("boot_args")).unwrap();
            writeln!(boot_args_file, "BOOT_ARGS_A=\"{boot_args_a}\"").unwrap();
            writeln!(boot_args_file, "BOOT_ARGS_B=\"{boot_args_b}\"").unwrap();

            fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").unwrap();
            fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

            boot_dir
        }

        fn get_grubenv(&self) -> GrubEnv {
            let grubenv_path = self.grub_partition.path().join("grubenv");
            GrubEnv::read_from(File::open(grubenv_path).unwrap()).unwrap()
        }
    }

    #[tokio::test]
    async fn test_boot_alternative_a() {
        let setup = TestSetup::new(BootAlternative::A, BootCycle::Stable, "args_a", "args_b");

        let config = prepare_direct_boot(false, &setup.provider)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(config.kernel_cmdline, "args_a");
        assert_eq!(fs::read(&config.kernel).unwrap(), b"fake kernel");
        assert_eq!(fs::read(&config.initrd).unwrap(), b"fake initrd");
    }

    #[tokio::test]
    async fn test_boot_alternative_b() {
        let setup = TestSetup::new(
            BootAlternative::B,
            BootCycle::Stable,
            "args_a",
            "args_b extra",
        );

        let config = prepare_direct_boot(false, &setup.provider)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(config.kernel_cmdline, "args_b extra");
    }

    #[tokio::test]
    async fn test_grubenv_refresh_stable_no_change() {
        let setup = TestSetup::new(BootAlternative::A, BootCycle::Stable, "args_a", "args_b");

        prepare_direct_boot(true, &setup.provider).await.unwrap();

        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::Stable));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::A));
    }

    #[tokio::test]
    async fn test_grubenv_refresh_install_to_stable() {
        let setup = TestSetup::new(BootAlternative::A, BootCycle::Install, "args_a", "args_b");

        prepare_direct_boot(true, &setup.provider).await.unwrap();

        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::Stable));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::A));
    }

    #[tokio::test]
    async fn test_grubenv_refresh_firstboot_to_failsafecheck() {
        let setup = TestSetup::new(BootAlternative::B, BootCycle::FirstBoot, "args_a", "args_b");

        prepare_direct_boot(true, &setup.provider).await.unwrap();

        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::FailsafeCheck));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::B));
    }

    #[tokio::test]
    async fn test_grubenv_refresh_failsafecheck_to_stable_opposite() {
        let setup = TestSetup::new(
            BootAlternative::A,
            BootCycle::FailsafeCheck,
            "args_a",
            "args_b",
        );

        prepare_direct_boot(true, &setup.provider).await.unwrap();

        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::Stable));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::B));
    }

    #[tokio::test]
    async fn test_grubenv_refresh_failsafecheck_b_to_stable_a() {
        let setup = TestSetup::new(
            BootAlternative::B,
            BootCycle::FailsafeCheck,
            "args_a",
            "args_b",
        );

        prepare_direct_boot(true, &setup.provider).await.unwrap();

        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::Stable));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::A));
    }

    #[tokio::test]
    async fn test_no_grubenv_refresh() {
        let setup = TestSetup::new(BootAlternative::A, BootCycle::FirstBoot, "args_a", "args_b");

        prepare_direct_boot(false, &setup.provider).await.unwrap();

        // Grubenv should remain unchanged
        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_cycle.unwrap(), Some(BootCycle::FirstBoot));
        assert_eq!(grubenv.boot_alternative.unwrap(), Some(BootAlternative::A));
    }

    #[tokio::test]
    async fn test_missing_grub_partition() {
        let provider = MockPartitionProvider::new(HashMap::new());

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Could not find partition"));
    }

    #[tokio::test]
    async fn test_missing_boot_partition() {
        let grub_partition =
            TestSetup::create_grub_partition(BootAlternative::A, BootCycle::Stable);
        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Could not find partition"));
    }

    #[tokio::test]
    async fn test_invalid_grubenv() {
        let grub_dir = Arc::new(TempDir::new().unwrap());
        fs::write(grub_dir.path().join("grubenv"), b"invalid content").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_dir);
        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_boot_args_file_returns_none() {
        let grub_partition =
            TestSetup::create_grub_partition(BootAlternative::A, BootCycle::Stable);
        let boot_dir = Arc::new(TempDir::new().unwrap());
        fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").unwrap();
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("A_boot".to_string(), boot_dir);
        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_missing_kernel_file() {
        let grub_partition =
            TestSetup::create_grub_partition(BootAlternative::A, BootCycle::Stable);
        let boot_dir = Arc::new(TempDir::new().unwrap());
        fs::write(boot_dir.path().join("boot_args"), "BOOT_ARGS_A=\"test\"").unwrap();
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("A_boot".to_string(), boot_dir);
        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_boot_args_without_quotes() {
        let grub_partition =
            TestSetup::create_grub_partition(BootAlternative::B, BootCycle::Stable);
        let boot_dir = Arc::new(TempDir::new().unwrap());
        fs::write(
            boot_dir.path().join("boot_args"),
            "BOOT_ARGS_B=quiet splash\n",
        )
        .unwrap();
        fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").unwrap();
        fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();

        let mut partitions = HashMap::new();
        partitions.insert("grub".to_string(), grub_partition);
        partitions.insert("B_boot".to_string(), boot_dir);
        let provider = MockPartitionProvider::new(partitions);

        let config = prepare_direct_boot(false, &provider)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(config.kernel_cmdline, "quiet splash");
    }
}
