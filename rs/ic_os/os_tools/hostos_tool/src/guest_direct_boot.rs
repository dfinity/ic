use crate::boot_args::read_boot_args;
use crate::mount::{FileSystem, MountOptions, PartitionProvider};
use anyhow::Context;
use anyhow::Result;
use config::guest_vm_config::DirectBootConfig;
use grub::{BootAlternative, BootCycle, GrubEnv, WithDefault};
use std::fs::File;
use tempfile::NamedTempFile;
use uuid::Uuid;

const fn const_unwrap(result: std::result::Result<Uuid, uuid::Error>) -> Uuid {
    match result {
        Ok(value) => value,
        Err(_) => panic!("Could not unwrap"),
    }
}

const GRUB_PARTITION_UUID: Uuid =
    const_unwrap(Uuid::try_parse("6788E4CF-F456-104E-9A34-A2C58CFB0EE6"));
const A_BOOT_PARTITION_UUID: Uuid =
    const_unwrap(Uuid::try_parse("DDF618FE-7244-B446-A175-3296E6B9D02E"));
const B_BOOT_PARTITION_UUID: Uuid =
    const_unwrap(Uuid::try_parse("D5214E4F-F7B0-B945-9A9B-52B9188DF4C5"));

const GRUB_PARTITION_FS: FileSystem = FileSystem::Vfat;
const BOOT_PARTITION_FS: FileSystem = FileSystem::Ext4;

/// Direct boot configuration extracted from the GuestOS
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
/// * `should_refresh_grubenv` - Whether the code should refresh the GRUB environment based on the
///   boot state transition rules
/// * `guest_partition_provider` - Provider for accessing partitions of the Guest
///
/// # Returns
/// * `Ok(Some(DirectBoot))` - Success
/// * `Ok(None)` - If direct boot is not supported because the necessary files are not available
///   (old GuestOS)
/// * `Err` - If any error occurs during preparation
pub async fn prepare_direct_boot(
    should_refresh_grubenv: bool,
    guest_partition_provider: &dyn PartitionProvider,
) -> Result<Option<DirectBoot>> {
    let grub_partition = guest_partition_provider
        .mount_partition(
            GRUB_PARTITION_UUID,
            MountOptions {
                readonly: !should_refresh_grubenv,
                file_system: GRUB_PARTITION_FS,
            },
        )
        .await?;

    let grubenv_path = grub_partition.mount_point().join("grubenv");
    let mut grubenv =
        GrubEnv::read_from(File::open(&grubenv_path).context("Could not open grubenv")?)?;

    let grubenv_is_changing = should_refresh_grubenv && refresh_grubenv(&mut grubenv)?;

    let boot_alternative = grubenv
        .boot_alternative
        .clone()
        .context("Failed to read boot_alternative from grubenv")?;

    // The variable name inside 'boot_args' that contains the kernel command line parameters.
    // Note that this depends on the boot alternative since they contain the root partition and
    // other boot alternative-specific parameters.
    let (boot_partition_uuid, boot_args_var_name) = match boot_alternative {
        BootAlternative::A => (A_BOOT_PARTITION_UUID, "BOOT_ARGS_A"),
        BootAlternative::B => (B_BOOT_PARTITION_UUID, "BOOT_ARGS_B"),
    };

    let boot_partition = guest_partition_provider
        .mount_partition(
            boot_partition_uuid,
            MountOptions {
                readonly: true,
                file_system: BOOT_PARTITION_FS,
            },
        )
        .await?;

    let boot_args_path = boot_partition.mount_point().join("boot_args");
    // Older GuestOS releases do not have the boot_args file. If the file exists, we have a modern
    // enough GuestOS that supports direct boot. If not, abandon direct boot by returning None.
    // Also note that we decide about abandoning direct boot before writing out grubenv below since
    // booting with GRUB will also try to refresh the grubenv and it's *not* an idempotent
    // operation. Therefore, we don't write out grubenv until we can ensure that we'll do a direct
    // boot.
    if !boot_args_path.exists() {
        return Ok(None);
    }

    let boot_args =
        read_boot_args(&boot_args_path, boot_args_var_name).context("Failed to read boot args")?;

    let kernel = NamedTempFile::new()?;
    let initrd = NamedTempFile::new()?;

    tokio::fs::copy(boot_partition.mount_point().join("vmlinuz"), &kernel)
        .await
        .context("Could not copy vmlinuz")?;
    tokio::fs::copy(boot_partition.mount_point().join("initrd.img"), &initrd)
        .await
        .context("Could not copy initrd.img")?;

    // We defer writing out the updated grubenv until we can ensure that the direct boot preparation
    // was successful.
    if grubenv_is_changing {
        grubenv
            .write_to_file(&grubenv_path)
            .context("Failed to upgrade grubenv")?;
    }

    Ok(Some(DirectBoot {
        kernel,
        initrd,
        kernel_cmdline: boot_args,
    }))
}

/// Refreshes the boot cycle and boot alternative in `grub_env`.
/// Returns true if `grub_env` changed.
fn refresh_grubenv(grub_env: &mut GrubEnv) -> Result<bool> {
    let mut boot_alternative = grub_env
        .boot_alternative
        .clone()
        .with_default_if_undefined(BootAlternative::A)
        .context("Invalid boot_alternative")?;
    let mut boot_cycle = grub_env
        .boot_cycle
        .clone()
        .with_default_if_undefined(BootCycle::Stable)
        .context("Invalid boot_cycle")?;

    match boot_cycle {
        BootCycle::Stable => {}
        BootCycle::Install => boot_cycle = BootCycle::Stable,
        BootCycle::FirstBoot => boot_cycle = BootCycle::FailsafeCheck,
        BootCycle::FailsafeCheck => {
            boot_cycle = BootCycle::Stable;
            boot_alternative = boot_alternative.get_opposite();
        }
    };
    let changed =
        grub_env.boot_alternative != Ok(boot_alternative) || grub_env.boot_cycle != Ok(boot_cycle);

    grub_env.boot_alternative = Ok(boot_alternative);
    grub_env.boot_cycle = Ok(boot_cycle);
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::testing::MockPartitionProvider;
    use grub::GrubEnvVariableError;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Builder for creating test setups with fluent interface
    struct TestSetupBuilder {
        boot_alternative: Option<BootAlternative>,
        boot_cycle: Option<BootCycle>,
        boot_args_a: String,
        boot_args_b: String,
        create_boot_args_files: bool,
        create_kernel_files: bool,
    }

    impl TestSetupBuilder {
        fn new() -> Self {
            Self {
                boot_alternative: None,
                boot_cycle: None,
                boot_args_a: "args_a".to_string(),
                boot_args_b: "args_b".to_string(),
                create_boot_args_files: true,
                create_kernel_files: true,
            }
        }

        fn with_grubenv(
            mut self,
            boot_alternative: BootAlternative,
            boot_cycle: BootCycle,
        ) -> Self {
            self.boot_alternative = Some(boot_alternative);
            self.boot_cycle = Some(boot_cycle);
            self
        }

        fn with_boot_args(mut self, args_a: &str, args_b: &str) -> Self {
            self.boot_args_a = args_a.to_string();
            self.boot_args_b = args_b.to_string();
            self
        }

        fn without_boot_args_files(mut self) -> Self {
            self.create_boot_args_files = false;
            self
        }

        fn without_kernel_files(mut self) -> Self {
            self.create_kernel_files = false;
            self
        }

        fn build(self) -> TestSetup {
            let grub_partition = create_grub_partition(self.boot_alternative, self.boot_cycle);

            let a_boot_partition = create_boot_partition(
                &self.boot_args_a,
                "SHOULD NOT BE USED",
                self.create_boot_args_files,
                self.create_kernel_files,
            );
            let b_boot_partition = create_boot_partition(
                "SHOULD NOT BE USED",
                &self.boot_args_b,
                self.create_boot_args_files,
                self.create_kernel_files,
            );

            let mut partitions = HashMap::new();
            partitions.insert(GRUB_PARTITION_UUID, grub_partition.clone());
            partitions.insert(A_BOOT_PARTITION_UUID, a_boot_partition);
            partitions.insert(B_BOOT_PARTITION_UUID, b_boot_partition);

            TestSetup {
                partition_provider: MockPartitionProvider::new(partitions),
                grub_partition,
            }
        }
    }

    /// Test helper to create a complete test setup with GRUB and boot partitions
    struct TestSetup {
        partition_provider: MockPartitionProvider,
        grub_partition: Arc<TempDir>,
    }

    impl TestSetup {
        async fn prepare_direct_boot(
            &self,
            should_refresh_grubenv: bool,
        ) -> Result<Option<DirectBoot>> {
            prepare_direct_boot(should_refresh_grubenv, &self.partition_provider).await
        }

        fn get_grubenv(&self) -> GrubEnv {
            let grubenv_path = self.grub_partition.path().join("grubenv");
            GrubEnv::read_from(File::open(grubenv_path).unwrap()).unwrap()
        }

        fn assert_grub_state(
            &self,
            expected_alternative: BootAlternative,
            expected_cycle: BootCycle,
        ) {
            let grubenv = self.get_grubenv();
            assert_eq!(grubenv.boot_cycle.unwrap(), expected_cycle);
            assert_eq!(grubenv.boot_alternative.unwrap(), expected_alternative);
        }
    }

    fn create_grub_partition(
        boot_alternative: Option<BootAlternative>,
        boot_cycle: Option<BootCycle>,
    ) -> Arc<TempDir> {
        let grub_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));
        let grubenv_path = grub_dir.path().join("grubenv");

        let grubenv = GrubEnv {
            boot_alternative: boot_alternative.ok_or(GrubEnvVariableError::Undefined),
            boot_cycle: boot_cycle.ok_or(GrubEnvVariableError::Undefined),
            ..GrubEnv::default()
        };
        grubenv
            .write_to_file(&grubenv_path)
            .expect("Failed to write grubenv");

        grub_dir
    }

    fn create_boot_partition(
        boot_args_a: &str,
        boot_args_b: &str,
        create_boot_args: bool,
        create_kernel_files: bool,
    ) -> Arc<TempDir> {
        let boot_dir = Arc::new(TempDir::new().expect("Failed to create temp dir"));

        if create_boot_args {
            let mut boot_args_file = File::create(boot_dir.path().join("boot_args")).unwrap();
            writeln!(boot_args_file, "BOOT_ARGS_A=\"{boot_args_a}\"").unwrap();
            writeln!(boot_args_file, "BOOT_ARGS_B=\"{boot_args_b}\"").unwrap();
        }

        if create_kernel_files {
            fs::write(boot_dir.path().join("vmlinuz"), b"fake kernel").unwrap();
            fs::write(boot_dir.path().join("initrd.img"), b"fake initrd").unwrap();
        }

        boot_dir
    }

    #[tokio::test]
    async fn test_boot_alternative_a() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::A, BootCycle::Stable)
            .build();

        let direct_boot = setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        assert_eq!(direct_boot.kernel_cmdline, "args_a");
        assert_eq!(fs::read(&direct_boot.kernel).unwrap(), b"fake kernel");
        assert_eq!(fs::read(&direct_boot.initrd).unwrap(), b"fake initrd");
    }

    #[tokio::test]
    async fn test_boot_alternative_b() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::B, BootCycle::Stable)
            .with_boot_args("args_a", "args_b extra")
            .build();

        let direct_boot = setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        assert_eq!(direct_boot.kernel_cmdline, "args_b extra");
    }

    // Test empty grubenv (happens on the very first boot)
    #[tokio::test]
    async fn test_empty_grubenv() {
        let setup = TestSetupBuilder::new().build();

        let direct_boot = setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::A, BootCycle::Stable);
        assert_eq!(direct_boot.kernel_cmdline, "args_a");
    }

    #[tokio::test]
    async fn test_grubenv_refresh_stable_no_change() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::A, BootCycle::Stable)
            .build();

        setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::A, BootCycle::Stable);
    }

    #[tokio::test]
    async fn test_grubenv_refresh_install_to_stable() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::A, BootCycle::Install)
            .build();

        setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::A, BootCycle::Stable);
    }

    #[tokio::test]
    async fn test_grubenv_refresh_firstboot_to_failsafecheck() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::B, BootCycle::FirstBoot)
            .build();

        setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::B, BootCycle::FailsafeCheck);
    }

    #[tokio::test]
    async fn test_grubenv_refresh_failsafecheck_to_stable_opposite() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::A, BootCycle::FailsafeCheck)
            .build();

        setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::B, BootCycle::Stable);
    }

    #[tokio::test]
    async fn test_grubenv_refresh_failsafecheck_b_to_stable_a() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::B, BootCycle::FailsafeCheck)
            .build();

        setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        setup.assert_grub_state(BootAlternative::A, BootCycle::Stable);
    }

    #[tokio::test]
    async fn test_no_grubenv_refresh() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::A, BootCycle::FirstBoot)
            .build();

        setup
            .prepare_direct_boot(false)
            .await
            .expect("prepare_direct_boot failed")
            .expect("prepare_direct_boot returned None");

        // Grubenv should remain unchanged
        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_alternative.unwrap(), BootAlternative::A);
        assert_eq!(grubenv.boot_cycle.unwrap(), BootCycle::FirstBoot);
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
            create_grub_partition(Some(BootAlternative::A), Some(BootCycle::Stable));
        let mut partitions = HashMap::new();
        partitions.insert(GRUB_PARTITION_UUID, grub_partition);
        let provider = MockPartitionProvider::new(partitions);

        let result = prepare_direct_boot(false, &provider).await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Could not find partition"));
    }

    #[tokio::test]
    async fn test_missing_boot_args_file() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::B, BootCycle::FailsafeCheck)
            .without_boot_args_files()
            .build();

        let result = setup
            .prepare_direct_boot(true)
            .await
            .expect("prepare_direct_boot failed");
        assert!(result.is_none());

        // Grubenv should remain unchanged
        let grubenv = setup.get_grubenv();
        assert_eq!(grubenv.boot_alternative.unwrap(), BootAlternative::B);
        assert_eq!(grubenv.boot_cycle.unwrap(), BootCycle::FailsafeCheck);
    }

    #[tokio::test]
    async fn test_missing_kernel_file() {
        let setup = TestSetupBuilder::new()
            .with_grubenv(BootAlternative::B, BootCycle::Stable)
            .without_kernel_files()
            .build();

        assert!(setup
            .prepare_direct_boot(false)
            .await
            .expect_err("prepare_direct_boot should fail")
            .to_string()
            .contains("vmlinuz"));
    }
}
