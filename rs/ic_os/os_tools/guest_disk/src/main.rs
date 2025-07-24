mod crypt;
mod generated_key;
mod partitions;
mod sev;

use crate::generated_key::{setup_disk_encryption_with_generated_key, GENERATED_KEY_PATH};
use crate::partitions::{partition_setup, PartitionSetup};
use crate::sev::{setup_disk_encryption_with_sev, PREVIOUS_KEY_PATH};
use anyhow::{Context, Result};
use clap::Parser;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use ic_sev::guest::key_deriver::SevKeyDeriver;
use std::io::Write;
use std::path::Path;

#[derive(clap::Parser)]
pub enum Args {
    SetupDiskEncryption { partition: Partition },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args {
        Args::SetupDiskEncryption { partition } => setup_disk_encryption(partition),
    }
}

fn setup_disk_encryption(partition: Partition) -> Result<()> {
    let guestos_config = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to read GuestOS config")?;

    let mut sev_key_deriver = guestos_config
        .icos_settings
        .enable_trusted_execution_environment
        .then(|| SevKeyDeriver::new())
        .transpose()?;

    setup_disk_encryption_impl(
        partition,
        &guestos_config,
        sev_key_deriver.as_mut(),
        Path::new(PREVIOUS_KEY_PATH),
        Path::new(GENERATED_KEY_PATH),
        &partition_setup(),
    )
}

/// Sets up disk encryption for the specified partition.
/// `sev_key_deriver` must be provided if the GuestOS is configured to use TEE in `guestos_config`.
fn setup_disk_encryption_impl(
    partition: Partition,
    guestos_config: &GuestOSConfig,
    sev_key_deriver: Option<&mut SevKeyDeriver>,
    previous_key_path: &Path,
    generated_key_path: &Path,
    partition_setup: &PartitionSetup,
) -> Result<()> {
    if guestos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        setup_disk_encryption_with_sev(
            partition,
            partition_setup,
            sev_key_deriver.context("SevKeyDeriver was None, but TEE is enabled")?,
            previous_key_path,
        )
        .with_context(|| {
            format!("Failed to setup disk encryption with SEV for partition {partition:?}")
        })
    } else {
        setup_disk_encryption_with_generated_key(partition, partition_setup, generated_key_path)
            .with_context(|| {
                format!(
                    "Failed to setup disk encryption with generated key for partition {partition:?}",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{
        DeploymentEnvironment, GuestVMType, ICOSSettings, Ipv6Config, NetworkSettings,
    };
    use ic_device::device_mapping::{Sectors, TempDevice};
    use ic_sev::guest::firmware::MockSevGuestFirmware;
    use std::path::PathBuf;
    use tempfile::{tempdir, NamedTempFile, TempDir};

    fn create_guestos_config(
        guest_vm_type: GuestVMType,
        enable_trusted_execution_environment: bool,
    ) -> GuestOSConfig {
        GuestOSConfig {
            config_version: "".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::RouterAdvertisement,
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: Default::default(),
                deployment_environment: DeploymentEnvironment::Mainnet,
                logging: Default::default(),
                use_nns_public_key: false,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            guestos_settings: Default::default(),
            guest_vm_type,
            upgrade_config: Default::default(),
            trusted_execution_environment_config: None,
        }
    }

    #[test]
    fn test_generated_disk_encryption() {
        dbg!(std::fs::read_dir("/dev")
            .expect("Failed to read /dev directory")
            .collect::<Vec<_>>());

        let store_device = TempDevice::new(Sectors(1024)).unwrap();
        let previous_key = NamedTempFile::new().unwrap();
        let generated_key = NamedTempFile::new().unwrap();
        let mut mock_guest_firmware = MockSevGuestFirmware::new();
        mock_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));

        let partition_setup = PartitionSetup {
            efi_partition_device: PathBuf::from("/dev/does_not_exist"),
            grub_partition_device: PathBuf::from("/dev/does_not_exist"),
            config_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_boot_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_root_partition_device: PathBuf::from("/dev/does_not_exist"),
            my_var_partition_device: PathBuf::from("/dev/does_not_exist"),
            alternative_boot_partition_device: PathBuf::from("/dev/does_not_exist"),
            alternative_root_partition_device: PathBuf::from("/dev/does_not_exist"),
            alternative_var_partition_device: PathBuf::from("/dev/does_not_exist"),
            store_partition_device: store_device.path().unwrap(),
        };

        setup_disk_encryption_impl(
            Partition::Store,
            &create_guestos_config(GuestVMType::Default, false),
            Some(&mut SevKeyDeriver::new_for_test(Box::new(
                mock_guest_firmware,
            ))),
            previous_key.path(),
            generated_key.path(),
            &partition_setup,
        )
        .expect("Failed to setup disk encryption with generated key for store partition");
        dbg!(std::fs::read_dir("/dev")
            .expect("Failed to read /dev directory")
            .collect::<Vec<_>>());
    }
}
