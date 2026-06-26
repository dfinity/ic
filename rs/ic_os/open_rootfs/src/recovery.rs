use crate::partitions::get_boot_partition_uuid;
use crate::proposal::read_and_verify_signed_bless_alternative_guest_os_version_proposal;
use anyhow::{Context, Result};
use attestation::attestation_package::AttestationPackageVerifier;
use attestation::custom_data::{SevCustomData, SevCustomDataNamespace};
use command_runner::CommandRunner;
use config_types::GuestOSConfig;
use ic_device::mount::{
    FileSystem, MountOptions, MountedPartition, PartitionProvider, PartitionSelector,
};
use rand::prelude::thread_rng;
use sev_guest::attestation_package::generate_attestation_package;
use sev_guest::firmware::SevGuestFirmware;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
#[cfg(any(feature = "dev", test))]
use tracing::info;

pub const CONFIG_DEVICE_LABEL: &str = "CONFIG";
pub const RECOVERY_PROPOSAL_FILE_NAME: &str = "alternative_guestos_proposal.cbor";

/// Reads and verifies an alternative GuestOS proposal, returning the rootfs hash from it.
/// Returns Ok(None) if no proposal is found and Err if the extraction/verification fails.
pub fn extract_and_verify_recovery_rootfs_hash(
    root_device: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
    command_runner: &dyn CommandRunner,
    partition_provider: &dyn PartitionProvider,
) -> Result<String> {
    let config_mount = mount_config_device_with_retry(partition_provider)?;

    let config_path = config_mount.mount_point().join("config.json");
    let guest_config: GuestOSConfig = config_tool::deserialize_config(&config_path)
        .context("Failed to deserialize GuestOS config")?;
    let trusted_execution_environment_config = guest_config
        .trusted_execution_environment_config
        .context("Missing trusted_execution_environment_config in GuestOS config")?;

    #[cfg(any(feature = "dev", test))]
    let nns_public_key_override = get_nns_public_key_override(config_mount.mount_point())?;

    drop(config_mount);

    let boot_mount = partition_provider.mount_partition(
        PartitionSelector::ByUuid(get_boot_partition_uuid(root_device, command_runner)?),
        MountOptions {
            file_system: FileSystem::Ext4,
            read_only: false, // Partition may need repair
        },
    )?;

    let proposal = read_and_verify_signed_bless_alternative_guest_os_version_proposal(
        &boot_mount.mount_point().join(RECOVERY_PROPOSAL_FILE_NAME),
        #[cfg(any(feature = "dev", test))]
        nns_public_key_override.as_deref(),
    )?;

    drop(boot_mount);

    // Generate an attestation package and verify the contents of the proposal against it.
    let attestation_package = generate_attestation_package(
        sev_firmware,
        &trusted_execution_environment_config,
        &SevCustomData::random(
            SevCustomDataNamespace::VerifyAlternativeGuestOsProposal,
            &mut thread_rng(),
        ),
    )
    .context("Failed to generate attestation package")?;

    let chip_ids = proposal
        .chip_ids
        .as_ref()
        .context("Proposal missing chip_ids")?;

    let guest_launch_measurements: Vec<&[u8]> = proposal
        .base_guest_launch_measurements
        .as_ref()
        .context("Proposal missing base_guest_launch_measurements")?
        .guest_launch_measurements
        .as_ref()
        .context("base_guest_launch_measurements missing guest_launch_measurements")?
        .iter()
        .filter_map(|m| m.measurement.as_deref())
        .collect();

    attestation_package
        .verify_chip_id(chip_ids)
        .context("This node's chip ID is not included in the expected chip IDs")?
        .verify_measurement(&guest_launch_measurements)
        .context("This node is not running a GuestOS with one of the base launch measurements")?
        .verify_guest_policy()
        .context("Guest policy verification failed")?;

    proposal.rootfs_hash.context("Proposal missing rootfs_hash")
}

/// Opens the device containing the config. Since the device may not be available in early boot,
/// retries a few times.
fn mount_config_device_with_retry(
    partition_provider: &dyn PartitionProvider,
) -> Result<Box<dyn MountedPartition>> {
    // We choose a high retry count since if this fails, there is no other recovery option.
    let mut attempts = 20;
    let config_mount = loop {
        match partition_provider.mount_partition(
            PartitionSelector::ByLabel(CONFIG_DEVICE_LABEL.to_string()),
            MountOptions {
                file_system: FileSystem::Vfat,
                read_only: true,
            },
        ) {
            Ok(config_mount) => break config_mount,
            Err(_err) if attempts > 0 => {
                attempts -= 1;
                sleep(Duration::from_secs(1));
            }
            Err(err) => return Err(err).context("Failed to mount CONFIG partition"),
        }
    };

    Ok(config_mount)
}

#[cfg(any(feature = "dev", test))]
fn get_nns_public_key_override(config_media_path: &Path) -> Result<Option<Vec<u8>>> {
    info!("Dev mode: reading NNS public key override from {config_media_path:?}");

    let guestos_config: GuestOSConfig =
        config_tool::deserialize_config(config_media_path.join("config.json"))?;

    let Some(nns_pub_key_pem) = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .nns_pub_key_override
    else {
        info!("No NNS public key override found in GuestOS config");
        return Ok(None);
    };

    let pem_object = pem::parse(&nns_pub_key_pem).context("Failed to parse PEM")?;

    Ok(Some(pem_object.into_contents()))
}
