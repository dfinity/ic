use crate::partitions::get_boot_partition_uuid;
use crate::proposal::read_and_verify_bless_alternative_guest_os_version_proposal;
use anyhow::{Context, Result, ensure};
use attestation::attestation_package::AttestationPackageVerifier;
use attestation::custom_data::{SevCustomData, SevCustomDataNamespace};
use command_runner::CommandRunner;
use config_types::GuestOSConfig;
use ic_device::mount::{FileSystem, MountOptions, PartitionProvider, PartitionSelector};
use rand::prelude::thread_rng;
use sev_guest::attestation_package::generate_attestation_package;
use sev_guest::firmware::SevGuestFirmware;
use std::path::Path;

#[cfg(feature = "dev")]
use std::fs;

pub const CONFIG_PARTITION_LABEL: &str = "CONFIG";
pub const RECOVERY_PROPOSAL_FILE_NAME: &str = "alternative_guestos_proposal.cbor";

/// Reads and verifies an alternative GuestOS proposal, returning the rootfs hash from it.
/// Returns Ok(None) if no proposal is found and Err if the extraction/verification fails.
pub fn extract_and_verify_recovery_rootfs_hash(
    root_device: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
    command_runner: &dyn CommandRunner,
    partition_provider: &dyn PartitionProvider,
) -> Result<Option<String>> {
    let config_mount = partition_provider
        .mount_partition(
            PartitionSelector::ByLabel(CONFIG_PARTITION_LABEL.to_string()),
            MountOptions {
                file_system: FileSystem::Vfat,
            },
        )
        .context("Failed to mount CONFIG partition")?;
    let config_path = config_mount.mount_point().join("config.json");
    let guest_config: GuestOSConfig = config_tool::deserialize_config(&config_path)
        .context("Failed to deserialize GuestOS config")?;
    let trusted_execution_environment_config = guest_config
        .trusted_execution_environment_config
        .context("Missing trusted_execution_environment_config in GuestOS config")?;

    #[cfg(feature = "dev")]
    let nns_public_key_override = get_nns_public_key_override(config_mount.mount_point())?;

    drop(config_mount);

    let boot_mount = partition_provider.mount_partition(
        PartitionSelector::ByUuid(get_boot_partition_uuid(root_device, command_runner)?),
        MountOptions {
            file_system: FileSystem::Ext4,
        },
    )?;

    let Some(proposal) = read_and_verify_bless_alternative_guest_os_version_proposal(
        &boot_mount.mount_point().join(RECOVERY_PROPOSAL_FILE_NAME),
        #[cfg(feature = "dev")]
        nns_public_key_override.as_deref(),
    )?
    else {
        // No alternative GuestOS proposal found
        return Ok(None);
    };

    drop(boot_mount);

    ensure!(
        proposal.rootfs_hash.is_some(),
        "Proposal missing rootfs_hash"
    );

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
        .context("This node is not running a GuestOS with one of the base launch measurements")?;

    Ok(proposal.rootfs_hash)
}

#[cfg(feature = "dev")]
fn get_nns_public_key_override(config_media_path: &Path) -> Result<Option<Vec<u8>>> {
    let nns_public_key_override_path = config_media_path.join("nns_public_key_override.pem");
    if !nns_public_key_override_path.exists() {
        return Ok(None);
    }

    eprintln!("Dev mode: reading NNS public key override from {nns_public_key_override_path:?}");

    let pem_contents = fs::read_to_string(&nns_public_key_override_path).with_context(|| {
        format!(
            "Failed to read NNS public key override from {:?}",
            nns_public_key_override_path
        )
    })?;
    let pem_object = pem::parse(&pem_contents).context("Failed to parse PEM")?;

    Ok(Some(pem_object.into_contents()))
}
