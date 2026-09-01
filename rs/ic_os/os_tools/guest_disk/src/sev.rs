use crate::crypt::{
    LuksHeaderLocation, SINGLE_KEYSLOT_INDEX, SevMetadata, activate_crypt_device, add_sev_metadata,
    check_encryption_key, destroy_keyslots_except_first, format_crypt_device, open_luks2_device,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail};
use attestation::attestation_report::AttestationReportExt;
use prometheus::Registry;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::{Path, PathBuf};
use tracing::info;

/// Disk encryption for SEV guests: the key is derived from the SEV firmware, bound to
/// the GuestOS's launch measurement. The Var partition uses an attached LUKS header; the
/// Store partition uses a detached header stored on the Var partition.
pub struct SevDiskEncryption {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    pub store_luks_header_path: PathBuf,
    pub metrics_registry: Registry,
}

impl SevDiskEncryption {
    fn header_location(&self, partition: Partition) -> LuksHeaderLocation<'_> {
        match partition {
            Partition::Store => LuksHeaderLocation::Detached(&self.store_luks_header_path),
            Partition::Var => LuksHeaderLocation::Attached,
        }
    }
}

impl DiskEncryption for SevDiskEncryption {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        activate_crypt_device(
            device_path,
            self.header_location(partition),
            crypt_name,
            key.as_bytes(),
            activate_flags(partition),
            /*verify_luks_params=*/ true,
            Some(&self.metrics_registry),
        )
        .with_context(|| format!("Failed to open the {partition:?} partition"))?;

        Ok(())
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let sev_metadata = get_sev_metadata_for_luks(self.sev_firmware.as_mut())?;

        if partition == Partition::Store && self.store_luks_header_path.exists() {
            bail!(
                "Refusing to format Store because detached LUKS header {} already exists. \
                Remove the stale header first if you really want to reformat the device.",
                self.store_luks_header_path.display()
            );
        }

        let mut crypt_device =
            format_crypt_device(device_path, self.header_location(partition), key.as_bytes())
                .context("Failed to format partition")?;
        add_sev_metadata(&mut crypt_device, sev_metadata)
            .context("Failed to write SEV keyslot metadata")?;

        Ok(())
    }
}

/// Reads the launch measurement and TCB version from the SEV firmware's attestation
/// report, for storage in the LUKS2 keyslot metadata token.
fn get_sev_metadata_for_luks(sev_firmware: &mut dyn SevGuestFirmware) -> Result<SevMetadata> {
    let report_bytes = sev_firmware
        .get_report(None, None, None)
        .context("Failed to get attestation report from SEV firmware")?;
    let report = AttestationReport::from_bytes(&report_bytes)
        .context("Failed to parse attestation report")?;

    Ok(SevMetadata {
        launch_measurement_hex: hex::encode(report.measurement),
        tcb_version: report
            .launch_tcb_as_u64()
            .context("Failed to get launch TCB from attestation report")?,
    })
}

/// Check whether the device can be opened with the SEV-derived key.
pub fn can_open(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    let derived_key =
        derive_key_from_sev_measurement(sev_firmware, Key::DiskEncryptionKey { device_path })?;

    Ok(check_encryption_key(device_path, header_location, derived_key.as_bytes()).is_ok())
}

/// Re-keys a LUKS2 device's header from `old_key` to the SEV-derived key.
pub fn rekey(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    old_key: &[u8],
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<()> {
    info!(
        "Re-keying the LUKS2 header for {} to the new GuestOS's SEV-derived key",
        device_path.display()
    );
    let new_key =
        derive_key_from_sev_measurement(sev_firmware, Key::DiskEncryptionKey { device_path })
            .context("Failed to derive the new SEV key for the device")?;
    let sev_metadata = get_sev_metadata_for_luks(sev_firmware)?;

    let mut crypt_device = open_luks2_device(device_path, header_location)
        .context("Failed to open the LUKS2 device")?;

    // Unlock with the old key (searching all keyslots) and set the first keyslot to the
    // new key. Fails if the old key does not unlock any keyslot.
    crypt_device
        .keyslot_handle()
        .change_by_passphrase(
            // TODO: after all nodes have a single keyslot at SINGLE_KEYSLOT_INDEX, change this to
            //  Some(SINGLE_KEYSLOT_INDEX)
            None,
            Some(SINGLE_KEYSLOT_INDEX),
            old_key,
            new_key.as_bytes(),
        )
        .context("Failed to replace the received key with the new SEV-derived key")?;
    // Removes the keyslots that legacy headers may still carry.
    // TODO: remove it (see comment on destroy_keyslots_except_first).
    destroy_keyslots_except_first(&mut crypt_device)?;
    add_sev_metadata(&mut crypt_device, sev_metadata)
        .context("Failed to write SEV keyslot metadata")?;

    Ok(())
}
