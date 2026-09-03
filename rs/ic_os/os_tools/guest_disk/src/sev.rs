//! SEV-SNP disk encryption for GuestOS.
//!
//! ## How derived keys work
//!
//! Each disk-encryption key is derived from the AMD SEV **sealing key**, which the
//! firmware derives from — among other inputs — the **launch measurement** (identifying
//! the GuestOS release) and the **launch TCB version** (identifying the AMD firmware
//! security level).
//!
//! Both change over the lifetime of a node: a GuestOS upgrade produces a new launch
//! measurement, a firmware upgrade a new launch TCB. When either changes, the sealing key
//! — and thus the disk-encryption key — changes, so the keyslot must be re-keyed.
//!
//! Each header carries a **single keyslot** (the first one); the Store partition carries
//! its LUKS header detached, on the per-slot Var partition, so every boot slot has its own
//! frozen header. Rollbacks therefore need no key exchange: the old slot simply boots with
//! its own header, and after a firmware *downgrade* the firmware refuses to derive keys
//! above the launch TCB, so the data is inaccessible until the firmware is upgraded again.
//!
//! ## LUKS2 metadata token
//!
//! The keyslot is paired with a LUKS2 token (`ic-key-metadata`) recording the launch
//! measurement and launch TCB it was derived under. Opening derives the passphrase at
//! exactly that TCB (which may be older than the current firmware's) and then, after a
//! firmware upgrade, re-keys the keyslot in place with [`rekey`] to a key derived at the
//! current TCB (TCB rotation).
//!
//! Invariants:
//!
//! - Creating a SEV keyslot always records a token; a tokenless keyslot is invisible at
//!   open time.
//! - Re-keying replaces the keyslot's passphrase in place and rewrites its token.

use crate::crypt::{
    LuksHeaderLocation, SINGLE_KEYSLOT_INDEX, SevMetadata, destroy_keyslots_except_first,
    export_luks_metrics, format_crypt_device, open_luks2_device, read_single_keyslot_token,
    write_keyslot_token,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail};
use attestation::attestation_report::{AttestationReportExt, tcb_version_from_u64};
use config_types::GuestVMType;
use libcryptsetup_rs::consts::flags::CryptActivate;
use prometheus::Registry;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Disk encryption for SEV guests: the key is derived from the SEV firmware, bound to
/// the GuestOS's launch measurement. The Var partition uses an attached LUKS header; the
/// Store partition uses a detached header stored on the Var partition.
pub struct SevDiskEncryption {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    pub store_luks_header_path: PathBuf,
    pub guest_vm_type: GuestVMType,
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
        let report = get_attestation_report(self.sev_firmware.as_mut())?;
        let header_location = self.header_location(partition);

        let mut crypt_device = open_luks2_device(device_path, header_location, true)
            .context("Failed to open device")?;

        // The single keyslot (the first one) has a token recording the TCB version its
        // key was derived at; the passphrase must be derived at exactly that TCB (which
        // may be older than the current firmware's after a firmware upgrade).
        let token = read_single_keyslot_token(&mut crypt_device)?;
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            token.sev_metadata.tcb_version,
        )
        .context("Failed to derive SEV key for disk encryption")?;

        crypt_device
            .activate_handle()
            .activate_by_passphrase(
                Some(crypt_name),
                Some(SINGLE_KEYSLOT_INDEX),
                key.as_bytes(),
                activate_flags(partition),
            )
            .context("Failed to activate cryptographic device")?;

        // After a firmware upgrade, the keyslot's TCB version is behind the current
        // launch TCB (it can never be newer: the firmware refuses to derive keys above
        // the platform TCB). Replace the keyslot with one derived at the current TCB.
        // Only the default VM rotates.
        let generation = report
            .generation()
            .context("Failed to get SEV generation from attestation report")?;
        let keyslot_tcb = tcb_version_from_u64(token.sev_metadata.tcb_version, generation)
            .context("Failed to parse keyslot TCB version")?;
        if keyslot_tcb < report.launch_tcb {
            if self.guest_vm_type != GuestVMType::Default {
                info!("Skipping TCB rotation for {:?} VM", self.guest_vm_type);
            } else {
                rekey(
                    device_path,
                    header_location,
                    key.as_bytes(),
                    self.sev_firmware.as_mut(),
                )?;
            }
        }

        export_luks_metrics(&mut crypt_device, device_path, 0, &self.metrics_registry);

        Ok(())
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        let report = get_attestation_report(self.sev_firmware.as_mut())?;
        let sev_metadata = sev_metadata_from_report(&report)?;
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            sev_metadata.tcb_version,
        )
        .context("Failed to derive SEV key for disk encryption")?;

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
        write_keyslot_token(&mut crypt_device, sev_metadata)
            .context("Failed to write SEV keyslot metadata")?;

        Ok(())
    }
}

/// Gets an attestation report from the SEV firmware.
fn get_attestation_report(sev_firmware: &mut dyn SevGuestFirmware) -> Result<AttestationReport> {
    let report_bytes = sev_firmware
        .get_report(None, None, None)
        .context("Failed to get attestation report from SEV firmware")?;
    AttestationReport::from_bytes(&report_bytes).context("Failed to parse attestation report")
}

/// Converts an attestation report to the metadata recorded in LUKS2 tokens: the launch
/// measurement (hex) and the launch TCB version.
fn sev_metadata_from_report(report: &AttestationReport) -> Result<SevMetadata> {
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
    let mut crypt_device = match open_luks2_device(device_path, header_location, true) {
        Ok(crypt_device) => crypt_device,
        Err(err) => {
            warn!("Failed to open LUKS2 device: {err:#}");
            return Ok(false);
        }
    };

    // Like open(): derive the passphrase at the TCB version recorded in the keyslot's
    // token and check that it unlocks the device.
    let key = (|| {
        let token = read_single_keyslot_token(&mut crypt_device)?;
        derive_key_from_sev_measurement(
            sev_firmware,
            Key::DiskEncryptionKey { device_path },
            token.sev_metadata.tcb_version,
        )
    })();
    let Some(key) = key else {
        return Ok(false);
    };

    let unlocks = crypt_device
        .activate_handle()
        .activate_by_passphrase(
            None,
            Some(SINGLE_KEYSLOT_INDEX),
            key.as_bytes(),
            CryptActivate::empty(),
        )
        .is_ok();

    Ok(unlocks)
}

/// Re-keys a LUKS2 device's header in place: the key unlocking the device (`old_key`) is
/// replaced with a key derived from the current launch measurement and TCB.
pub fn rekey(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    old_key: &[u8],
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<()> {
    info!("Re-keying the LUKS2 header for {}", device_path.display());
    let report = get_attestation_report(sev_firmware)?;
    let sev_metadata = sev_metadata_from_report(&report)?;
    let new_key = derive_key_from_sev_measurement(
        sev_firmware,
        Key::DiskEncryptionKey { device_path },
        sev_metadata.tcb_version,
    )
    .context("Failed to derive the new SEV key for the device")?;

    let mut crypt_device = open_luks2_device(device_path, header_location, false)
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
        .context("Failed to replace the old key with the new SEV-derived key")?;
    // Removes the keyslots that legacy headers may still carry.
    destroy_keyslots_except_first(&mut crypt_device)?;
    write_keyslot_token(&mut crypt_device, sev_metadata)
        .context("Failed to write SEV keyslot metadata")?;

    Ok(())
}
