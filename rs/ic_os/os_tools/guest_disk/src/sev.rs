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

use crate::crypt::{
    KeyslotToken, LuksHeaderLocation, SINGLE_KEYSLOT_INDEX, SevMetadata, activate,
    destroy_keyslots_except_first, format_crypt_device, open_luks2_device,
    read_single_keyslot_token, write_keyslot_token,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail};
use attestation::attestation_report::AttestationReportExt;
use config_types::GuestVMType;
use libcryptsetup_rs::CryptDevice;
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
    fn header_location(&self, partition: Partition) -> LuksHeaderLocation {
        match partition {
            Partition::Store => LuksHeaderLocation::Detached(self.store_luks_header_path.clone()),
            Partition::Var => LuksHeaderLocation::Attached,
        }
    }
}

impl DiskEncryption for SevDiskEncryption {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let (mut crypt_device, token, mut passphrase) = open_keyslot(
            device_path,
            &self.header_location(partition),
            self.sev_firmware.as_mut(),
        )?;

        let sev_metadata = get_sev_metadata_for_luks(self.sev_firmware.as_mut())?;
        // If the TCB versions differ (e.g. after firmware upgrade), replace the keyslot with one
        // derived at the current TCB (but only if this is the Default VM).
        if token.sev_metadata.tcb_version != sev_metadata.tcb_version {
            if self.guest_vm_type == GuestVMType::Default {
                passphrase = rekey_crypt_device(
                    &mut crypt_device,
                    passphrase.as_bytes(),
                    self.sev_firmware.as_mut(),
                )?;
            } else {
                info!("Skipping TCB rotation for {:?} VM", self.guest_vm_type);
            }
        }

        activate(
            &mut crypt_device,
            crypt_name,
            passphrase.as_bytes(),
            activate_flags(partition),
            &self.metrics_registry,
        )
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        let sev_metadata = get_sev_metadata_for_luks(self.sev_firmware.as_mut())?;
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

        let mut crypt_device = format_crypt_device(
            device_path,
            &self.header_location(partition),
            key.as_bytes(),
        )
        .context("Failed to format partition")?;
        write_keyslot_token(&mut crypt_device, sev_metadata)
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

fn open_keyslot(
    device_path: &Path,
    header_location: &LuksHeaderLocation,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<(CryptDevice, KeyslotToken, String)> {
    let mut crypt_device =
        open_luks2_device(device_path, header_location, true).context("Failed to open device")?;
    let token = read_single_keyslot_token(&mut crypt_device)?;
    let passphrase = derive_key_from_sev_measurement(
        sev_firmware,
        Key::DiskEncryptionKey { device_path },
        token.sev_metadata.tcb_version,
    )
    .context("Failed to derive SEV key for disk encryption")?;

    Ok((crypt_device, token, passphrase))
}

/// Check whether the device can be opened with the SEV-derived key.
pub fn can_open(
    device_path: &Path,
    header_location: &LuksHeaderLocation,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    let (mut crypt_device, _, passphrase) =
        match open_keyslot(device_path, header_location, sev_firmware) {
            Ok(result) => result,
            Err(err) => {
                warn!("Failed to open the keyslot: {err:#}");
                return Ok(false);
            }
        };

    // Check that the passphrase unlocks the keyslot.
    Ok(crypt_device
        .activate_handle()
        .activate_by_passphrase(
            None,
            Some(SINGLE_KEYSLOT_INDEX),
            passphrase.as_bytes(),
            CryptActivate::empty(),
        )
        .is_ok())
}

/// Re-keys a LUKS2 device's header in place: the key unlocking the device (`old_key`) is
/// replaced with a key derived from the current launch measurement and TCB.
pub fn rekey(
    device_path: &Path,
    header_location: &LuksHeaderLocation,
    old_key: &[u8],
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<()> {
    let mut crypt_device = open_luks2_device(device_path, header_location, true)
        .context("Failed to open the LUKS2 device")?;
    rekey_crypt_device(&mut crypt_device, old_key, sev_firmware).map(|_| ())
}

/// Same as [`rekey`], but on an already-open crypt device. Returns the new key.
fn rekey_crypt_device(
    crypt_device: &mut CryptDevice,
    old_key: &[u8],
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<String> {
    let device_path = crypt_device
        .status_handle()
        .get_device_path()
        .context("Failed to get the device path")?
        .to_path_buf();
    info!("Re-keying the LUKS2 header for {}", device_path.display());
    let sev_metadata = get_sev_metadata_for_luks(sev_firmware)?;
    let new_key = derive_key_from_sev_measurement(
        sev_firmware,
        Key::DiskEncryptionKey {
            device_path: &device_path,
        },
        sev_metadata.tcb_version,
    )
    .context("Failed to derive the new SEV key for the device")?;

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
    // Remove the keyslots that legacy headers may still carry.
    destroy_keyslots_except_first(crypt_device)?;
    write_keyslot_token(crypt_device, sev_metadata)
        .context("Failed to write SEV keyslot metadata")?;

    Ok(new_key)
}
