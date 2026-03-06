use crate::crypt::{
    KeySlotMetadata, activate_crypt_device, check_encryption_key, destroy_key_slots_except,
    format_crypt_device, read_key_slot_metadata, write_key_slot_metadata,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result};
use config_types::GuestVMType;
use sev::Generation;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::{SevGuestFirmware, parse_attestation_report};
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::Path;

/// Default path to the GuestOS version file.
pub const GUESTOS_VERSION_FILE: &str = "/opt/ic/share/version.txt";

pub struct SevDiskEncryption<'a> {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    /// Path to the previous SEV key file. This is used when a new GuestOS version boots up for the
    /// first time after an upgrade. The previous key file stores the disk encryption key that was
    /// retrieved from the previous GuestOS version using the upgrade protocol.
    pub previous_key_path: &'a Path,
    pub guest_vm_type: GuestVMType,
    /// GuestOS version string (read from `/opt/ic/share/version.txt`).
    pub guestos_version: String,
}

impl SevDiskEncryption<'_> {
    /// Gets an attestation report from the firmware and parses it.
    fn get_attestation_report(&mut self) -> Result<AttestationReport> {
        let report_bytes = self
            .sev_firmware
            .get_report(None, None, None)
            .context("Failed to get attestation report from SEV firmware")?;
        parse_attestation_report(&report_bytes).context("Failed to parse attestation report")
    }

    /// Performs LUKS key slot rotation when the TCB version has changed (firmware upgrade).
    /// Reads the old TCB from the LUKS2 token metadata, derives the old key, unlocks the
    /// device, adds a new key derived with the current TCB version, and removes the old
    /// key slot.
    fn rotate_key_for_tcb_change(
        &mut self,
        device_path: &Path,
        crypt_name: &str,
        partition: Partition,
        old_tcb_u64: u64,
        new_tcb_u64: u64,
        report: &AttestationReport,
    ) -> Result<()> {
        println!(
            "TCB version changed, rotating LUKS key slots for {}",
            device_path.display()
        );

        let old_key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            old_tcb_u64,
        )
        .context("Failed to derive old SEV key for TCB rotation")?;

        let new_key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            new_tcb_u64,
        )
        .context("Failed to derive new SEV key for TCB rotation")?;

        let (mut crypt_device, _old_keyslot) = activate_crypt_device(
            device_path,
            crypt_name,
            old_key.as_bytes(),
            activate_flags(partition),
        )
        .context("Failed to unlock device with old TCB key during rotation")?;

        println!("Adding new key derived with updated TCB version");
        let new_keyslot = crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, old_key.as_bytes(), new_key.as_bytes())
            .context("Failed to add new TCB key to device")?;

        println!("Removing old TCB key slots");
        if let Err(err) = destroy_key_slots_except(&mut crypt_device, &[new_key.as_bytes()]) {
            debug_assert!(false, "Failed to destroy old TCB key slots: {err:?}");
            eprintln!("Failed to destroy old TCB key slots: {err:?}");
        }

        // Update LUKS2 token metadata (write_key_slot_metadata replaces any existing
        // token for this keyslot automatically).
        let metadata = KeySlotMetadata::new(
            new_keyslot,
            self.guestos_version.clone(),
            &report.measurement,
            new_tcb_u64,
        );
        write_key_slot_metadata(&mut crypt_device, &metadata, new_keyslot)
            .context("Failed to write token metadata after TCB rotation")?;

        println!("TCB key rotation complete");
        Ok(())
    }

    fn setup_store_with_previous_key(
        &mut self,
        device_path: &Path,
        crypt_name: &str,
        new_key: &[u8],
        report: &AttestationReport,
    ) -> Result<()> {
        let previous_key = std::fs::read(self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        println!("Found previous key for store partition, will use it to unlock the partition");
        let (mut crypt_device, _old_keyslot) = activate_crypt_device(
            device_path,
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
        )
        .context("Failed to unlock store partition with previous key")?;

        println!("Adding new SEV key to store partition");
        let new_keyslot = crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        println!("Removing old key slots from store partition");
        if let Err(err) = destroy_key_slots_except(&mut crypt_device, &[&previous_key, new_key]) {
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            eprintln!("Failed to destroy key slots: {err:?}");
        }

        // Update LUKS2 token metadata for the new key slot (write_key_slot_metadata
        // replaces any existing token for this keyslot automatically).
        let tcb_u64 = reported_tcb_from_attestation_report(report)
            .context("Failed to get TCB from attestation report")?;
        let metadata = KeySlotMetadata::new(
            new_keyslot,
            self.guestos_version.clone(),
            &report.measurement,
            tcb_u64,
        );
        write_key_slot_metadata(&mut crypt_device, &metadata, new_keyslot)
            .context("Failed to write token metadata after previous key setup")?;

        // Clean up the previous key on the first boot after upgrade if own key was added
        // successfully.
        if self.guest_vm_type == GuestVMType::Default {
            println!(
                "Removing previous store key file: {}",
                self.previous_key_path.display()
            );
            if let Err(err) = std::fs::remove_file(self.previous_key_path) {
                debug_assert!(false, "Failed to remove previous key file: {err:?}");
                eprintln!("Failed to remove previous key file: {err:?}");
            }
        }

        Ok(())
    }
}

impl DiskEncryption for SevDiskEncryption<'_> {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let report = self.get_attestation_report()?;
        let current_tcb = reported_tcb_from_attestation_report(&report)
            .context("Failed to get current TCB from attestation report")?;

        // Check LUKS2 token metadata for a TCB version change (firmware upgrade).
        // If the stored TCB differs from the current one, rotate the key.
        if let Ok(mut crypt_device) = crate::crypt::open_luks2_device(device_path) {
            if let Ok(tokens) = read_key_slot_metadata(&mut crypt_device) {
                if let Some(token) = tokens.first() {
                    let stored_tcb = token.tcb();
                    if stored_tcb != current_tcb {
                        match self.rotate_key_for_tcb_change(
                            device_path,
                            crypt_name,
                            partition,
                            stored_tcb,
                            current_tcb,
                            &report,
                        ) {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                eprintln!("Failed to rotate key for TCB change: {err:?}");
                            }
                        }
                    }
                }
            }
        }

        // Derive the key using the current TCB version (0 means current).
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            0,
        )
        .context("Failed to derive SEV key for disk encryption")?;

        match partition {
            Partition::Var => {
                let (mut crypt_device, keyslot) = activate_crypt_device(
                    device_path,
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                )
                .context("Failed to open crypt device for var partition")?;

                // Write token metadata after successful open.
                self.write_metadata_for_key(&mut crypt_device, keyslot, &report)
                    .context("Failed to write token metadata for var partition")?;
            }

            Partition::Store => {
                // The logic should be kept consistent with can_open_store below
                if self.previous_key_path.exists() {
                    println!(
                        "Unlocking store with existing key from {}",
                        self.previous_key_path.display()
                    );
                    match self.setup_store_with_previous_key(
                        device_path,
                        crypt_name,
                        key.as_bytes(),
                        &report,
                    ) {
                        Ok(()) => return Ok(()),
                        Err(err) => {
                            eprintln!(
                                "Failed to unlock store partition with previous key: {err:?}"
                            );
                            // Fall through and try to open the device with the new key
                        }
                    }
                }

                let (mut crypt_device, keyslot) = activate_crypt_device(
                    device_path,
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                )
                .context("Failed to initialize crypt device for store partition")?;

                // Write token metadata after successful open.
                self.write_metadata_for_key(&mut crypt_device, keyslot, &report)
                    .context("Failed to write token metadata for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&mut self, device_path: &Path, _partition: Partition) -> Result<()> {
        let report = self.get_attestation_report()?;

        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            reported_tcb_from_attestation_report(&report)?,
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let (mut crypt_device, keyslot) = format_crypt_device(device_path, key.as_bytes())
            .context("Failed to format partition")?;

        // Write token metadata after formatting.
        self.write_metadata_for_key(&mut crypt_device, keyslot, &report)
            .context("Failed to write token metadata after format")?;

        Ok(())
    }
}

impl SevDiskEncryption<'_> {
    /// Writes LUKS2 token metadata for the current key to the device.
    fn write_metadata_for_key(
        &mut self,
        crypt_device: &mut libcryptsetup_rs::CryptDevice,
        keyslot: u32,
        report: &AttestationReport,
    ) -> Result<()> {
        let tcb_u64 = reported_tcb_from_attestation_report(report)
            .context("Failed to get TCB from attestation report")?;
        // write_key_slot_metadata replaces any existing token for this keyslot automatically.
        let metadata = KeySlotMetadata::new(
            keyslot,
            self.guestos_version.clone(),
            &report.measurement,
            tcb_u64,
        );
        write_key_slot_metadata(crypt_device, &metadata, keyslot)
            .context("Failed to write token metadata")?;
        Ok(())
    }
}

/// Check whether we can open the store partition with either the previous key or the SEV derived
/// key. Also checks with TCB versions from LUKS2 token metadata if available.
pub fn can_open_store(
    device_path: &Path,
    previous_key_path: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    // TODO: can it be bool?
    // The logic should be kept consistent with open above
    if previous_key_path.exists()
        && let Ok(key) = std::fs::read(previous_key_path)
        && check_encryption_key(device_path, &key).is_ok()
    {
        return Ok(true);
    }

    // Try with TCB versions from LUKS2 token metadata (handles firmware upgrade case).
    if let Ok(mut crypt_device) = crate::crypt::open_luks2_device(device_path) {
        if let Ok(tokens) = read_key_slot_metadata(&mut crypt_device) {
            for token in &tokens {
                if let Ok(derived_key) = derive_key_from_sev_measurement(
                    sev_firmware,
                    Key::DiskEncryptionKey { device_path },
                    token.tcb(),
                ) {
                    if check_encryption_key(device_path, derived_key.as_bytes()).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // Try with the default TCB version (0 means current platform TCB).
    let derived_key =
        derive_key_from_sev_measurement(sev_firmware, Key::DiskEncryptionKey { device_path }, 0)?;
    Ok(check_encryption_key(device_path, derived_key.as_bytes()).is_ok())
}

fn reported_tcb_from_attestation_report(report: &AttestationReport) -> Result<u64> {
    let generation = Generation::identify_cpu(
        report
            .cpuid_fam_id
            .context("Family ID not found in attestation report")?,
        report
            .cpuid_mod_id
            .context("Model ID not found in attestation report")?,
    )
    .context("Failed to identify SEV generation from attestation report")?;

    Ok(u64::from_le_bytes(
        report.reported_tcb.to_bytes_with(generation)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::firmware::host::TcbVersion;
    use sev::parser::ByteParser;
    use sev_guest_testing::AttestationReportBuilder;

    #[test]
    fn test_reported_tcb_from_attestation_report() {
        let report = AttestationReportBuilder::new()
            .with_reported_tcb(TcbVersion {
                fmc: Some(42),
                bootloader: 11,
                tee: 22,
                snp: 33,
                microcode: 44,
            })
            .build_unsigned();
        let report_bytes = report.to_bytes().unwrap();
        let tcb_u64 = reported_tcb_from_attestation_report(&report).unwrap();
        // Reported TCB is 64 bytes starting at offset 0x180
        let reported_tcb_in_report = &report_bytes[0x180..0x188];

        assert_eq!(&tcb_u64.to_bytes().unwrap(), reported_tcb_in_report);
    }
}
