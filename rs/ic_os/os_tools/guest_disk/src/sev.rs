use crate::crypt::{
    KeyslotMetadata, activate_crypt_device, check_encryption_key, destroy_key_slots_except,
    format_crypt_device, open_luks2_device, read_keyslot_metadata, write_keyslot_metadata,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, ensure};
use attestation::attestation_report::AttestationReportExt;
use config_types::GuestVMType;
use hex;
use libcryptsetup_rs::CryptDevice;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::Path;

pub struct SevDiskEncryption<'a> {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    /// Path to the previous SEV key file. This is used when a new GuestOS version boots up for the
    /// first time after an upgrade. The previous key file stores the disk encryption key that was
    /// retrieved from the previous GuestOS version using the upgrade protocol.
    pub previous_key_path: &'a Path,
    pub guest_vm_type: GuestVMType,
}

impl SevDiskEncryption<'_> {
    /// Gets an attestation report from the firmware and parses it.
    fn get_attestation_report(&mut self) -> Result<AttestationReport> {
        let report_bytes = self
            .sev_firmware
            .get_report(None, None, None)
            .context("Failed to get attestation report from SEV firmware")?;
        AttestationReport::from_bytes(&report_bytes).context("Failed to parse attestation report")
    }

    fn setup_store_with_previous_key(
        &mut self,
        crypt_device: &mut CryptDevice,
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
        activate_crypt_device(
            crypt_device,
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
            None, // keyslot for the previous key is not known in advance
        )
        .context("Failed to unlock store partition with previous key")?;

        println!("Adding new SEV key to store partition");
        let new_keyslot = crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        println!("Removing old key slots from store partition");
        if let Err(err) = destroy_key_slots_except(crypt_device, &[&previous_key, new_key]) {
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            eprintln!("Failed to destroy key slots: {err:?}");
        }

        // Update LUKS2 token metadata for the new key slot (write_key_slot_metadata
        // replaces any existing token for this keyslot automatically).
        let metadata = KeyslotMetadata::new(
            new_keyslot,
            &report.measurement,
            report
                .launch_tcb_as_u64()
                .context("Failed to get launch TCB from attestation report")?,
        );
        write_keyslot_metadata(crypt_device, &metadata)
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
        let mut crypt_device = open_luks2_device(device_path).context("Failed to open device")?;
        let report = self.get_attestation_report()?;
        let launch_tcb = report
            .launch_tcb_as_u64()
            .context("Failed to get launch TCB from attestation report")?;

        // For the store partition, first try opening via the previous key file left by the
        // previous OS installation.  This handles the OS-upgrade migration path and is
        // independent of the measurement-based enumeration below.
        if partition == Partition::Store && self.previous_key_path.exists() {
            println!(
                "Unlocking store with existing key from {}",
                self.previous_key_path.display()
            );
            let new_key = derive_key_from_sev_measurement(
                self.sev_firmware.as_mut(),
                Key::DiskEncryptionKey { device_path },
                None,
            )
            .context("Failed to derive new SEV key for previous-key migration")?;
            match self.setup_store_with_previous_key(
                &mut crypt_device,
                crypt_name,
                new_key.as_bytes(),
                &report,
            ) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    eprintln!("Failed to unlock store partition with previous key: {err:?}");
                    // Fall through to measurement-based enumeration.
                }
            }
        }

        let measurement_hex = hex::encode(&report.measurement);
        let keyslot_metadata =
            read_keyslot_metadata(&mut crypt_device).context("Failed to get active keyslots")?;
        ensure!(!keyslot_metadata.is_empty(), "No active keyslots found");

        let mut errors = vec![];
        let mut successful_activation = None;
        for candidate in keyslot_metadata {
            let attempt = || -> Result<(KeyslotMetadata, String)> {
                let key = derive_key_from_sev_measurement(
                    self.sev_firmware.as_mut(),
                    Key::DiskEncryptionKey { device_path },
                    Some(candidate.tcb_version),
                )
                .context("Failed to derive key via SEV")?;

                activate_crypt_device(
                    &mut crypt_device,
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                    Some(candidate.keyslot()?),
                )
                .with_context(|| {
                    if candidate.measurement == measurement_hex {
                        "Failed to activate device with keyslot".to_string()
                    } else {
                        format!(
                            "Failed to activate device with keyslot (keyslot measurement: {}, \
                                own measurement: {})",
                            candidate.measurement, measurement_hex
                        )
                    }
                })?;

                Ok((candidate, key))
            };

            match attempt() {
                Ok(success) => {
                    successful_activation = Some(success);
                    break;
                }
                Err(err) => errors.push(err),
            }
        }

        let (metadata, key) = successful_activation.with_context(|| {
            format!("Failed to open encrypted device with any keyslots: {errors:#?}")
        })?;

        println!("Activated keyslot {}", metadata.keyslot()?);

        if metadata.tcb_version != launch_tcb {
            println!(
                "TCB version changed, rotating LUKS key slots for {}",
                device_path.display()
            );
            let new_key = derive_key_from_sev_measurement(
                self.sev_firmware.as_mut(),
                Key::DiskEncryptionKey { device_path },
                Some(launch_tcb),
            )
            .context("Failed to derive new SEV key for TCB rotation")?;
            let keyslot = metadata.keyslot()?;
            crypt_device
                .keyslot_handle()
                .change_by_passphrase(
                    Some(keyslot),
                    Some(keyslot),
                    key.as_bytes(),
                    new_key.as_bytes(),
                )
                .context("Failed to change passphrase during TCB rotation")?;

            let new_metadata = KeyslotMetadata {
                tcb_version: launch_tcb,
                ..metadata
            };
            write_keyslot_metadata(&mut crypt_device, &new_metadata)
                .context("Failed to write token metadata")?;
        }

        Ok(())
    }

    fn format(&mut self, device_path: &Path, _partition: Partition) -> Result<()> {
        let report = self.get_attestation_report()?;

        let launch_tcb = report
            .launch_tcb_as_u64()
            .context("Failed to get launch TCB from attestation report")?;
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            Some(launch_tcb),
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let (mut crypt_device, keyslot) = format_crypt_device(device_path, key.as_bytes())
            .context("Failed to format partition")?;

        let metadata = KeyslotMetadata::new(keyslot, &report.measurement, launch_tcb);
        write_keyslot_metadata(&mut crypt_device, &metadata).context("Failed to write metadata")?;
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
    // The logic should be kept consistent with open above
    if previous_key_path.exists()
        && let Ok(key) = std::fs::read(previous_key_path)
        && check_encryption_key(device_path, &key).is_ok()
    {
        return Ok(true);
    }

    let mut crypt_device = open_luks2_device(device_path).context("Failed to open LUKS2 device")?;
    let keyslots =
        read_keyslot_metadata(&mut crypt_device).context("Failed to get active keyslots")?;
    for token in &keyslots {
        if let Ok(derived_key) = derive_key_from_sev_measurement(
            sev_firmware,
            Key::DiskEncryptionKey { device_path },
            Some(token.tcb_version),
        ) {
            if check_encryption_key(device_path, derived_key.as_bytes()).is_ok() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::firmware::host::TcbVersion;
    use sev::parser::ByteParser;
    use sev_guest_testing::AttestationReportBuilder;

    #[test]
    fn test_reported_tcb_as_u64() {
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
        let tcb_u64 = report.reported_tcb_as_u64().unwrap();
        // Reported TCB is 64 bytes starting at offset 0x180
        let reported_tcb_in_report = &report_bytes[0x180..0x188];

        assert_eq!(&tcb_u64.to_bytes().unwrap(), reported_tcb_in_report);
    }
}
