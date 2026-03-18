use crate::crypt::{
    KeyslotMetadata, SevMetadata, activate_crypt_device, check_encryption_key,
    destroy_key_slots_except, format_crypt_device, open_luks2_device, read_keyslot_metadata,
    write_keyslot_metadata,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail, ensure};
use attestation::attestation_report::AttestationReportExt;
use config_types::{GuestOSConfig, GuestVMType};
use hex;
use libcryptsetup_rs::CryptDevice;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::attestation_package::generate_attestation_package;
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

/// A successfully unlocked LUKS2 keyslot together with the passphrase used to open it.
/// Produced by `unlock_by_candidate_enumeration` and consumed by `rotate_tcb_if_stale`.
struct ActiveKeyslot {
    metadata: KeyslotMetadata,
    key: String,
}

impl SevDiskEncryption<'_> {
    /// Unlocks the store partition using the key left by the previous OS installation, then
    /// replaces it with the current SEV-derived key and writes updated LUKS2 token metadata.
    /// Returns `Ok(())` on success so the caller can return early; falls through on failure.
    fn setup_store_with_previous_key(
        &mut self,
        crypt_device: &mut CryptDevice,
        crypt_name: &str,
        sev_metadata: &SevMetadata,
    ) -> Result<()> {
        let previous_key = std::fs::read(self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        let device_path = crypt_device
            .status_handle()
            .get_device_path()
            .context("Failed to get device path")?
            .to_path_buf();
        let new_key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey {
                device_path: &device_path,
            },
            sev_metadata.tcb_version,
        )
        .context("Failed to derive new SEV key for previous-key migration")?;

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
            .add_by_passphrase(None, &previous_key, new_key.as_bytes())
            .context("Failed to add new key to store partition")?;

        println!("Removing old key slots from store partition");
        if let Err(err) =
            destroy_key_slots_except(crypt_device, &[&previous_key, new_key.as_bytes()])
        {
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            eprintln!("Failed to destroy key slots: {err:?}");
        }

        // Update LUKS2 token metadata for the new key slot (write_keyslot_metadata
        // replaces any existing token for this keyslot automatically).
        let metadata = KeyslotMetadata::new_sev(new_keyslot, sev_metadata.clone());
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

    /// Iterates LUKS2 keyslot candidates, derives the SEV key for each candidate's recorded TCB
    /// version, and activates the first one that succeeds. Returns the winning keyslot and
    /// passphrase (needed by the caller for any subsequent key rotation).
    fn unlock_by_candidate_enumeration(
        &mut self,
        crypt_device: &mut CryptDevice,
        crypt_name: &str,
        partition: Partition,
        sev_metadata: &SevMetadata,
    ) -> Result<ActiveKeyslot> {
        let device_path = crypt_device
            .status_handle()
            .get_device_path()
            .context("Failed to get device path")?
            .to_path_buf();
        let keyslot_metadata =
            read_keyslot_metadata(crypt_device).context("Failed to get active keyslots")?;
        ensure!(!keyslot_metadata.is_empty(), "No active keyslots found");

        let mut errors = vec![];
        println!("Current TCB version: {}", sev_metadata.tcb_version);
        println!("Current guest SVN: {}", sev_metadata.guest_svn);
        println!(
            "Current launch measurement: {}",
            sev_metadata.launch_measurement_hex
        );
        println!("Device path: {}", device_path.display());
        for candidate in keyslot_metadata {
            println!(
                "Candidate TCB version: {}",
                candidate.sev_metadata.tcb_version
            );
            println!(
                "Candidate launch measurement: {}",
                candidate.sev_metadata.launch_measurement_hex
            );
            println!("Candidate guest SVN: {}", candidate.sev_metadata.guest_svn);
            let key = match derive_key_from_sev_measurement(
                self.sev_firmware.as_mut(),
                Key::DiskEncryptionKey {
                    device_path: &device_path,
                },
                candidate.sev_metadata.tcb_version,
            ) {
                Ok(k) => k,
                Err(err) => {
                    errors.push(err.context("Failed to derive key via SEV"));
                    continue;
                }
            };

            println!("Debug key: {}", hex::encode(key.as_bytes()));

            match activate_crypt_device(
                crypt_device,
                crypt_name,
                key.as_bytes(),
                activate_flags(partition),
                Some(candidate.keyslot()?),
            ) {
                Ok(_) => {
                    return Ok(ActiveKeyslot {
                        metadata: candidate,
                        key,
                    });
                }
                Err(err) => {
                    let error_context = if candidate.sev_metadata.launch_measurement_hex
                        == sev_metadata.launch_measurement_hex
                    {
                        "Failed to activate device with keyslot even though measurements match"
                            .to_string()
                    } else {
                        format!(
                            "Failed to activate device with keyslot (keyslot measurement: {}, \
                            own measurement: {})",
                            candidate.sev_metadata.launch_measurement_hex,
                            sev_metadata.launch_measurement_hex,
                        )
                    };
                    errors.push(err.context(error_context));
                }
            }
        }

        bail!("Failed to open encrypted device with any keyslots: {errors:#?}")
    }

    /// If the activated keyslot's TCB is behind the current firmware's launch TCB, derives the
    /// new key, rotates the LUKS2 keyslot in place, and updates the token so future boots find
    /// the slot immediately without needing to try stale versions.
    fn rotate_tcb_if_stale(
        &mut self,
        crypt_device: &mut CryptDevice,
        active_keyslot: ActiveKeyslot,
        current_sev_metadata: &SevMetadata,
    ) -> Result<()> {
        // If the TCB version matches, no rotation is needed.
        if active_keyslot.metadata.sev_metadata.tcb_version == current_sev_metadata.tcb_version {
            return Ok(());
        }

        match self.guest_vm_type {
            GuestVMType::Upgrade => {
                println!("Skipping TCB rotation for upgrade VM");
                return Ok(());
            }
            GuestVMType::Unknown => {
                println!("Skipping TCB rotation for unknown VM type");
                return Ok(());
            }
            GuestVMType::Default => {
                // Fall through
            }
        }

        println!("TCB version changed, rotating LUKS key slots.");
        let device_path = crypt_device
            .status_handle()
            .get_device_path()
            .context("Failed to get device path")?
            .to_path_buf();
        let new_key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey {
                device_path: &device_path,
            },
            current_sev_metadata.tcb_version,
        )
        .context("Failed to derive new SEV key for TCB rotation")?;

        let keyslot = active_keyslot.metadata.keyslot()?;
        crypt_device
            .keyslot_handle()
            .change_by_passphrase(
                Some(keyslot),
                Some(keyslot),
                active_keyslot.key.as_bytes(),
                new_key.as_bytes(),
            )
            .context("Failed to change passphrase during TCB rotation")?;

        write_keyslot_metadata(
            crypt_device,
            &KeyslotMetadata::new_sev(keyslot, current_sev_metadata.clone()),
        )
        .context("Failed to write token metadata")
    }

    /// Gets an attestation report from the SEV firmware and extracts the two fields the
    /// disk en/decryption logic needs: the launch measurement (hex) and the launch TCB version.
    fn get_crypt_sev_metadata(&mut self) -> Result<SevMetadata> {
        let report_bytes = self
            .sev_firmware
            .get_report(None, None, None)
            .context("Failed to get attestation report from SEV firmware")?;
        let report = AttestationReport::from_bytes(&report_bytes)
            .context("Failed to parse attestation report")?;
        println!("Generated attestation report: {}", report);
        Ok(SevMetadata {
            launch_measurement_hex: hex::encode(report.measurement),
            tcb_version: report
                .launch_tcb_as_u64()
                .context("Failed to get launch TCB from attestation report")?,
        })
    }
}

impl DiskEncryption for SevDiskEncryption<'_> {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let mut crypt_device = open_luks2_device(device_path).context("Failed to open device")?;
        let sev_metadata = self.get_crypt_sev_metadata()?;

        // For the store partition, first try opening via the previous key file left by the
        // previous OS installation.  This handles the OS-upgrade migration path and is
        // independent of the measurement-based enumeration below.
        if partition == Partition::Store && self.previous_key_path.exists() {
            println!(
                "Unlocking store with existing key from {}",
                self.previous_key_path.display()
            );
            match self.setup_store_with_previous_key(&mut crypt_device, crypt_name, &sev_metadata) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    eprintln!("Failed to unlock store partition with previous key: {err:?}");
                    // Fall through to measurement-based enumeration.
                }
            }
        }

        let active = self.unlock_by_candidate_enumeration(
            &mut crypt_device,
            crypt_name,
            partition,
            &sev_metadata,
        )?;

        println!("Activated keyslot {}", active.metadata.keyslot()?);

        self.rotate_tcb_if_stale(&mut crypt_device, active, &sev_metadata)
    }

    fn format(&mut self, device_path: &Path, _partition: Partition) -> Result<()> {
        let sev_metadata = self.get_crypt_sev_metadata()?;
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            sev_metadata.tcb_version,
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let (mut crypt_device, keyslot) = format_crypt_device(device_path, key.as_bytes())
            .context("Failed to format partition")?;

        let metadata = KeyslotMetadata::new_sev(keyslot, sev_metadata);
        write_keyslot_metadata(&mut crypt_device, &metadata).context("Failed to write metadata")
    }
}

/// Check whether we can open the store partition with either the previous key or the SEV derived
/// key.
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
            token.sev_metadata.tcb_version,
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
