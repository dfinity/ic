use crate::crypt::{
    activate_crypt_device, check_encryption_key, deactivate_crypt_device, destroy_keyslots_and_assigned_tokens, destroy_keyslots_except,
    format_crypt_device, has_attached_luks_header, open_luks2_device,
    read_keyslot_metadata, wipe_attached_luks_header, write_keyslot_metadata, KeyslotMetadata,
    LuksHeaderLocation, SevMetadata,
};
use crate::metrics::export_attached_luks2_header_status;
use crate::{activate_flags, DiskEncryption, Partition};
use anyhow::{bail, ensure, Context, Result};
use attestation::attestation_report::AttestationReportExt;
use config_types::GuestVMType;
use libcryptsetup_rs::CryptDevice;
use prometheus::Registry;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{derive_key_from_sev_measurement, Key};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub struct SevDiskEncryption {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    /// Path to the previous SEV key file. This is used when a new GuestOS version boots up for the
    /// first time after an upgrade. The previous key file stores the disk encryption key that was
    /// retrieved from the previous GuestOS version using the upgrade protocol.
    pub previous_key_path: PathBuf,
    pub store_luks_header_path: PathBuf,
    pub guest_vm_type: GuestVMType,
    pub metrics_registry: Registry,
}

/// A successfully unlocked LUKS2 keyslot together with the passphrase used to open it.
struct ActiveKeyslot {
    metadata: KeyslotMetadata,
    key: String,
}

impl SevDiskEncryption {
    fn header_location(&self, partition: Partition) -> LuksHeaderLocation<'_> {
        match partition {
            Partition::Var => LuksHeaderLocation::Attached,
            Partition::Store => LuksHeaderLocation::Detached(&self.store_luks_header_path),
        }
    }

    /// Records the attached LUKS2 header status in the metrics registry. Failures are logged as
    /// warnings and never propagated, because a metrics export failure must not prevent the
    /// partition from being opened.
    fn export_attached_header_status(
        &self,
        device_path: &Path,
        attached_header_present: Result<bool>,
    ) {
        if let Err(e) = export_attached_luks2_header_status(
            &self.metrics_registry,
            device_path,
            attached_header_present,
        ) {
            warn!("Failed to export attached LUKS2 header status metric: {e:#}");
        }
    }

    /// Checks whether the device carries an attached (on-device) LUKS2 header. If a detached
    /// header is available and an attached header is still present, the attached header is wiped
    /// so that only the detached header is used going forward. Finally, the attached-header status
    /// is recorded in the metrics registry.
    ///
    /// TODO: once no nodes with attached Store LUKS headers remain, remove this logic.
    fn wipe_and_export_attached_luks2_header(&self, device_path: &Path) {
        let attached_header_present = has_attached_luks_header(device_path).unwrap_or_else(|e| {
            warn!(
                "Failed to check for attached LUKS2 header on {}: {e:#}. \
                Continuing without wiping.",
                device_path.display()
            );
            false
        });

        if self.store_luks_header_path.exists() && attached_header_present {
            if let Err(e) = open_luks2_device(
                device_path,
                LuksHeaderLocation::Detached(&self.store_luks_header_path),
            ) {
                warn!(
                    "Refusing to wipe attached LUKS2 header on {}: detached header {} \
                    cannot be read by libcryptsetup: {e:#}",
                    device_path.display(),
                    self.store_luks_header_path.display()
                );
            } else {
                info!(
                    "Detached Store LUKS header available and attached header still present \
                    on {}. Wiping attached header.",
                    device_path.display()
                );
                if let Err(e) = wipe_attached_luks_header(device_path) {
                    warn!(
                        "Failed to wipe attached LUKS2 header on {}: {e:#}. \
                        Continuing with detached header.",
                        device_path.display()
                    );
                }
            }
        }

        self.export_attached_header_status(
            device_path,
            // Note that we don't use `attached_header_present` here, because the header may
            // have been wiped above.
            has_attached_luks_header(device_path),
        );
    }

    /// Removes keyslots that should be removed during the firmware upgrade.
    fn destroy_stale_keyslots_after_firmware_upgrade(
        &self,
        crypt_device: &mut CryptDevice,
        current_sev_metadata: &SevMetadata,
    ) -> Result<()> {
        let metadata =
            read_keyslot_metadata(crypt_device).context("Failed to read keyslot metadata")?;
        let stale_keyslots =
            Self::stale_keyslots_after_firmware_upgrade(&metadata, current_sev_metadata)?;

        destroy_keyslots_and_assigned_tokens(crypt_device, &stale_keyslots)
            .context("Failed to destroy stale key slots")
    }

    /// Returns the keyslots that should be removed during firmware-upgrade cleanup.
    ///
    /// The policy is:
    /// - keep keyslots from other GuestOS measurements untouched,
    /// - among keyslots for the current measurement, keep exactly one with the current TCB,
    /// - remove all remaining current-measurement keyslots.
    fn stale_keyslots_after_firmware_upgrade(
        metadata: &[KeyslotMetadata],
        current_sev_metadata: &SevMetadata,
    ) -> Result<Vec<u32>> {
        let mut kept_current_keyslot = false;
        let mut stale_keyslots = Vec::new();

        for entry in metadata {
            let sev_metadata = &entry.sev_metadata;

            // Don't remove keyslots that are not associated with the current GuestOS. These will
            // be removed during GuestOS upgrade.
            // TODO: Unify the cleanup path during GuestOS upgrade and firmware upgrade.
            if sev_metadata.launch_measurement_hex != current_sev_metadata.launch_measurement_hex {
                continue;
            }

            // Of the keyslots that are associated with the current GuestOS, keep the one that
            // has the current TCB version.
            if sev_metadata.tcb_version == current_sev_metadata.tcb_version {
                if kept_current_keyslot {
                    stale_keyslots.push(entry.keyslot()?);
                } else {
                    kept_current_keyslot = true;
                }
                continue;
            }

            stale_keyslots.push(entry.keyslot()?);
        }

        Ok(stale_keyslots)
    }

    /// Unlocks the store partition using the key left by the previous OS installation, then
    /// replaces it with the current SEV-derived key and writes updated LUKS2 token metadata.
    /// Returns `Ok(())` on success so the caller can return early; falls through on failure.
    fn setup_store_with_previous_key(
        &mut self,
        device_path: &Path,
        crypt_name: &str,
        sev_metadata: &SevMetadata,
    ) -> Result<()> {
        let previous_key = std::fs::read(&self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        let new_key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            sev_metadata.tcb_version,
        )
        .context("Failed to derive new SEV key for previous-key migration")?;

        info!("Found previous key for store partition, will use it to unlock the partition");
        let mut crypt_device = activate_crypt_device(
            device_path,
            LuksHeaderLocation::Detached(&self.store_luks_header_path),
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
            /*verify_luks_params=*/ true,
            Some(&self.metrics_registry),
        )
        .context("Failed to unlock store partition with previous key")?;

        info!("Adding new SEV key to store partition");
        let new_keyslot = crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key.as_bytes())
            .context("Failed to add new key to store partition")?;

        // Write token metadata for the new key slot before destroying old keyslots, so
        // destroy_keyslots_except can identify the keyslot to keep by its metadata.
        let metadata = KeyslotMetadata::new_sev(new_keyslot, sev_metadata.clone());
        write_keyslot_metadata(&mut crypt_device, &metadata)
            .context("Failed to write token metadata after previous key setup")?;

        info!("Removing old key slots from store partition");
        if let Err(err) =
            destroy_keyslots_except(&mut crypt_device, std::slice::from_ref(sev_metadata))
        {
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            warn!("Failed to destroy key slots: {err:?}");
        }

        // Clean up the previous key on the first boot after upgrade if own key was added
        // successfully.
        if self.guest_vm_type == GuestVMType::Default {
            info!(
                "Removing previous store key file: {}",
                self.previous_key_path.display()
            );
            if let Err(err) = std::fs::remove_file(&self.previous_key_path) {
                debug_assert!(false, "Failed to remove previous key file: {err:?}");
                warn!("Failed to remove previous key file: {err:?}");
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
        current_sev_metadata: &SevMetadata,
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
        for candidate in keyslot_metadata {
            let passphrase = match derive_key_from_sev_measurement(
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

            match crypt_device
                .activate_handle()
                .activate_by_passphrase(
                    Some(crypt_name),
                    Some(candidate.keyslot()?),
                    passphrase.as_bytes(),
                    activate_flags(partition),
                )
                .context("Failed to activate cryptographic device")
            {
                Ok(_) => {
                    return Ok(ActiveKeyslot {
                        metadata: candidate,
                        key: passphrase,
                    });
                }
                Err(err) => {
                    let candidate_sev_metadata = &candidate.sev_metadata;
                    let error_context = if candidate_sev_metadata.launch_measurement_hex
                        == current_sev_metadata.launch_measurement_hex
                    {
                        "Failed to activate device with keyslot even though measurements match"
                            .to_string()
                    } else {
                        format!(
                            "Failed to activate device with keyslot (keyslot measurement: {}, \
                            current measurement: {})",
                            candidate_sev_metadata.launch_measurement_hex,
                            current_sev_metadata.launch_measurement_hex,
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
        let sev_metadata = &active_keyslot.metadata.sev_metadata;

        // If the TCB version matches, no rotation is needed.
        if sev_metadata.tcb_version == current_sev_metadata.tcb_version {
            return Ok(());
        }

        match self.guest_vm_type {
            GuestVMType::Upgrade | GuestVMType::Unknown => {
                info!("Skipping TCB rotation for {:?} VM", self.guest_vm_type);
                return Ok(());
            }
            GuestVMType::Default => {
                // Fall through
            }
        }

        info!("TCB version changed, rotating LUKS key slots.");
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
        .context("Failed to write token metadata")?;

        self.destroy_stale_keyslots_after_firmware_upgrade(crypt_device, current_sev_metadata)
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
        Ok(SevMetadata {
            launch_measurement_hex: hex::encode(report.measurement),
            tcb_version: report
                .launch_tcb_as_u64()
                .context("Failed to get launch TCB from attestation report")?,
        })
    }
}

impl DiskEncryption for SevDiskEncryption {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let sev_metadata = self.get_crypt_sev_metadata()?;

        if partition == Partition::Store {
            self.wipe_and_export_attached_luks2_header(device_path);
        }

        if partition == Partition::Store && self.previous_key_path.exists() {
            info!(
                "Unlocking store with existing key from {}",
                self.previous_key_path.display()
            );
            match self.setup_store_with_previous_key(device_path, crypt_name, &sev_metadata) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    warn!("Failed to unlock store partition with previous key: {err:?}");
                    // Deactivate any partially-set-up mapper so the fallback path can
                    // re-activate cleanly.
                    let _ = deactivate_crypt_device(crypt_name);
                }
            }
        }

        let mut crypt_device =
            open_luks2_device(device_path, self.header_location(partition), true)
                .context("Failed to open device")?;

        let active = self.unlock_by_candidate_enumeration(
            &mut crypt_device,
            crypt_name,
            partition,
            &sev_metadata,
        )?;

        info!("Activated keyslot {}", active.metadata.keyslot()?);

        self.rotate_tcb_if_stale(&mut crypt_device, active, &sev_metadata)
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        let sev_metadata = self.get_crypt_sev_metadata()?;
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
            sev_metadata.tcb_version,
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let header_location = match partition {
            Partition::Store => {
                if self.store_luks_header_path.exists() {
                    bail!(
                        "Refusing to format Store because detached LUKS header {} already exists. \
                        Remove the stale header first if you really want to reformat the device.",
                        self.store_luks_header_path.display()
                    );
                }
                LuksHeaderLocation::Detached(&self.store_luks_header_path)
            }
            Partition::Var => LuksHeaderLocation::Attached,
        };

        let (mut crypt_device, keyslot) =
            format_crypt_device(device_path, header_location, key.as_bytes())
                .context("Failed to format partition")?;

        let metadata = KeyslotMetadata::new_sev(keyslot, sev_metadata);
        write_keyslot_metadata(&mut crypt_device, &metadata).context("Failed to write metadata")?;

        Ok(())
    }
}

/// Check whether we can open the store partition with either the previous key or the SEV derived
/// key.
pub fn can_open_store(
    device_path: &Path,
    previous_key_path: &Path,
    store_luks_header_path: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    // Keep key selection consistent with open() above.
    if previous_key_path.exists()
        && let Ok(key) = std::fs::read(previous_key_path)
        && check_encryption_key(
            device_path,
            LuksHeaderLocation::Detached(store_luks_header_path),
            &key,
        )
        .is_ok()
    {
        return Ok(true);
    }

    let mut crypt_device = match open_luks2_device(
        device_path,
        LuksHeaderLocation::Detached(store_luks_header_path),
        true,
    ) {
        Ok(crypt_device) => crypt_device,
        Err(err) => {
            debug!("Failed to open Store LUKS2 device: {err:#}");
            return Ok(false);
        }
    };
    let keyslots = read_keyslot_metadata(&mut crypt_device)
        .context("Failed to read Store key-slot metadata")?;
    for token in &keyslots {
        let Ok(derived_key) = derive_key_from_sev_measurement(
            sev_firmware,
            Key::DiskEncryptionKey { device_path },
            token.sev_metadata.tcb_version,
        ) else {
            warn!("Failed to derive key from SEV measurement: {err:?}");
            continue;
        };

        if check_encryption_key(
            device_path,
            LuksHeaderLocation::Detached(store_luks_header_path),
            derived_key.as_bytes(),
        )
        .is_ok()
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[mockall::automock]
pub trait DiskCryptoOps: Send + Sync {
    /// Returns whether the Store partition can already be unlocked locally.
    ///
    /// Implementations may use the previous key, the detached LUKS header, and/or the current
    /// SEV-derived key to determine whether key exchange can be skipped.
    fn can_open_store(
        &self,
        device_path: &Path,
        previous_key_path: &Path,
        store_luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<bool>;
}

pub struct DefaultSevStoreCryptoOps;

impl DiskCryptoOps for DefaultSevStoreCryptoOps {
    fn can_open_store(
        &self,
        device_path: &Path,
        previous_key_path: &Path,
        store_luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<bool> {
        can_open_store(
            device_path,
            previous_key_path,
            store_luks_header_path,
            sev_firmware,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(keyslot: u32, measurement: &str, tcb_version: u64) -> KeyslotMetadata {
        KeyslotMetadata::new_sev(
            keyslot,
            SevMetadata {
                launch_measurement_hex: measurement.to_string(),
                tcb_version,
            },
        )
    }

    fn current_sev_metadata(measurement: &str, tcb_version: u64) -> SevMetadata {
        SevMetadata {
            launch_measurement_hex: measurement.to_string(),
            tcb_version,
        }
    }

    #[test]
    fn keeps_token_with_same_measurement_and_same_tcb() {
        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[metadata(3, "measurement-a", 11)],
            &current_sev_metadata("measurement-a", 11),
        )
        .unwrap();

        assert!(stale_keyslots.is_empty());
    }

    #[test]
    fn drops_token_with_same_measurement_and_different_tcb() {
        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[metadata(3, "measurement-a", 11)],
            &current_sev_metadata("measurement-a", 22),
        )
        .unwrap();

        assert_eq!(stale_keyslots, vec![3]);
    }

    #[test]
    fn keeps_token_with_different_measurement_even_if_tcb_differs() {
        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[metadata(3, "measurement-a", 11)],
            &current_sev_metadata("measurement-b", 22),
        )
        .unwrap();

        assert!(stale_keyslots.is_empty());
    }

    #[test]
    fn returns_only_stale_keyslots_for_current_measurement() {
        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[
                metadata(1, "measurement-a", 10),
                metadata(2, "measurement-a", 20),
                metadata(3, "measurement-b", 10),
                metadata(4, "measurement-a", 30),
            ],
            &current_sev_metadata("measurement-a", 20),
        )
        .unwrap();

        assert_eq!(stale_keyslots, vec![1, 4]);
    }

    #[test]
    fn keeps_one_current_tcb_keyslot_and_drops_duplicate_current_tcb_keyslots() {
        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[
                metadata(1, "measurement-a", 20),
                metadata(2, "measurement-a", 10),
                metadata(3, "measurement-a", 20),
                metadata(4, "measurement-b", 20),
                metadata(5, "measurement-a", 20),
            ],
            &current_sev_metadata("measurement-a", 20),
        )
        .unwrap();

        assert_eq!(stale_keyslots, vec![2, 3, 5]);
    }

    #[test]
    fn guestos_upgrade_before_firmware_upgrade_keeps_old_measurement_metadata() {
        let after_guestos_upgrade = vec![
            metadata(1, "measurement-old", 10),
            metadata(2, "measurement-new", 10),
        ];

        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &after_guestos_upgrade,
            &current_sev_metadata("measurement-new", 20),
        )
        .unwrap();

        assert_eq!(stale_keyslots, vec![2]);
        assert!(!stale_keyslots.contains(&after_guestos_upgrade[0].keyslot().unwrap()));
    }

    #[test]
    fn firmware_upgrade_before_guestos_upgrade_keeps_only_latest_tcb_for_current_measurement() {
        let after_firmware_upgrade = vec![metadata(1, "measurement-old", 20)];

        let stale_keyslots = SevDiskEncryption::stale_keyslots_after_firmware_upgrade(
            &[
                after_firmware_upgrade[0].clone(),
                metadata(2, "measurement-new", 20),
            ],
            &current_sev_metadata("measurement-new", 20),
        )
        .unwrap();

        assert!(stale_keyslots.is_empty());
        assert!(!stale_keyslots.contains(&after_firmware_upgrade[0].keyslot().unwrap()));
    }
}
