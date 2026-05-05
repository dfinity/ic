use crate::metrics::export_luks_parameters;
use anyhow::{Context, Result, anyhow, bail, ensure};
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle};
use std::fs;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{info, warn};

/// Number of bytes to use for the LUKS2 volume key
const VOLUME_KEY_BYTES: usize = 512 / 8; // 512 bits
const KEYSLOT_KEY_BYTES: usize = 512 / 8; // 512 bits
const ENCRYPTION_FORMAT: EncryptionFormat = EncryptionFormat::Luks2;
const CIPHER: &str = "aes";
const CIPHER_MODE: &str = "xts-plain64";
const PBKDF_TYPE: CryptKdf = CryptKdf::Pbkdf2;
const PBKDF_ITERATIONS: u32 = 1000;
/// Number of key slots supported by LUKS2
const LUKS2_N_KEY_SLOTS: u32 = 32;

#[derive(Debug)]
pub(crate) struct LuksParameters {
    pub(crate) format: EncryptionFormat,
    pub(crate) cipher: String,
    pub(crate) cipher_mode: String,
    pub(crate) volume_key_size: usize,
    pub(crate) keyslots: Vec<KeyslotParameters>,
}

#[derive(Debug)]
pub(crate) struct KeyslotParameters {
    pub(crate) slot: u32,
    pub(crate) status: KeyslotInfo,
    pub(crate) pbkdf_type: Option<CryptKdf>,
    pub(crate) pbkdf_iterations: Option<u32>,
    pub(crate) cipher: Option<String>,
    pub(crate) key_size: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub enum LuksHeaderLocation<'a> {
    /// Use the attached LUKS header on the device.
    Attached,
    /// Use the detached LUKS header at the specified path.
    Detached(&'a Path),
}

/// Obtains a cryptsetup handle for `device_path`.
/// `header_location` selects whether the LUKS header is read from the device itself or from a
/// detached header file while `device_path` remains the data device.
fn obtain_crypt_device_handle(
    device_path: &Path,
    header_location: LuksHeaderLocation,
) -> Result<CryptDevice> {
    if !device_path.exists() {
        bail!("Device does not exist: {}", device_path.display());
    }

    match header_location {
        LuksHeaderLocation::Detached(header_path) => {
            obtain_crypt_device_handle_with_detached_header(device_path, header_path)
                .with_context(|| format!("Detached header {} failed", header_path.display()))
        }
        LuksHeaderLocation::Attached => {
            obtain_crypt_device_handle_with_attached_header(device_path)
                .context("Attached header failed")
        }
    }
}

fn obtain_crypt_device_handle_with_attached_header(device_path: &Path) -> Result<CryptDevice> {
    CryptInit::init(device_path)
        .context("Failed to initialize cryptographic device with attached header")
}

fn obtain_crypt_device_handle_with_detached_header(
    device_path: &Path,
    header_path: &Path,
) -> Result<CryptDevice> {
    CryptInit::init_with_data_device(Right((header_path, device_path)))
        .context("Failed to initialize cryptographic device with detached header")
}

/// Initializes a cryptographic device at the specified path with LUKS2 format and activates it
/// using the provided name and encryption key.
pub fn activate_crypt_device(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    name: &str,
    encryption_key: &[u8],
    flags: CryptActivate,
    verify_luks_params: bool,
    metrics_file: Option<&Path>,
) -> Result<CryptDevice> {
    let mut crypt_device = open_luks2_device(device_path, header_location)?;

    let luks_parameters = extract_luks_parameters(&mut crypt_device);
    maybe_verify_luks_parameters(&luks_parameters, device_path, verify_luks_params)?;

    let active_keyslot = crypt_device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, encryption_key, flags)
        .context("Failed to activate cryptographic device")?;

    if let Some(metrics_file) = metrics_file {
        let log_result = luks_parameters.and_then(|luks_parameters| {
            export_luks_parameters(metrics_file, &luks_parameters, device_path, active_keyslot)
        });
        if let Err(e) = log_result {
            warn!("Failed to export LUKS parameters: {e:#}");
        }
    }

    Ok(crypt_device)
}

/// Deactivates the cryptographic device with the given name.
pub fn deactivate_crypt_device(crypt_name: &str) -> Result<()> {
    CryptDevice::from_ptr(std::ptr::null_mut())
        .activate_handle()
        .deactivate(
            crypt_name,
            libcryptsetup_rs::consts::flags::CryptDeactivate::empty(),
        )
        .context("Failed to deactivate cryptographic device")?;
    Ok(())
}

/// Formats the given cryptographic device with LUKS2 and initializes it with the provided
/// encryption key.
/// WARNING: Leads to data loss on the device!
pub fn format_crypt_device(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    encryption_key: &[u8],
) -> Result<CryptDevice> {
    if let LuksHeaderLocation::Detached(header_path) = header_location {
        File::create(header_path)
            .context("Failed to create detached LUKS header file")?
            .set_len(16 * 1024 * 1024)
            .context("Failed to set size of detached LUKS header file")?;
    }

    let mut crypt_device = obtain_crypt_device_handle(device_path, header_location)?;
    info!(
        "Formatting {} with LUKS2 and initializing it with an encryption key",
        device_path.display()
    );
    // TODO: We should revisit the use of Pbkdf2 and consider using the LUKS2 default KDF, Argon2i
    let mut pbkdf_params = CryptSettingsHandle::get_pbkdf_type_params(&PBKDF_TYPE)
        .context("Failed to get PBKDF2 params")?;
    // Set minimal iteration count -- we already use a random key with
    // maximal entropy, pbkdf doesn't gain anything (besides slowing
    // down boot by a couple seconds which needlessly annoys for testing).
    pbkdf_params.iterations = PBKDF_ITERATIONS;
    crypt_device
        .settings_handle()
        .set_pbkdf_type(&pbkdf_params)
        .context("Failed to set PBKDF2 type")?;
    crypt_device
        .context_handle()
        .format::<CryptParamsLuks2Ref>(
            ENCRYPTION_FORMAT,
            (CIPHER, CIPHER_MODE),
            None,
            Right(VOLUME_KEY_BYTES),
            None,
        )
        .context("Failed to call format")?;
    crypt_device
        .keyslot_handle()
        .add_by_key(None, None, encryption_key, CryptVolumeKey::empty())
        .context("Could not add key to cryptographic device")?;

    Ok(crypt_device)
}

/// Opens a LUKS2 device at the specified path and loads its context. Does not activate the device.
pub fn open_luks2_device(
    device_path: &Path,
    header_location: LuksHeaderLocation,
) -> Result<CryptDevice> {
    let mut crypt_device = obtain_crypt_device_handle(device_path, header_location)?;

    crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(ENCRYPTION_FORMAT), None)?;

    Ok(crypt_device)
}

/// Checks if the provided encryption key can activate the cryptographic device at the given path.
/// Does not activate the device.
pub fn check_encryption_key(
    device_path: &Path,
    header_location: LuksHeaderLocation,
    encryption_key: &[u8],
) -> Result<()> {
    // This method simply checks if the key works, we don't care about LUKS parameters
    let mut crypt_device =
        open_luks2_device(device_path, header_location).context("Failed to open LUKS2 device")?;

    crypt_device
        .activate_handle()
        .activate_by_passphrase(None, None, encryption_key, CryptActivate::empty())
        .context("Failed to activate device")?;

    Ok(())
}

pub fn backup_luks_header_to_file(device_path: &Path, header_path: &Path) -> Result<()> {
    let parent_dir = header_path
        .parent()
        .context("LUKS header path does not have a parent directory")?;
    fs::create_dir_all(parent_dir).with_context(|| {
        format!(
            "Failed to create parent directory for LUKS header {}",
            header_path.display()
        )
    })?;

    // Export into a temporary sibling path and rename it into place so we only replace an existing
    // detached header once cryptsetup has produced a complete backup.
    let temp_dir = tempfile::tempdir_in(parent_dir)
        .context("Failed to create temporary directory for LUKS header backup")?;
    let temp_header_path = temp_dir.path().join("header");

    let mut crypt_device = open_luks2_device(device_path, LuksHeaderLocation::Attached)
        .context("Failed to open LUKS2 device for header backup")?;
    crypt_device
        .backup_handle()
        .header_backup(Some(EncryptionFormat::Luks2), &temp_header_path)
        .with_context(|| {
            format!(
                "Failed to back up LUKS header to {}",
                temp_header_path.display()
            )
        })?;
    fs::set_permissions(&temp_header_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set permissions on temporary detached LUKS header file")?;

    fs::rename(&temp_header_path, header_path)
        .with_context(|| format!("Failed to persist LUKS header to {}", header_path.display()))?;

    Ok(())
}

/// Checks if the LUKS parameters match the expected values set in format_crypt_device.
/// If verify_luks_params is false, it will only log a warning if the verification fails.
fn maybe_verify_luks_parameters(
    luks_parameters: &Result<LuksParameters>,
    device_path: &Path,
    verify_luks_params: bool,
) -> Result<()> {
    let verification_result = luks_parameters
        .as_ref()
        .map_err(|e| anyhow!("Failed to extract LUKS parameters: {e:#}"))
        .and_then(verify_luks_parameters);

    if let Err(e) = verification_result {
        if verify_luks_params {
            return Err(e);
        }

        warn!(
            "LUKS parameters verification failed for device {} but verification is not \
            enforced: {e:#}",
            device_path.display()
        );
        return Ok(());
    }

    info!(
        "LUKS parameters verification succeeded for device {}",
        device_path.display()
    );

    Ok(())
}

pub(crate) fn extract_luks_parameters(crypt_device: &mut CryptDevice) -> Result<LuksParameters> {
    let format = crypt_device
        .format_handle()
        .get_type()
        .context("Failed to get encryption format")?;

    let mut status_handle = crypt_device.status_handle();
    let cipher = status_handle
        .get_cipher()
        .context("Failed to get cipher")?
        .to_string();
    let cipher_mode = status_handle
        .get_cipher_mode()
        .context("Failed to get cipher mode")?
        .to_string();
    let volume_key_size = status_handle.get_volume_key_size() as usize;

    let mut keyslot_handle = crypt_device.keyslot_handle();
    let mut keyslots = Vec::with_capacity(LUKS2_N_KEY_SLOTS as usize);

    for key_slot in 0..LUKS2_N_KEY_SLOTS {
        let status = keyslot_handle
            .status(key_slot)
            .with_context(|| format!("Failed to get status for keyslot {key_slot}"))?;
        let is_active = matches!(status, KeyslotInfo::Active | KeyslotInfo::ActiveLast);

        let mut keyslot_parameters = KeyslotParameters {
            slot: key_slot,
            status,
            pbkdf_type: None,
            pbkdf_iterations: None,
            cipher: None,
            key_size: None,
        };

        if is_active {
            let pbkdf = keyslot_handle
                .get_pbkdf(key_slot)
                .with_context(|| format!("Failed to get PBKDF type for keyslot {key_slot}"))?;
            let encryption = keyslot_handle
                .get_encryption(Some(key_slot))
                .with_context(|| format!("Failed to get encryption for keyslot {key_slot}"))?;

            keyslot_parameters.pbkdf_type = Some(pbkdf.type_);
            keyslot_parameters.pbkdf_iterations = Some(pbkdf.iterations);
            keyslot_parameters.cipher = Some(encryption.0.to_string());
            keyslot_parameters.key_size = Some(encryption.1);
        }

        keyslots.push(keyslot_parameters);
    }

    Ok(LuksParameters {
        format,
        cipher,
        cipher_mode,
        volume_key_size,
        keyslots,
    })
}

/// Verifies that the LUKS parameters match the expected values set in format_crypt_device
pub(crate) fn verify_luks_parameters(luks_parameters: &LuksParameters) -> Result<()> {
    ensure!(
        luks_parameters.format == ENCRYPTION_FORMAT,
        "Unexpected encryption format: {:?}",
        luks_parameters.format
    );
    ensure!(
        luks_parameters.cipher == CIPHER,
        "Unexpected cipher: {}",
        luks_parameters.cipher
    );
    ensure!(
        luks_parameters.cipher_mode == CIPHER_MODE,
        "Unexpected cipher mode: {}",
        luks_parameters.cipher_mode
    );
    ensure!(
        luks_parameters.volume_key_size == VOLUME_KEY_BYTES,
        "Unexpected volume key size: {}",
        luks_parameters.volume_key_size
    );

    for keyslot in &luks_parameters.keyslots {
        match keyslot.status {
            KeyslotInfo::Active | KeyslotInfo::ActiveLast => {
                let pbkdf_type = keyslot
                    .pbkdf_type
                    .as_ref()
                    .with_context(|| format!("Missing PBKDF type for keyslot {}", keyslot.slot))?;
                ensure!(
                    // Because of NODE-1939, we fall back to Argon2id when changing the passphrase
                    // after an upgrade.
                    pbkdf_type == &PBKDF_TYPE || pbkdf_type == &CryptKdf::Argon2Id,
                    "Unexpected keyslot PBKDF type: {:?}",
                    pbkdf_type
                );

                let cipher = keyslot
                    .cipher
                    .as_ref()
                    .with_context(|| format!("Missing cipher for keyslot {}", keyslot.slot))?;
                let key_size = keyslot
                    .key_size
                    .with_context(|| format!("Missing key size for keyslot {}", keyslot.slot))?;

                ensure!(
                    cipher == &format!("{CIPHER}-{CIPHER_MODE}"),
                    "Unexpected keyslot encryption: {}",
                    cipher
                );
                ensure!(
                    key_size == KEYSLOT_KEY_BYTES,
                    "Unexpected keyslot key size: {}",
                    key_size
                );
            }
            KeyslotInfo::Invalid | KeyslotInfo::Unbound | KeyslotInfo::Inactive => {}
        }
    }

    Ok(())
}

/// Destroys all key slots in the cryptographic device except for the one that is activated with the
/// provided encryption keys.
pub fn destroy_key_slots_except(
    crypt_device: &mut CryptDevice,
    encryption_keys_to_keep: &[&[u8]],
) -> Result<()> {
    let key_slots_to_keep = encryption_keys_to_keep
        .iter()
        .map(|keep| {
            crypt_device.activate_handle().activate_by_passphrase(
                None,
                None,
                keep,
                CryptActivate::empty(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .context("Cannot activate device with encryption key that we should keep")?;

    for key_slot in 0..LUKS2_N_KEY_SLOTS {
        // If this key slot is active and not the one we want to keep, destroy it.
        if !key_slots_to_keep.contains(&key_slot)
            && matches!(
                crypt_device.keyslot_handle().status(key_slot),
                Ok(KeyslotInfo::Active | KeyslotInfo::ActiveLast)
            )
        {
            match crypt_device.keyslot_handle().destroy(key_slot) {
                Ok(_) => {
                    info!("Destroyed old key slot {key_slot}");
                }
                Err(err) => {
                    // It's not a critical error if we fail to destroy a key slot, but it's a
                    // security risk, so we should log it. We panic in debug builds.
                    debug_assert!(false, "Failed to remove old keyslot {key_slot}: {err:?}",);
                    warn!("Failed to remove old keyslot {key_slot}: {err:?}",)
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inactive_keyslot(slot: u32) -> KeyslotParameters {
        KeyslotParameters {
            slot,
            status: KeyslotInfo::Inactive,
            pbkdf_type: None,
            pbkdf_iterations: None,
            cipher: None,
            key_size: None,
        }
    }

    fn active_keyslot(slot: u32) -> KeyslotParameters {
        KeyslotParameters {
            slot,
            status: KeyslotInfo::Active,
            pbkdf_type: Some(PBKDF_TYPE),
            pbkdf_iterations: Some(PBKDF_ITERATIONS),
            cipher: Some(format!("{CIPHER}-{CIPHER_MODE}")),
            key_size: Some(KEYSLOT_KEY_BYTES),
        }
    }

    fn valid_luks_parameters() -> LuksParameters {
        LuksParameters {
            format: ENCRYPTION_FORMAT,
            cipher: CIPHER.to_string(),
            cipher_mode: CIPHER_MODE.to_string(),
            volume_key_size: VOLUME_KEY_BYTES,
            keyslots: vec![active_keyslot(0), inactive_keyslot(1)],
        }
    }

    #[test]
    fn verify_luks_parameters_accepts_expected_parameters() {
        verify_luks_parameters(&valid_luks_parameters()).unwrap();
    }

    #[test]
    fn verify_luks_parameters_accepts_argon2id_keyslot() {
        let mut luks_parameters = valid_luks_parameters();
        luks_parameters.keyslots[0].pbkdf_type = Some(CryptKdf::Argon2Id);

        verify_luks_parameters(&luks_parameters).unwrap();
    }

    #[test]
    fn verify_luks_parameters_accepts_invalid_keyslot() {
        let mut luks_parameters = valid_luks_parameters();
        luks_parameters.keyslots[0].status = KeyslotInfo::Invalid;

        verify_luks_parameters(&luks_parameters).unwrap();
    }

    #[test]
    fn verify_luks_parameters_rejects_unexpected_format() {
        let mut luks_parameters = valid_luks_parameters();
        luks_parameters.format = EncryptionFormat::Plain;

        let err = verify_luks_parameters(&luks_parameters).unwrap_err();

        assert!(format!("{err:#}").contains("Unexpected encryption format"));
    }
}
