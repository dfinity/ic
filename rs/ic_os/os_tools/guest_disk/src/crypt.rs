use crate::metrics::export_luks_parameters;
use anyhow::{Context, Result, bail, ensure};
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle};
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

/// Initializes a cryptographic device at the specified path with LUKS2 format and activates it
/// using the provided name and encryption key.
pub fn activate_crypt_device(
    device_path: &Path,
    name: &str,
    encryption_key: &[u8],
    flags: CryptActivate,
    verify_luks_params: bool,
    metrics_file: Option<&Path>,
) -> Result<CryptDevice> {
    if !device_path.exists() {
        bail!("Device does not exist: {}", device_path.display());
    }

    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;

    crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(ENCRYPTION_FORMAT), None)
        .context("Failed to load cryptographic context")?;

    maybe_verify_luks_parameters(&mut crypt_device, device_path, verify_luks_params)?;

    let active_keyslot = crypt_device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, encryption_key, flags)
        .context("Failed to activate cryptographic device")?;

    if let Some(metrics_file) = metrics_file {
        let log_result =
            export_luks_parameters(metrics_file, &mut crypt_device, device_path, active_keyslot);
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
pub fn format_crypt_device(device_path: &Path, encryption_key: &[u8]) -> Result<CryptDevice> {
    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;
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

/// Opens a LUKS2 device at the specified path and loads its context.
fn open_luks2_device(device_path: &Path, verify_luks_params: bool) -> Result<CryptDevice> {
    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;

    crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(ENCRYPTION_FORMAT), None)?;

    maybe_verify_luks_parameters(&mut crypt_device, device_path, verify_luks_params)?;

    Ok(crypt_device)
}

/// Checks if the provided encryption key can activate the cryptographic device at the given path.
/// Does not activate the device.
pub fn check_encryption_key(device_path: &Path, encryption_key: &[u8]) -> Result<()> {
    // This method simply checks if the key works, we don't care about LUKS parameters
    let mut crypt_device = open_luks2_device(device_path, /*verify_luks_params=*/ false)
        .context("Failed to open LUKS2 device")?;

    crypt_device
        .activate_handle()
        .activate_by_passphrase(None, None, encryption_key, CryptActivate::empty())
        .context("Failed to activate device")?;

    Ok(())
}

fn maybe_verify_luks_parameters(
    crypt_device: &mut CryptDevice,
    device_path: &Path,
    verify_luks_params: bool,
) -> Result<()> {
    if let Err(e) = verify_luks_parameters(crypt_device) {
        if verify_luks_params {
            return Err(e);
        }

        warn!(
            "LUKS parameters verification failed for device {} but verification is not \
            enforced: {e:#}",
            device_path.display()
        );
    } else {
        info!(
            "LUKS parameters verification succeeded for device {}",
            device_path.display()
        );
    }

    Ok(())
}

/// Verifies that the LUKS parameters match the expected values set in format_crypt_device
pub(crate) fn verify_luks_parameters(crypt_device: &mut CryptDevice) -> Result<()> {
    let format = crypt_device
        .format_handle()
        .get_type()
        .context("Failed to get encryption format")?;
    ensure!(format == ENCRYPTION_FORMAT, "Unexpected encryption format");

    let mut status_handle = crypt_device.status_handle();
    let cipher = status_handle.get_cipher().context("Failed to get cipher")?;
    ensure!(cipher == CIPHER, "Unexpected cipher: {}", cipher);

    let cipher_mode = status_handle
        .get_cipher_mode()
        .context("Failed to get cipher mode")?;
    ensure!(
        cipher_mode == CIPHER_MODE,
        "Unexpected cipher mode: {}",
        cipher_mode
    );

    let volume_key_size = status_handle.get_volume_key_size();
    ensure!(
        volume_key_size == VOLUME_KEY_BYTES as std::os::raw::c_int,
        "Unexpected volume key size: {}",
        volume_key_size
    );

    let mut active_keyslots = 0;
    let mut keyslot_handle = crypt_device.keyslot_handle();
    for key_slot in 0..LUKS2_N_KEY_SLOTS {
        let status = keyslot_handle
            .status(key_slot)
            .with_context(|| format!("Failed to get status for keyslot {key_slot}"))?;

        match status {
            KeyslotInfo::Active | KeyslotInfo::ActiveLast => {
                active_keyslots += 1;

                let pbkdf = keyslot_handle
                    .get_pbkdf(key_slot)
                    .with_context(|| format!("Failed to get PBKDF type for keyslot {key_slot}"))?;
                ensure!(
                    pbkdf.type_ == PBKDF_TYPE,
                    "Unexpected keyslot PBKDF type: {:?}",
                    pbkdf.type_
                );

                let encryption = keyslot_handle
                    .get_encryption(Some(key_slot))
                    .with_context(|| format!("Failed to get encryption for keyslot {key_slot}"))?;

                ensure!(
                    encryption.0 == format!("{CIPHER}-{CIPHER_MODE}"),
                    "Unexpected keyslot encryption: {}",
                    encryption.0
                );
                ensure!(
                    encryption.1 == KEYSLOT_KEY_BYTES,
                    "Unexpected keyslot key size: {}",
                    encryption.1
                );
            }
            KeyslotInfo::Invalid | KeyslotInfo::Unbound => {
                bail!("Unexpected keyslot status for slot {key_slot}: {status:?}");
            }
            KeyslotInfo::Inactive => {}
        }
    }

    ensure!(active_keyslots > 0, "No active keyslots found");

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
