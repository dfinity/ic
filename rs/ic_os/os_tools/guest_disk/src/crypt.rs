use anyhow::{Context, Result, bail};
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle};
use libcryptsetup_rs::{CryptTokenInfo, TokenInput};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Number of bytes to use for the LUKS2 volume key
const VOLUME_KEY_BYTES: usize = 512 / 8; // 512 bits

/// LUKS2 token type identifier for our key slot metadata.
const IC_KEY_TOKEN_TYPE: &str = "ic-key-metadata";

/// LUKS2 supports up to 32 key slots.
const LUKS2_N_KEY_SLOTS: u32 = 32;

/// LUKS2 supports up to 32 tokens.
const LUKS2_N_TOKENS: u32 = 32;

/// Metadata stored as a LUKS2 token for each key slot. Records the parameters
/// that were used to derive the encryption key in that slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySlotMetadata {
    /// LUKS2 token type — must be set to [`IC_KEY_TOKEN_TYPE`].
    #[serde(rename = "type")]
    pub token_type: String,
    /// Key slots this token is associated with (LUKS2 requires this field).
    pub keyslots: Vec<String>,
    /// GuestOS version string (e.g. the content of `/opt/ic/share/version.txt`).
    pub guestos_version: String,
    /// Hex-encoded SEV launch measurement (48 bytes → 96 hex chars).
    pub measurement: String,
    /// TCB version (raw `u64`, little-endian AMD SEV-SNP ABI layout) used for key derivation.
    pub tcb_version: u64,
}

impl KeySlotMetadata {
    pub fn new(
        keyslot: u32,
        guestos_version: String,
        measurement: &[u8],
        tcb_version: u64,
    ) -> Self {
        Self {
            token_type: IC_KEY_TOKEN_TYPE.to_string(),
            keyslots: vec![keyslot.to_string()],
            guestos_version,
            measurement: hex::encode(measurement),
            tcb_version,
        }
    }

    /// Returns the TCB version as a raw `u64`.
    pub fn tcb(&self) -> u64 {
        self.tcb_version
    }
}

/// Initializes a cryptographic device at the specified path with LUKS2 format and activates it
/// using the provided name and encryption key.
///
/// Returns the `CryptDevice` and the key slot number that was used for activation.
pub fn activate_crypt_device(
    device_path: &Path,
    name: &str,
    encryption_key: &[u8],
    flags: CryptActivate,
) -> Result<(CryptDevice, u32)> {
    if !device_path.exists() {
        bail!("Device does not exist: {}", device_path.display());
    }

    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;

    crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(EncryptionFormat::Luks2), None)
        .context("Failed to load cryptographic context")?;

    let keyslot = crypt_device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, encryption_key, flags)
        .context("Failed to activate cryptographic device")?;

    Ok((crypt_device, keyslot))
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
    encryption_key: &[u8],
) -> Result<(CryptDevice, u32)> {
    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;
    println!(
        "Formatting {} with LUKS2 and initializing it with an encryption key",
        device_path.display()
    );
    // TODO: We should revisit the use of Pbkdf2 and consider using the LUKS2 default KDF, Argon2i
    let mut pbkdf_params = CryptSettingsHandle::get_pbkdf_type_params(&CryptKdf::Pbkdf2)
        .context("Failed to get PBKDF2 params")?;
    // Set minimal iteration count -- we already use a random key with
    // maximal entropy, pbkdf doesn't gain anything (besides slowing
    // down boot by a couple seconds which needlessly annoys for testing).
    pbkdf_params.iterations = 1000;
    crypt_device
        .settings_handle()
        .set_pbkdf_type(&pbkdf_params)
        .context("Failed to set PBKDF2 type")?;
    crypt_device
        .context_handle()
        .format::<CryptParamsLuks2Ref>(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            Right(VOLUME_KEY_BYTES),
            None,
        )
        .context("Failed to call format")?;
    let keyslot = crypt_device
        .keyslot_handle()
        .add_by_key(None, None, encryption_key, CryptVolumeKey::empty())
        .context("Could not add key to cryptographic device")?;

    Ok((crypt_device, keyslot))
}

/// Opens a LUKS2 device at the specified path and loads its context.
pub fn open_luks2_device(device_path: &Path) -> Result<CryptDevice> {
    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;

    crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(EncryptionFormat::Luks2), None)?;

    Ok(crypt_device)
}

/// Checks if the provided encryption key can activate the cryptographic device at the given path.
/// Does not activate the device.
pub fn check_encryption_key(device_path: &Path, encryption_key: &[u8]) -> Result<()> {
    let mut crypt_device = open_luks2_device(device_path).context("Failed to open LUKS2 device")?;

    crypt_device
        .activate_handle()
        .activate_by_passphrase(None, None, encryption_key, CryptActivate::empty())
        .context("Failed to activate device")?;

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
                Ok(KeyslotInfo::Active)
            )
        {
            match crypt_device.keyslot_handle().destroy(key_slot) {
                Ok(_) => {
                    println!("Destroyed old key slot {key_slot}");
                }
                Err(err) => {
                    // It's not a critical error if we fail to destroy a key slot, but it's a
                    // security risk, so we should log it. We panic in debug builds.
                    debug_assert!(false, "Failed to remove old keyslot {key_slot}: {err:?}",);
                    eprintln!("Failed to remove old keyslot {key_slot}: {err:?}",)
                }
            }
        }
    }
    Ok(())
}

/// Reads all IC SEV key-slot metadata tokens from a LUKS2 device.
pub fn read_key_slot_metadata(crypt_device: &mut CryptDevice) -> Result<Vec<KeySlotMetadata>> {
    let mut result = Vec::new();
    let mut token_handle = crypt_device.token_handle();
    for token_id in 0..LUKS2_N_TOKENS {
        let status = token_handle.status(token_id);
        match status {
            Ok(CryptTokenInfo::External(ref t)) | Ok(CryptTokenInfo::ExternalUnknown(ref t))
                if t == IC_KEY_TOKEN_TYPE =>
            {
                match token_handle.json_get(token_id) {
                    Ok(json) => {
                        let meta: KeySlotMetadata = serde_json::from_value(json)
                            .context("Failed to parse IC SEV token metadata")?;
                        result.push(meta);
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to read token {token_id}: {e:?}");
                    }
                }
            }
            _ => {}
        }
    }
    Ok(result)
}

/// Writes a key-slot metadata token to a LUKS2 device for the given key slot.
///
/// If a token of our type already exists for this key slot, it is replaced.
/// This enforces a 1:1 relationship between tokens and key slots.
pub fn write_key_slot_metadata(
    crypt_device: &mut CryptDevice,
    metadata: &KeySlotMetadata,
    keyslot: u32,
) -> Result<()> {
    // Remove any existing token for this keyslot first.
    remove_key_slot_metadata(crypt_device, keyslot)?;

    let json = serde_json::to_value(metadata).context("Failed to serialize key slot metadata")?;
    let mut token_handle = crypt_device.token_handle();
    let token_id = token_handle
        .json_set(TokenInput::AddToken(&json))
        .context("Failed to write LUKS2 token")?;
    token_handle
        .assign_keyslot(token_id, Some(keyslot))
        .context("Failed to assign token to key slot")?;
    Ok(())
}

/// Removes the IC key-slot metadata token associated with a specific key slot.
pub fn remove_key_slot_metadata(crypt_device: &mut CryptDevice, keyslot: u32) -> Result<()> {
    let keyslot_str = keyslot.to_string();
    let mut token_handle = crypt_device.token_handle();
    for token_id in 0..LUKS2_N_TOKENS {
        let status = token_handle.status(token_id);
        match status {
            Ok(CryptTokenInfo::External(ref t)) | Ok(CryptTokenInfo::ExternalUnknown(ref t))
                if t == IC_KEY_TOKEN_TYPE =>
            {
                if let Ok(json) = token_handle.json_get(token_id) {
                    if let Ok(meta) = serde_json::from_value::<KeySlotMetadata>(json) {
                        if meta.keyslots.contains(&keyslot_str) {
                            if let Err(e) = token_handle.json_set(TokenInput::RemoveToken(token_id))
                            {
                                eprintln!("Warning: failed to remove token {token_id}: {e:?}");
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Removes all IC key-slot metadata tokens from a LUKS2 device.
pub fn remove_all_key_slot_metadata(crypt_device: &mut CryptDevice) -> Result<()> {
    let mut token_handle = crypt_device.token_handle();
    for token_id in 0..LUKS2_N_TOKENS {
        let status = token_handle.status(token_id);
        match status {
            Ok(CryptTokenInfo::External(ref t)) | Ok(CryptTokenInfo::ExternalUnknown(ref t))
                if t == IC_KEY_TOKEN_TYPE =>
            {
                if let Err(e) = token_handle.json_set(TokenInput::RemoveToken(token_id)) {
                    eprintln!("Warning: failed to remove token {token_id}: {e:?}");
                }
            }
            _ => {}
        }
    }
    Ok(())
}
