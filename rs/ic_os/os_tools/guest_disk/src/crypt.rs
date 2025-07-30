use anyhow::{bail, Context, Result};
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::{CryptKdf, EncryptionFormat, KeyslotInfo};
use libcryptsetup_rs::{
    CryptDevice, CryptInit, CryptParamsLuks2Ref, CryptSettingsHandle, LibcryptErr,
};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct FormatOptions {
    /// If true, the device will be formatted if it isn't LUKS2.
    pub allow_if_uninit: bool,
    /// If true, the device will be formatted if activation fails with the provided passphrase.
    pub allow_if_cannot_activate: bool,
}

/// Initializes a cryptographic device at the specified path with LUKS2 format and activates it
/// using the provided name and passphrase.
/// Depending on the `format_options`, it may format the device if it is uninitialized or if
/// activation fails.
pub fn activate_crypt_device(
    device_path: &Path,
    name: &str,
    passphrase: &[u8],
    format_options: FormatOptions,
) -> Result<CryptDevice> {
    if !device_path.exists() {
        bail!("Device does not exist: {}", device_path.display());
    }

    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;

    let load_result = crypt_device
        .context_handle()
        .load::<CryptParamsLuks2Ref>(Some(EncryptionFormat::Luks2), None);

    let mut formatted = false;
    if let Err(err) = load_result {
        if format_options.allow_if_uninit {
            println!("Device is uninitialized, formatting it with LUKS2");
            format_and_init(&mut crypt_device, passphrase)
                .context("Failed to format and initialize cryptographic device")?;
            formatted = true;
        } else {
            return Err(err).context("Failed to load cryptographic context");
        }
    }

    if let Err(err) = activate(&mut crypt_device, name, passphrase) {
        // If the device was just formatted, don't try to format it again.
        if formatted {
            return Err(err).context(format!(
                "Failed to activate cryptographic device {} with the provided passphrase after \
                 formatting (should never happen)",
                device_path.display()
            ));
        }

        // If we are not allowed to format the device after activation failure, return the error.
        if !format_options.allow_if_cannot_activate {
            return Err(err).context(format!(
                "Failed to activate cryptographic device {}",
                device_path.display()
            ));
        }

        println!("Failed to activate device with the provided passphrase, will try to format it");
        crypt_device = CryptInit::init(device_path)
            .context("Failed to reinitialize cryptographic device after activation failure")?;
        format_and_init(&mut crypt_device, device_path, passphrase).context(
            "Failed to format and initialize cryptographic device after activation failure",
        )?;
        activate(&mut crypt_device, name, passphrase)
            .context("Failed to activate cryptographic device after formatting")?;
    }

    Ok(crypt_device)
}

pub fn format_crypt_device(
    device_path: &Path,
    passphrase: &[u8],
    activate_name: Option<&str>,
) -> Result<CryptDevice> {
    let mut crypt_device =
        CryptInit::init(device_path).context("Failed to initialize cryptographic device")?;
    println!(
        "Formatting {} with LUKS2 and initializing it with a passphrase",
        device_path.display()
    );
    format_and_init(&mut crypt_device, passphrase)
        .context("Failed to format and initialize cryptographic device")?;

    if let Some(name) = activate_name {
        activate(&mut crypt_device, name, passphrase)
            .context("Failed to activate cryptographic device after formatting")?;
    }

    Ok(crypt_device)
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

/// Checks if the provided passphrase can activate the cryptographic device at the given path.
pub fn check_passphrase(device_path: &Path, passphrase: &[u8]) -> Result<()> {
    let mut crypt_device = open_luks2_device(device_path).context("Failed to open LUKS2 device")?;

    crypt_device
        .activate_handle()
        .activate_by_passphrase(None, None, passphrase, CryptActivate::empty())
        .context("Failed to activate device")?;

    Ok(())
}

/// Destroys all key slots in the cryptographic device except for the one that is activated with the
/// provided passphrase.
pub fn destroy_key_slots_except(crypt_device: &mut CryptDevice, keep: &[u8]) -> Result<()> {
    // LUKS2 supports up to 32 key slots.
    const LUKS2_N_KEY_SLOTS: u32 = 32;

    let key_slot_to_keep = crypt_device
        .activate_handle()
        .activate_by_passphrase(None, None, &keep, CryptActivate::empty())
        .context("Cannot activate device with passphrase that we should keep")?;

    for key_slot in 0..LUKS2_N_KEY_SLOTS {
        if key_slot != key_slot_to_keep {
            if matches!(
                crypt_device.keyslot_handle().status(key_slot),
                Ok(KeyslotInfo::Active)
            ) {
                let _ = crypt_device
                    .keyslot_handle()
                    .destroy(key_slot)
                    .inspect_err(|err| {
                        debug_assert!(false, "Failed to remove old keyslot {key_slot}: {err:?}",);
                        eprintln!("Failed to remove old keyslot {key_slot}: {err:?}",)
                    });
            }
        }
    }
    Ok(())
}

/// Activates the given cryptographic device using the specified name and key.
fn activate(crypt_device: &mut CryptDevice, name: &str, key: &[u8]) -> Result<()> {
    crypt_device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, key, CryptActivate::empty())
        .context("Could not activate partition")?;
    Ok(())
}

/// Formats the given cryptographic device with LUKS2 and initializes it with the provided passphrase.
/// WARNING: Leads to data loss on the device!
fn format_and_init(crypt_device: &mut CryptDevice, passphrase: &[u8]) -> Result<()> {
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
            Right(512 / 8), // 512 bits
            None,
        )
        .context("Failed to call format")?;
    crypt_device
        .keyslot_handle()
        .add_by_key(None, None, passphrase, CryptVolumeKey::empty())
        .context("Could not add key to partition")?;
    Ok(())
}
