use anyhow::{Context, Result};
use itertools::Either::Right;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::EncryptionFormat;
use libcryptsetup_rs::{CryptInit, CryptParamsLuks2Ref};
use std::path::Path;

pub fn activate(device: &Path, key: &[u8]) -> Result<()> {
    let mut crypt = CryptInit::init(device)?;
    crypt
        .activate_handle()
        .activate_by_passphrase(Some("var_crypt"), None, key, CryptActivate::empty())
        .context("Could not activate partition with passphrase")?;
    Ok(())
}

pub fn format(device: &Path, key: &[u8]) -> Result<()> {
    let mut crypt = CryptInit::init(device)?;
    crypt
        .format_handle()
        .get_type()
        .context("Could not get device format type")?
        == EncryptionFormat::Luks2;
    crypt.context_handle().format::<CryptParamsLuks2Ref>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain64"),
        None,
        Right(16),
        None,
    )?;
    crypt
        .keyslot_handle()
        .add_by_key(None, None, key, CryptVolumeKey::empty())
        .context("Could not add key to partition")?;
    Ok(())
}

pub fn is_luks2(device: &Path) -> Result<bool> {
    let mut crypt = CryptInit::init(device)?;
    let format = crypt
        .format_handle()
        .get_type()
        .context("Could not get device format type")?;
    Ok(format == EncryptionFormat::Luks2)
}
