use crate::guest::firmware::SevGuestFirmware;
use anyhow::Context;
use anyhow::Result;
use hkdf::SimpleHkdf;
use sev::firmware::guest::{DerivedKey, GuestFieldSelect};
use sha2::Sha256;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Derives a key for the given `Key` variant using the SEV firmware.
/// The key is in base64 format (useful e.g., if the key must be entered manually).
pub fn derive_key_from_sev_measurement(
    sev_firmware: &mut dyn SevGuestFirmware,
    key: Key,
) -> Result<String> {
    let mut field_select = GuestFieldSelect::default();
    field_select.set_measurement(true);

    let derived_key = sev_firmware
        .get_derived_key(Some(1), DerivedKey::new(false, field_select, 0, 0, 0, None))
        .context("Failed to get derived key from SEV firmware")?;

    let mut output = vec![0; 32];
    // Should not be InvalidLength, since we hardcoded 32 bytes for the derived key length
    SimpleHkdf::<Sha256>::new(/*salt=*/ None, &derived_key)
        .expand_multi_info(key.as_info().as_slice(), &mut output)
        .unwrap();

    Ok(base64::encode(&output))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key<'a> {
    DiskEncryptionKey { device_path: &'a Path },
}

impl Key<'_> {
    fn as_info(&self) -> [&[u8]; 2] {
        // change to Vec once necessary
        match self {
            Key::DiskEncryptionKey { device_path } => [
                b"ic-disk-encryption-key",
                device_path.as_os_str().as_bytes(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::firmware::MockSevGuestFirmware;
    use std::collections::HashSet;

    #[test]
    fn test_derives_key() {
        let mut mock_sev_guest_firmware = MockSevGuestFirmware::new();
        mock_sev_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));

        assert_eq!(
            derive_key_from_sev_measurement(
                &mut mock_sev_guest_firmware,
                Key::DiskEncryptionKey {
                    device_path: Path::new("/dev/vda8")
                }
            )
            .unwrap(),
            // This value does not have any particular meaning, but it should not change
            // unless the key derivation algorithm changes.
            "f0ap27QRjRgVHqeQBK8RO0GYHnSxYRLsgpJ8Ad3j/r8="
        );
    }

    #[test]
    fn test_derives_unique_keys() {
        let mut mock_sev_guest_firmware = MockSevGuestFirmware::new();
        mock_sev_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));

        let all_keys = (1..=10)
            .map(|i| {
                derive_key_from_sev_measurement(
                    &mut mock_sev_guest_firmware,
                    Key::DiskEncryptionKey {
                        device_path: Path::new(&format!("/dev/vda{i}")),
                    },
                )
                .unwrap()
            })
            .collect::<HashSet<String>>();

        assert_eq!(all_keys.len(), 10, "Keys should be unique");
    }
}
