use crate::guest::firmware::SevGuestFirmware;
use anyhow::Context;
use anyhow::Result;
use hkdf::SimpleHkdf;
use sev::firmware::guest::{DerivedKey, GuestFieldSelect};
use sha2::Sha256;

/// A key derivation provider that uses the SEV firmware to derive keys.
pub struct SevKeyDeriver {
    sev_firmware: Box<dyn SevGuestFirmware>,
}

impl SevKeyDeriver {
    pub fn new() -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("SEV key derivation is only supported on Linux");
        }

        #[cfg(target_os = "linux")]
        Ok(Self {
            sev_firmware: Box::new(
                sev::firmware::guest::Firmware::open().context("Could not open SEV firmware")?,
            ),
        })
    }

    pub fn new_for_test(sev_firmware: Box<dyn SevGuestFirmware>) -> Self {
        Self { sev_firmware }
    }

    /// Derives a key for the given `Key` variant using the SEV firmware.
    /// The key is in base64 format (useful e.g., if the key must be entered manually).
    pub fn derive_key(&mut self, key: Key) -> Result<String> {
        let mut field_select = GuestFieldSelect::default();
        field_select.set_measurement(true);

        let derived_key = self
            .sev_firmware
            .get_derived_key(Some(1), DerivedKey::new(false, field_select, 0, 0, 0))
            .context("Failed to get derived key from SEV firmware")?;

        let mut output = vec![0; 32];
        // Should not be InvalidLength, since we hardcoded 32 bytes for the derived key length
        SimpleHkdf::<Sha256>::new(/*salt=*/ None, &derived_key)
            .expand_multi_info(key.as_info(), &mut output)
            .unwrap();

        Ok(base64::encode(&output))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::EnumIter)]
pub enum Key {
    /// Encrypted var partition
    VarPartitionEncryptionKey,
    /// Encrypted store partition
    StorePartitionEncryptionKey,
}

impl Key {
    fn as_info(&self) -> &[&[u8]] {
        match self {
            Key::VarPartitionEncryptionKey => &[b"ic-disk-encryption-key", b"var"],
            Key::StorePartitionEncryptionKey => &[b"ic-disk-encryption-key", b"store"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::firmware::MockSevGuestFirmware;
    use std::collections::HashSet;
    use strum::IntoEnumIterator;

    #[test]
    fn test_derives_key() {
        let mut mock_sev_guest_firmware = MockSevGuestFirmware::new();
        mock_sev_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));
        let mut key_provider = SevKeyDeriver::new_for_test(Box::new(mock_sev_guest_firmware));

        assert_eq!(
            key_provider
                .derive_key(Key::StorePartitionEncryptionKey)
                .unwrap(),
            // This value does not have any particular meaning, but it should not change
            // unless the key derivation algorithm changes.
            "bmZDYEiOUvevnLLaE+KyTcO2rKXIuAAc64OspcMTeYA="
        );
    }

    #[test]
    fn test_derives_unique_keys() {
        let mut mock_sev_guest_firmware = MockSevGuestFirmware::new();
        mock_sev_guest_firmware
            .expect_get_derived_key()
            .returning(|_, _| Ok([42; 32]));
        let mut key_provider = SevKeyDeriver::new_for_test(Box::new(mock_sev_guest_firmware));

        let all_keys = Key::iter()
            .map(|key| key_provider.derive_key(key).expect("Failed to derive key"))
            .collect::<HashSet<String>>();

        assert_eq!(all_keys.len(), Key::iter().count(), "Keys should be unique");
    }
}
