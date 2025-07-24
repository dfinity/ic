use crate::guest::firmware::SevGuestFirmware;
use anyhow::Context;
use anyhow::Result;
// use base64::{engine::general_purpose::STANDARD, Engine as _};
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

pub struct SevKeyDeriver {
    sev_firmware: Box<dyn SevGuestFirmware>,
}

impl SevKeyDeriver {
    pub fn new() -> Result<Self> {
        Ok(Self {
            sev_firmware: Box::new(Firmware::open().context("Could not open SEV firmware")?),
        })
    }

    pub fn new_for_test(sev_firmware: Box<dyn SevGuestFirmware>) -> Self {
        Self { sev_firmware }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Encrypted var partition, private to the current GuestOS version.
    VarPartitionEncryptionKey,
    /// Encrypted store partition, shared between GuestOS releases.
    StorePartitionEncryptionKey,
}

impl Key {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Key::VarPartitionEncryptionKey => b"ic-disk-encryption-key/var",
            Key::StorePartitionEncryptionKey => b"ic-disk-encryption-key/store",
        }
    }
}

impl SevKeyDeriver {
    pub fn derive_key(&mut self, key: Key) -> Result<Vec<u8>> {
        let mut field_select = GuestFieldSelect::default();
        // TODO: review this
        field_select.set_measurement(true);

        let derived_key = self
            .sev_firmware
            .get_derived_key(Some(1), DerivedKey::new(false, field_select, 0, 0, 0))
            .context("Failed to get derived key from SEV firmware")?;

        Ok("abcdef".to_string().into_bytes())
        //
        // let derived_key = [32; 32];
        //
        // let mut key = vec![];
        // key.extend(derived_key);
        // let domain = format!("ic-disk-encryption-key/{}", partition.name()).into_bytes();
        // key.push(domain.len().try_into().expect("Domain too long"));
        // key.extend(domain);
        //
        // let digest = ring::digest::digest(&ring::digest::SHA256, &key);
        // Ok(STANDARD.encode(digest.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use sev::firmware::guest::Firmware;

    #[test]
    fn test_get_disk_encryption_key() {
        // Mock a Firmware instance, or use a suitable framework for mocking where possible
        // let firmware = Firmware::default(); // Assuming default implementation exists for testing
        // let mut key_provider = DiskEncryptionKeyProvider { sev_firmware: firmware };
        let key_provider = SevKeyDeriver::new().unwrap();

        let key_result = key_provider.derive_key(Partition::Store);

        assert!(
            key_result.is_ok(),
            "Expected the key result to be Ok, got Err: {:?}",
            key_result.err()
        );

        let key = key_result.unwrap();
        println!("Derived key: {}", key);
        assert!(!key.is_empty(), "Derived key should not be empty");
        assert_eq!(key.len(), 44, "Derived key length mismatch"); // Adjust this condition if the result's length is different
    }
}
