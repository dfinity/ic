pub mod api;
pub mod custom_data;
pub mod registry;
pub mod server;
pub mod sev_status;
pub mod tls;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sev::firmware::guest::GuestFieldSelect;

pub struct DiskEncryptionKeyProvider {
    // sev_firmware: Firmware,
}

impl DiskEncryptionKeyProvider {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            // sev_firmware: Firmware::open()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Partition {
    /// Encrypted var partition, private to the current GuestOS version.
    Var,
    /// Encrypted store partition, shared between GuestOS releases.
    Store,
}

impl Partition {
    fn name(&self) -> &str {
        // The name must be max. 200 bytes
        match self {
            Self::Var => "var",
            Self::Store => "store",
        }
    }
}

impl DiskEncryptionKeyProvider {
    pub fn get_disk_encryption_key(&self, partition: Partition) -> anyhow::Result<String> {
        let mut field_select = GuestFieldSelect::default();
        // TODO: review this
        field_select.set_measurement(true);

        // let derived_key = self
        //     .sev_firmware
        //     .get_derived_key(Some(1), DerivedKey::new(false, field_select, 0, 0, 0))?;
        let derived_key = [32; 32];

        let mut key = vec![];
        key.extend(derived_key);
        let domain = format!("ic-disk-encryption-key/{}", partition.name()).into_bytes();
        key.push(domain.len().try_into().expect("Domain too long"));
        key.extend(domain);

        let digest = ring::digest::digest(&ring::digest::SHA256, &key);
        Ok(STANDARD.encode(digest.as_ref()))
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
        let key_provider = DiskEncryptionKeyProvider::new().unwrap();

        let key_result = key_provider.get_disk_encryption_key(Partition::Store);

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
