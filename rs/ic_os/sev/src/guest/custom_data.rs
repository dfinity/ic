use thiserror::Error;

/// Namespaces for SEV custom data. Namespacing ensures that an attestation report for generated
/// for one purpose won't be accidentally or maliciously used for another purpose.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SevCustomDataNamespace {
    // Reassigning/reusing integer values between namespaces may break backward compatibility.
    // The enum variants can be renamed as long as the semantics remain.
    /// Can be used in tests.
    Test = u32::MAX,
    /// Unused. Default custom data is [0; 64], so it should not be a valid namespace.
    DoNotUse = 0,
    /// Raw custom data for remote attestation. Clients can send an arbitrary byte array starting
    /// with the namespace.
    RawRemoteAttestation = 1,
    /// Custom data for disk encryption key exchange during GuestOS upgrades.
    GetDiskEncryptionKeyToken = 2,
}

impl SevCustomDataNamespace {
    pub fn as_bytes(&self) -> [u8; 4] {
        (*self as u32).to_le_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevCustomData {
    pub namespace: SevCustomDataNamespace,
    pub data: [u8; 60],
}

impl SevCustomData {
    /// Constructs a `SevCustomData` from the given `namespace` and `data`.
    pub fn new(namespace: SevCustomDataNamespace, data: [u8; 60]) -> Self {
        Self { namespace, data }
    }

    /// Generates a random `SevCustomData` with the given `namespace`.
    pub fn random(namespace: SevCustomDataNamespace, rng: &mut impl rand::Rng) -> Self {
        let mut data = [0u8; 60];
        rng.fill(&mut data[..]);
        Self { namespace, data }
    }

    /// Checks that `data` starts with `namespace.as_bytes()` and if so, constructs a
    /// `SevCustomData` from it.
    pub fn from_namespaced_data(
        namespace: SevCustomDataNamespace,
        data: [u8; 64],
    ) -> Result<Self, InvalidNamespace> {
        let data = data
            .strip_prefix(&namespace.as_bytes())
            .ok_or(InvalidNamespace)?;
        Ok(Self {
            namespace,
            data: data.try_into().unwrap(),
        })
    }

    /// Returns the raw bytes of the custom data which can be passed to the SEV firmware for use in
    /// attestation report generation.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..4].copy_from_slice(&self.namespace.as_bytes());
        result[4..].copy_from_slice(&self.data);
        result
    }
}

#[derive(Error, Debug)]
#[error("Invalid SEV custom data namespace")]
pub struct InvalidNamespace;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_raw_custom_data_is_preserved() {
        let data = [
            1, 0, 0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
        ];
        let custom_data =
            SevCustomData::from_namespaced_data(SevCustomDataNamespace::RawRemoteAttestation, data)
                .unwrap();
        assert_eq!(custom_data.to_bytes(), data);
    }

    #[test]
    fn test_error_on_invalid_namespace() {
        let data = [
            // Invalid namespace (42)
            42, 0, 0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
        ];
        assert!(
            SevCustomData::from_namespaced_data(SevCustomDataNamespace::RawRemoteAttestation, data)
                .is_err()
        );
    }
}
