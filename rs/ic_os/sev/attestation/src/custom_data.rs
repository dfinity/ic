use der::Encode;
use sha2::{Digest, Sha256, Sha512};
use std::error::Error;
use std::fmt::Debug;
use thiserror::Error;

/// Namespaces for SEV custom data. Namespacing ensures that an attestation report generated
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
    /// Custom data for node registration attestation to prove its chip_id.
    NodeRegistration = 3,
    /// Custom data for verifying alternative GuestOS proposal.
    VerifyAlternativeGuestOsProposal = 4,
}

impl SevCustomDataNamespace {
    pub fn as_bytes(&self) -> [u8; 4] {
        (*self as u32).to_le_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevCustomData {
    pub namespace: SevCustomDataNamespace,
    pub data: [u8; 32],
}

impl SevCustomData {
    /// Constructs a `SevCustomData` from the given `namespace` and `data`.
    pub fn new(namespace: SevCustomDataNamespace, data: [u8; 32]) -> Self {
        Self { namespace, data }
    }

    /// Generates a random `SevCustomData` with the given `namespace`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn random(namespace: SevCustomDataNamespace, rng: &mut impl rand::Rng) -> Self {
        let mut data = [0u8; 32];
        rng.fill(&mut data[..]);
        Self { namespace, data }
    }

    /// Verifies that the given custom data (from an attestation report) matches this
    /// `SevCustomData`.
    pub fn verify(&self, custom_data_from_attestation_report: &[u8; 64]) -> bool {
        custom_data_from_attestation_report.starts_with(&self.namespace.as_bytes())
            && custom_data_from_attestation_report[32..] == self.data
    }

    /// Returns the raw bytes of the custom data which can be passed to the SEV firmware for use in
    /// attestation report generation.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..4].copy_from_slice(&self.namespace.as_bytes());
        result[32..].copy_from_slice(&self.data);
        result
    }
}

/// Alternative syntax for verifying attestation report custom data.
/// Allows direct comparison with a 64-byte long array using ==.
impl PartialEq<[u8; 64]> for SevCustomData {
    fn eq(&self, other: &[u8; 64]) -> bool {
        self.verify(other)
    }
}

#[derive(Debug, Error)]
#[error("EncodingError({0})")]
pub struct EncodingError(#[from] pub Box<dyn Error + Send + Sync>);

/// A trait for types that can be encoded into a `SevCustomData` struct for use as SEV custom data.
/// It's important that the encoding is deterministic and does not change between versions or
/// environments.
pub trait EncodeSevCustomData {
    /// Encodes the struct into a SevCustomData object for use as SEV custom data.
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError>;

    // TODO(NODE-1784): Remove encode_for_sev_legacy and needs_legacy_encoding after the migration to new
    // encoding is done.
    /// Encodes the struct into a legacy 64-byte array for use as SEV custom data.
    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError>;

    /// True if the type was available before the migration to new encoding.
    /// New types should not override this method and return false.
    fn needs_legacy_encoding() -> bool;
}

/// A trait for types that can be encoded into SEV custom data using DER encoding.
pub trait DerEncodedCustomData: Encode {
    fn namespace(&self) -> SevCustomDataNamespace;

    /// True if the type was available before the migration to new encoding.
    /// New types should not override this method and return false.
    fn needs_legacy_encoding() -> bool {
        false
    }
}

impl<T: DerEncodedCustomData> EncodeSevCustomData for T {
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        let hash_bytes: [u8; 32] = Sha256::digest(&encoded).into();

        Ok(SevCustomData::new(self.namespace(), hash_bytes))
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        let hash: [u8; 64] = Sha512::digest(&encoded).into();
        Ok(hash)
    }

    fn needs_legacy_encoding() -> bool {
        T::needs_legacy_encoding()
    }
}

impl EncodeSevCustomData for SevCustomData {
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError> {
        Ok(*self)
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        Ok(self.to_bytes())
    }

    fn needs_legacy_encoding() -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify() {
        let custom_data = SevCustomData::new(SevCustomDataNamespace::RawRemoteAttestation, [1; 32]);
        assert!(!custom_data.verify(&[1; 64]));
        assert!(custom_data.verify(&[
            // namespace
            1, 0, 0, 0, //
            // ignored
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            // data
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1
        ]));
        assert!(custom_data.verify(&[
            // namespace
            1, 0, 0, 0, //
            // ignored
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // data
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1
        ]));
    }

    #[test]
    fn test_to_bytes() {
        let custom_data = SevCustomData::new(SevCustomDataNamespace::RawRemoteAttestation, [1; 32]);
        assert_eq!(
            custom_data.to_bytes(),
            [
                // namespace
                1, 0, 0, 0, //
                // ignored (0s currently)
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                // data
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1
            ]
        );
    }

    #[test]
    fn test_equals() {
        let custom_data = SevCustomData::new(SevCustomDataNamespace::Test, [255; 32]);
        assert_eq!(custom_data, [255; 64]);
    }
}
