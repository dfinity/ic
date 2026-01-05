use der::Encode;
use std::error::Error;
use std::fmt::Debug;
use thiserror::Error;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SevCustomDataNamespace {
    // Reassigning/reusing integer values between namespaces may break backward compatibility.
    // The enum variants can be renamed as long as the semantics remain.
    Test = u32::MAX,
    DoNotUse = 0, // Default custom data is [0; 64], it should not be a valid namespace
    RawRemoteAttestation = 1,
    GetDiskEncryptionKeyToken = 2,
}

impl SevCustomDataNamespace {
    pub fn as_bytes(&self) -> [u8; 4] {
        (*self as u32).to_le_bytes()
    }
}

#[derive(Debug, Error)]
#[error("EncodingError({0})")]
pub struct EncodingError(#[from] pub Box<dyn Error + Send + Sync>);

/// A trait for types that can be encoded into a 64-byte array suitable for use as SEV custom data.
/// It's important that the encoding is deterministic and does not change between versions or
/// environments.
pub trait EncodeSevCustomData {
    /// Encodes the struct into a SevCustomData object for use as SEV custom data.
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError>;

    /// Encodes the struct into a legacy 64-byte array for use as SEV custom data.
    #[deprecated = "Should only be used for verifying potentially old clients"]
    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError>;
}

pub trait DerEncodedCustomData: Encode {
    fn namespace(&self) -> SevCustomDataNamespace;
}

// /// Wrapper to implement `EncodeSevCustomData` for all types that implement `der::Encode`
// ///
// /// DER is a well-defined, stable encoding format. We apply the also stable SHA-512 hash function to
// /// the output of the DER encoding to produce a 64-byte array.
// ///
// /// This makes it easy to make a type suitable for SEV custom data by annotating it with
// /// `#[derive(der::Sequence)]`.
// pub struct DerEncodedCustomData<T>(pub T);

impl<T: DerEncodedCustomData> EncodeSevCustomData for T {
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        // Take first 60 bytes of SHA-512 hash
        let hash = ring::digest::digest(&ring::digest::SHA512, &encoded);
        Ok(SevCustomData::new(
            self.namespace(),
            hash.as_ref()[..60].try_into().unwrap(),
        ))
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        let hash = ring::digest::digest(&ring::digest::SHA512, &encoded);
        Ok(hash.as_ref().try_into().unwrap())
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
        if data[0..4] != namespace.as_bytes() {
            return Err(InvalidNamespace);
        }
        Ok(Self {
            namespace,
            data: data[4..].try_into().unwrap(),
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

impl EncodeSevCustomData for SevCustomData {
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError> {
        Ok(*self)
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        Ok(self.to_bytes())
    }
}

#[derive(Error, Debug)]
#[error("Invalid namespace")]
pub struct InvalidNamespace;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_raw_custom_data() {
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
}
