use der::Encode;
use ic_sev::guest::custom_data::SevCustomData;
use std::error::Error;
use std::fmt::Debug;
use thiserror::Error;

// Re-export SevCustomDataNamespace so DerEncodedCustomData implementors don't need to directly
// depend on the ic_sev crate.
pub use ic_sev::guest::custom_data::SevCustomDataNamespace;

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

        let hash = ring::digest::digest(&ring::digest::SHA256, &encoded);
        let hash_bytes: [u8; 32] = hash
            .as_ref()
            .try_into()
            .expect("SHA-256 hash should be 32 bytes");

        Ok(SevCustomData::new(self.namespace(), hash_bytes))
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        let hash = ring::digest::digest(&ring::digest::SHA512, &encoded);
        Ok(hash.as_ref().try_into().unwrap())
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
