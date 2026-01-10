use der::Encode;
use ic_sev::guest::custom_data::SevCustomData;
use std::error::Error;
use std::fmt::Debug;
use thiserror::Error;

// Re-export SevCustomDataNamespace so DerEncodedCustomData implementors don't need to directly
// depend on the ic_sev crate.
pub use ic_sev::guest::custom_data::SevCustomDataNamespace;

/// Empty custom data for node registration attestation.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Default)]
pub struct NodeRegistrationAttestationCustomData;

impl Encode for NodeRegistrationAttestationCustomData {
    fn encoded_len(&self) -> der::Result<der::Length> {
        // Empty DER SEQUENCE: tag (1 byte) + length (1 byte) = 2 bytes total
        Ok(der::Length::new(2))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        // Encode as empty DER SEQUENCE: 0x30 (SEQUENCE tag) + 0x00 (zero length)
        encoder.write(&[0x30, 0x00])
    }
}

impl DerEncodedCustomData for NodeRegistrationAttestationCustomData {
    fn namespace(&self) -> SevCustomDataNamespace {
        SevCustomDataNamespace::NodeRegistration
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

/// A trait for types that can be encoded into SEV custom data using DER encoding.
pub trait DerEncodedCustomData: Encode {
    fn namespace(&self) -> SevCustomDataNamespace;
}

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

impl EncodeSevCustomData for SevCustomData {
    fn encode_for_sev(&self) -> Result<SevCustomData, EncodingError> {
        Ok(*self)
    }

    fn encode_for_sev_legacy(&self) -> Result<[u8; 64], EncodingError> {
        Ok(self.to_bytes())
    }
}
