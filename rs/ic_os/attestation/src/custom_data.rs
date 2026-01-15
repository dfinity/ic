use der::Encode;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("EncodingError({0})")]
pub struct EncodingError(#[from] pub Box<dyn Error + Send + Sync>);

/// A trait for types that can be encoded into a 64-byte array suitable for use as SEV custom data.
/// It's important that the encoding is deterministic and does not change between versions or
/// environments.
pub trait EncodeSevCustomData {
    fn encode_for_sev(&self) -> Result<[u8; 64], EncodingError>;
}

/// Wrapper to implement `EncodeSevCustomData` for all types that implement `der::Encode`
///
/// DER is a well-defined, stable encoding format. We apply the also stable SHA-512 hash function to
/// the output of the DER encoding to produce a 64-byte array.
///
/// This makes it easy to make a type suitable for SEV custom data by annotating it with
/// `#[derive(der::Sequence)]`.
pub struct DerEncodedCustomData<T>(pub T);

impl<T: Encode> EncodeSevCustomData for DerEncodedCustomData<T> {
    fn encode_for_sev(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.0
            .encode(&mut encoded)
            .map_err(|err| EncodingError(Box::new(err)))?;

        let hash = ring::digest::digest(&ring::digest::SHA512, &encoded);
        Ok(hash.as_ref().try_into().unwrap())
    }
}

impl<T: Debug> Debug for DerEncodedCustomData<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A simple implementation of `EncodeSevCustomData` that directly uses a raw 64-byte array.
#[derive(Clone, Copy)]
pub struct RawCustomData(pub [u8; 64]);

impl EncodeSevCustomData for RawCustomData {
    fn encode_for_sev(&self) -> Result<[u8; 64], EncodingError> {
        Ok(self.0)
    }
}

impl Debug for RawCustomData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
