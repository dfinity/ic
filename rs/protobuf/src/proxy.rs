//! A proxy for encoding arbitrary Rust structs in protocol buffer binary format
//! by means of a "proxy message" (a generated `prost::Message`) plus `Into` /
//! `TryInto` implementations to convert between the Rust struct and the proxy
//! message.
//!
//! The only major downside when compared to `serde` (which doesn't support
//! protocol buffers) or using a `prost`-generated struct directly is that (due
//! to `prost`-generated structs insisting on owning their data, e.g. using
//! `Vec<u8>` instead of `&[u8]`) is that encoding consumes the provided struct.
//!
//! # Example
//!
//! ```ignore
//! use pb;  // Module containing generated `prost::Message`.
//!
//! // Rust struct to be encoded/decoded.
//! struct Block {
//!     pub height: Height,
//!     pub contents: Blob,
//! }
//!
//! // To be provided by the client.
//! impl From<Block> for pb::Block {
//!     ...
//! }
//! impl TryFrom<pb::Block> for Block {
//!     ...
//! }
//!
//! let b = Block {
//!     height: Height(1),
//!     payload: Blob(vec![1, 2, 3]),
//! };
//!
//! // Encode.
//! let bytes: Vec<u8> = pb::Block::proxy_encode(b).unwrap();
//!
//! // Decode.
//! assert_eq!(
//!     Block {
//!         height: Height(1),
//!         payload: Blob(vec![1, 2, 3]),
//!     },
//!     pb::Block::proxy_decode(&bytes).unwrap()
//! );
//! ```

use prost::{DecodeError, EncodeError};
use std::convert::{Infallible, TryFrom, TryInto};
use std::error::Error;

#[cfg(test)]
mod tests;

/// Allows a `prost::Message` to act as a proxy for encoding and decoding a Rust
/// type `T`, as long as `Into` / `TryInto` implementations are provided to
/// convert from one to the other and back.
pub trait ProtoProxy<T> {
    /// Encodes `t` into a vector via this proxy.
    fn proxy_encode(t: T) -> Result<Vec<u8>, EncodeError>;

    /// Decodes a `T` from a slice via this proxy.
    fn proxy_decode(bytes: &[u8]) -> Result<T, ProxyDecodeError>;
}

impl<T, M> ProtoProxy<T> for M
where
    T: Into<M>,
    M: prost::Message + TryInto<T> + Default,
    M::Error: Into<ProxyDecodeError>,
{
    fn proxy_encode(t: T) -> Result<Vec<u8>, EncodeError> {
        let mut buf = vec![];
        t.into().encode(&mut buf).map(|()| buf)
    }

    fn proxy_decode(bytes: &[u8]) -> Result<T, ProxyDecodeError> {
        Self::decode(bytes)
            .map_err(ProxyDecodeError::DecodeError)?
            .try_into()
            .map_err(|e| e.into())
    }
}

/// Errors that may result when mapping a proto to a Rust struct.
#[derive(Debug)]
pub enum ProxyDecodeError {
    /// Protobuf message decoding error.
    DecodeError(DecodeError),

    /// CBOR message decoding error.
    CborDecodeError(Box<dyn Error + Sync + Send + 'static>),

    /// Required struct field missing from proto.
    MissingField(&'static str),

    /// Invalid value for type.
    ValueOutOfRange { typ: &'static str, err: String },

    /// Blob-to-`PrincipalId` parse error.
    InvalidPrincipalId(Box<dyn Error + Sync + Send + 'static>),

    /// Blob-to-`CanisterId` parse error.
    InvalidCanisterId(Box<dyn Error + Sync + Send + 'static>),

    /// Invalid `Digest` length.
    InvalidDigestLength { expected: usize, actual: usize },

    /// Invalid `MessageID`.
    InvalidMessageId { expected: usize, actual: usize },

    /// Replica version parsing error.
    ReplicaVersionParseError(Box<dyn Error + Sync + Send + 'static>),

    /// Duplicate map entry.
    DuplicateEntry { key: String, v1: String, v2: String },

    /// Generic error.
    Other(String),
}

impl ProxyDecodeError {
    /// Compares the wrapped source error (where applicable) with the given
    /// error.
    pub fn source_eq<T>(&self, other_err: T) -> bool
    where
        T: Error + Eq + 'static,
    {
        self.source()
            .map_or(false, |err| err.downcast_ref() == Some(&other_err))
    }
}

// Allows for Rust types that provide `impl Into<T> for <ProxyMessage>`
// (instead of `TryInto<T>`) to be proxied. Specifically, `prost::Messages` can
// proxy themselves.
impl From<Infallible> for ProxyDecodeError {
    fn from(i: Infallible) -> ProxyDecodeError {
        match i {}
    }
}

// TODO: remove when we have protobufs all the way down.
impl From<bincode::Error> for ProxyDecodeError {
    fn from(e: bincode::Error) -> ProxyDecodeError {
        Self::Other(e.to_string())
    }
}

impl std::fmt::Display for ProxyDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeError(err) => write!(f, "Protobuf decoding error: {}", err),
            Self::CborDecodeError(err) => write!(f, "CBOR decoding error: {}", err),
            Self::MissingField(name) => write!(f, "Missing required struct field: {}", name),
            Self::ValueOutOfRange { typ, err } => {
                write!(f, "Value out of range for type {}: {}", typ, err)
            }
            Self::InvalidPrincipalId(err) => write!(f, "{}", err),
            Self::InvalidCanisterId(err) => write!(f, "{}", err),
            Self::InvalidDigestLength { expected, actual } => write!(
                f,
                "Digest: expected a blob of length {}, got {}",
                expected, actual
            ),
            Self::InvalidMessageId { expected, actual } => write!(
                f,
                "MessageID: expected a blob of length {}, got {}",
                expected, actual
            ),
            Self::ReplicaVersionParseError(err) => write!(f, "{}", err),
            Self::DuplicateEntry { key, v1, v2 } => write!(
                f,
                "Entry {:?} repeats multiple times. Previous: {}, current: {}",
                key, v1, v2
            ),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

impl Error for ProxyDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DecodeError(err) => Some(err),
            Self::CborDecodeError(err) => Some(err.as_ref()),
            Self::InvalidPrincipalId(err) => Some(err.as_ref()),
            Self::InvalidCanisterId(err) => Some(err.as_ref()),
            Self::ReplicaVersionParseError(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

/// Converts an optional proto field into a Rust type using `From` / `TryFrom`.
/// Returns `Err(ProtoMappingError::MissingField(field))` if the field is
/// `None`.
pub fn try_from_option_field<F, T, E>(
    field: Option<F>,
    field_name: &'static str,
) -> Result<T, ProxyDecodeError>
where
    T: TryFrom<F, Error = E>,
    ProxyDecodeError: From<E>,
{
    Ok(T::try_from(
        field.ok_or(ProxyDecodeError::MissingField(field_name))?,
    )?)
}
