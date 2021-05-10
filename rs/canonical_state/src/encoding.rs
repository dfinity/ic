//! Provides canonical CBOR encoding for Canonical State tree leaves.
//!
//! In order to maintain a stable canonical representation with support for
//! forward and backward compatibility, mirror types are provided in the `types`
//! module, as well as a suite of compatibility tests (guarding against possibly
//! incompatible changes: field addition / removal / type changes).
//!
//! The canonical CBOR representation uses the "packed" CBOR format, where field
//! names are replaced by indices (similar to protocol buffers), for more
//! concise encoding. This is safe to do given the use of canonical types
//! covered by compatibility tests.

use ic_protobuf::proxy::ProxyDecodeError;
use ic_replicated_state::metadata_state::SystemMetadata;
use ic_types::{messages::RequestOrResponse, xnet::StreamHeader};
use std::convert::TryInto;

pub(crate) mod types;

#[cfg(test)]
mod tests {
    mod compatibility;
    mod conversion;
    mod encoding;
    mod test_fixtures;
}

/// Allows a canonical type to act as a proxy for encoding a Rust type `T` as
/// canonical CBOR, provided an `Into` implementation for `T`.
pub trait CborProxyEncoder<T> {
    /// Encodes `t` into a vector via this proxy.
    fn proxy_encode(t: T) -> Result<Vec<u8>, serde_cbor::Error>;
}

/// Allows a canonical type to act as a proxy for encoding a Rust type `T` as
/// canonical CBOR, provided a `TryInto<T>` implementation for the canonical
/// type.
pub trait CborProxyDecoder<'de, T> {
    /// Decodes a `T` from a slice via this proxy.
    fn proxy_decode(bytes: &'de [u8]) -> Result<T, ProxyDecodeError>;
}

impl<T, M> CborProxyEncoder<T> for M
where
    T: Into<M>,
    M: serde::Serialize,
{
    fn proxy_encode(t: T) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::ser::to_vec_packed(&t.into())
    }
}

impl<'de, T, M> CborProxyDecoder<'de, T> for M
where
    M: serde::Deserialize<'de> + TryInto<T>,
    M::Error: Into<ProxyDecodeError>,
{
    fn proxy_decode(bytes: &'de [u8]) -> Result<T, ProxyDecodeError> {
        let m: M = serde_cbor::from_slice(bytes)
            .map_err(|err| ProxyDecodeError::CborDecodeError(Box::new(err)))?;
        m.try_into().map_err(|e| e.into())
    }
}

/// Encodes a `RequestOrResponse` into canonical CBOR representation.
pub fn encode_message(msg: &RequestOrResponse) -> Vec<u8> {
    types::RequestOrResponse::proxy_encode(msg).unwrap()
}

/// Decodes a `RequestOrResponse` from canonical CBOR representation.
pub fn decode_message(bytes: &[u8]) -> Result<RequestOrResponse, ProxyDecodeError> {
    types::RequestOrResponse::proxy_decode(bytes)
}

/// Encodes a `StreamHeader` into canonical CBOR representation.
pub fn encode_stream_header(header: &StreamHeader) -> Vec<u8> {
    types::StreamHeader::proxy_encode(header).unwrap()
}

/// Decodes a `StreamHeader` from canonical CBOR representation.
pub fn decode_stream_header(bytes: &[u8]) -> Result<StreamHeader, ProxyDecodeError> {
    types::StreamHeader::proxy_decode(bytes)
}

/// Encodes a `SystemMetadata` into canonical CBOR representation.
pub fn encode_metadata(msg: &SystemMetadata) -> Vec<u8> {
    types::SystemMetadata::proxy_encode(msg).unwrap()
}
