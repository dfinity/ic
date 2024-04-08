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

use crate::CertificationVersion;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_replicated_state::metadata_state::{SubnetMetrics, SystemMetadata};
use ic_types::{messages::RequestOrResponse, xnet::StreamHeader, PrincipalId};
use serde::Serialize;
use std::collections::BTreeSet;
use std::convert::TryInto;

pub mod old_types;
pub mod types;

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
pub fn encode_message(
    msg: &RequestOrResponse,
    certification_version: CertificationVersion,
) -> Vec<u8> {
    types::RequestOrResponse::proxy_encode((msg, certification_version)).unwrap()
}

/// Decodes a `RequestOrResponse` from canonical CBOR representation.
pub fn decode_message(bytes: &[u8]) -> Result<RequestOrResponse, ProxyDecodeError> {
    types::RequestOrResponse::proxy_decode(bytes)
}

/// Encodes a `StreamHeader` into canonical CBOR representation.
pub fn encode_stream_header(
    header: &StreamHeader,
    certification_version: CertificationVersion,
) -> Vec<u8> {
    types::StreamHeader::proxy_encode((header, certification_version)).unwrap()
}

/// Decodes a `StreamHeader` from canonical CBOR representation.
pub fn decode_stream_header(bytes: &[u8]) -> Result<StreamHeader, ProxyDecodeError> {
    types::StreamHeader::proxy_decode(bytes)
}

/// Encodes a `SystemMetadata` into canonical CBOR representation.
pub fn encode_metadata(
    metadata: &SystemMetadata,
    certification_version: CertificationVersion,
) -> Vec<u8> {
    types::SystemMetadata::proxy_encode((metadata, certification_version)).unwrap()
}

/// Encodes the list of canister ID ranges assigned to a subnet according to
/// the interface specification.
///
/// See https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-subnet
pub fn encode_subnet_canister_ranges(ranges: Option<&Vec<(PrincipalId, PrincipalId)>>) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    match ranges {
        Some(ranges) => ranges.serialize(&mut serializer).unwrap(),
        None => Vec::<(PrincipalId, PrincipalId)>::new()
            .serialize(&mut serializer)
            .unwrap(),
    }
    serializer.into_inner()
}

/// Encodes a `SubnetMetrics` into canonical CBOR representation.
pub fn encode_subnet_metrics(
    metrics: &SubnetMetrics,
    certification_version: CertificationVersion,
) -> Vec<u8> {
    types::SubnetMetrics::proxy_encode((metrics, certification_version)).unwrap()
}

/// Serializes controllers as a CBOR list.
///
/// From the spec:
///
/// The value consists of a CBOR data item with major type 6
/// (“Semantic tag”) and tag value `55799` followed by an array
/// of principals in their binary form
/// (CDDL `#6.55799([* bytes .size (0..29)])`)
pub fn encode_controllers(controllers: &BTreeSet<PrincipalId>) -> Vec<u8> {
    let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    controllers.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

#[cfg(test)]
mod tests {
    mod compatibility;
    mod conversion;
    mod encoding;
    mod test_fixtures;
}
