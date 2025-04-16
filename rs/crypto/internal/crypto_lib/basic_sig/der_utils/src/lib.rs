//!DER conversion utilities for basic signatures.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use simple_asn1::{ASN1Block, OID};

#[cfg(test)]
mod tests;

/// The parameters of an AlgorithmIdentifier as described in RFC 5480
///
/// This enum can be extended to support alternate types as required
/// when different algorithms are implemented
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum PkixAlgorithmParameters {
    /// An ASN.1 object identifier
    ObjectIdentifier(OID),
    /// An ASN.1 explicit NULL
    Null,
}

/// An AlgorithmIdentifier as described in RFC 5480
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PkixAlgorithmIdentifier {
    pub oid: OID,
    pub params: Option<PkixAlgorithmParameters>,
}

impl PkixAlgorithmIdentifier {
    pub fn new_with_empty_param(algo_oid: OID) -> Self {
        Self {
            oid: algo_oid,
            params: None,
        }
    }

    pub fn new_with_null_param(algo_oid: OID) -> Self {
        Self {
            oid: algo_oid,
            params: Some(PkixAlgorithmParameters::Null),
        }
    }

    pub fn new_with_oid_param(algo_oid: OID, algo_params: OID) -> Self {
        Self {
            oid: algo_oid,
            params: Some(PkixAlgorithmParameters::ObjectIdentifier(algo_params)),
        }
    }
}

/// Encodes the given `key` according to
/// [RFC 8410](https://tools.ietf.org/html/rfc8410#section-4).
///
/// The encoding is as follows:
/// ```text
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///    algorithm         AlgorithmIdentifier,
///    subjectPublicKey  BIT STRING
/// }
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///    algorithm   OBJECT IDENTIFIER,
///    parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
///
/// # Errors
/// * `Err(String)` if the DER encoding failed.
pub fn subject_public_key_info_der(algorithm: OID, key: &[u8]) -> Result<Vec<u8>, String> {
    let algorithm = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, algorithm)]);
    let subject_public_key = ASN1Block::BitString(0, key.len() * 8, key.to_vec());
    let subject_public_key_info = ASN1Block::Sequence(0, vec![algorithm, subject_public_key]);
    simple_asn1::to_der(&subject_public_key_info)
        .map_err(|e| format!("failed to encode as DER: {}", e))
}

/// The provided DER-encoded bytes are malformed.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyDerParsingError {
    pub internal_error: String,
}

/// Parses a DER-wrapped public key, and returns the
/// PkixAlgorithmIdentifier and the public key.
///
/// See [RFC 8410](https://tools.ietf.org/html/rfc8410#section-4).
///
/// # Returns
/// The `PkixAlgorithmIdentifier` and public key bytes
///
/// # Errors:
/// * `KeyDerParsingError` if:
///   - `pk_der` is malformed ASN.1
///   - `pk_der` is *not* the expected ASN.1 structure
pub fn algo_id_and_public_key_bytes_from_der(
    der: &[u8],
) -> Result<(PkixAlgorithmIdentifier, Vec<u8>), KeyDerParsingError> {
    let kp = KeyDerParser::new(der);
    kp.get_algo_id_and_public_key_bytes()
}

/// Parse a public key and verify if it is of the expected type and size
///
/// The format is SubjectPublicKeyInfo as defined in RFC 5480
pub fn parse_public_key(
    der: &[u8],
    algorithm: AlgorithmId,
    expected_algo_id: PkixAlgorithmIdentifier,
    expected_pk_len: Option<usize>,
) -> CryptoResult<Vec<u8>> {
    let (algo_id, pk_bytes) = algo_id_and_public_key_bytes_from_der(der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm,
            key_bytes: Some(der.to_vec()),
            internal_error: e.internal_error,
        }
    })?;

    if algo_id != expected_algo_id {
        return Err(CryptoError::MalformedPublicKey {
            algorithm,
            key_bytes: Some(der.to_vec()),
            internal_error: format!(
                "Wrong algorithm identifier for {:?}: expected {:?} got {:?}",
                algorithm, expected_algo_id, algo_id
            ),
        });
    }

    if let Some(expected_pk_len) = expected_pk_len {
        if pk_bytes.len() != expected_pk_len {
            return Err(CryptoError::MalformedPublicKey {
                algorithm,
                key_bytes: Some(der.to_vec()),
                internal_error: format!(
                    "Wrong length for {:?} expected {} got {}",
                    algorithm,
                    expected_pk_len,
                    pk_bytes.len()
                ),
            });
        }
    }

    Ok(pk_bytes)
}

/// Parser for DER-encoded keys.
struct KeyDerParser {
    key_der: Vec<u8>,
}

impl KeyDerParser {
    /// Creates a new helper, for the given DER-encoded key.
    pub fn new(key_der: &[u8]) -> Self {
        Self {
            key_der: Vec::from(key_der),
        }
    }

    /// Parses the DER key of this parser as a public key, and returns the
    /// resulting components.
    pub fn get_algo_id_and_public_key_bytes(
        &self,
    ) -> Result<(PkixAlgorithmIdentifier, Vec<u8>), KeyDerParsingError> {
        let asn1_parts = self.parse_pk()?;
        let key_seq = Self::ensure_single_asn1_sequence(asn1_parts)?;
        if key_seq.len() != 2 {
            return Err(Self::parsing_error("Expected exactly two ASN.1 blocks."));
        }

        let algo_id = Self::algorithm_identifier(&key_seq[0])?;
        let pk_bytes = Self::public_key_bytes(&key_seq[1])?;
        Ok((algo_id, pk_bytes))
    }

    /// Retrieves PkixAlgorithmIdentifier from the given ASN1Block.
    fn algorithm_identifier(
        oid_seq: &ASN1Block,
    ) -> Result<PkixAlgorithmIdentifier, KeyDerParsingError> {
        // PkixAlgorithmIdentifier is a pair of an OID plus anything (or nothing)
        // whose type depends on the leading OID. However in our current usage
        // the second parameter is always either absent or a second OID

        if let ASN1Block::Sequence(_offset_oid, oid_parts) = oid_seq {
            if oid_parts.len() == 1 || oid_parts.len() == 2 {
                let algo_oid = oid_parts
                    .first()
                    .expect("Missing OID from algorithm identifier");
                let algo_params = oid_parts.get(1);

                match (algo_oid, algo_params) {
                    (ASN1Block::ObjectIdentifier(_, algo_oid), Some(ASN1Block::Null(_))) => Ok(
                        PkixAlgorithmIdentifier::new_with_null_param(algo_oid.clone()),
                    ),
                    (
                        ASN1Block::ObjectIdentifier(_, algo_oid),
                        Some(ASN1Block::ObjectIdentifier(_, algo_params)),
                    ) => Ok(PkixAlgorithmIdentifier::new_with_oid_param(
                        algo_oid.clone(),
                        algo_params.clone(),
                    )),
                    (ASN1Block::ObjectIdentifier(_, algo_oid), None) => Ok(
                        PkixAlgorithmIdentifier::new_with_empty_param(algo_oid.clone()),
                    ),
                    (_, _) => Err(Self::parsing_error(
                        "algorithm identifier has unexpected type",
                    )),
                }
            } else {
                Err(Self::parsing_error(
                    "algorithm identifier has unexpected size",
                ))
            }
        } else {
            Err(Self::parsing_error("Expected algorithm identifier"))
        }
    }

    /// Retrieves raw public key bytes from the given ASN1Block.
    fn public_key_bytes(key_part: &ASN1Block) -> Result<Vec<u8>, KeyDerParsingError> {
        if let ASN1Block::BitString(_offset, bits_count, key_bytes) = key_part {
            if *bits_count != key_bytes.len() * 8 {
                return Err(Self::parsing_error("Inconsistent key length"));
            }
            Ok(key_bytes.to_vec())
        } else {
            Err(Self::parsing_error(&format!(
                "Expected BitString, got {:?}",
                key_part
            )))
        }
    }

    /// Converts `msg` into a `KeyDerParsingError`.
    fn parsing_error(msg: &str) -> KeyDerParsingError {
        KeyDerParsingError {
            internal_error: msg.to_string(),
        }
    }

    /// parses the entire DER-string provided upon construction.
    fn parse_pk(&self) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        simple_asn1::from_der(&self.key_der)
            .map_err(|e| Self::parsing_error(&format!("Error in DER encoding: {}", e)))
    }

    /// Verifies that the specified `parts` contain exactly one ASN1Block, and
    /// that this block is an ASN1 Sequence. Returns the contents of that
    /// Sequence.
    fn ensure_single_asn1_sequence(
        mut parts: Vec<ASN1Block>,
    ) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        if parts.len() != 1 {
            return Err(Self::parsing_error("Expected exactly one ASN.1 block."));
        }
        if let ASN1Block::Sequence(_offset, part) = parts.remove(0) {
            Ok(part)
        } else {
            Err(Self::parsing_error("Expected an ASN.1 sequence."))
        }
    }
}
