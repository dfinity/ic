//!DER conversion utilities for basic signatures.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use simple_asn1::{ASN1Block, ASN1Class, BigInt, BigUint, OID};

#[cfg(test)]
mod tests;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyDerParsingError {
    pub internal_error: String,
}

/// Parses a DER-wrapped COSE public key, and returns the public key.
///
/// See [the Interface Spec](https://sdk.dfinity.org/docs/interface-spec/index.html#signatures)
/// and [RFC 8410](https://tools.ietf.org/html/rfc8410#section-4).
///
/// # Returns
/// COSE-encoded public key bytes
///
/// # Errors:
/// * `KeyDerParsingError` if:
///   - `pk_der` is malformed ASN.1
///   - `pk_der` is *not* the expected ASN.1 structure
///   - The OID specified in `pk_der` is *not* 1.3.6.1.4.1.56387.1.1
pub fn public_key_bytes_from_der_wrapped_cose(
    pk_der: &[u8],
) -> Result<Vec<u8>, KeyDerParsingError> {
    let (oid, pk_bytes) = oid_and_public_key_bytes_from_der(pk_der)?;
    ensure_der_wrapped_cose_oid(oid)?;
    Ok(pk_bytes)
}

/// Parses a DER-wrapped COSE public key, and returns the OID and the public
/// key.
///
/// See [RFC 8410](https://tools.ietf.org/html/rfc8410#section-4).
///
/// # Returns
/// The `OID` and COSE-encoded public key bytes
///
/// # Errors:
/// * `KeyDerParsingError` if:
///   - `pk_der` is malformed ASN.1
///   - `pk_der` is *not* the expected ASN.1 structure
pub fn oid_and_public_key_bytes_from_der(
    pk_der: &[u8],
) -> Result<(OID, Vec<u8>), KeyDerParsingError> {
    let der_parser = KeyDerParser::new(pk_der);
    der_parser.get_oid_and_public_key_bytes()
}

/// The secret and public keys as bytes, as well as the OID.
pub struct SecretKeyData {
    pub oid: OID,
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Option<Vec<u8>>,
}

/// Parses a DER-wrapped secret key, and returns the OID and the keypair.
///
/// See [RFC 8410](see https://tools.ietf.org/html/rfc8410#section-7).
///
/// # Errors:
/// * `KeyDerParsingError` if:
///   - `sk_der` is malformed ASN.1
///   - `sk_der` is *not* the expected ASN.1 structure
pub fn oid_and_key_pair_bytes_from_der(sk_der: &[u8]) -> Result<SecretKeyData, KeyDerParsingError> {
    let der_parser = KeyDerParser::new(sk_der);
    der_parser.get_oid_and_key_pair_bytes()
}

/// Returns an error if `oid` is *not* the OID for an IC public key.
fn ensure_der_wrapped_cose_oid(oid: simple_asn1::OID) -> Result<(), KeyDerParsingError> {
    if oid != simple_asn1::oid!(1, 3, 6, 1, 4, 1, 56387, 1, 1) {
        return Err(KeyDerParsingError {
            internal_error: format!("Wrong OID: {:?}", oid),
        });
    }
    Ok(())
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
    pub fn get_oid_and_public_key_bytes(&self) -> Result<(OID, Vec<u8>), KeyDerParsingError> {
        let asn1_parts = self.parse_pk()?;
        let mut key_seq = self.ensure_single_asn1_sequence(asn1_parts)?;
        if key_seq.len() != 2 {
            return Err(self.parsing_error("Expected exactly two ASN.1 blocks."));
        }

        let oid_seq = key_seq.remove(0);
        let oid = self.oid(oid_seq)?;
        let pk_part = key_seq.remove(0);
        let pk_bytes = self.public_key_bytes(pk_part)?;
        Ok((oid, pk_bytes))
    }

    /// Parses the DER key of this parser as a secret key with a corresponding
    /// public key, and returns the resulting components.
    pub fn get_oid_and_key_pair_bytes(&self) -> Result<SecretKeyData, KeyDerParsingError> {
        let asn1_parts = self.parse_pk()?;
        let mut key_seq = self.ensure_single_asn1_sequence(asn1_parts)?;
        if key_seq.len() != 4 {
            return Err(self.parsing_error("Expected exactly four ASN.1 blocks."));
        }
        let version_part = key_seq.remove(0);
        if let ASN1Block::Integer(_offset, version) = version_part {
            if version != BigInt::from(1) {
                return Err(self.parsing_error("Version must be equal 1"));
            }
        } else {
            return Err(self.parsing_error("Expected version part"));
        }
        let oid_seq = key_seq.remove(0);
        let oid = self.oid(oid_seq)?;
        let sk_part = key_seq.remove(0);
        let sk_bytes = self.secret_key_bytes(sk_part)?;
        let (pk_part, tag) = self.unwrap_explicitly_tagged_block(key_seq.remove(0))?;
        if tag != BigUint::from_bytes_le(&[1]) {
            return Err(self.parsing_error(&format!("Expected tag [1], got {:?}", tag)));
        }
        let pk_bytes = self.public_key_bytes(pk_part)?;
        Ok(SecretKeyData {
            oid,
            sk_bytes,
            pk_bytes: Some(pk_bytes),
        })
    }

    /// Retrieves OID from the given ASN1Block.
    fn oid(&self, oid_seq: ASN1Block) -> Result<OID, KeyDerParsingError> {
        if let ASN1Block::Sequence(_offset_oid, mut oid_parts) = oid_seq {
            if oid_parts.len() != 1 {
                return Err(self.parsing_error("OID sequence must have exactly one part"));
            }
            if let ASN1Block::ObjectIdentifier(_offset, oid) = oid_parts.remove(0) {
                Ok(oid)
            } else {
                Err(self.parsing_error("Expected OID."))
            }
        } else {
            Err(self.parsing_error("Expected sequence of OID parts"))
        }
    }

    /// Attempts to parse the given ASN1Block as an explicitly tagged type
    fn unwrap_explicitly_tagged_block(
        &self,
        wrapped: ASN1Block,
    ) -> Result<(ASN1Block, BigUint), KeyDerParsingError> {
        if let ASN1Block::Explicit(ASN1Class::ContextSpecific, _offset, tag, unwrapped) = wrapped {
            Ok((*unwrapped, tag))
        } else {
            Err(self.parsing_error(&format!("Expected Explict-block, got {:?}", wrapped)))
        }
    }

    /// Retrieves raw public key bytes from the given ASN1Block.
    fn public_key_bytes(&self, key_part: ASN1Block) -> Result<Vec<u8>, KeyDerParsingError> {
        if let ASN1Block::BitString(_offset, bits_count, key_bytes) = key_part {
            if bits_count != key_bytes.len() * 8 {
                return Err(self.parsing_error("Inconsistent key length"));
            }
            Ok(key_bytes)
        } else {
            Err(self.parsing_error(&format!("Expected BitString, got {:?}", key_part)))
        }
    }

    /// Retrieves raw secret key bytes from the given ASN1Block.
    fn secret_key_bytes(&self, key_part: ASN1Block) -> Result<Vec<u8>, KeyDerParsingError> {
        if let ASN1Block::OctetString(_offset, key_bytes_string) = key_part {
            let mut key_bytes_block = simple_asn1::from_der(&key_bytes_string).map_err(|e| {
                self.parsing_error(&*format!("Error in DER encoding: {}", e.to_string()))
            })?;
            if key_bytes_block.len() != 1 {
                return Err(self.parsing_error("Expected single block"));
            }
            if let ASN1Block::OctetString(_offset, key_bytes) = key_bytes_block.remove(0) {
                return Ok(key_bytes);
            }
        }
        Err(self.parsing_error("Expected octet string."))
    }

    /// Converts `msg` into a `KeyDerParsingError`.
    fn parsing_error(&self, msg: &str) -> KeyDerParsingError {
        KeyDerParsingError {
            internal_error: msg.to_string(),
        }
    }

    /// parses the entire DER-string provided upon construction.
    fn parse_pk(&self) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        simple_asn1::from_der(&self.key_der)
            .map_err(|e| self.parsing_error(&*format!("Error in DER encoding: {}", e.to_string())))
    }

    /// Verifies that the specified `parts` contain exactly one ASN1Block, and
    /// that this block is an ASN1 Sequence. Returns the contents of that
    /// Sequence.
    fn ensure_single_asn1_sequence(
        &self,
        mut parts: Vec<ASN1Block>,
    ) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        if parts.len() != 1 {
            return Err(self.parsing_error("Expected exactly one ASN.1 block."));
        }
        if let ASN1Block::Sequence(_offset, part) = parts.remove(0) {
            Ok(part)
        } else {
            Err(self.parsing_error("Expected an ASN.1 sequence."))
        }
    }
}
