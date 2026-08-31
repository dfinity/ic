//!DER conversion utilities for basic signatures.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

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
        .map_err(|e| format!("failed to encode as DER: {e}"))
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

/// The maximum nesting depth of constructed ASN.1 elements accepted in a
/// DER-encoded key.
pub const MAX_DER_NESTING_DEPTH: usize = 4;

const SEQUENCE_TAG_NUMBER: u8 = 0x10;
const SET_TAG_NUMBER: u8 = 0x11;

const INCOMPLETE_ELEMENT: &str = "DER ends in the middle of an element";
const LENGTH_TOO_LARGE: &str = "DER element length is too large";

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
            return Err(Self::parsing_error(&format!(
                "Expected the SubjectPublicKeyInfo SEQUENCE to contain 2 elements \
                 (algorithm and subjectPublicKey), got {}",
                key_seq.len()
            )));
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
                    (_, _) => Err(Self::parsing_error(&format!(
                        "Expected the AlgorithmIdentifier SEQUENCE to contain an OBJECT \
                         IDENTIFIER optionally followed by NULL or another OBJECT IDENTIFIER, \
                         got {}{}",
                        Self::asn1_type_name(algo_oid),
                        algo_params
                            .map(|params| format!(" followed by {}", Self::asn1_type_name(params)))
                            .unwrap_or_default()
                    ))),
                }
            } else {
                Err(Self::parsing_error(&format!(
                    "Expected the AlgorithmIdentifier SEQUENCE to contain 1 or 2 elements \
                     (algorithm and optional parameters), got {}",
                    oid_parts.len()
                )))
            }
        } else {
            Err(Self::parsing_error(&format!(
                "Expected the algorithm to be an AlgorithmIdentifier SEQUENCE, got {}",
                Self::asn1_type_name(oid_seq)
            )))
        }
    }

    /// Retrieves raw public key bytes from the given ASN1Block.
    fn public_key_bytes(key_part: &ASN1Block) -> Result<Vec<u8>, KeyDerParsingError> {
        if let ASN1Block::BitString(_offset, bits_count, key_bytes) = key_part {
            if *bits_count != key_bytes.len() * 8 {
                return Err(Self::parsing_error(&format!(
                    "Expected the subjectPublicKey BIT STRING to contain whole octets, \
                     got {} bits in {} octets",
                    bits_count,
                    key_bytes.len()
                )));
            }
            Ok(key_bytes.to_vec())
        } else {
            Err(Self::parsing_error(&format!(
                "Expected the subjectPublicKey to be a BIT STRING, got {}",
                Self::asn1_type_name(key_part)
            )))
        }
    }

    /// Returns the name of the ASN.1 type of `block`, for use in error
    /// messages. Only the name is returned, not the contents.
    fn asn1_type_name(block: &ASN1Block) -> &'static str {
        match block {
            ASN1Block::Boolean(..) => "a BOOLEAN",
            ASN1Block::Integer(..) => "an INTEGER",
            ASN1Block::BitString(..) => "a BIT STRING",
            ASN1Block::OctetString(..) => "an OCTET STRING",
            ASN1Block::Null(..) => "NULL",
            ASN1Block::ObjectIdentifier(..) => "an OBJECT IDENTIFIER",
            ASN1Block::Sequence(..) => "a SEQUENCE",
            ASN1Block::Set(..) => "a SET",
            ASN1Block::Explicit(..) => "an explicitly tagged value",
            ASN1Block::Unknown(..) => "a value of an unknown ASN.1 type",
            _ => "a value of another ASN.1 type",
        }
    }

    /// Converts `msg` into a `KeyDerParsingError`.
    fn parsing_error(msg: &str) -> KeyDerParsingError {
        KeyDerParsingError {
            internal_error: msg.to_string(),
        }
    }

    /// Returns an error if `der` nests ASN.1 elements more than
    /// [`MAX_DER_NESTING_DEPTH`] levels deep, or if its tag-length headers
    /// cannot be walked from start to end.
    fn check_der_nesting_depth(der: &[u8]) -> Result<(), KeyDerParsingError> {
        // Exclusive end offsets of the elements that are currently open; their
        // number is the current nesting depth.
        let mut open_elements_end: Vec<usize> = Vec::new();
        let mut index = 0;
        while index < der.len() {
            while let Some(&end) = open_elements_end.last() {
                if end <= index {
                    open_elements_end.pop();
                } else {
                    break;
                }
            }

            // Identifier octets: skip the high-tag-number form if present.
            let first_identifier_octet = der[index];
            let universal_class = first_identifier_octet & 0xc0 == 0;
            let constructed = first_identifier_octet & 0x20 != 0;
            let tag_number = first_identifier_octet & 0x1f;
            let high_tag_number_form = tag_number == 0x1f;
            index += 1;
            if high_tag_number_form {
                while let Some(octet) = der.get(index)
                    && octet & 0x80 != 0
                {
                    index += 1;
                }
                index += 1;
            }

            // SEQUENCEs and SETs hold other elements whatever their
            // constructed bit says; elements of the other classes hold other
            // elements when it is set. The high-tag-number form can encode the
            // SEQUENCE and SET tag numbers, so it is counted as well.
            let container = if high_tag_number_form {
                true
            } else if universal_class {
                tag_number == SEQUENCE_TAG_NUMBER || tag_number == SET_TAG_NUMBER
            } else {
                constructed
            };

            // Length octets: short form, or long form giving the octet count.
            // A first octet of 0x80 gives a length of zero.
            let Some(&first_length_octet) = der.get(index) else {
                return Err(Self::parsing_error(INCOMPLETE_ELEMENT));
            };
            index += 1;
            let content_length = if first_length_octet & 0x80 == 0 {
                first_length_octet as usize
            } else {
                let num_length_octets = (first_length_octet & 0x7f) as usize;
                if num_length_octets > core::mem::size_of::<usize>() {
                    return Err(Self::parsing_error(LENGTH_TOO_LARGE));
                }
                let mut length = 0;
                for _ in 0..num_length_octets {
                    let Some(&octet) = der.get(index) else {
                        return Err(Self::parsing_error(INCOMPLETE_ELEMENT));
                    };
                    length = (length << 8) | octet as usize;
                    index += 1;
                }
                length
            };

            let Some(content_end) = index.checked_add(content_length) else {
                return Err(Self::parsing_error(LENGTH_TOO_LARGE));
            };
            if content_end > der.len() {
                return Err(Self::parsing_error(INCOMPLETE_ELEMENT));
            }
            if container {
                if open_elements_end.len() + 1 > MAX_DER_NESTING_DEPTH {
                    return Err(Self::parsing_error(&format!(
                        "DER nesting depth exceeds the maximum of {MAX_DER_NESTING_DEPTH}"
                    )));
                }
                open_elements_end.push(content_end);
            } else {
                index = content_end;
            }
        }
        Ok(())
    }

    /// parses the entire DER-string provided upon construction.
    fn parse_pk(&self) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        Self::check_der_nesting_depth(&self.key_der)?;
        simple_asn1::from_der(&self.key_der)
            .map_err(|e| Self::parsing_error(&format!("Error in DER encoding: {e}")))
    }

    /// Verifies that the specified `parts` contain exactly one ASN1Block, and
    /// that this block is an ASN1 Sequence. Returns the contents of that
    /// Sequence.
    fn ensure_single_asn1_sequence(
        mut parts: Vec<ASN1Block>,
    ) -> Result<Vec<ASN1Block>, KeyDerParsingError> {
        if parts.len() != 1 {
            return Err(Self::parsing_error(&format!(
                "Expected a single top-level SubjectPublicKeyInfo element, got {}",
                parts.len()
            )));
        }
        let part = parts.remove(0);
        if let ASN1Block::Sequence(_offset, part) = part {
            Ok(part)
        } else {
            Err(Self::parsing_error(&format!(
                "Expected the SubjectPublicKeyInfo to be a SEQUENCE, got {}",
                Self::asn1_type_name(&part)
            )))
        }
    }
}
