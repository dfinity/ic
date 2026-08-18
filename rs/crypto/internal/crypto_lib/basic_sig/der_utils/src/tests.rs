use super::*;
use simple_asn1::oid;

#[test]
fn should_have_compatible_subject_public_key_info_der_encoder_and_decoder() {
    let oid = oid!(1, 2, 3, 4, 5);
    let pubkey = b"subject public key";

    let pubkey_der_encoded = subject_public_key_info_der(oid.clone(), pubkey).unwrap();
    let (algo_id, pubkey_bytes) =
        algo_id_and_public_key_bytes_from_der(&pubkey_der_encoded).unwrap();

    assert_eq!(algo_id.oid, oid);
    assert_eq!(pubkey_bytes, pubkey);
}

/// Encodes `content_length` in the DER definite-length form.
fn der_definite_length(content_length: usize) -> Vec<u8> {
    if content_length < 0x80 {
        return vec![content_length as u8];
    }
    let mut length_octets = Vec::new();
    let mut remaining = content_length;
    while remaining > 0 {
        length_octets.insert(0, (remaining & 0xff) as u8);
        remaining >>= 8;
    }
    let mut encoded = vec![0x80 | length_octets.len() as u8];
    encoded.extend_from_slice(&length_octets);
    encoded
}

/// Builds a DER `NULL` wrapped in `depth` definite-length `SEQUENCE`s.
fn sequences_around_null(depth: usize) -> Vec<u8> {
    let null = [0x05_u8, 0x00];
    let mut headers: Vec<Vec<u8>> = Vec::with_capacity(depth);
    let mut inner_length = null.len();
    for _ in 0..depth {
        let mut header = vec![0x30_u8];
        header.extend_from_slice(&der_definite_length(inner_length));
        inner_length += header.len();
        headers.push(header);
    }
    let mut der = Vec::with_capacity(inner_length);
    for header in headers.iter().rev() {
        der.extend_from_slice(header);
    }
    der.extend_from_slice(&null);
    der
}

#[test]
fn should_reject_key_with_der_nesting_above_the_maximum_depth() {
    let der = sequences_around_null(MAX_DER_NESTING_DEPTH + 1);
    assert!(algo_id_and_public_key_bytes_from_der(&der).is_err());
}

#[test]
fn should_accept_der_nesting_up_to_the_maximum_depth() {
    let der = sequences_around_null(MAX_DER_NESTING_DEPTH);
    assert_eq!(KeyDerParser::check_der_nesting_depth(&der), Ok(()));
}

#[test]
fn should_reject_der_nesting_above_the_maximum_depth() {
    let der = sequences_around_null(MAX_DER_NESTING_DEPTH + 1);
    assert!(KeyDerParser::check_der_nesting_depth(&der).is_err());
}

#[test]
fn should_accept_realistic_public_key_der() {
    let oid = oid!(1, 2, 3, 4, 5);
    let der = subject_public_key_info_der(oid, b"subject public key").unwrap();
    assert_eq!(KeyDerParser::check_der_nesting_depth(&der), Ok(()));
}

#[test]
fn should_name_the_asn1_type_of_an_unexpected_subject_public_key() {
    let der = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid!(1, 2, 3, 4, 5))]),
            ASN1Block::OctetString(0, b"subject public key".to_vec()),
        ],
    ))
    .unwrap();

    let error = algo_id_and_public_key_bytes_from_der(&der).unwrap_err();

    assert_eq!(
        error.internal_error,
        "Expected the subjectPublicKey to be a BIT STRING, got an OCTET STRING"
    );
}

#[test]
fn should_report_the_number_of_elements_of_a_malformed_algorithm_identifier() {
    let der = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, oid!(1, 2, 3, 4, 5)),
                    ASN1Block::Null(0),
                    ASN1Block::Null(0),
                ],
            ),
            ASN1Block::BitString(0, 8, vec![0x00]),
        ],
    ))
    .unwrap();

    let error = algo_id_and_public_key_bytes_from_der(&der).unwrap_err();

    assert_eq!(
        error.internal_error,
        "Expected the AlgorithmIdentifier SEQUENCE to contain 1 or 2 elements \
         (algorithm and optional parameters), got 3"
    );
}

#[test]
fn should_report_the_types_of_unexpected_algorithm_identifier_parameters() {
    let der = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, oid!(1, 2, 3, 4, 5)),
                    ASN1Block::Integer(0, 42.into()),
                ],
            ),
            ASN1Block::BitString(0, 8, vec![0x00]),
        ],
    ))
    .unwrap();

    let error = algo_id_and_public_key_bytes_from_der(&der).unwrap_err();

    assert_eq!(
        error.internal_error,
        "Expected the AlgorithmIdentifier SEQUENCE to contain an OBJECT IDENTIFIER \
         optionally followed by NULL or another OBJECT IDENTIFIER, got an OBJECT IDENTIFIER \
         followed by an INTEGER"
    );
}
