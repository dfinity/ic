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

/// Returns a pseudo-random byte sequence of the given length.
fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 33) as u8
        })
        .collect()
}

#[test]
fn should_terminate_on_malformed_der() {
    let mut inputs: Vec<Vec<u8>> = vec![
        // Headers declaring more content than the input holds.
        vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // Truncated headers.
        vec![0x30],
        vec![0x30, 0x81],
        vec![0x1f, 0xff, 0xff],
        // The indefinite length form, which is not valid DER.
        vec![0x30, 0x80, 0x05, 0x00],
        // Empty constructed elements, and constructed elements whose content
        // reaches beyond the end of their parent.
        [0x30, 0x00].repeat(100_000),
        vec![0x30, 0x02, 0x30, 0x7f, 0x05, 0x00],
        // Primitive elements without any content.
        [0x05, 0x00].repeat(500_000),
    ];
    // Inputs that are not DER at all.
    inputs.extend((0..64).map(|seed| pseudo_random_bytes(4096, seed)));

    for input in inputs {
        // The test terminating at all is what is being verified here.
        let _ = KeyDerParser::check_der_nesting_depth(&input);
        let _ = algo_id_and_public_key_bytes_from_der(&input);
    }
}

/// Builds a DER `NULL` wrapped in `depth` definite-length elements with the
/// given identifier octet.
fn nested_with_tag(tag: u8, depth: usize) -> Vec<u8> {
    let null = [0x05_u8, 0x00];
    let mut headers: Vec<Vec<u8>> = Vec::with_capacity(depth);
    let mut inner_length = null.len();
    for _ in 0..depth {
        let mut header = vec![tag];
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

/// SEQUENCEs and SETs are counted whatever their constructed bit says.
#[test]
fn should_count_the_depth_of_universal_containers_without_the_constructed_bit() {
    for tag in [0x10_u8, 0x11] {
        assert_eq!(
            KeyDerParser::check_der_nesting_depth(&nested_with_tag(tag, MAX_DER_NESTING_DEPTH)),
            Ok(())
        );
        assert!(
            KeyDerParser::check_der_nesting_depth(&nested_with_tag(tag, MAX_DER_NESTING_DEPTH + 1))
                .is_err(),
            "nesting with tag {tag:#04x} was not rejected"
        );
        assert!(algo_id_and_public_key_bytes_from_der(&nested_with_tag(tag, 100)).is_err());
    }
}

/// Elements using the high-tag-number form can carry the SEQUENCE and SET tag
/// numbers, so their depth is counted as well.
#[test]
fn should_count_the_depth_of_elements_using_the_high_tag_number_form() {
    // The SEQUENCE tag number encoded in the (non-minimal) long form.
    let der = nested_with_tag_bytes(&[0x1f, 0x90, 0x10], MAX_DER_NESTING_DEPTH + 1);

    assert!(KeyDerParser::check_der_nesting_depth(&der).is_err());
}

/// Keys whose headers cannot be walked from start to end are rejected.
#[test]
fn should_reject_der_that_cannot_be_scanned_in_full() {
    let unscannable: [&[u8]; 4] = [
        // An element whose content reaches beyond the end of the input.
        &[0x30, 0x82, 0xff, 0xff],
        // A length that needs more octets than a usize holds.
        &[0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // Headers that stop in the middle.
        &[0x30],
        &[0x30, 0x81],
    ];

    for prefix in unscannable {
        let mut der = prefix.to_vec();
        der.extend_from_slice(&nested_with_tag(0x30, 100));
        assert!(
            KeyDerParser::check_der_nesting_depth(&der).is_err(),
            "unscannable prefix {prefix:02x?} was accepted"
        );
    }
}

/// Builds a DER `NULL` wrapped in `depth` definite-length elements with the
/// given identifier octets.
fn nested_with_tag_bytes(tag: &[u8], depth: usize) -> Vec<u8> {
    let null = [0x05_u8, 0x00];
    let mut headers: Vec<Vec<u8>> = Vec::with_capacity(depth);
    let mut inner_length = null.len();
    for _ in 0..depth {
        let mut header = tag.to_vec();
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
