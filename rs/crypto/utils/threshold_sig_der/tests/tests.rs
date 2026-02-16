use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_utils_threshold_sig_der::*;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
struct TestVector {
    raw_hex: String,
    der_hex: String,
    pem: String,
}

fn test_vectors() -> Vec<TestVector> {
    vec![
        TestVector {
            raw_hex: "a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5".to_string(),
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5".to_string(),
            pem: "-----BEGIN PUBLIC KEY-----\nMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKdiOpPNtWxNI9mc\nFCFq+qs9/W1PnrPbI9A4KAttXLLKruKhndksnfcAHe3iO/A2vA8zmC37Qej6m46W\ntdw+g9VcpN0UbH6y6LaFnLWl24FduGgQuNEs7hWItdvzSk3JpQ==\n-----END PUBLIC KEY-----\n".to_string(),
        },
        TestVector {
            raw_hex: "b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed".to_string(),
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed".to_string(),
            pem: "-----BEGIN PUBLIC KEY-----\nMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhALYTMDvaGA5rR0vB\nUYOHCCjFSZnuOkeXyd0Ayr5ZznjjB7ISiEh47EN66f1z9cHxPQHzTt8edGwZL39u\nlhS8lQtwW10oJdh0mcl3jbKwMpVbrbW06xA7RrD0+kdrRbeE7Q==\n-----END PUBLIC KEY-----\n".to_string(),
        },
        TestVector {
            raw_hex: "a398dd093da937ac09168b198e016ff590e707f186251c6b885b54845f3a43e536d5d283f0077dfe5021c9163e27dec9107f4bd0358e38355dd28fe6549e99833a5554eb1a18d2854c07a9599d38127ca1fa5bdbea95ff6a69bf173edce141bc".to_string(),
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a398dd093da937ac09168b198e016ff590e707f186251c6b885b54845f3a43e536d5d283f0077dfe5021c9163e27dec9107f4bd0358e38355dd28fe6549e99833a5554eb1a18d2854c07a9599d38127ca1fa5bdbea95ff6a69bf173edce141bc".to_string(),
            pem: "-----BEGIN PUBLIC KEY-----\nMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk9qTesCRaL\nGY4Bb/WQ5wfxhiUca4hbVIRfOkPlNtXSg/AHff5QIckWPifeyRB/S9A1jjg1XdKP\n5lSemYM6VVTrGhjShUwHqVmdOBJ8ofpb2+qV/2ppvxc+3OFBvA==\n-----END PUBLIC KEY-----\n".to_string(),
        },
        // NNS public key
        TestVector {
            raw_hex: "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae".to_string(),
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae".to_string(),
            pem: "-----BEGIN PUBLIC KEY-----\nMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9\ngTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bW\nW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg==\n-----END PUBLIC KEY-----\n".to_string(),
        },
    ]
}

fn raw_bytes(tv: &TestVector) -> [u8; PublicKeyBytes::SIZE] {
    let mut bytes = [0u8; PublicKeyBytes::SIZE];
    bytes.copy_from_slice(&hex::decode(&tv.raw_hex).unwrap());
    bytes
}

fn der_bytes(tv: &TestVector) -> Vec<u8> {
    hex::decode(&tv.der_hex).unwrap()
}

fn public_key(tv: &TestVector) -> ThresholdSigPublicKey {
    ThresholdSigPublicKey::from(PublicKeyBytes(raw_bytes(tv)))
}

#[test]
fn should_use_correct_key_size_in_der_utils() {
    assert_eq!(PUBLIC_KEY_SIZE, PublicKeyBytes::SIZE);
}

//Test conversion from raw public key to DER and back roundtrip
#[test]
fn test_raw_to_der_roundtrip() {
    for tv in test_vectors() {
        let expected_raw = raw_bytes(&tv);
        let expected_der = der_bytes(&tv);

        // Key -> DER
        let parsed_der = public_key_to_der(&expected_raw).unwrap();
        assert_eq!(parsed_der, expected_der);

        // DER -> Key
        let parsed_raw = public_key_from_der(&parsed_der).unwrap();
        assert_eq!(parsed_raw, expected_raw);
    }
}

#[test]
fn test_corrupted_der_fails() {
    for tv in test_vectors() {
        let mut buf = der_bytes(&tv);
        buf[0] = !buf[0]; // Corrupt the first byte of the DER
        assert!(public_key_from_der(&buf).is_err());
    }
}

#[test]
fn test_public_key_to_der_wrong_key_size() {
    // Key too short
    let short_key = [0u8; PUBLIC_KEY_SIZE - 1];
    assert!(public_key_to_der(&short_key).is_err());

    // Key too long
    let long_key = [0u8; PUBLIC_KEY_SIZE + 1];
    assert!(public_key_to_der(&long_key).is_err());

    // Empty key
    let empty_key: [u8; 0] = [];
    assert!(public_key_to_der(&empty_key).is_err());
}

//Test conversion from ThresholdSigPublicKey to DER and back roundtrip
#[test]
fn test_threshold_sig_public_key_to_der_roundtrip() {
    for tv in test_vectors() {
        let expected_raw = raw_bytes(&tv);
        let expected_pk = public_key(&tv);
        let expected_der = der_bytes(&tv);

        // Key -> DER
        let parsed_der = threshold_sig_public_key_to_der(expected_pk).unwrap();
        assert_eq!(parsed_der, expected_der);

        // DER -> Key
        let parsed_pk = parse_threshold_sig_key_from_der(&parsed_der).unwrap();
        assert_eq!(parsed_pk, expected_pk);
        assert_eq!(parsed_pk.into_bytes(), expected_raw);
    }
}

// =============================================================================
// DER <-> PEM conversions
// =============================================================================

//Test conversion from DER to PEM
#[test]
fn test_der_to_pem() {
    for tv in test_vectors() {
        let der = der_bytes(&tv);
        let pem = public_key_der_to_pem(&der);
        assert_eq!(pem, tv.pem.as_bytes());
    }
}

//Test conversion from ThresholdSigPublicKey to PEM and back roundtrip
#[test]
fn test_threshold_sig_public_key_to_pem_roundtrip() {
    use std::io::Write;
    for tv in test_vectors() {
        let expected_raw = raw_bytes(&tv);
        let expected_pk = public_key(&tv);
        let expected_pem = tv.pem.as_bytes();

        // Key -> PEM
        let parsed_pem = threshold_sig_public_key_to_pem(expected_pk).unwrap();
        assert_eq!(parsed_pem, expected_pem);

        // PEM File -> Key
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&parsed_pem).unwrap();
        let parsed_pk = parse_threshold_sig_key_from_pem_file(tmpfile.path()).unwrap();
        assert_eq!(parsed_pk, expected_pk);
        assert_eq!(parsed_pk.into_bytes(), expected_raw);
    }
}

#[test]
fn test_pem_missing_begin_header() {
    use std::io::Write;

    let bad_pem = "MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk=\n\
                   -----END PUBLIC KEY-----\n";
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(bad_pem.as_bytes()).unwrap();
    let result = parse_threshold_sig_key_from_pem_file(tmpfile.path());
    assert!(matches!(result, Err(KeyConversionError::InvalidPem(_))));
}

#[test]
fn test_pem_missing_end_header() {
    use std::io::Write;

    let bad_pem = "-----BEGIN PUBLIC KEY-----\n\
                   MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKOY3Qk=\n";
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(bad_pem.as_bytes()).unwrap();
    let result = parse_threshold_sig_key_from_pem_file(tmpfile.path());
    assert!(matches!(result, Err(KeyConversionError::InvalidPem(_))));
}

#[test]
fn test_pem_empty_content() {
    use std::io::Write;

    // Valid PEM structure but with no content between the headers.
    // The pem crate parses this successfully, then DER parsing fails on empty content.
    let bad_pem = "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n";
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(bad_pem.as_bytes()).unwrap();
    let result = parse_threshold_sig_key_from_pem_file(tmpfile.path());
    assert!(matches!(result, Err(KeyConversionError::InvalidDer(_))));
}

#[test]
fn test_pem_invalid_base64() {
    use std::io::Write;

    // Contains invalid base64 character '!'
    let bad_pem =
        "-----BEGIN PUBLIC KEY-----\nMIGCMB0GDSsGAQQBgtx8BQMB!gEGDCs=\n-----END PUBLIC KEY-----\n";
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(bad_pem.as_bytes()).unwrap();
    let result = parse_threshold_sig_key_from_pem_file(tmpfile.path());
    assert!(matches!(result, Err(KeyConversionError::InvalidPem(_))));
}

#[test]
fn test_pem_invalid_der_content() {
    use std::io::Write;

    // Valid PEM structure but garbage DER content
    let bad_pem = "-----BEGIN PUBLIC KEY-----\nZ2FyYmFnZQ==\n-----END PUBLIC KEY-----\n";
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    tmpfile.write_all(bad_pem.as_bytes()).unwrap();
    let result = parse_threshold_sig_key_from_pem_file(tmpfile.path());
    assert!(
        matches!(result, Err(KeyConversionError::InvalidDer(_))),
        "Expected InvalidDer, got {:?}",
        result
    );
}

#[test]
fn test_der_invalid_content() {
    let garbage = b"not valid der";
    let result = parse_threshold_sig_key_from_der(garbage);
    assert!(matches!(result, Err(KeyConversionError::InvalidDer(_))));
}
