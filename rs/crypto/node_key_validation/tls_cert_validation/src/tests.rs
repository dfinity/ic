use super::*;
use chrono::{Duration, Utc};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto_test_utils::tls::x509_certificates::ed25519_key_pair;
use ic_crypto_test_utils::tls::x509_certificates::prime256v1_key_pair;
use ic_crypto_test_utils::tls::x509_certificates::CertBuilder;
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::PrincipalId;
use openssl::hash::MessageDigest;
use std::ops::Range;

#[test]
fn should_fail_if_tls_certificate_is_empty() {
    let cert = X509PublicKeyCert {
        certificate_der: vec![],
    };

    let result = validate_tls_certificate(&cert, node_id(1));

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: failed to parse DER")
    ));
}

#[test]
fn should_fail_if_tls_certificate_has_invalid_der_encoding() {
    let (mut cert, node_id) = valid_cert_and_node_id();
    cert.certificate_der.iter_mut().for_each(|x| *x ^= 0xff);

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: failed to parse DER")
    ));
}

#[test]
fn should_fail_if_tls_certificate_der_encoding_has_remainder() {
    let (mut cert, node_id) = valid_cert_and_node_id();
    cert.certificate_der.push(0x42);

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: DER not fully consumed when parsing. Remainder: 0x42")
    ));
}

#[test]
/// Tests the error class of invalid subject CNs by means
/// of a duplicate subject CN.
fn should_fail_if_tls_certificate_has_invalid_subject_cn() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .with_duplicate_subject_cn()
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: invalid subject common name (CN): found second common name (CN)")
    ));
}

#[test]
fn should_fail_if_tls_certificate_subject_cn_is_not_node_id() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: CertWithPrivateKey::builder()
            .cn("incorrect node ID".to_string())
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: subject common name (CN) does not match node ID")
    ));
}

#[test]
/// Tests the error class of invalid issuer CNs by means
/// of a duplicate issuer CN.
fn should_fail_if_tls_certificate_has_invalid_issuer_cn() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .with_duplicate_issuer_cn()
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: invalid issuer common name (CN): found second common name (CN)")
    ));
}

#[test]
fn should_fail_if_tls_certificate_issuer_cn_not_equal_subject_cn() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .with_ca_signing(ed25519_key_pair(), "issuer CN, not node ID".to_string())
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: issuer common name (CN) does not match \
                           subject common name (CN)")
    ));
}

#[test]
fn should_fail_if_tls_certificate_version_is_not_3() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .version(2)
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: X509 version is not 3")
    ));
}

#[test]
fn should_fail_if_tls_certificate_notbefore_date_is_not_latest_in_two_minutes_from_now() {
    let node_id = node_id(1);
    let five_minutes_from_now = Utc::now() + Duration::minutes(5);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .not_before_unix(five_minutes_from_now.timestamp())
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: notBefore date")
        && error.contains("is later than two minutes from now")
    ));
}

#[test]
fn should_succeed_if_tls_certificate_notbefore_date_is_one_minute_from_now() {
    let node_id = node_id(1);
    let one_minute_from_now = Utc::now() + Duration::minutes(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .not_before_unix(one_minute_from_now.timestamp())
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(result.is_ok());
}

#[test]
fn should_fail_if_tls_certificate_notafter_date_is_not_99991231235959z() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .validity_days(42)
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: notAfter date is not RFC 5280 value 99991231235959Z")
    ));
}

#[test]
fn should_fail_if_tls_certificate_has_expired() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .validity_days(0)
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: notAfter date is not RFC 5280 value 99991231235959Z")
    ));
}

#[test]
fn should_fail_if_tls_certificate_signature_alg_is_not_ed25519() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .build_prime256v1()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: signature algorithm is not Ed25519 (OID 1.3.101.112)")
    ));
}

#[test]
fn should_fail_if_tls_certificate_pubkey_is_malformed() {
    let node_id = node_id(1);
    let key_pair_for_signing = ed25519_key_pair();
    let non_ed25519_key_pair = prime256v1_key_pair();
    assert_ne!(
        non_ed25519_key_pair.public_key_to_der().unwrap(),
        key_pair_for_signing.public_key_to_der().unwrap()
    );
    let cert_with_invalid_sig = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .with_ca_signing(key_pair_for_signing, node_id.get().to_string())
            .build(non_ed25519_key_pair, MessageDigest::null())
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert_with_invalid_sig, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: conversion to Ed25519 public key failed")
    ));
}

#[test]
fn should_fail_if_tls_certificate_pubkey_verification_fails() {
    let node_id = node_id(1);
    let mut cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };
    replace_tls_certificate_pubkey_with_invalid_one(&mut cert);

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: public key verification failed")
    ));
}

#[test]
fn should_fail_if_tls_certificate_signature_verification_fails() {
    let node_id = node_id(1);
    let key_pair_for_signing = ed25519_key_pair();
    let key_pair = ed25519_key_pair();
    assert_ne!(
        key_pair.public_key_to_der().unwrap(),
        key_pair_for_signing.public_key_to_der().unwrap()
    );
    let cert_that_is_not_self_signed = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .with_ca_signing(key_pair_for_signing, node_id.get().to_string())
            .build(key_pair, MessageDigest::null())
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert_that_is_not_self_signed, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("invalid TLS certificate: signature verification failed")
    ));
}

#[test]
fn should_fail_if_tls_certificate_is_ca() {
    let node_id = node_id(1);
    let cert = X509PublicKeyCert {
        certificate_der: valid_cert_builder(node_id)
            .set_ca_key_usage_extension()
            .build_ed25519()
            .x509()
            .to_der()
            .unwrap(),
    };

    let result = validate_tls_certificate(&cert, node_id);

    assert!(matches!(result, Err(TlsCertValidationError { error })
        if error.contains("BasicConstraints:CA is True")
    ));
}

fn valid_cert_builder(node_id: NodeId) -> CertBuilder {
    CertWithPrivateKey::builder().cn(node_id.get().to_string())
}

/// Replaces the TLS certificate's valid public key with an invalid one.
/// The replacement is done by directly manipulating the DER encoding rather
/// than using a respective API because such an API currently exists neither
/// in the openssl crate nor in the x509_parser crate.
fn replace_tls_certificate_pubkey_with_invalid_one(cert: &mut X509PublicKeyCert) {
    let x509_cert_der = &cert.certificate_der;
    let (_, x509_cert) = x509_parser::parse_x509_certificate(x509_cert_der).unwrap();
    let pubkey_raw = x509_cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    let range_of_pubkey_raw_in_der = range_of_needle_in_haystack(pubkey_raw, x509_cert_der);
    let invalid_pubkey = invalidate_valid_ed25519_pubkey_bytes(pubkey_raw);
    cert.certificate_der
        .splice(range_of_pubkey_raw_in_der, invalid_pubkey.0.iter().copied());
}

fn range_of_needle_in_haystack(needle: &[u8], haystack: &[u8]) -> Range<usize> {
    let position_of_needle_in_haystack =
        find_needle_in_haystack(needle, haystack).expect("cannot find needle in haystack");
    position_of_needle_in_haystack..(position_of_needle_in_haystack + needle.len())
}

/// Inefficient implementation for finding a needle in a haystack that is
/// efficient enough for our testing purposes.
fn find_needle_in_haystack(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|win| win == needle)
}

fn invalidate_valid_ed25519_pubkey(
    valid_pubkey: BasicSigEd25519PublicKeyBytes,
) -> BasicSigEd25519PublicKeyBytes {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let point_of_prime_order = CompressedEdwardsY(valid_pubkey.0).decompress().unwrap();
    let point_of_order_8 = CompressedEdwardsY([0; 32]).decompress().unwrap();
    let point_of_composite_order = point_of_prime_order + point_of_order_8;
    assert!(!point_of_composite_order.is_torsion_free());
    BasicSigEd25519PublicKeyBytes(point_of_composite_order.compress().0)
}

fn invalidate_valid_ed25519_pubkey_bytes(pubkey_bytes: &[u8]) -> BasicSigEd25519PublicKeyBytes {
    let mut buf = [0u8; BasicSigEd25519PublicKeyBytes::SIZE];
    buf.copy_from_slice(pubkey_bytes);
    invalidate_valid_ed25519_pubkey(BasicSigEd25519PublicKeyBytes(buf))
}

fn valid_cert_and_node_id() -> (X509PublicKeyCert, NodeId) {
    let temp_dir = temp_dir();
    let (node_keys, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
    (node_keys.tls_certificate.unwrap(), node_id)
}

fn node_id(n: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(n))
}
