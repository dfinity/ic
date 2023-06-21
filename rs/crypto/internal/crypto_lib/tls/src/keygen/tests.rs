#![allow(clippy::unwrap_used)]

use super::*;
use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
use openssl::pkey::{Id, Public};
use openssl::x509::X509VerifyResult;
use rand::SeedableRng;

const VALIDITY_SECS: i64 = 1000;
const NOT_BEFORE_SECS: i64 = 123;

#[test]
fn should_return_certificate_as_der() {
    let (cert, _sk) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair DER failed");

    let result = X509::from_der(&cert.bytes);

    assert!(result.is_ok());
}

#[test]
fn should_return_secret_key_as_der() {
    let (_cert, sk) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair DER failed");

    let result = PKey::private_key_from_der(sk.bytes.expose_secret());

    assert!(result.is_ok());
}

#[test]
fn should_return_self_signed_certificate() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    assert_eq!(cert.issued(&cert), X509VerifyResult::OK);
}

#[test]
fn should_validate_signature_with_own_public_key() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let public_key = cert.public_key().unwrap();
    assert_eq!(cert.verify(&public_key).ok(), Some(true));
}

#[test]
fn should_set_correct_signature_algorithm() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let signature_algorithm = cert.signature_algorithm().object();
    assert_eq!(signature_algorithm.nid().as_raw(), Id::ED25519.as_raw());
    assert_eq!(signature_algorithm.to_string(), "ED25519");
}

#[test]
fn should_generate_public_key_with_correct_algorithm() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let public_key: &PKey<Public> = &cert.public_key().unwrap();

    assert_eq!(public_key.id(), Id::ED25519);
}

#[test]
fn should_set_subject_cn_as_common_name() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let subject_name = cert.subject_name();
    assert_eq!(subject_name.entries_by_nid(Nid::COMMONNAME).count(), 1);
    let subject_cn = subject_name.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(b"common name", subject_cn.data().as_slice());
}

#[test]
fn should_set_issuer_cn_as_common_name() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let issuer_name = cert.issuer_name();
    assert_eq!(issuer_name.entries_by_nid(Nid::COMMONNAME).count(), 1);
    let issuer_cn = issuer_name.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(b"common name", issuer_cn.data().as_slice());
}

#[test]
fn should_set_issuer_cn_and_subject_cn_to_same_value() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    let subject_cn = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!(issuer_cn.data().as_slice(), subject_cn.data().as_slice());
}

/// Smoke tests that the certificate serial number that is generated at random is
/// indeed at most 20 octets according to https://tools.ietf.org/html/rfc5280
/// Section 4.1.2.2. The 19 bytes serial number argument is interpreted as an
/// unsigned integer and thus fits in 20 bytes, encoded as a signed ASN1 integer.
#[test]
fn should_have_serial_with_at_most_20_octets() {
    let max_serial_bytes: [u8; 19] = [255; 19];
    let max_serial_bignum = BigNum::from_slice(&max_serial_bytes).unwrap();

    for _ in 1..=10 {
        let (cert, _sk) = generate_tls_key_pair(
            &mut reproducible_rng(),
            "common name",
            &not_before(),
            &not_after(),
        )
        .expect("generation of TLS key pair failed");
        assert!(cert.serial_number().to_bn().unwrap() <= max_serial_bignum);
    }
}

#[test]
fn should_not_set_subject_alt_name() {
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    let subject_alt_names = cert.subject_alt_names();
    assert!(subject_alt_names.is_none());
}

#[test]
fn should_set_not_before_correctly() {
    let not_before = not_before();
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before,
        &not_after(),
    )
    .expect("generation of TLS key pair failed");

    assert!(cert.not_before() == not_before);
}

#[test]
fn should_return_error_if_not_after_date_is_not_after_not_before_date() {
    let not_after = Asn1Time::from_str_x509("19700101000000Z").unwrap();
    let not_before = Asn1Time::from_str_x509("19700101000001Z").unwrap();
    let result = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before,
        &not_after,
    );
    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidNotAfterDate { message })
        if message.contains(&format!("'not after' date ({}) must be after 'not before' date ", *not_after))
    );
}

#[test]
fn should_return_error_if_not_after_date_equals_not_before_date() {
    let not_after = Asn1Time::from_str_x509("19700101000000Z").unwrap();
    let not_before = Asn1Time::from_str_x509("19700101000000Z").unwrap();
    let result = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before,
        &not_after,
    );
    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidNotAfterDate { message })
        if message.contains(&format!("'not after' date ({}) must be after 'not before' date ", *not_after))
    );
}

#[test]
fn should_set_not_after_correctly() {
    let not_after = &not_after();
    let (cert, _sk) = generate_tls_key_pair(
        &mut reproducible_rng(),
        "common name",
        &not_before(),
        not_after,
    )
    .expect("generation of TLS key pair failed");

    assert!(cert.not_after() == not_after);
}

#[test]
fn should_redact_tls_ed25519_secret_key_der_bytes_debug() {
    let sk = TlsEd25519SecretKeyDerBytes::new(vec![1u8; 5]);
    assert_eq!(format!("{:?}", sk), "REDACTED");
}

#[test]
fn should_have_stable_representation_of_private_key() {
    let mut rng = ReproducibleRng::from_seed([0x42u8; 32]);

    let (_cert, sk) =
        generate_tls_key_pair_der(&mut rng, "common name", &not_before(), &not_after())
            .expect("generation of TLS key pair failed");

    let serialized_sk = serde_cbor::to_vec(&sk).unwrap();

    assert_eq!(hex::encode(serialized_sk),
               "a16562797465735830302e020100300506032b657004220420ff2fa8b8bea7a4d9aa95a41cffcd0fd54cb020cf83af28ea5ad80335ea48a959");
}

fn not_before() -> Asn1Time {
    Asn1Time::from_unix(NOT_BEFORE_SECS).expect("failed to construct Asn1Time date")
}

fn not_after() -> Asn1Time {
    Asn1Time::from_unix(NOT_BEFORE_SECS + VALIDITY_SECS).expect("failed to construct Asn1Time date")
}
