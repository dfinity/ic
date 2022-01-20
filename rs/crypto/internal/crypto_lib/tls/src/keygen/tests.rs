#![allow(clippy::unwrap_used)]
use super::*;
use openssl::pkey::{Id, Public};
use openssl::x509::X509VerifyResult;
use rand::rngs::ThreadRng;

const SERIAL: [u8; 19] = [42; 19];
const VALIDITY_DAYS: u32 = 365;

#[test]
fn should_return_certificate_as_der() {
    let (cert, _sk) = generate_tls_key_pair_der(&mut csprng(), "common name", SERIAL, &not_after());

    let result = X509::from_der(&cert.bytes);

    assert!(result.is_ok());
}

#[test]
fn should_return_secret_key_as_der() {
    let (_cert, sk) = generate_tls_key_pair_der(&mut csprng(), "common name", SERIAL, &not_after());

    let result = PKey::private_key_from_der(&sk.bytes);

    assert!(result.is_ok());
}

#[test]
fn should_return_self_signed_certificate() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    assert_eq!(cert.issued(&cert), X509VerifyResult::OK);
}

#[test]
fn should_validate_signature_with_own_public_key() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let public_key = cert.public_key().unwrap();
    assert_eq!(cert.verify(&public_key).ok(), Some(true));
}

#[test]
fn should_set_correct_signature_algorithm() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let signature_algorithm = cert.signature_algorithm().object();
    assert_eq!(signature_algorithm.nid().as_raw(), Id::ED25519.as_raw());
    assert_eq!(signature_algorithm.to_string(), "ED25519");
}

#[test]
fn should_generate_public_key_with_correct_algorithm() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let public_key: &PKey<Public> = &cert.public_key().unwrap();

    assert_eq!(public_key.id(), Id::ED25519);
}

#[test]
fn should_set_subject_cn_as_common_name() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let subject_name = cert.subject_name();
    assert_eq!(subject_name.entries_by_nid(Nid::COMMONNAME).count(), 1);
    let subject_cn = subject_name.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(b"common name", subject_cn.data().as_slice());
}

#[test]
fn should_set_issuer_cn_as_common_name() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let issuer_name = cert.issuer_name();
    assert_eq!(issuer_name.entries_by_nid(Nid::COMMONNAME).count(), 1);
    let issuer_cn = issuer_name.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(b"common name", issuer_cn.data().as_slice());
}

#[test]
fn should_set_issuer_cn_and_subject_cn_to_same_value() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

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

#[test]
fn should_set_serial_number() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let serial = cert.serial_number().to_bn().unwrap();
    let expected_serial = BigNum::from_slice(&SERIAL).unwrap();
    assert_eq!(expected_serial, serial);
}

#[test]
fn should_set_max_serial_number() {
    let max_serial: [u8; 19] = [255; 19];
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", max_serial, &not_after());

    let serial = cert.serial_number().to_bn().unwrap();
    let expected_serial = BigNum::from_slice(&max_serial).unwrap();
    assert_eq!(expected_serial, serial);
}

#[test]
fn should_not_set_subject_alt_name() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let subject_alt_names = cert.subject_alt_names();
    assert!(subject_alt_names.is_none());
}

#[test]
fn should_set_not_before_to_now() {
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &not_after());

    let now = Asn1Time::days_from_now(0).unwrap();
    let not_before = cert.not_before();
    assert!(not_before <= now);
}

#[test]
#[should_panic(expected = "'not after' date must not be in the past")]
fn should_panic_if_not_after_date_is_in_the_past() {
    let date_in_the_past = Asn1Time::from_str_x509("20211004235959Z").unwrap();
    let _panic = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, &date_in_the_past);
}

#[test]
fn should_set_not_after_correctly() {
    let not_after = &not_after();
    let (cert, _sk) = generate_tls_key_pair(&mut csprng(), "common name", SERIAL, not_after);

    assert!(cert.not_after() == not_after);
}

#[test]
fn should_redact_tls_ed25519_secret_key_der_bytes_debug() {
    let sk = TlsEd25519SecretKeyDerBytes {
        bytes: vec![1u8, 5],
    };
    assert_eq!(format!("{:?}", sk), "REDACTED");
}

fn csprng() -> ThreadRng {
    rand::thread_rng()
}

fn not_after() -> Asn1Time {
    Asn1Time::days_from_now(VALIDITY_DAYS).expect("failed to construct Asn1Time date")
}
