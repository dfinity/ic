#![allow(clippy::unwrap_used)]
use ic_crypto_tls::generate_tls_keys;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::x509::{X509NameEntries, X509VerifyResult, X509};

const NOT_AFTER: &str = "20701231235959Z";

#[test]
fn should_generate_valid_self_signed_certificate() {
    let (cert, _sk) = generate_tls_keys("some common name", NOT_AFTER);

    let x509_cert = X509::from_pem(&cert.to_pem().unwrap()).unwrap();
    let public_key = x509_cert.public_key().unwrap();
    assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
    assert_eq!(x509_cert.issued(&x509_cert), X509VerifyResult::OK);
}

#[test]
fn should_set_cert_subject_cn() {
    const SUBJECT_CN: &str = "some common name";

    let (cert, _sk) = generate_tls_keys(SUBJECT_CN, NOT_AFTER);

    let x509_cert = X509::from_pem(&cert.to_pem().unwrap()).unwrap();
    assert_eq!(subject_cn_entries(&x509_cert).count(), 1);
    let subject_cn = subject_cn_entries(&x509_cert).next().unwrap();
    assert_eq!(SUBJECT_CN.as_bytes(), subject_cn.data().as_slice());
}

#[test]
fn should_set_cert_issuer_cn_to_subject_cn() {
    const SUBJECT_CN: &str = "some common name";

    let (cert, _sk) = generate_tls_keys(SUBJECT_CN, NOT_AFTER);

    let x509_cert = X509::from_pem(&cert.to_pem().unwrap()).unwrap();
    assert_eq!(issuer_cn_entries(&x509_cert).count(), 1);
    let issuer_cn = issuer_cn_entries(&x509_cert).next().unwrap();
    assert_eq!(SUBJECT_CN.as_bytes(), issuer_cn.data().as_slice());
}

#[test]
fn should_set_different_serial_numbers_for_multiple_certs() {
    let (cert_1, _sk_1) = generate_tls_keys("some common name 1", NOT_AFTER);
    let (cert_2, _sk_2) = generate_tls_keys("some common name 2", NOT_AFTER);
    let (cert_3, _sk_3) = generate_tls_keys("some common name 3", NOT_AFTER);

    let x509_cert_1 = X509::from_pem(&cert_1.to_pem().unwrap()).unwrap();
    let x509_cert_2 = X509::from_pem(&cert_2.to_pem().unwrap()).unwrap();
    let x509_cert_3 = X509::from_pem(&cert_3.to_pem().unwrap()).unwrap();
    let serial_1 = serial_number(&x509_cert_1);
    let serial_2 = serial_number(&x509_cert_2);
    let serial_3 = serial_number(&x509_cert_3);
    assert_ne!(serial_1, serial_2);
    assert_ne!(serial_2, serial_3);
    assert_ne!(serial_1, serial_3);
}

#[test]
fn should_set_cert_not_after_correctly() {
    const NOT_AFTER: &str = "20701231235959Z";

    let (cert, _sk) = generate_tls_keys("some common name", NOT_AFTER);

    let x509_cert = X509::from_pem(&cert.to_pem().unwrap()).unwrap();
    assert!(x509_cert.not_after() == Asn1Time::from_str_x509(NOT_AFTER).unwrap());
}

#[test]
#[should_panic(expected = "'not after' date must not be in the past")]
fn should_return_error_if_not_after_is_in_the_past() {
    const NOT_AFTER: &str = "19991231235959Z";

    let _panic = generate_tls_keys("some common name", NOT_AFTER);
}

#[test]
#[should_panic(expected = "unable to parse not after as ASN1Time")]
fn should_return_error_if_not_after_cannot_be_parsed() {
    const INVALID_NOT_AFTER: &str = "cannot be parsed as date";

    let _panic = generate_tls_keys("some common name", INVALID_NOT_AFTER);
}

fn issuer_cn_entries(x509_cert: &X509) -> X509NameEntries {
    x509_cert.issuer_name().entries_by_nid(Nid::COMMONNAME)
}

fn subject_cn_entries(x509_cert: &X509) -> X509NameEntries {
    x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
}

fn serial_number(cert: &X509) -> BigNum {
    cert.serial_number().to_bn().unwrap()
}
