use std::time::Duration;

use assert_matches::assert_matches;
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;
use ic_crypto_internal_tls::TlsKeyPairAndCertGenerationError;
use ic_crypto_internal_tls::generate_tls_key_pair_der;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::time::{GENESIS, Time};
use ic_types::{NodeId, PrincipalId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use time::OffsetDateTime;
use time::macros::datetime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::{X509Name, X509Version};

#[test]
fn should_generate_x509_v3_certificate_in_der_encoding() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    assert_matches!(
        X509Certificate::from_der(&cert.bytes), Ok((remainder, x509))
        if remainder.is_empty() && x509.version() == X509Version::V3
    );
}

#[test]
fn should_generate_ed25519_secret_key_as_pkcs8_v1_format_in_der_encoding() {
    let (_cert, secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    assert_matches!(
        ic_ed25519::PrivateKey::deserialize_pkcs8(secret_key.bytes.expose_secret()),
        Ok(_)
    );
}

#[test]
fn should_have_stable_representation_of_private_key() {
    let rng = &mut ChaCha20Rng::from_seed([0x42u8; 32]);

    let (_cert, secret_key) =
        generate_tls_key_pair_der(rng, "common name", not_before(), not_after())
            .expect("failed to generate TLS keys");

    let serialized_sk = serde_cbor::to_vec(&secret_key).unwrap();

    assert_eq!(
        hex::encode(serialized_sk),
        "a16562797465735830302e020100300506032b657004220420ff2fa8b8bea7a4d9aa95a41cffcd0fd54cb020cf83af28ea5ad80335ea48a959"
    );
}

#[test]
fn should_generate_self_signed_certificate() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();

    let sig = x509.signature_value.data.to_vec();
    let msg = x509.tbs_certificate.as_ref();

    let pk = ic_ed25519::PublicKey::deserialize_raw(
        &x509.tbs_certificate.subject_pki.subject_public_key.data,
    )
    .expect("conversion to Ed25519 public key failed");

    assert_eq!(pk.verify_signature(msg, &sig), Ok(()));
}

#[test]
fn should_set_correct_signature_algorithm() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(
        x509.signature_algorithm.oid(),
        &x509_parser::oid_registry::OID_SIG_ED25519,
    );
}

#[test]
fn should_generate_valid_public_key_with_correct_algorithm() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();

    // Parsing implicitly validates the key
    let _pk = ic_ed25519::PublicKey::deserialize_raw(
        &x509.tbs_certificate.subject_pki.subject_public_key.data,
    )
    .expect("conversion to Ed25519 public key failed");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(
        x509.public_key().algorithm.oid(),
        &x509_parser::oid_registry::OID_SIG_ED25519
    );
}

#[test]
fn should_generate_cert_with_equal_and_correct_subject_cn_and_issuer_cn() {
    let common_name = "a common name, I am";
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        common_name,
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(x509.subject(), x509.issuer());
    assert_single_cn_eq(x509.subject(), common_name);
    assert_single_cn_eq(x509.issuer(), common_name);
}

/// Smoke tests that the certificate serial number that is generated at random is
/// indeed at most 20 octets according to https://tools.ietf.org/html/rfc5280
/// Section 4.1.2.2. The 19 bytes serial number argument is interpreted as an
/// unsigned integer and thus fits in 20 bytes, encoded as a signed ASN1 integer.
#[test]
fn should_have_serial_with_at_most_20_octets() {
    let max_serial_bytes: [u8; 19] = [255; 19];
    let max_serial_biguint = x509_parser::num_bigint::BigUint::from_bytes_be(&max_serial_bytes);

    let rng = &mut reproducible_rng();
    for _ in 1..=10 {
        let (cert, _secret_key) =
            generate_tls_key_pair_der(rng, "common name", not_before(), not_after())
                .expect("failed to generate TLS keys");

        let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
        assert!(x509.serial <= max_serial_biguint);
    }
}

#[test]
fn should_not_set_subject_alt_name() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(x509.subject_alternative_name(), Ok(None));
}

#[test]
fn should_set_not_before_correctly() {
    let not_before = GENESIS;
    let not_after = GENESIS + Duration::from_secs(12345);
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before.as_secs_since_unix_epoch(),
        not_after.as_secs_since_unix_epoch(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(
        x509.validity().not_before.timestamp(),
        unix_timestamp(not_before)
    );
}

#[test]
fn should_set_not_after_correctly() {
    let not_before = GENESIS;
    let not_after = GENESIS + Duration::from_secs(12345);
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before.as_secs_since_unix_epoch(),
        not_after.as_secs_since_unix_epoch(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert_eq!(
        x509.validity().not_after.timestamp(),
        unix_timestamp(not_after)
    );
}

#[test]
fn should_fail_if_notafter_date_is_not_after_notbefore_date() {
    let not_before = GENESIS;
    let not_after = not_before;
    let not_before_str = OffsetDateTime::from_unix_timestamp(unix_timestamp(not_before))
        .unwrap()
        .to_string();
    let not_after_str = OffsetDateTime::from_unix_timestamp(unix_timestamp(not_after))
        .unwrap()
        .to_string();

    let result = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before.as_secs_since_unix_epoch(),
        not_after.as_secs_since_unix_epoch(),
    );

    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidArguments(e))
        if e.contains(&format!("notBefore date ({not_before_str}) must be before notAfter date ({not_after_str})"))
    );
}

#[test]
fn should_fail_if_notbefore_date_is_too_large_for_i64() {
    let result = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        u64::MAX,
        GENESIS.as_secs_since_unix_epoch(),
    );

    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidArguments(e))
        if e == "invalid notBefore date: failed to convert to i64"
    );
}

#[test]
fn should_fail_if_notbefore_date_is_invalid_offsetdatetime() {
    let max_possible_offsetdatetime = 253_402_300_799_u64; // unix timestamp for "99991231235959Z" == "9999-12-31 23:59:59.0 +00:00:00"

    let result = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        max_possible_offsetdatetime + 1,
        0,
    );

    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidArguments(e))
        if e.starts_with("invalid notBefore date: failed to convert to OffsetDateTime")
    );
}

#[test]
fn should_fail_if_notafter_date_is_too_large_for_i64() {
    let result = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        GENESIS.as_secs_since_unix_epoch(),
        u64::MAX,
    );

    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidArguments(e))
        if e == "invalid notAfter date: failed to convert to i64"
    );
}

#[test]
fn should_fail_if_notafter_date_is_invalid_offsetdatetime() {
    let max_possible_offsetdatetime = 253_402_300_799_u64; // unix timestamp for "99991231235959Z" == "9999-12-31 23:59:59.0 +00:00:00"

    let result = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        GENESIS.as_secs_since_unix_epoch(),
        max_possible_offsetdatetime + 1,
    );

    assert_matches!(result, Err(TlsKeyPairAndCertGenerationError::InvalidArguments(e))
        if e.starts_with("invalid notAfter date: failed to convert to OffsetDateTime")
    );
}

#[test]
fn should_redact_tls_ed25519_secret_key_der_bytes_debug() {
    let sk = TlsEd25519SecretKeyDerBytes::new(vec![1u8; 5]);
    assert_eq!(format!("{sk:?}"), "REDACTED");
}

#[test]
fn should_generate_non_ca_cert() {
    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        "common name",
        not_before(),
        not_after(),
    )
    .expect("failed to generate TLS keys");

    let (_remainder, x509) = X509Certificate::from_der(&cert.bytes).unwrap();
    assert!(!x509.tbs_certificate.is_ca());
}

#[test]
fn should_create_cert_that_passes_node_key_validation() {
    let node_id = node_id(4242);
    let not_before = GENESIS
        .saturating_sub(Duration::from_secs(1000))
        .as_secs_since_unix_epoch();
    let not_after = datetime!(9999-12-31 23:59:59 UTC).unix_timestamp() as u64;
    let current_time = GENESIS;

    let (cert, _secret_key) = generate_tls_key_pair_der(
        &mut reproducible_rng(),
        node_id.get().to_string().as_str(),
        not_before,
        not_after,
    )
    .expect("failed to generate TLS keys");

    assert_matches!(
        ic_crypto_node_key_validation::ValidTlsCertificate::try_from((
            ic_protobuf::registry::crypto::v1::X509PublicKeyCert {
                certificate_der: cert.bytes,
            },
            node_id,
            current_time,
        )),
        Ok(_)
    );
}

fn assert_single_cn_eq(name: &X509Name<'_>, cn_str: &str) {
    let mut cn_iter = name.iter_common_name();
    let first_cn_str = cn_iter
        .next()
        .unwrap()
        .as_str()
        .expect("common name (CN) not a string");
    assert_eq!(first_cn_str, cn_str);
    assert_eq!(cn_iter.next(), None, "more than one common name");
}

fn node_id(n: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(n))
}

fn not_before() -> u64 {
    GENESIS.as_secs_since_unix_epoch()
}

fn not_after() -> u64 {
    (GENESIS + Duration::from_secs(1000)).as_secs_since_unix_epoch()
}

fn unix_timestamp(time: Time) -> i64 {
    i64::try_from(time.as_secs_since_unix_epoch()).expect("invalid i64")
}
