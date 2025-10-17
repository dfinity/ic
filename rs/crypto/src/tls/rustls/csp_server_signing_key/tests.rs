use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::vault::api::CspTlsSignError;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use rustls::{Error as TLSError, SignatureAlgorithm, SignatureScheme, sign::SigningKey};
use std::sync::Arc;

#[test]
fn should_produce_same_signature_as_csp_server_if_ed25519_is_chosen() {
    let key_id = tls_public_key_certificate_key_id();
    let msg_to_sign = b"some message";
    let expected_signature_bytes = [1_u8; 64];
    let mut vault = MockLocalCspVault::new();
    vault
        .expect_tls_sign()
        .times(1)
        .withf(move |message_, key_id_| message_ == msg_to_sign && *key_id_ == key_id)
        .return_const(Ok(CspSignature::Ed25519(ed25519_types::SignatureBytes(
            expected_signature_bytes,
        ))));

    let signing_key = CspServerEd25519SigningKey::new(key_id, Arc::new(vault));
    let signer = signing_key
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .expect("failed to choose scheme");
    let signature_bytes = signer.sign(msg_to_sign);

    assert_matches!(signature_bytes, Ok(actual) if actual == expected_signature_bytes.to_vec());
}

#[test]
fn should_return_ed25519_as_signing_key_algorithm() {
    let signing_key = CspServerEd25519SigningKey::new(
        tls_public_key_certificate_key_id(),
        Arc::new(MockLocalCspVault::new()),
    );

    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ED25519);
}

#[test]
fn should_return_no_signer_if_ed25519_not_offered() {
    let signing_key = CspServerEd25519SigningKey::new(
        tls_public_key_certificate_key_id(),
        Arc::new(MockLocalCspVault::new()),
    );
    let signer = signing_key.choose_scheme(&[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
    ]);

    assert!(signer.is_none());
}

#[test]
fn should_return_ed25519_as_signer_scheme() {
    let signing_key = CspServerEd25519SigningKey::new(
        tls_public_key_certificate_key_id(),
        Arc::new(MockLocalCspVault::new()),
    );
    let signer = signing_key
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .expect("failed to sign");

    assert_eq!(signer.scheme(), SignatureScheme::ED25519);
}

#[test]
fn should_return_error_from_csp() {
    let key_id = tls_public_key_certificate_key_id();
    let msg_to_sign = b"some message";
    let mut vault = MockLocalCspVault::new();
    vault
        .expect_tls_sign()
        .times(1)
        .withf(move |message_, key_id_| message_ == msg_to_sign && *key_id_ == key_id)
        .return_const(Err(CspTlsSignError::SecretKeyNotFound { key_id }));
    let signing_key = CspServerEd25519SigningKey::new(key_id, Arc::new(vault));
    let signer = signing_key
        .choose_scheme(&[SignatureScheme::ED25519])
        .expect("failed to choose scheme");

    let result = signer.sign("some message".as_bytes());

    assert_matches!(result, Err(TLSError::General(message))
         if message.contains("Failed to create signature during TLS handshake by means of the CspServerEd25519Signer: SecretKeyNotFound")
    );
}

fn tls_public_key_certificate_key_id() -> KeyId {
    KeyId::from([
        33, 64, 176, 153, 202, 203, 77, 103, 99, 53, 40, 124, 149, 143, 14, 250, 60, 107, 18, 199,
        97, 227, 145, 240, 166, 78, 29, 145, 34, 13, 150, 32,
    ])
}
