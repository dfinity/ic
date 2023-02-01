use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use assert_matches::assert_matches;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::vault::api::CspTlsSignError;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use std::sync::Arc;
use tokio_rustls::rustls::internal::msgs::enums::SignatureAlgorithm;
use tokio_rustls::rustls::sign::SigningKey;
use tokio_rustls::rustls::{SignatureScheme, TLSError};

#[test]
fn should_produce_same_signature_as_csp_server_if_ed25519_is_chosen() {
    let tls_certificate = tls_public_key_certificate();
    let key_id = KeyId::from(&tls_certificate);
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

    let signing_key = CspServerEd25519SigningKey::new(&tls_certificate, Arc::new(vault));
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
        &tls_public_key_certificate(),
        Arc::new(MockLocalCspVault::new()),
    );

    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ED25519);
}

#[test]
fn should_return_no_signer_if_ed25519_not_offered() {
    let signing_key = CspServerEd25519SigningKey::new(
        &tls_public_key_certificate(),
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
        &tls_public_key_certificate(),
        Arc::new(MockLocalCspVault::new()),
    );
    let signer = signing_key
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .expect("failed to sign");

    assert_eq!(signer.get_scheme(), SignatureScheme::ED25519);
}

#[test]
fn should_return_error_from_csp() {
    let tls_certificate = tls_public_key_certificate();
    let key_id = KeyId::from(&tls_certificate);
    let msg_to_sign = b"some message";
    let mut vault = MockLocalCspVault::new();
    vault
        .expect_tls_sign()
        .times(1)
        .withf(move |message_, key_id_| message_ == msg_to_sign && *key_id_ == key_id)
        .return_const(Err(CspTlsSignError::SecretKeyNotFound { key_id }));

    let signing_key = CspServerEd25519SigningKey::new(&tls_certificate, Arc::new(vault));
    let signer = signing_key
        .choose_scheme(&[SignatureScheme::ED25519])
        .expect("failed to choose scheme");
    let result = signer.sign("some message".as_bytes());

    assert_matches!(result, Err(TLSError::General(message))
         if message.contains("Failed to create signature during TLS handshake by means of the CspServerEd25519Signer: SecretKeyNotFound")
    );
}

fn tls_public_key_certificate() -> TlsPublicKeyCert {
    let certificate_der = hex_decode(
        "3082015630820108a00302010202140098d074\
                7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
                c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
                6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
                232313130343138313231345a180f39393939313233313233353935395a304a314830\
                4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
                365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
                6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
                9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
                649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
                bb905f52faf28707735f1d90ab654380b",
    );
    TlsPublicKeyCert::new_from_der(certificate_der).expect("invalid certificated der")
}

fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    hex::decode(data).expect("failed to decode hex")
}
