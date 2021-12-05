use crate::tls_stub::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use ic_crypto_internal_csp::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::LocalCspVault;
use ic_crypto_internal_csp::TlsHandshakeCspVault;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_test_utils::tls::x509_certificates::generate_ed25519_tlscert;
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities::types::ids::NODE_1;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio_rustls::rustls::internal::msgs::enums::SignatureAlgorithm;
use tokio_rustls::rustls::sign::SigningKey;
use tokio_rustls::rustls::{SignatureScheme, TLSError};

const NOT_AFTER: &str = "25670102030405Z";

#[test]
fn should_produce_same_signature_as_csp_server_if_ed25519_is_chosen() {
    let csp_server = Arc::new(local_csp_server());
    let (key_id, cert) = csp_server
        .gen_tls_key_pair(NODE_1, NOT_AFTER)
        .expect("Generation of TLS keys failed.");
    let msg_to_sign = "some message";
    let expected_sig_bytes = match csp_server
        .tls_sign(msg_to_sign.as_bytes(), &key_id)
        .expect("failed to sign")
    {
        CspSignature::Ed25519(sig_bytes) => sig_bytes.0.to_vec(),
        _ => panic!("expected Ed25519 signature"),
    };

    let signing_key = CspServerEd25519SigningKey::new(&cert, csp_server);
    let signer = signing_key
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .expect("failed to choose scheme");
    let sig_bytes = signer.sign(msg_to_sign.as_bytes()).expect("failed to sign");

    assert!(!sig_bytes.is_empty());
    // We don't verify the ed25519 signature here since this is the responsibility
    // of the csp_server.
    assert_eq!(sig_bytes, expected_sig_bytes);
}

#[test]
fn should_return_ed25519_as_signing_key_algorithm() {
    let csp_server = Arc::new(local_csp_server());
    let (_, cert) = csp_server
        .gen_tls_key_pair(NODE_1, NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let signing_key = CspServerEd25519SigningKey::new(&cert, csp_server);

    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ED25519);
}

#[test]
fn should_return_no_signer_if_ed25519_not_offered() {
    let csp_server = Arc::new(local_csp_server());
    let (_, cert) = csp_server
        .gen_tls_key_pair(NODE_1, NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let signing_key = CspServerEd25519SigningKey::new(&cert, csp_server);
    let signer = signing_key.choose_scheme(&[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
    ]);

    assert!(signer.is_none());
}

#[test]
fn should_return_ed25519_as_signer_scheme() {
    let csp_server = Arc::new(local_csp_server());
    let (_, cert) = csp_server
        .gen_tls_key_pair(NODE_1, NOT_AFTER)
        .expect("Generation of TLS keys failed.");

    let signing_key = CspServerEd25519SigningKey::new(&cert, csp_server);
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
    let csp_server = Arc::new(local_csp_server());

    let (_, cert_without_private_key_in_store) = generate_ed25519_tlscert();

    let signing_key =
        CspServerEd25519SigningKey::new(&cert_without_private_key_in_store, csp_server);
    let signer = signing_key
        .choose_scheme(&[SignatureScheme::ED25519])
        .expect("failed to choose scheme");
    let result = signer.sign("some message".as_bytes());

    assert!(matches!(result, Err(TLSError::General(message))
             if message.contains("Failed to create signature during TLS handshake by means of the CspServerEd25519Signer: SecretKeyNotFound")
    ));
}

fn local_csp_server() -> LocalCspVault<OsRng, VolatileSecretKeyStore, VolatileSecretKeyStore> {
    LocalCspVault::new_with_os_rng(
        VolatileSecretKeyStore::new(),
        VolatileSecretKeyStore::new(),
        Arc::new(CryptoMetrics::none()),
        no_op_logger(),
    )
}
