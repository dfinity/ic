#![allow(clippy::unwrap_used)]
use crate::api::tls_errors::CspTlsServerHandshakeError;
use crate::api::CspTlsServerHandshake;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::tls_stub::test_utils::{
    dummy_csprng, secret_key_store_with_csp_key, secret_key_store_with_key,
    tls_secret_key_with_bytes,
};
use crate::types::CspSecretKey;
use crate::Csp;
use ic_crypto_internal_multi_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_test_utils::tls::x509_certificates::{generate_ed25519_tlscert, private_key_to_der};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use openssl::ssl::SslVerifyMode;
use std::collections::HashSet;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn should_return_acceptor_from_clib_if_no_error_occurs() {
    let (private_key, self_cert) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_client_cert) = generate_ed25519_tlscert();

    let mut trusted_certs_set = HashSet::new();
    assert!(trusted_certs_set.insert(trusted_client_cert));
    let acceptor = csp
        .tls_acceptor(self_cert.clone(), Some(trusted_certs_set))
        .unwrap();

    // only check a few acceptor properties (details are tested in the CLib)
    assert_eq!(
        TlsPublicKeyCert::new_from_x509(acceptor.context().certificate().unwrap().to_owned())
            .expect("failed to convert X509 to TlsPublicKeyCert"),
        self_cert
    );
    assert_eq!(
        private_key_to_der(acceptor.context().private_key().unwrap()),
        private_key_to_der(&private_key)
    );
}

#[test]
fn should_return_acceptor_with_correct_verify_peer_settings_with_auth() {
    let (private_key, self_cert) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_client_cert) = generate_ed25519_tlscert();

    let mut trusted_certs_set = HashSet::new();
    assert!(trusted_certs_set.insert(trusted_client_cert));
    let acceptor_with_auth = csp
        .tls_acceptor(self_cert, Some(trusted_certs_set))
        .unwrap();

    assert_eq!(
        acceptor_with_auth.context().verify_mode(),
        SslVerifyMode::PEER
    );
}

#[test]
fn should_return_acceptor_with_correct_verify_peer_settings_without_auth() {
    let (private_key, self_cert) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);

    let acceptor_no_auth = csp.tls_acceptor(self_cert, None).unwrap();

    assert_eq!(
        acceptor_no_auth.context().verify_mode(),
        SslVerifyMode::NONE
    );
}

#[tokio::test]
async fn should_return_create_acceptor_error_from_clib() {
    let (private_key, self_cert) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);

    let result = csp
        .perform_tls_server_handshake(dummy_tcp_stream().await, self_cert, HashSet::new())
        .await;

    assert!(matches!(result,
            Err(CspTlsServerHandshakeError::CreateAcceptorError{description, .. })
            if description == "The trusted client certs must not be empty."));
}

#[tokio::test]
async fn should_return_error_if_secret_key_not_found() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let empty_sks = TempSecretKeyStore::new();
    let csp = Csp::of(dummy_csprng(), empty_sks);

    let result = csp
        .perform_tls_server_handshake(dummy_tcp_stream().await, self_cert, HashSet::new())
        .await;

    assert!(matches!(
        result,
        Err(CspTlsServerHandshakeError::SecretKeyNotFound)
    ));
}

#[tokio::test]
async fn should_return_error_if_secret_key_not_found_no_client_auth() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let empty_sks = TempSecretKeyStore::new();
    let csp = Csp::of(dummy_csprng(), empty_sks);

    let result = csp
        .perform_tls_server_handshake_without_client_auth(dummy_tcp_stream().await, self_cert)
        .await;

    assert!(matches!(
        result,
        Err(CspTlsServerHandshakeError::SecretKeyNotFound)
    ));
}

#[tokio::test]
async fn should_return_error_on_wrong_secret_key_type() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let secret_key_with_wrong_type =
        CspSecretKey::MultiBls12_381(SecretKeyBytes([42; SecretKeyBytes::SIZE]));
    let sks = secret_key_store_with_csp_key(&self_cert, secret_key_with_wrong_type);
    let csp = Csp::of(dummy_csprng(), sks);

    let result = csp
        .perform_tls_server_handshake(dummy_tcp_stream().await, self_cert, HashSet::new())
        .await;

    assert!(matches!(
        result,
        Err(CspTlsServerHandshakeError::WrongSecretKeyType)
    ));
}

#[tokio::test]
async fn should_return_error_on_malformed_secret_key() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let malformed_secret_key = tls_secret_key_with_bytes(vec![42; 10]);
    let sks = secret_key_store_with_csp_key(&self_cert, malformed_secret_key);
    let csp = Csp::of(dummy_csprng(), sks);

    let result = csp
        .perform_tls_server_handshake(dummy_tcp_stream().await, self_cert, HashSet::new())
        .await;

    assert!(matches!(
        result,
        Err(CspTlsServerHandshakeError::MalformedSecretKey { .. })
    ));
}

async fn dummy_tcp_stream() -> TcpStream {
    let listener = TcpListener::bind(("0.0.0.0", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}
