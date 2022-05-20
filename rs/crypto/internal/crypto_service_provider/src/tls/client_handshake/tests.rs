#![allow(clippy::unwrap_used)]
use crate::api::tls_errors::CspTlsClientHandshakeError;
use crate::api::CspTlsClientHandshake;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::tls::test_utils::{
    dummy_csprng, secret_key_store_with_csp_key, secret_key_store_with_key,
    tls_secret_key_with_bytes,
};
use crate::types::CspSecretKey;
use crate::Csp;
use ic_crypto_internal_multi_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_test_utils::tls::x509_certificates::{generate_ed25519_tlscert, private_key_to_der};
use ic_crypto_tls_interfaces::{TlsPublicKeyCert, TlsStream};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn should_return_connector_from_clib_if_no_error_occurs() {
    let (private_key, self_cert) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_server_cert) = generate_ed25519_tlscert();

    let connector = csp
        .tls_connector(self_cert.clone(), trusted_server_cert)
        .unwrap();

    // only check a few connector properties (details are tested in the CLib)
    assert_eq!(
        TlsPublicKeyCert::new_from_x509(connector.ssl_context().certificate().unwrap().to_owned())
            .expect("failed to convert X509 to TlsPublicKeyCert"),
        self_cert
    );
    assert_eq!(
        private_key_to_der(connector.ssl_context().private_key().unwrap()),
        private_key_to_der(&private_key)
    );
}

#[tokio::test]
async fn should_return_create_connector_error_from_clib() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let (inconsistent_private_key, _) = generate_ed25519_tlscert();
    let sks = secret_key_store_with_key(&inconsistent_private_key, &self_cert);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_server_cert) = generate_ed25519_tlscert();

    let result = csp
        .perform_tls_client_handshake(dummy_tcp_stream().await, self_cert, trusted_server_cert)
        .await;

    assert_create_connector_error(result, "Inconsistent private key and certificate.")
}

#[tokio::test]
async fn should_return_error_if_secret_key_not_found() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let empty_sks = TempSecretKeyStore::new();
    let csp = Csp::of(dummy_csprng(), empty_sks);
    let (_, trusted_server_cert) = generate_ed25519_tlscert();

    let result = csp
        .perform_tls_client_handshake(dummy_tcp_stream().await, self_cert, trusted_server_cert)
        .await;

    assert!(matches!(
        result,
        Err(CspTlsClientHandshakeError::SecretKeyNotFound)
    ));
}

#[tokio::test]
async fn should_return_error_on_wrong_secret_key_type() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let secret_key_with_wrong_type =
        CspSecretKey::MultiBls12_381(SecretKeyBytes([42; SecretKeyBytes::SIZE]));
    let sks = secret_key_store_with_csp_key(&self_cert, secret_key_with_wrong_type);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_server_cert) = generate_ed25519_tlscert();

    let result = csp
        .perform_tls_client_handshake(dummy_tcp_stream().await, self_cert, trusted_server_cert)
        .await;

    assert!(matches!(
        result,
        Err(CspTlsClientHandshakeError::WrongSecretKeyType)
    ));
}

#[tokio::test]
async fn should_return_error_on_malformed_secret_key() {
    let (_, self_cert) = generate_ed25519_tlscert();
    let malformed_secret_key = tls_secret_key_with_bytes(vec![42; 10]);
    let sks = secret_key_store_with_csp_key(&self_cert, malformed_secret_key);
    let csp = Csp::of(dummy_csprng(), sks);
    let (_, trusted_server_cert) = generate_ed25519_tlscert();

    let result = csp
        .perform_tls_client_handshake(dummy_tcp_stream().await, self_cert, trusted_server_cert)
        .await;

    assert!(matches!(
        result,
        Err(CspTlsClientHandshakeError::MalformedSecretKey { .. })
    ));
}

fn assert_create_connector_error(
    result: Result<(TlsStream, TlsPublicKeyCert), CspTlsClientHandshakeError>,
    expected_description: &str,
) {
    if let Err(CspTlsClientHandshakeError::CreateConnectorError { description, .. }) = result {
        assert_eq!(description, expected_description);
    } else {
        panic!("Expected CreateConnectorError");
    }
}

async fn dummy_tcp_stream() -> TcpStream {
    let listener = TcpListener::bind(("0.0.0.0", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}
