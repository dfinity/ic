#![allow(clippy::unwrap_used)]
use ic_crypto_test_utils::tls::custom_server::CustomServer;
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls::{
    generate_tls_keys, perform_tls_client_handshake, TlsClientHandshakeError, TlsPrivateKey,
    TlsPublicKeyCert,
};
use ic_crypto_tls_interfaces::TlsStream;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::{NodeId, PrincipalId};
use openssl::ssl::SslVersion;
use tokio::net::TcpStream;

const COMMON_NAME: &str = "common name";
const NOT_AFTER: &str = "20701231235959Z";
const SERVER_ID: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

#[tokio::test]
async fn should_perform_client_handshake() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(client_result.is_ok());
}

#[tokio::test]
async fn should_allow_connection_to_custom_server_only_supporting_aes_128_cipher() {
    const AES_128_ONLY_CIPHER_SUITE: &str = "TLS_AES_128_GCM_SHA256";
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_allowed_cipher_suites(AES_128_ONLY_CIPHER_SUITE)
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(client_result.is_ok());
}

#[tokio::test]
async fn should_allow_connection_to_custom_server_only_supporting_aes_256_cipher() {
    const AES_256_ONLY_CIPHER_SUITE: &str = "TLS_AES_256_GCM_SHA384";
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_allowed_cipher_suites(AES_256_ONLY_CIPHER_SUITE)
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(client_result.is_ok());
}

#[tokio::test]
async fn should_allow_connection_to_server_with_very_old_certificate() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder().build(
        CertWithPrivateKey::builder()
            // Once upon a time in year 1012 in ASN.1 YYYYMMDDHHMMSSZ
            .not_before("10121224075600Z")
            .cn(SERVER_ID.to_string())
            .build_ed25519(),
        vec![x509_pub_key_cert(&client_cert)],
    );

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(client_result.is_ok());
}

#[tokio::test]
async fn should_perform_handshake_with_client_prime256v1_cert() {
    let prime256v1_client_cert_with_private_key = CertWithPrivateKey::builder()
        .cn(COMMON_NAME.to_string())
        .build_prime256v1();
    let prime256v1_client_cert =
        TlsPublicKeyCert::new_from_pem(prime256v1_client_cert_with_private_key.cert_pem()).unwrap();
    let prime256v1_client_private_key =
        TlsPrivateKey::new_from_pem(prime256v1_client_cert_with_private_key.key_pair_pem())
            .unwrap();
    let server = CustomServer::builder().build_with_default_server_cert(
        SERVER_ID,
        vec![x509_pub_key_cert(&prime256v1_client_cert)],
    );

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            prime256v1_client_cert,
            prime256v1_client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(client_result.is_ok())
}

#[tokio::test]
async fn should_return_error_if_private_key_does_not_match_cert() {
    let (client_cert, _) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let (_, wrong_client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .expect_error("the handshake failed: unexpected EOF")
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            wrong_client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert!(
        matches!(client_result, Err(TlsClientHandshakeError::CreateConnectorError { description, .. })
        if description == "Inconsistent private key and certificate.")
    )
}

#[tokio::test]
async fn should_return_error_if_server_does_not_support_tls_1_3() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_max_protocol_version(SslVersion::TLS1_2)
        .expect_error("tls_early_post_process_client_hello:unsupported protocol")
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "tlsv1 alert protocol version")
}

#[tokio::test]
async fn should_return_error_if_server_does_not_support_required_ciphers() {
    const CIPHER_SUITES_NOT_SUPPORTED_BY_CLIENT: &str = "TLS_CHACHA20_POLY1305_SHA256";
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_allowed_cipher_suites(CIPHER_SUITES_NOT_SUPPORTED_BY_CLIENT)
        .expect_error("no shared cipher")
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
}

#[tokio::test]
async fn should_return_error_if_server_does_not_support_ed25519_sig_alg() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_allowed_signature_algorithms("ECDSA+SHA256:RSA+SHA256")
        .expect_error("no shared signature algorithms")
        .build_with_default_server_cert(SERVER_ID, vec![x509_pub_key_cert(&client_cert)]);

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
}

#[tokio::test]
async fn should_return_error_if_server_does_not_use_ed25519_cert() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .with_allowed_signature_algorithms("ECDSA+SHA256:RSA+SHA256:ed25519")
        .expect_error("no suitable signature algorithm")
        .build(
            CertWithPrivateKey::builder()
                .cn(SERVER_ID.to_string())
                .build_prime256v1(),
            vec![x509_pub_key_cert(&client_cert)],
        );

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
}

#[tokio::test]
async fn should_return_error_if_server_uses_expired_cert() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .expect_error("sslv3 alert certificate expired")
        .build(
            CertWithPrivateKey::builder()
                .cn(SERVER_ID.to_string())
                .validity_days(0) // current time
                .build_ed25519(),
            vec![x509_pub_key_cert(&client_cert)],
        );

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "certificate has expired");
}

#[tokio::test]
async fn should_return_error_if_server_cert_not_yet_valid() {
    let (client_cert, client_private_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);
    let server = CustomServer::builder()
        .expect_error("sslv3 alert bad certificate")
        .build(
            CertWithPrivateKey::builder()
                .cn(SERVER_ID.to_string())
                .not_before_days_from_now(3) // 3 days in the future
                .build_ed25519(),
            vec![x509_pub_key_cert(&client_cert)],
        );

    let (client_result, _) = tokio::join!(
        perform_tls_client_handshake(
            tcp_stream(server.port()).await,
            client_cert.clone(),
            client_private_key,
            tls_pubkey_cert(&server),
        ),
        server.run()
    );

    assert_handshake_client_error_containing(&client_result, "certificate is not yet valid");
}

fn x509_pub_key_cert(cert: &TlsPublicKeyCert) -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: cert.to_der().unwrap(),
    }
}

async fn tcp_stream(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("failed to connect")
}

fn tls_pubkey_cert(server: &CustomServer) -> TlsPublicKeyCert {
    TlsPublicKeyCert::new_from_pem(server.cert_pem()).expect("unable to read cert from PEM")
}

fn assert_handshake_client_error_containing(
    client_result: &Result<TlsStream, TlsClientHandshakeError>,
    error_substring: &str,
) {
    let error = client_result.as_ref().err().unwrap();
    if let TlsClientHandshakeError::HandshakeError { internal_error } = error {
        assert!(
            internal_error.contains(error_substring),
            "expected internal error \"{}\" to contain \"{}\"",
            internal_error,
            error_substring
        );
    } else {
        panic!("expected HandshakeError error, got {:?}", error)
    }
}
