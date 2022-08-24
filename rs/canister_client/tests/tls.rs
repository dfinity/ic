use ic_canister_client::{Agent, HttpClient, Sender};
use ic_crypto_test_utils::tls::custom_server::CustomServer;
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_types::CanisterId;
use openssl::ssl::SslVersion;

#[tokio::test]
// This highlights that the canister client trusts ANY server certificate. Depending on the context
// where the client is used, this may be a security issue since anyone could act as server / MITM.
async fn should_perform_tls_1_2_handshake_with_server_with_bogus_cert() {
    let server = CustomServer::builder()
        .with_max_protocol_version(SslVersion::TLS1_2)
        .with_allowed_signature_algorithms("ECDSA+SHA256")
        .build(CertWithPrivateKey::builder().build_prime256v1());

    let agent = agent_for(&server);

    let id = CanisterId::from_u64(42);
    let (client_result, server_result) = tokio::join!(
        agent.execute_query(&id, "some method", vec![]),
        server.run()
    );

    assert!(server_result.is_ok());
    // The server closes the channel after successful TLS handshake, so the agent returns this error:
    assert!(client_result
        .err()
        .unwrap()
        .contains("hyper::Error(ChannelClosed)"));
}

#[tokio::test]
async fn should_fail_handshake_if_no_shared_sig_algorithms() {
    let server = CustomServer::builder()
        .with_allowed_signature_algorithms("ed25519")
        .expect_error("no shared cipher")
        .build(CertWithPrivateKey::builder().build_prime256v1());

    let agent = agent_for(&server);

    let id = CanisterId::from_u64(42);
    let (result, _) = tokio::join!(
        agent.execute_query(&id, "some method", vec![]),
        server.run()
    );

    assert!(result.err().unwrap().contains("handshake failure"));
}

fn agent_for(server: &CustomServer) -> Agent {
    let client = HttpClient::new();
    let server_url_string = format!("https://127.0.0.1:{}", server.port());
    let url = url::Url::parse(&server_url_string).unwrap();
    Agent::new_with_client(client, url, Sender::Anonymous)
}
