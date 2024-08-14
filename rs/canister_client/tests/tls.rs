use ic_canister_client::{Agent, HttpClient, Sender};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_test_utils_tls::custom_server::CustomServer;
use ic_crypto_test_utils_tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_test_utils_tls::{CipherSuite, TlsVersion};
use ic_types::CanisterId;

#[tokio::test]
// This highlights that the canister client trusts ANY server certificate. Depending on the context
// where the client is used, this may be a security issue since anyone could act as server / MITM.
async fn should_perform_tls_1_2_handshake_with_server_with_bogus_cert() {
    let rng = &mut reproducible_rng();
    let server = CustomServer::builder()
        .with_protocol_versions(vec![TlsVersion::TLS1_2])
        .with_allowed_cipher_suites(vec![CipherSuite::TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .build(CertWithPrivateKey::builder().build_prime256v1(rng));

    let agent = agent_for(&server);

    let id = CanisterId::from_u64(42);
    let (client_result, server_result) = tokio::join!(
        agent.execute_query(&id, "some method", vec![]),
        server.run()
    );

    assert!(server_result.is_ok());
    // The test server closes the channel without responding after successful TLS handshake, so the agent's client will time out:
    assert!(client_result.err().unwrap().contains("Elapsed(())"));
}

#[tokio::test]
async fn should_fail_handshake_if_no_shared_sig_algorithms() {
    let rng = &mut reproducible_rng();
    let server = CustomServer::builder()
        .with_protocol_versions(vec![TlsVersion::TLS1_2])
        .with_allowed_cipher_suites(vec![CipherSuite::TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
        .expect_error("NoCipherSuitesInCommon")
        .build(CertWithPrivateKey::builder().build_prime256v1(rng));

    let agent = agent_for(&server);

    let id = CanisterId::from_u64(42);
    let (result, _) = tokio::join!(
        agent.execute_query(&id, "some method", vec![]),
        server.run()
    );

    assert!(result.err().unwrap().contains("HandshakeFailure"));
}

fn agent_for(server: &CustomServer) -> Agent {
    let client = HttpClient::new();
    let server_url_string = format!("https://127.0.0.1:{}", server.port());
    let url = url::Url::parse(&server_url_string).unwrap();
    Agent::new_with_client(client, url, Sender::Anonymous)
}
