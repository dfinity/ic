#![allow(clippy::unwrap_used)]
use crate::tls_utils::registry::TlsRegistry;
use crate::tls_utils::temp_crypto_component_with_tls_keys;
use crate::tls_utils::test_client::{Client, ClientBuilder};
use crate::tls_utils::test_server::{Server, ServerBuilder};
use ic_crypto_tls_interfaces::{
    AuthenticatedPeer, MalformedPeerCertificateError, TlsClientHandshakeError, TlsPublicKeyCert,
    TlsServerHandshakeError,
};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5};
use ic_types::NodeId;
use std::sync::Arc;

mod tls_utils;

const SERVER_ID_1: NodeId = NODE_1;
const SERVER_ID_2: NodeId = NODE_2;

const CLIENT_ID_1: NodeId = NODE_3;
const CLIENT_ID_2: NodeId = NODE_4;
const CLIENT_ID_3: NodeId = NODE_5;

mod handshakes {
    use super::*;
    use ic_crypto_test_utils::tls::x509_certificates::{x509_public_key_cert, CertWithPrivateKey};

    #[tokio::test]
    async fn should_perform_tls_handshake() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, authenticated_client) =
            tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok());
        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_if_multiple_clients_allowed() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_2)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client_1_cert = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .cn(CLIENT_ID_1.to_string())
                .build_ed25519()
                .x509(),
        );
        let client_2 = Client::builder(CLIENT_ID_2, SERVER_ID_1).build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_2, client_2.cert())
            .add_cert(CLIENT_ID_1, client_1_cert)
            .update();

        let (client_result, authenticated_client) =
            tokio::join!(client_2.run(server.port()), server.run());

        assert!(client_result.is_ok());
        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_ID_2);
    }
}

mod server_with_certs {
    use super::*;
    use ic_crypto_test_utils::tls::custom_client::CustomClient;
    use ic_crypto_test_utils::tls::x509_certificates::{
        ed25519_key_pair, x509_public_key_cert, CertWithPrivateKey,
    };
    use openssl::hash::MessageDigest;

    #[tokio::test]
    async fn should_perform_tls_handshake_with_cert() {
        let registry = TlsRegistry::new();
        let allowed_cert = CertWithPrivateKey::builder().build_ed25519();
        let allowed_cert_proto = x509_public_key_cert(&allowed_cert.x509());
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client_cert(allowed_cert_proto.clone())
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(allowed_cert)
            .build(server.cert());
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_cert_eq(server_result.unwrap(), allowed_cert_proto);
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_with_ca_cert() {
        const CLIENT_CA_CN: &str = "certificate authority";
        const CLIENT_LEAF_CN: &str = "client certificate";

        let ca_cert_key_pair = ed25519_key_pair();
        let leaf_cert_key_pair = ed25519_key_pair();
        let leaf_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_LEAF_CN.to_string())
            .with_ca_signing(ca_cert_key_pair.clone(), CLIENT_CA_CN.to_string())
            .build(leaf_cert_key_pair.clone(), MessageDigest::null());
        let leaf_cert_proto = x509_public_key_cert(&leaf_cert.x509());
        let ca_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_CA_CN.to_string())
            .set_ca_key_usage_extension()
            .build(ca_cert_key_pair, MessageDigest::null())
            .x509();
        let ca_cert_proto = x509_public_key_cert(&ca_cert);

        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client_cert(ca_cert_proto.clone())
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(leaf_cert)
            .with_extra_chain_certs(vec![ca_cert])
            .build(server.cert());
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_cert_eq(server_result.unwrap(), leaf_cert_proto);
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_with_ca_and_intermediate_cert() {
        const CLIENT_CA_CN: &str = "certificate authority";
        const CLIENT_INTERMEDIATE_CA_CN: &str = "intermediate certificate authority";
        const CLIENT_LEAF_CN: &str = "client certificate";

        let ca_cert_key_pair = ed25519_key_pair();
        let intermediate_ca_cert_key_pair = ed25519_key_pair();
        let leaf_cert_key_pair = ed25519_key_pair();
        let leaf_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_LEAF_CN.to_string())
            .with_ca_signing(
                intermediate_ca_cert_key_pair.clone(),
                CLIENT_INTERMEDIATE_CA_CN.to_string(),
            )
            .build(leaf_cert_key_pair.clone(), MessageDigest::null());
        let leaf_cert_proto = x509_public_key_cert(&leaf_cert.x509());
        let intermediate_ca_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_INTERMEDIATE_CA_CN.to_string())
            .set_ca_key_usage_extension()
            .with_ca_signing(ca_cert_key_pair.clone(), CLIENT_CA_CN.to_string())
            .build(intermediate_ca_cert_key_pair.clone(), MessageDigest::null())
            .x509();
        let ca_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_CA_CN.to_string())
            .set_ca_key_usage_extension()
            .build(ca_cert_key_pair, MessageDigest::null())
            .x509();
        let ca_cert_proto = x509_public_key_cert(&ca_cert);

        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client_cert(ca_cert_proto.clone())
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(leaf_cert)
            .with_extra_chain_certs(vec![intermediate_ca_cert, ca_cert])
            .build(server.cert());
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_cert_eq(server_result.unwrap(), leaf_cert_proto);
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_with_cert_if_both_node_and_cert_are_allowed() {
        let registry = TlsRegistry::new();
        let allowed_cert = CertWithPrivateKey::builder().build_ed25519();
        let allowed_cert_proto = x509_public_key_cert(&allowed_cert.x509());
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .add_allowed_client_cert(allowed_cert_proto.clone())
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(allowed_cert)
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, generate_cert_using_temp_crypto(CLIENT_ID_1))
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_cert_eq(server_result.unwrap(), allowed_cert_proto);
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_with_node_if_both_node_and_cert_are_allowed() {
        let registry = TlsRegistry::new();
        let allowed_cert = CertWithPrivateKey::builder().build_ed25519();
        let allowed_cert_proto = x509_public_key_cert(&allowed_cert.x509());
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .add_allowed_client_cert(allowed_cert_proto)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(server_result.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_return_error_if_allowed_client_cert_has_bad_sig() {
        let registry = TlsRegistry::new();
        let allowed_cert = CertWithPrivateKey::builder()
            .self_sign_with_wrong_secret_key()
            .build_ed25519();
        let allowed_cert_proto = x509_public_key_cert(&allowed_cert.x509());
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client_cert(allowed_cert_proto.clone())
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(allowed_cert)
            .build(server.cert());
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }
}

mod server_allowing_all_nodes {
    use super::*;
    use crate::tls_utils::REG_V1;

    #[tokio::test]
    async fn should_perform_handshake_if_all_nodes_allowed_and_registry_contains_only_client_node()
    {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .allow_all_nodes()
            .build(registry.get());
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_node_record(CLIENT_ID_1)
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, authenticated_client) =
            tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok());
        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_perform_handshake_if_all_nodes_allowed_and_registry_contains_several_nodes() {
        const CLIENT_THAT_CONNECTS: NodeId = CLIENT_ID_1;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .allow_all_nodes()
            .build(registry.get());
        let client = Client::builder(CLIENT_THAT_CONNECTS, SERVER_ID_1).build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_node_record(CLIENT_THAT_CONNECTS)
            .add_cert(CLIENT_THAT_CONNECTS, client.cert())
            .add_node_record(CLIENT_ID_2)
            .add_cert(CLIENT_ID_2, generate_cert_using_temp_crypto(CLIENT_ID_2))
            .add_node_record(CLIENT_ID_3)
            .add_cert(CLIENT_ID_3, generate_cert_using_temp_crypto(CLIENT_ID_3))
            .update();

        let (client_result, authenticated_client) =
            tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok());
        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_THAT_CONNECTS);
    }

    #[tokio::test]
    async fn should_return_error_if_a_node_does_not_have_cert_in_registry() {
        const NODE_WITHOUT_CERT_IN_REGISTRY: NodeId = CLIENT_ID_3;
        const CLIENT_THAT_CONNECTS: NodeId = CLIENT_ID_1;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .allow_all_nodes()
            .build(registry.get());
        let client = Client::builder(CLIENT_THAT_CONNECTS, SERVER_ID_1).build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_node_record(CLIENT_THAT_CONNECTS)
            .add_cert(CLIENT_THAT_CONNECTS, client.cert())
            .add_node_record(CLIENT_ID_2)
            .add_cert(CLIENT_ID_2, generate_cert_using_temp_crypto(CLIENT_ID_2))
            .add_node_record(NODE_WITHOUT_CERT_IN_REGISTRY)
            .update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::CertificateNotInRegistry {
                node_id: NODE_WITHOUT_CERT_IN_REGISTRY,
                registry_version: REG_V1
            }
        )
    }

    #[tokio::test]
    async fn should_return_error_if_node_record_of_connecting_client_missing() {
        const CLIENT_THAT_CONNECTS_WITHOUT_NODE_RECORD: NodeId = CLIENT_ID_1;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .allow_all_nodes()
            .build(registry.get());
        let client = Client::builder(CLIENT_THAT_CONNECTS_WITHOUT_NODE_RECORD, SERVER_ID_1)
            .build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            // we even add the client's certificate to the registry:
            .add_cert(CLIENT_THAT_CONNECTS_WITHOUT_NODE_RECORD, client.cert())
            .add_node_record(CLIENT_ID_2)
            .add_cert(CLIENT_ID_2, generate_cert_using_temp_crypto(CLIENT_ID_2))
            .add_node_record(CLIENT_ID_3)
            .add_cert(CLIENT_ID_3, generate_cert_using_temp_crypto(CLIENT_ID_3))
            .update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }
}

mod server {
    use super::*;
    use crate::tls_utils::REG_V1;
    use ic_crypto_test_utils::tls::custom_client::CustomClient;
    use ic_crypto_test_utils::tls::x509_certificates::{
        ed25519_key_pair, x509_public_key_cert, CertWithPrivateKey,
    };
    use ic_crypto_tls_interfaces::PeerNotAllowedError;
    use openssl::hash::MessageDigest;
    use openssl::ssl::SslVersion;

    #[tokio::test]
    async fn should_return_error_if_client_not_allowed_and_allowed_clients_exist() {
        const NOT_ALLOWED_CLIENT: NodeId = CLIENT_ID_3;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .add_allowed_client(CLIENT_ID_2)
            .build(registry.get());
        assert!(!server.allowed_clients().contains(&NOT_ALLOWED_CLIENT));
        let client = Client::builder(NOT_ALLOWED_CLIENT, SERVER_ID_1).build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(NOT_ALLOWED_CLIENT, client.cert())
            .add_cert(CLIENT_ID_1, generate_cert_using_temp_crypto(CLIENT_ID_1))
            .add_cert(CLIENT_ID_2, generate_cert_using_temp_crypto(CLIENT_ID_2))
            .update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(
            &server_result,
            "Handshake failed in tokio_openssl:accept",
        );
        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_in_registry_is_malformed() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, malformed_cert())
            .update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_malformed_client_cert_server_error_containing(
            &server_result,
            "asn1 encoding routines:ASN1_get_object:too long",
        );
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_in_registry_is_malformed() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, malformed_cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_malformed_self_cert_server_error_containing(
            &server_result,
            "asn1 encoding routines:ASN1_get_object:too long",
        );
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_not_in_registry() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_client_result, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::CertificateNotInRegistry {
                node_id: CLIENT_ID_1,
                registry_version: REG_V1
            }
        )
    }

    #[tokio::test]
    #[should_panic(expected = "CSP TLS server handshake error: The secret key was not found")]
    async fn should_panic_if_secret_key_not_found() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        let wrong_server_cert = generate_cert_using_temp_crypto(SERVER_ID_1);
        assert_ne!(wrong_server_cert, server.cert());
        registry
            .add_cert(SERVER_ID_1, wrong_server_cert)
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let _panic = tokio::join!(client.run(server.port()), server.run());
    }

    #[tokio::test]
    async fn should_allow_connection_from_custom_client_with_valid_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(server_result.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_allow_connection_from_custom_client_only_supporting_aes_128_cipher() {
        const AES_128_ONLY_CIPHER_SUITE: &str = "TLS_AES_128_GCM_SHA256";
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_allowed_cipher_suites(AES_128_ONLY_CIPHER_SUITE)
            .with_default_client_auth(CLIENT_ID_1)
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(server_result.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_allow_connection_from_custom_client_only_supporting_aes_256_cipher() {
        const AES_256_ONLY_CIPHER_SUITE: &str = "TLS_AES_256_GCM_SHA384";
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_allowed_cipher_suites(AES_256_ONLY_CIPHER_SUITE)
            .with_default_client_auth(CLIENT_ID_1)
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(server_result.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_allow_connection_from_client_with_very_old_certificate() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    // Once upon a time in year 1012 in ASN.1 YYYYMMDDHHMMSSZ
                    .not_before("10121224075600Z")
                    .cn(CLIENT_ID_1.to_string())
                    .build_ed25519(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(server_result.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_return_error_if_client_does_not_support_tls_1_3() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .with_max_protocol_version(SslVersion::TLS1_2)
            .expect_error("tlsv1 alert protocol version")
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(
            &server_result,
            "tls_early_post_process_client_hello:unsupported protocol",
        )
    }

    #[tokio::test]
    async fn should_return_error_if_client_does_not_support_required_ciphers() {
        const CIPHER_SUITES_NOT_SUPPORTED_BY_SERVER: &str = "TLS_CHACHA20_POLY1305_SHA256";
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .with_allowed_cipher_suites(CIPHER_SUITES_NOT_SUPPORTED_BY_SERVER)
            .expect_error("sslv3 alert handshake failure")
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "no shared cipher")
    }

    #[tokio::test]
    async fn should_return_error_if_client_does_not_support_ed25519_sig_alg() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .with_allowed_signature_algorithms("ECDSA+SHA256:RSA+SHA256")
            .expect_error("sslv3 alert handshake failure")
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "no shared signature algorithms")
    }

    #[tokio::test]
    async fn should_return_error_if_client_does_not_use_ed25519_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_allowed_signature_algorithms("ed25519")
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(CLIENT_ID_1.to_string())
                    .build_prime256v1(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::UnauthenticatedClient
        );
    }

    #[tokio::test]
    async fn should_return_error_if_client_does_not_authenticate_with_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .without_client_auth()
            .build(server.cert());
        let client_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_ID_1.to_string())
            .build_ed25519();
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, x509_public_key_cert(&client_cert.x509()))
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::UnauthenticatedClient
        );
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_has_wrong_node_id() {
        const REGISTERED_NODE_ID: NodeId = CLIENT_ID_1;
        const WRONG_NODE_ID: NodeId = CLIENT_ID_2;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(REGISTERED_NODE_ID)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(WRONG_NODE_ID.to_string())
                    .build_ed25519(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            // add the cert used by the client, so that the handshake succeeds:
            .add_cert(REGISTERED_NODE_ID, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::ClientNotAllowed(
                PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed
            )
        );
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_has_wrong_node_id_and_honest_node_is_allowed() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .add_allowed_client(CLIENT_ID_2)
            .build(registry.get());
        let legal_client_1_cert = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .cn(CLIENT_ID_1.to_string())
                .build_ed25519()
                .x509(),
        );
        let client_2_with_illegal_cn = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(CLIENT_ID_1.to_string())
                    .build_ed25519(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, legal_client_1_cert)
            .add_cert(CLIENT_ID_2, client_2_with_illegal_cn.client_auth_cert())
            .update();

        let (_, server_result) =
            tokio::join!(client_2_with_illegal_cn.run(server.port()), server.run());

        // When OpenSSL is given two certificates in the trust store that both use
        // CLIENT_ID_1 as subject and issuer CNs, it can only "see" one of them
        // (the one it was given first) during the handshake.
        // Because we store the certs in a HashSet, their ordering is non-deterministic
        // across tests (it depends on their hashes, which depend on the particular keys
        // generated each run).
        // That means CLIENT_ID_2 can get rejected in two ways in this test:
        // - If OpenSSL only "sees" CLIENT_ID_1's certificate, we get a HandshakeError,
        // - If OpenSSL "sees" CLIENT_ID_2's certificate, the TLS handshake will succeed
        //   but then the Registry check of the cert will fail, and we get a
        //   ClientNotAllowed error.
        match server_result.unwrap_err() {
            TlsServerHandshakeError::HandshakeError { internal_error } => {
                assert_string_contains(internal_error, "certificate verify failed");
            }
            TlsServerHandshakeError::ClientNotAllowed(PeerNotAllowedError::CertificatesDiffer) => {}
            e => panic!(
                "expected HandshakeError or ClientNotAllowed error, got {}",
                e
            ),
        }
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_does_not_match_registry_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_default_client_auth(CLIENT_ID_1)
            .build(server.cert());
        let different_client_cert_in_registry = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .cn(CLIENT_ID_1.to_string())
                .build_ed25519()
                .x509(),
        );
        assert_ne!(client.client_auth_cert(), different_client_cert_in_registry);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, different_client_cert_in_registry)
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_does_not_match_registry_cert_and_signed_with_same_key(
    ) {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let ed25519_key_pair = ed25519_key_pair();
        let client = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(CLIENT_ID_1.to_string())
                    .build(ed25519_key_pair.clone(), MessageDigest::null()),
            )
            .build(server.cert());
        let different_client_cert_in_registry_with_same_key = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .validity_days(3) // ensures this cert differs!
                .cn(CLIENT_ID_1.to_string())
                .build(ed25519_key_pair, MessageDigest::null())
                .x509(),
        );
        assert_ne!(
            different_client_cert_in_registry_with_same_key,
            client.client_auth_cert()
        );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, different_client_cert_in_registry_with_same_key)
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_is_issued_by_other_cert_in_registry() {
        const CLIENT_CA_ID: NodeId = CLIENT_ID_1;
        const CLIENT_LEAF_ID: NodeId = CLIENT_ID_2;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_CA_ID)
            .build(registry.get());
        let ca_cert_key_pair = ed25519_key_pair();
        let leaf_cert_key_pair = ed25519_key_pair();
        let leaf_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_LEAF_ID.to_string())
            .with_ca_signing(ca_cert_key_pair.clone(), CLIENT_CA_ID.to_string())
            .build(leaf_cert_key_pair.clone(), MessageDigest::null());
        let ca_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_CA_ID.to_string())
            .set_ca_key_usage_extension()
            .build(ca_cert_key_pair, MessageDigest::null())
            .x509();
        let x509_client_ca_cert = x509_public_key_cert(&ca_cert);
        let client = CustomClient::builder()
            .with_client_auth(leaf_cert)
            .with_extra_chain_certs(vec![ca_cert])
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_CA_ID, x509_client_ca_cert)
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            server_result.unwrap_err(),
            TlsServerHandshakeError::ClientNotAllowed(
                PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed
            )
        );
    }

    #[tokio::test]
    async fn should_return_error_if_client_uses_expired_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(CLIENT_ID_1.to_string())
                    .validity_days(0) // current time
                    .build_ed25519(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_client_cert_not_yet_valid() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .with_client_auth(
                CertWithPrivateKey::builder()
                    .cn(CLIENT_ID_1.to_string())
                    .not_before_days_from_now(3) // 3 days in the future
                    .build_ed25519(),
            )
            .build(server.cert());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.client_auth_cert())
            .update();

        let (_, server_result) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_server_error_containing(&server_result, "certificate verify failed");
    }
}

mod server_with_optional_client_auth {
    use crate::tls_utils::registry::TlsRegistry;
    use crate::tls_utils::test_server::Server;
    use crate::{
        matching_server_and_client, matching_server_and_client_builders, CLIENT_ID_1, SERVER_ID_1,
    };
    use ic_crypto_test_utils::tls::custom_client::CustomClient;
    use ic_crypto_test_utils::tls::x509_certificates::{x509_public_key_cert, CertWithPrivateKey};
    use ic_crypto_tls_interfaces::{AuthenticatedPeer, Peer};

    #[tokio::test]
    async fn should_perform_tls_handshake_with_client_auth() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, peer) = tokio::join!(
            client.run(server.port()),
            server.run_with_optional_client_auth()
        );

        assert!(client_result.is_ok());
        assert_eq!(
            peer.unwrap(),
            Peer::Authenticated(AuthenticatedPeer::Node(CLIENT_ID_1))
        );
    }

    #[tokio::test]
    async fn should_send_message_from_server_to_client_with_client_auth() {
        let registry = TlsRegistry::new();
        let (server_builder, client_builder) =
            matching_server_and_client_builders(SERVER_ID_1, CLIENT_ID_1);
        let msg = "hello from server";
        let server = server_builder
            .with_msg_for_client(msg)
            .build(registry.get());
        let client = client_builder
            .expect_msg_from_server(msg)
            .build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (_client_result, peer) = tokio::join!(
            client.run(server.port()),
            server.run_with_optional_client_auth()
        );

        assert_eq!(
            peer.unwrap(),
            Peer::Authenticated(AuthenticatedPeer::Node(CLIENT_ID_1))
        );
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_without_client_sending_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .without_client_auth()
            .build(server.cert());
        let client_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_ID_1.to_string())
            .build_ed25519();
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, x509_public_key_cert(&client_cert.x509()))
            .update();

        let (_, peer) = tokio::join!(
            client.run(server.port()),
            server.run_with_optional_client_auth()
        );

        assert_eq!(peer.unwrap(), Peer::Unauthenticated);
    }

    #[tokio::test]
    async fn should_send_message_from_server_to_client_without_client_auth() {
        let registry = TlsRegistry::new();
        let msg = "hello from server";
        let server = Server::builder(SERVER_ID_1)
            .with_msg_for_client(msg)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .expect_msg_from_server(msg)
            .without_client_auth()
            .build(server.cert());
        let client_cert = CertWithPrivateKey::builder()
            .cn(CLIENT_ID_1.to_string())
            .build_ed25519();
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, x509_public_key_cert(&client_cert.x509()))
            .update();

        let (_, peer) = tokio::join!(
            client.run(server.port()),
            server.run_with_optional_client_auth()
        );

        assert_eq!(peer.unwrap(), Peer::Unauthenticated);
    }
}

mod server_without_client_auth {
    use crate::tls_utils::registry::TlsRegistry;
    use crate::tls_utils::test_server::Server;
    use crate::{matching_server_and_client, CLIENT_ID_1, SERVER_ID_1};
    use ic_crypto_test_utils::tls::custom_client::CustomClient;

    #[tokio::test]
    async fn should_perform_tls_handshake_without_server_asking_for_cert() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, server_result) =
            tokio::join!(client.run(server.port()), server.run_without_client_auth());

        assert!(client_result.is_ok());
        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn should_perform_tls_handshake_without_client_cert_and_without_server_asking_for_cert() {
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .build(registry.get());
        let client = CustomClient::builder()
            .without_client_auth()
            .build(server.cert());
        registry.add_cert(SERVER_ID_1, server.cert()).update();

        let (_, server_result) =
            tokio::join!(client.run(server.port()), server.run_without_client_auth());

        assert!(server_result.is_ok());
    }
}

mod client {
    use super::*;
    use crate::tls_utils::REG_V1;
    use ic_crypto_test_utils::tls::custom_server::CustomServer;
    use ic_crypto_test_utils::tls::x509_certificates::{
        ed25519_key_pair, x509_public_key_cert, CertWithPrivateKey,
    };
    use ic_crypto_tls_interfaces::{PeerNotAllowedError, TlsClientHandshakeError};
    use openssl::hash::MessageDigest;
    use openssl::ssl::SslVersion;

    #[tokio::test]
    async fn should_return_error_if_client_cert_in_registry_is_malformed() {
        // the server is only required so the client can connect somewhere
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, malformed_cert())
            .update();

        let result = client.run(server.port()).await;

        assert_malformed_self_cert_client_error_containing(
            &result,
            "asn1 encoding routines:ASN1_get_object:too long",
        );
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_in_registry_is_malformed() {
        // the server is only required so the client can connect somewhere
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, malformed_cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let result = client.run(server.port()).await;

        assert_malformed_server_cert_client_error_containing(
            &result,
            "asn1 encoding routines:ASN1_get_object:too long",
        );
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_not_in_registry() {
        // the server is only required so the client can connect somewhere
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        registry.add_cert(CLIENT_ID_1, client.cert()).update();

        let result = client.run(server.port()).await;

        assert_eq!(
            result.unwrap_err(),
            TlsClientHandshakeError::CertificateNotInRegistry {
                node_id: SERVER_ID_1,
                registry_version: REG_V1
            }
        )
    }

    /// It is surprising that the handshake on the client side succeeds in this
    /// case. However, this is no issue because it is the server's
    /// responsibility to reject clients that do not present a valid
    /// certificate. From the client's perspective, things look fine as the
    /// server is successfully authenticated.
    #[tokio::test]
    async fn should_connect_even_if_server_rejects_client_cert_but_get_error_on_read() {
        const NOT_ALLOWED_CLIENT: NodeId = CLIENT_ID_3;
        let registry = TlsRegistry::new();
        let server = Server::builder(SERVER_ID_1)
            .add_allowed_client(CLIENT_ID_1)
            .add_allowed_client(CLIENT_ID_2)
            .build(registry.get());
        assert!(!server.allowed_clients().contains(&NOT_ALLOWED_CLIENT));
        let client = Client::builder(NOT_ALLOWED_CLIENT, SERVER_ID_1)
            .expect_error_when_reading_stream_contains("tlsv1 alert unknown ca")
            .build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(NOT_ALLOWED_CLIENT, client.cert())
            .add_cert(CLIENT_ID_1, generate_cert_using_temp_crypto(CLIENT_ID_1))
            .add_cert(CLIENT_ID_2, generate_cert_using_temp_crypto(CLIENT_ID_2))
            .update();

        let (client_result, _server_result) = tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok());
    }

    #[tokio::test]
    #[should_panic(expected = "TLS client handshake error: The secret key was not found")]
    async fn should_panic_if_secret_key_not_found() {
        let (server, client, registry) = matching_server_and_client(SERVER_ID_1, CLIENT_ID_1);
        let wrong_client_cert = generate_cert_using_temp_crypto(CLIENT_ID_1);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, wrong_client_cert)
            .update();

        let _panic = tokio::join!(client.run(server.port()), server.run());
    }

    #[tokio::test]
    async fn should_allow_connection_to_custom_server_with_valid_cert() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok())
    }

    #[tokio::test]
    async fn should_allow_connection_to_custom_server_only_supporting_aes_128_cipher() {
        const AES_128_ONLY_CIPHER_SUITE: &str = "TLS_AES_128_GCM_SHA256";
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_allowed_cipher_suites(AES_128_ONLY_CIPHER_SUITE)
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok())
    }

    #[tokio::test]
    async fn should_allow_connection_to_custom_server_only_supporting_aes_256_cipher() {
        const AES_256_ONLY_CIPHER_SUITE: &str = "TLS_AES_256_GCM_SHA384";
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_allowed_cipher_suites(AES_256_ONLY_CIPHER_SUITE)
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok())
    }

    #[tokio::test]
    async fn should_allow_connection_to_server_with_very_old_certificate() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder().build(
            CertWithPrivateKey::builder()
                // Once upon a time in year 1012 in ASN.1 YYYYMMDDHHMMSSZ
                .not_before("10121224075600Z")
                .cn(SERVER_ID_1.to_string())
                .build_ed25519(),
            vec![client.cert()],
        );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert!(client_result.is_ok())
    }

    #[tokio::test]
    async fn should_return_error_if_server_does_not_support_tls_1_3() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_max_protocol_version(SslVersion::TLS1_2)
            .expect_error("tls_early_post_process_client_hello:unsupported protocol")
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "tlsv1 alert protocol version")
    }

    #[tokio::test]
    async fn should_return_error_if_server_does_not_support_required_ciphers() {
        const CIPHER_SUITES_NOT_SUPPORTED_BY_CLIENT: &str = "TLS_CHACHA20_POLY1305_SHA256";
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_allowed_cipher_suites(CIPHER_SUITES_NOT_SUPPORTED_BY_CLIENT)
            .expect_error("no shared cipher")
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
    }

    #[tokio::test]
    async fn should_return_error_if_server_does_not_support_ed25519_sig_alg() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_allowed_signature_algorithms("ECDSA+SHA256:RSA+SHA256")
            .expect_error("no shared signature algorithms")
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
    }

    #[tokio::test]
    async fn should_return_error_if_server_does_not_use_ed25519_cert() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .with_allowed_signature_algorithms("ECDSA+SHA256:RSA+SHA256:ed25519")
            .expect_error("no suitable signature algorithm")
            .build(
                CertWithPrivateKey::builder()
                    .cn(SERVER_ID_1.to_string())
                    .build_prime256v1(),
                vec![client.cert()],
            );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "sslv3 alert handshake failure")
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_has_wrong_node_id() {
        const WRONG_NODE_ID: NodeId = SERVER_ID_2;
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder().build(
            CertWithPrivateKey::builder()
                .cn(WRONG_NODE_ID.to_string())
                .build_ed25519(),
            vec![client.cert()],
        );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            client_result.unwrap_err(),
            TlsClientHandshakeError::ServerNotAllowed(
                PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed
            )
        );
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_does_not_match_registry_cert() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .expect_error("tlsv1 alert unknown ca")
            .build_with_default_server_cert(SERVER_ID_1, vec![client.cert()]);
        let different_server_cert_in_registry = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .cn(SERVER_ID_1.to_string())
                .build_ed25519()
                .x509(),
        );
        assert_ne!(different_server_cert_in_registry, server.cert());
        registry
            .add_cert(SERVER_ID_1, different_server_cert_in_registry)
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "certificate verify failed")
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_does_not_match_registry_cert_and_signed_with_same_key(
    ) {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let ed25519_key_pair = ed25519_key_pair();
        let server = CustomServer::builder()
            .expect_error("tlsv1 alert unknown")
            .build(
                CertWithPrivateKey::builder()
                    .cn(SERVER_ID_1.to_string())
                    .build(ed25519_key_pair.clone(), MessageDigest::null()),
                vec![client.cert()],
            );
        let different_server_cert_in_registry_with_same_key = x509_public_key_cert(
            &CertWithPrivateKey::builder()
                .validity_days(3) // ensures this cert differs!
                .cn(SERVER_ID_1.to_string())
                .build(ed25519_key_pair, MessageDigest::null())
                .x509(),
        );
        assert_ne!(
            different_server_cert_in_registry_with_same_key,
            server.cert()
        );
        registry
            .add_cert(SERVER_ID_1, different_server_cert_in_registry_with_same_key)
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "certificate verify failed")
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_is_issued_by_other_ca_in_registry() {
        const SERVER_CA_ID: NodeId = SERVER_ID_1;
        const SERVER_LEAF_ID: NodeId = SERVER_ID_2;
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_CA_ID).build(registry.get());
        let ca_cert_key_pair = ed25519_key_pair();
        let leaf_cert_key_pair = ed25519_key_pair();
        let leaf_cert = CertWithPrivateKey::builder()
            .cn(SERVER_LEAF_ID.to_string())
            .with_ca_signing(ca_cert_key_pair.clone(), SERVER_CA_ID.to_string())
            .build(leaf_cert_key_pair.clone(), MessageDigest::null());
        let server = CustomServer::builder().build(leaf_cert, vec![client.cert()]);
        let ca_cert = CertWithPrivateKey::builder()
            .set_ca_key_usage_extension()
            .cn(SERVER_CA_ID.to_string())
            .build(ca_cert_key_pair, MessageDigest::null())
            .x509();
        registry
            .add_cert(SERVER_CA_ID, x509_public_key_cert(&ca_cert))
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_eq!(
            client_result.unwrap_err(),
            TlsClientHandshakeError::ServerNotAllowed(
                PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed
            )
        );
    }

    #[tokio::test]
    async fn should_return_error_if_server_uses_expired_cert() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .expect_error("sslv3 alert certificate expired")
            .build(
                CertWithPrivateKey::builder()
                    .cn(SERVER_ID_1.to_string())
                    .validity_days(0) // current time
                    .build_ed25519(),
                vec![client.cert()],
            );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_server_cert_not_yet_valid() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .expect_error("sslv3 alert bad certificate")
            .build(
                CertWithPrivateKey::builder()
                    .cn(SERVER_ID_1.to_string())
                    .not_before_days_from_now(3) // 3 days in the future
                    .build_ed25519(),
                vec![client.cert()],
            );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "certificate verify failed");
    }

    #[tokio::test]
    async fn should_return_error_if_allowed_server_cert_has_bad_sig() {
        let registry = TlsRegistry::new();
        let client = Client::builder(CLIENT_ID_1, SERVER_ID_1).build(registry.get());
        let server = CustomServer::builder()
            .expect_error("tlsv1 alert decrypt error")
            .build(
                CertWithPrivateKey::builder()
                    .self_sign_with_wrong_secret_key()
                    .build_ed25519(),
                vec![client.cert()],
            );
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (client_result, _) = tokio::join!(client.run(server.port()), server.run());

        assert_handshake_client_error_containing(&client_result, "certificate verify failed");
    }
}

mod communication {
    use super::*;

    #[tokio::test]
    async fn should_send_message_from_server_to_client() {
        let registry = TlsRegistry::new();
        let (server_builder, client_builder) =
            matching_server_and_client_builders(SERVER_ID_1, CLIENT_ID_1);
        let msg = "hello from server";
        let server = server_builder
            .with_msg_for_client(msg)
            .build(registry.get());
        let client = client_builder
            .expect_msg_from_server(msg)
            .build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (_client_result, authenticated_client) =
            tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_ID_1);
    }

    #[tokio::test]
    async fn should_send_message_from_client_to_server() {
        let registry = TlsRegistry::new();
        let (server_builder, client_builder) =
            matching_server_and_client_builders(SERVER_ID_1, CLIENT_ID_1);
        let msg = "hello from client";
        let server = server_builder
            .expect_msg_from_client(msg)
            .build(registry.get());
        let client = client_builder
            .with_message_for_server(msg)
            .build(registry.get());
        registry
            .add_cert(SERVER_ID_1, server.cert())
            .add_cert(CLIENT_ID_1, client.cert())
            .update();

        let (_client_result, authenticated_client) =
            tokio::join!(client.run(server.port()), server.run());

        assert_peer_node_eq(authenticated_client.unwrap(), CLIENT_ID_1);
    }
}

fn matching_server_and_client(
    server_node_id: NodeId,
    client_node_id: NodeId,
) -> (Server, Client, TlsRegistry) {
    let registry = TlsRegistry::new();
    let (server_builder, client_builder) =
        matching_server_and_client_builders(server_node_id, client_node_id);
    let server = server_builder.build(registry.get());
    let client = client_builder.build(registry.get());
    (server, client, registry)
}

fn matching_server_and_client_builders(
    server_node_id: NodeId,
    client_node_id: NodeId,
) -> (ServerBuilder, ClientBuilder) {
    let server = Server::builder(server_node_id).add_allowed_client(client_node_id);
    let client = Client::builder(client_node_id, server_node_id);
    (server, client)
}

/// Uses a crypto component to generate a TLS certificate
fn generate_cert_using_temp_crypto(node_id: NodeId) -> X509PublicKeyCert {
    let unused_dummy_registry = Arc::new(FakeRegistryClient::new(Arc::clone(&Arc::new(
        ProtoRegistryDataProvider::new(),
    )) as Arc<_>));
    let (_crypto, cert) = temp_crypto_component_with_tls_keys(unused_dummy_registry, node_id);
    cert.to_proto()
}

fn malformed_cert() -> X509PublicKeyCert {
    X509PublicKeyCert {
        certificate_der: vec![42; 10],
    }
}

fn assert_handshake_server_error_containing(
    server_result: &Result<AuthenticatedPeer, TlsServerHandshakeError>,
    error_substring: &str,
) {
    let error = server_result.clone().unwrap_err();
    if let TlsServerHandshakeError::HandshakeError { internal_error } = error {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected HandshakeError error, got {}", error)
    }
}

fn assert_malformed_self_cert_client_error_containing(
    client_result: &Result<(), TlsClientHandshakeError>,
    error_substring: &str,
) {
    let error = client_result.clone().unwrap_err();
    if let TlsClientHandshakeError::MalformedSelfCertificate { internal_error } = error {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected MalformedSelfCertificate error, got {}", error)
    }
}

fn assert_malformed_server_cert_client_error_containing(
    client_result: &Result<(), TlsClientHandshakeError>,
    error_substring: &str,
) {
    let error = client_result.clone().unwrap_err();
    if let TlsClientHandshakeError::MalformedServerCertificate(MalformedPeerCertificateError {
        internal_error,
    }) = error
    {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected MalformedServerCertificate error, got {}", error)
    }
}

fn assert_handshake_client_error_containing(
    client_result: &Result<(), TlsClientHandshakeError>,
    error_substring: &str,
) {
    let error = client_result.clone().unwrap_err();
    if let TlsClientHandshakeError::HandshakeError { internal_error } = error {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected HandshakeError error, got {}", error)
    }
}

fn assert_malformed_client_cert_server_error_containing(
    server_result: &Result<AuthenticatedPeer, TlsServerHandshakeError>,
    error_substring: &str,
) {
    let error = server_result.clone().unwrap_err();
    if let TlsServerHandshakeError::MalformedClientCertificate(MalformedPeerCertificateError {
        internal_error,
    }) = error
    {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected MalformedClientCertificate error, got {}", error)
    }
}

fn assert_malformed_self_cert_server_error_containing(
    server_result: &Result<AuthenticatedPeer, TlsServerHandshakeError>,
    error_substring: &str,
) {
    let error = server_result.clone().unwrap_err();
    if let TlsServerHandshakeError::MalformedSelfCertificate { internal_error } = error {
        assert_string_contains(internal_error, error_substring);
    } else {
        panic!("expected MalformedSelfCertificate error, got {}", error)
    }
}

fn assert_string_contains(internal_error: String, expected_substring: &str) {
    assert!(
        internal_error.contains(expected_substring),
        "expected internal error \"{}\" to contain \"{}\"",
        internal_error,
        expected_substring
    )
}

fn assert_peer_node_eq(peer: AuthenticatedPeer, node_id: NodeId) {
    match peer {
        AuthenticatedPeer::Node(n) => assert_eq!(n, node_id),
        AuthenticatedPeer::Cert(_) => panic!("expected peer to be a node not a cert"),
    }
}

fn assert_peer_cert_eq(peer: AuthenticatedPeer, cert: X509PublicKeyCert) {
    match peer {
        AuthenticatedPeer::Cert(c) => assert_eq!(
            c,
            TlsPublicKeyCert::new_from_der(cert.certificate_der)
                .expect("failed to convert DER to TlsPublicKeyCert")
        ),
        AuthenticatedPeer::Node(_) => panic!("expected peer to be a cert not a node"),
    }
}
