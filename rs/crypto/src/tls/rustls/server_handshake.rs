use crate::tls::rustls::node_cert_verifier::NodeClientCertVerifier;
use ic_crypto_internal_csp::{api::CspTlsHandshakeSignerProvider, TlsHandshakeCspVault};
use ic_crypto_tls_interfaces::SomeOrAllNodes;
use ic_interfaces_registry::RegistryClient;
use ic_types::NodeId;
use rustls::{
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert},
    version::TLS13,
    ServerConfig,
};
use std::sync::Arc;

use super::cert_resolver::RegistryCertResolver;

pub fn server_config<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    allowed_clients: SomeOrAllNodes,
) -> ServerConfig {
    let client_cert_verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
        allowed_clients.clone(),
        registry_client.clone(),
    );
    server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
        self_node_id,
        Arc::new(client_cert_verifier),
        registry_client,
        signer_provider.handshake_signer(),
    )
}

pub fn server_config_without_client_auth<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
) -> ServerConfig {
    let config = server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
        self_node_id,
        Arc::new(NoClientAuth),
        registry_client,
        signer_provider.handshake_signer(),
    );
    config
}

fn server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
    node_id: NodeId,
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
    registry_client: Arc<dyn RegistryClient>,
    tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
) -> ServerConfig {
    let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
    ring_crypto_provider.cipher_suites = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

    ServerConfig::builder_with_provider(Arc::new(ring_crypto_provider))
        .with_protocol_versions(&[&TLS13])
        .expect("Valid rustls server config.")
        .with_client_cert_verifier(client_cert_verifier)
        .with_cert_resolver(registry_cert_resolver(
            node_id,
            registry_client,
            tls_csp_vault,
        ))
}

fn registry_cert_resolver(
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
) -> Arc<dyn ResolvesServerCert> {
    Arc::new(RegistryCertResolver::new(
        node_id,
        registry_client,
        tls_csp_vault,
    ))
}
