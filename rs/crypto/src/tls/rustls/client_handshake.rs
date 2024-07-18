use std::sync::Arc;

use crate::tls::rustls::node_cert_verifier::NodeServerCertVerifier;
use ic_crypto_internal_csp::{api::CspTlsHandshakeSignerProvider, TlsHandshakeCspVault};
use ic_crypto_tls_interfaces::SomeOrAllNodes;
use ic_interfaces_registry::RegistryClient;
use ic_types::NodeId;
use rustls::{
    client::ResolvesClientCert,
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    version::TLS13,
    ClientConfig,
};

use super::cert_resolver::RegistryCertResolver;

pub fn client_config<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    server: NodeId,
) -> ClientConfig {
    let server_cert_verifier = NodeServerCertVerifier::new(
        SomeOrAllNodes::new_with_single_node(server),
        registry_client.clone(),
    );
    let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
    ring_crypto_provider.cipher_suites = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

    ClientConfig::builder_with_provider(Arc::new(ring_crypto_provider))
        .with_protocol_versions(&[&TLS13])
        .expect("Valid rustls client config.")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
        .with_client_cert_resolver(registry_cert_resolver(
            self_node_id,
            registry_client,
            signer_provider.handshake_signer(),
        ))
}

fn registry_cert_resolver(
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
) -> Arc<dyn ResolvesClientCert> {
    Arc::new(RegistryCertResolver::new(
        node_id,
        registry_client,
        tls_csp_vault,
    ))
}
