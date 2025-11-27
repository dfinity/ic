use crate::tls::rustls::cert_resolver::StaticCertResolver;
use crate::tls::rustls::certified_key;
use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use crate::tls::rustls::node_cert_verifier::NodeServerCertVerifier;
use crate::tls::tls_cert_from_registry;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfigError};
use ic_interfaces_registry::RegistryClient;
use ic_types::{NodeId, RegistryVersion};
use rustls::{
    ClientConfig, SignatureScheme,
    client::ResolvesClientCert,
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    sign::CertifiedKey,
    version::TLS13,
};
use std::sync::Arc;

pub fn client_config(
    vault: &Arc<dyn CspVault>,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    server: NodeId,
    registry_version: RegistryVersion,
) -> Result<ClientConfig, TlsConfigError> {
    let self_tls_cert =
        tls_cert_from_registry(registry_client.as_ref(), self_node_id, registry_version)?;
    let self_tls_cert_key_id = KeyId::from(&self_tls_cert);
    let ed25519_signing_key =
        CspServerEd25519SigningKey::new(self_tls_cert_key_id, Arc::clone(vault));
    let server_cert_verifier = NodeServerCertVerifier::new(
        SomeOrAllNodes::new_with_single_node(server),
        registry_client,
        registry_version,
    );
    let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
    ring_crypto_provider.cipher_suites = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

    Ok(
        ClientConfig::builder_with_provider(Arc::new(ring_crypto_provider))
            .with_protocol_versions(&[&TLS13])
            .expect("Valid rustls client config.")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
            .with_client_cert_resolver(static_cert_resolver(
                certified_key(self_tls_cert, ed25519_signing_key),
                SignatureScheme::ED25519,
            )),
    )
}

fn static_cert_resolver(key: CertifiedKey, scheme: SignatureScheme) -> Arc<dyn ResolvesClientCert> {
    Arc::new(StaticCertResolver::new(key, scheme).expect(
        "Failed to create the static cert resolver because the signing key referenced \
        in the certified key is incompatible with the signature scheme. This is an implementation error.",
    ))
}
