use crate::tls::rustls::cert_resolver::StaticCertResolver;
use crate::tls::rustls::certified_key;
use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use crate::tls::rustls::node_cert_verifier::NodeClientCertVerifier;
use crate::tls::tls_cert_from_registry;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfigError, TlsPublicKeyCert};
use ic_interfaces_registry::RegistryClient;
use ic_types::{NodeId, RegistryVersion};
use rustls::{
    crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    server::{danger::ClientCertVerifier, NoClientAuth, ResolvesServerCert},
    sign::CertifiedKey,
    version::TLS13,
    ServerConfig, SignatureScheme,
};
use std::sync::Arc;

pub fn server_config(
    vault: &Arc<dyn CspVault>,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    allowed_clients: SomeOrAllNodes,
    registry_version: RegistryVersion,
) -> Result<ServerConfig, TlsConfigError> {
    let self_tls_cert =
        tls_cert_from_registry(registry_client.as_ref(), self_node_id, registry_version)?;
    let self_tls_cert_key_id = KeyId::try_from(&self_tls_cert).map_err(|error| {
        TlsConfigError::MalformedSelfCertificate {
            internal_error: format!("Cannot instantiate KeyId: {:?}", error),
        }
    })?;
    let client_cert_verifier = NodeClientCertVerifier::new_with_mandatory_client_auth(
        allowed_clients.clone(),
        registry_client,
        registry_version,
    );
    let ed25519_signing_key =
        CspServerEd25519SigningKey::new(self_tls_cert_key_id, Arc::clone(vault));
    Ok(
        server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
            Arc::new(client_cert_verifier),
            self_tls_cert,
            ed25519_signing_key,
        ),
    )
}

pub fn server_config_without_client_auth(
    vault: &Arc<dyn CspVault>,
    self_node_id: NodeId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<ServerConfig, TlsConfigError> {
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)?;
    let self_tls_cert_key_id = KeyId::try_from(&self_tls_cert).map_err(|error| {
        TlsConfigError::MalformedSelfCertificate {
            internal_error: format!("Cannot instantiate KeyId: {:?}", error),
        }
    })?;
    let ed25519_signing_key =
        CspServerEd25519SigningKey::new(self_tls_cert_key_id, Arc::clone(vault));
    let config = server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
        Arc::new(NoClientAuth),
        self_tls_cert,
        ed25519_signing_key,
    );
    Ok(config)
}

fn server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
    self_tls_cert: TlsPublicKeyCert,
    ed25519_signing_key: CspServerEd25519SigningKey,
) -> ServerConfig {
    let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
    ring_crypto_provider.cipher_suites = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

    ServerConfig::builder_with_provider(Arc::new(ring_crypto_provider))
        .with_protocol_versions(&[&TLS13])
        .expect("Valid rustls server config.")
        .with_client_cert_verifier(client_cert_verifier)
        .with_cert_resolver(static_cert_resolver(
            certified_key(self_tls_cert, ed25519_signing_key),
            SignatureScheme::ED25519,
        ))
}

fn static_cert_resolver(key: CertifiedKey, scheme: SignatureScheme) -> Arc<dyn ResolvesServerCert> {
    Arc::new(StaticCertResolver::new(key, scheme).expect(
        "Failed to create the static cert resolver because the signing key referenced \
        in the certified key is incompatible with the signature scheme. This is an implementation error.",
    ))
}
