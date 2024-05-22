use crate::tls::rustls::cert_resolver::StaticCertResolver;
use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use crate::tls::rustls::node_cert_verifier::NodeClientCertVerifier;
use crate::tls::rustls::{certified_key, RustlsTlsStream};
use crate::tls::tls_cert_from_registry;
use ic_crypto_internal_csp::api::CspTlsHandshakeSignerProvider;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_tls_interfaces::{
    AuthenticatedPeer, SomeOrAllNodes, TlsConfigError, TlsPublicKeyCert, TlsServerHandshakeError,
    TlsStream,
};
use ic_crypto_utils_tls::node_id_from_rustls_certs;
use ic_interfaces_registry::RegistryClient;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{
        cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
        server::{ClientCertVerifier, NoClientAuth, ResolvesServerCert},
        sign::CertifiedKey,
        version::TLS13,
        ServerConfig, SignatureScheme,
    },
    TlsAcceptor,
};

pub fn server_config<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
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
        CspServerEd25519SigningKey::new(self_tls_cert_key_id, signer_provider.handshake_signer());
    Ok(
        server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
            Arc::new(client_cert_verifier),
            self_tls_cert,
            ed25519_signing_key,
        ),
    )
}

pub fn server_config_without_client_auth<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
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
        CspServerEd25519SigningKey::new(self_tls_cert_key_id, signer_provider.handshake_signer());
    let config = server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
        NoClientAuth::boxed(),
        self_tls_cert,
        ed25519_signing_key,
    );
    Ok(config)
}

pub async fn perform_tls_server_handshake<P: CspTlsHandshakeSignerProvider>(
    signer_provider: &P,
    self_node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    allowed_clients: SomeOrAllNodes,
    registry_version: RegistryVersion,
) -> Result<(Box<dyn TlsStream>, AuthenticatedPeer), TlsServerHandshakeError> {
    let config = server_config(
        signer_provider,
        self_node_id,
        registry_client,
        allowed_clients,
        registry_version,
    )?;

    let rustls_stream = accept_connection(tcp_stream, config).await?;

    let peer_cert = rustls_stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or(TlsServerHandshakeError::HandshakeError {
            internal_error: "missing peer certificates in session".to_string(),
        })?
        .first()
        .ok_or(TlsServerHandshakeError::HandshakeError {
            internal_error: "a single cert must be present".to_string(),
        })?;

    let authenticated_peer = node_id_from_rustls_certs(peer_cert).map_err(|err| {
        TlsServerHandshakeError::HandshakeError {
            internal_error: format!("{:?}", err),
        }
    })?;

    let tls_stream = RustlsTlsStream::new(tokio_rustls::TlsStream::from(rustls_stream));

    Ok((
        Box::new(tls_stream),
        AuthenticatedPeer::Node(authenticated_peer),
    ))
}

fn server_config_with_tls13_and_aes_ciphersuites_and_ed25519_signing_key(
    client_cert_verifier: Arc<dyn ClientCertVerifier>,
    self_tls_cert: TlsPublicKeyCert,
    ed25519_signing_key: CspServerEd25519SigningKey,
) -> ServerConfig {
    ServerConfig::builder()
        .with_cipher_suites(&[TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .expect("Valid rustls server config.")
        .with_client_cert_verifier(client_cert_verifier)
        .with_cert_resolver(static_cert_resolver(
            certified_key(self_tls_cert, ed25519_signing_key),
            SignatureScheme::ED25519,
        ))
}

async fn accept_connection(
    tcp_stream: TcpStream,
    config: ServerConfig,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, TlsServerHandshakeError> {
    TlsAcceptor::from(Arc::new(config))
        .accept(tcp_stream)
        .await
        .map_err(|e| TlsServerHandshakeError::HandshakeError {
            internal_error: format!("{}", e),
        })
}

fn static_cert_resolver(key: CertifiedKey, scheme: SignatureScheme) -> Arc<dyn ResolvesServerCert> {
    Arc::new(StaticCertResolver::new(key, scheme).expect(
        "Failed to create the static cert resolver because the signing key referenced \
        in the certified key is incompatible with the signature scheme. This is an implementation error.",
    ))
}
