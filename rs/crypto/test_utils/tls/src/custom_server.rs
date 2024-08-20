//! A custom, configurable TLS server that does not rely on the crypto
//! implementation. It is purely for testing the client.
#![allow(clippy::unwrap_used)]
use crate::x509_certificates::CertWithPrivateKey;
use crate::CipherSuite;
use crate::CipherSuite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
use crate::TlsVersion;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::NodeId;
use rand::{CryptoRng, Rng};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    SupportedCipherSuite, SupportedProtocolVersion,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

static DEFAULT_PROTOCOL_VERSIONS: &[TlsVersion] = &[TlsVersion::TLS1_3];
static DEFAULT_ALLOWED_CIPHER_SUITES: &[CipherSuite] =
    &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];

/// A builder that allows to configure and build a `CustomServer` using a fluent
/// API.
pub struct CustomServerBuilder {
    protocol_versions: Option<Vec<TlsVersion>>,
    allowed_cipher_suites: Option<Vec<CipherSuite>>,
    expected_error: Option<String>,
}

impl CustomServerBuilder {
    pub fn with_protocol_versions(mut self, protocol_versions: Vec<TlsVersion>) -> Self {
        self.protocol_versions = Some(protocol_versions);
        self
    }

    pub fn with_allowed_cipher_suites(mut self, allowed_cipher_suites: Vec<CipherSuite>) -> Self {
        self.allowed_cipher_suites = Some(allowed_cipher_suites);
        self
    }

    pub fn expect_error(mut self, expected_error: &str) -> Self {
        self.expected_error = Some(expected_error.to_string());
        self
    }

    pub fn build_with_default_server_cert<R: Rng + CryptoRng>(
        self,
        server_node: NodeId,
        rng: &mut R,
    ) -> CustomServer {
        let cert = CertWithPrivateKey::builder()
            .cn(server_node.to_string())
            .build_ed25519(rng);
        self.build(cert)
    }

    pub fn build(self, server_cert: CertWithPrivateKey) -> CustomServer {
        let protocol_versions = self
            .protocol_versions
            .unwrap_or(DEFAULT_PROTOCOL_VERSIONS.to_vec());
        let allowed_cipher_suites = self
            .allowed_cipher_suites
            .unwrap_or_else(|| DEFAULT_ALLOWED_CIPHER_SUITES.to_vec());
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        CustomServer {
            listener,
            server_cert,
            protocol_versions,
            allowed_cipher_suites,
            expected_error: self.expected_error,
        }
    }
}

/// A custom, configurable TLS server that does not rely on the crypto
/// implementation. It is purely for testing the client.
pub struct CustomServer {
    listener: std::net::TcpListener,
    server_cert: CertWithPrivateKey,
    protocol_versions: Vec<TlsVersion>,
    allowed_cipher_suites: Vec<CipherSuite>,
    expected_error: Option<String>,
}

impl CustomServer {
    pub fn builder() -> CustomServerBuilder {
        CustomServerBuilder {
            protocol_versions: None,
            allowed_cipher_suites: None,
            expected_error: None,
        }
    }

    /// Run this client asynchronously. This allows a client to connect.
    pub async fn run(&self) -> Result<(), String> {
        self.listener
            .set_nonblocking(true)
            .expect("failed to make listener non-blocking");
        let tokio_tcp_listener = TcpListener::from_std(self.listener.try_clone().unwrap())
            .expect("failed to create tokio TcpListener");
        let (tcp_stream, _peer_address) = tokio_tcp_listener
            .accept()
            .await
            .expect("failed to accept connection");

        let cipher_suites: Vec<_> = self
            .allowed_cipher_suites
            .iter()
            .map(SupportedCipherSuite::from)
            .collect();
        let protocol_versions: Vec<_> = self
            .protocol_versions
            .iter()
            .map(<&SupportedProtocolVersion>::from)
            .collect();
        let cert_chain = vec![CertificateDer::from(self.server_cert.cert_der())];
        let key_der =
            PrivateKeyDer::try_from(self.server_cert.key_pair().serialize_for_rustls()).unwrap();

        let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
        ring_crypto_provider.cipher_suites = cipher_suites;

        let config = ServerConfig::builder_with_provider(Arc::new(ring_crypto_provider))
            .with_protocol_versions(&protocol_versions)
            .expect("Valid rustls server config.")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .expect("failed to build rustls server config");

        let result: Result<_, String> = TlsAcceptor::from(Arc::new(config))
            .accept(tcp_stream)
            .await
            .map_err(|e| format!("TlsAcceptor::accept failed: {e}"));

        if let Some(expected_error) = &self.expected_error {
            let error = result.as_ref().expect_err("expected error");
            if !error.to_string().contains(expected_error) {
                panic!(
                    "expected the server error to contain \"{}\" but got error: {:?}",
                    expected_error, error
                )
            }
        } else if let Err(error) = &result {
            panic!(
                "expected the server result to be ok but got error: {}",
                error
            )
        }
        result.map(|_tls_stream| ())
    }

    /// Returns the port this server is running on.
    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .expect("failed to get local_addr")
            .port()
    }

    /// Returns the server certificate.
    pub fn cert(&self) -> X509PublicKeyCert {
        self.server_cert.x509().to_proto()
    }

    /// Returns the PEM encoded server certificate.
    pub fn cert_pem(&self) -> Vec<u8> {
        self.server_cert.cert_pem()
    }
}
