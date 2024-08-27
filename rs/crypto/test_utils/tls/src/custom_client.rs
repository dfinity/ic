//! A custom, configurable TLS client that does not rely on the crypto
//! implementation. It is purely for testing the server.
#![allow(clippy::unwrap_used)]
use crate::x509_certificates::CertWithPrivateKey;
use crate::CipherSuite;
use crate::CipherSuite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
use crate::TlsVersion;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::NodeId;
use rand::{CryptoRng, Rng};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

static DEFAULT_PROTOCOL_VERSIONS: &[TlsVersion] = &[TlsVersion::TLS1_3];
static DEFAULT_ALLOWED_CIPHER_SUITES: &[CipherSuite] =
    &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];

/// A builder that allows to configure and build a `CustomClient` using a fluent
/// API.
pub struct CustomClientBuilder {
    protocol_versions: Option<Vec<TlsVersion>>,
    allowed_cipher_suites: Option<Vec<CipherSuite>>,
    expected_error: Option<String>,
    client_auth_data: Option<CertWithPrivateKey>,
    extra_chain_certs: Option<Vec<TlsPublicKeyCert>>,
}

impl CustomClientBuilder {
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

    pub fn with_default_client_auth<R: Rng + CryptoRng>(
        self,
        client_node: NodeId,
        rng: &mut R,
    ) -> Self {
        self.with_client_auth(
            CertWithPrivateKey::builder()
                .cn(client_node.to_string())
                .build_ed25519(rng),
        )
    }

    pub fn with_client_auth(mut self, cert: CertWithPrivateKey) -> Self {
        self.client_auth_data = Some(cert);
        self
    }

    pub fn without_client_auth(mut self) -> Self {
        self.client_auth_data = None;
        self
    }

    pub fn with_extra_chain_certs(mut self, extra_chain_certs: Vec<TlsPublicKeyCert>) -> Self {
        self.extra_chain_certs = Some(extra_chain_certs);
        self
    }

    pub fn build(self, server_cert: X509PublicKeyCert) -> CustomClient {
        let protocol_versions = self
            .protocol_versions
            .unwrap_or(DEFAULT_PROTOCOL_VERSIONS.to_vec());
        let allowed_cipher_suites = self
            .allowed_cipher_suites
            .unwrap_or_else(|| DEFAULT_ALLOWED_CIPHER_SUITES.to_vec());
        let server_cert =
            TlsPublicKeyCert::try_from(server_cert).expect("Unable to parse server cert.");
        CustomClient {
            client_auth_data: self.client_auth_data,
            extra_chain_certs: self.extra_chain_certs,
            server_cert,
            protocol_versions,
            allowed_cipher_suites,
            expected_error: self.expected_error,
        }
    }
}

/// A custom, configurable TLS client that does not rely on the crypto
/// implementation. It is purely for testing the server.
pub struct CustomClient {
    client_auth_data: Option<CertWithPrivateKey>,
    extra_chain_certs: Option<Vec<TlsPublicKeyCert>>,
    server_cert: TlsPublicKeyCert,
    protocol_versions: Vec<TlsVersion>,
    allowed_cipher_suites: Vec<CipherSuite>,
    expected_error: Option<String>,
}

impl CustomClient {
    pub fn builder() -> CustomClientBuilder {
        CustomClientBuilder {
            protocol_versions: None,
            allowed_cipher_suites: None,
            expected_error: None,
            client_auth_data: None,
            extra_chain_certs: None,
        }
    }

    /// Run this client asynchronously. This tries to connect to the configured
    /// server.
    pub async fn run(&self, server_port: u16) {
        let tcp_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("failed to connect");

        let cipher_suites: Vec<_> = self
            .allowed_cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::from)
            .collect();
        let protocol_versions: Vec<_> = self
            .protocol_versions
            .iter()
            .map(<&rustls::SupportedProtocolVersion>::from)
            .collect();
        let matching_end_entity_cert_verifier = MatchingEndEntityCertVerifier {
            end_entity: self.server_cert.clone(),
        };

        let mut ring_crypto_provider = rustls::crypto::ring::default_provider();
        ring_crypto_provider.cipher_suites = cipher_suites;

        let config_builder = ClientConfig::builder_with_provider(Arc::new(ring_crypto_provider))
            .with_protocol_versions(&protocol_versions)
            .expect("Valid rustls client config.")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(matching_end_entity_cert_verifier)); // disables hostname verification

        let config = if let Some(cert_with_key) = &self.client_auth_data {
            let key_der = rustls::pki_types::PrivateKeyDer::try_from(
                cert_with_key.key_pair().serialize_for_rustls(),
            )
            .unwrap();
            let mut cert_chain = vec![rustls::pki_types::CertificateDer::from(
                cert_with_key.cert_der(),
            )];
            if let Some(extra_chain_certs) = &self.extra_chain_certs {
                extra_chain_certs
                    .iter()
                    .map(|x| rustls::pki_types::CertificateDer::from(x.as_der().clone()))
                    .for_each(|cert| cert_chain.push(cert));
            }
            config_builder
                .with_client_auth_cert(cert_chain, key_der)
                .expect("failed to set client auth data")
        } else {
            config_builder.with_no_client_auth()
        };

        // Even though the domain is irrelevant here because hostname verification is disabled,
        // it is important that the domain is well-formed because some TLS implementations
        // (e.g., Rustls) abort the handshake if parsing of the domain fails (e.g., for SNI when
        // sent to the server)
        let irrelevant_domain = "domain.is-irrelevant-as-hostname-verification-is.disabled";
        let result = TlsConnector::from(Arc::new(config))
            .connect(
                irrelevant_domain
                    .try_into()
                    .expect("failed to create domain"),
                tcp_stream,
            )
            .await
            .map_err(|e| format!("TlsConnector::connect failed: {e}"));

        if let Some(expected_error) = &self.expected_error {
            let error = result.expect_err("expected error");
            if !error.to_string().contains(expected_error) {
                panic!(
                    "expected the client error to contain \"{}\" but got error: {:?}",
                    expected_error, error
                )
            }
        } else {
            match result {
                Err(error) => panic!(
                    "expected the client result to be ok but got error: {}",
                    error
                ),
                Ok(_tls_stream) => (),
            }
        }
    }

    /// Returns the certificate used for client authentication.
    pub fn client_auth_cert(&self) -> X509PublicKeyCert {
        if let Some(cert_with_private_key) = &self.client_auth_data {
            return cert_with_private_key.x509().to_proto();
        }
        panic!("no certificate since client auth is disabled")
    }
}

/// A server cert verifier for testing that considers a
/// certificate chain valid iff
/// * the `end_entity` exactly matches a given reference
///   certificate, and
/// * the `intermediates` certs are empty.
///   All other parameters (server name, time, etc.) are ignored.
#[derive(Debug)]
struct MatchingEndEntityCertVerifier {
    end_entity: TlsPublicKeyCert,
}

impl rustls::client::danger::ServerCertVerifier for MatchingEndEntityCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() != self.end_entity.as_der() {
            return Err(rustls::Error::General("not an exact match".to_string()));
        }
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "intermediates not empty".to_string(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
