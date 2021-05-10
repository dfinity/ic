//! A custom, configurable TLS server that does not rely on the crypto
//! implementation. It is purely for testing the client.
#![allow(clippy::unwrap_used)]
use crate::tls::set_peer_verification_cert_store;
use crate::tls::x509_certificates::CertWithPrivateKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::NodeId;
use openssl::ssl::{SslAcceptor, SslContextBuilder, SslMethod, SslVersion};
use openssl::x509::X509;
use tokio::net::TcpListener;

const DEFAULT_MAX_PROTO_VERSION: SslVersion = SslVersion::TLS1_3;
const DEFAULT_ALLOWED_CIPHER_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
const DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS: &str = "ed25519";

/// A builder that allows to configure and build a `CustomServer` using a fluent
/// API.
pub struct CustomServerBuilder {
    max_proto_version: Option<SslVersion>,
    allowed_cipher_suites: Option<String>,
    allowed_signature_algorithms: Option<String>,
    expected_error: Option<String>,
}

impl CustomServerBuilder {
    pub fn with_max_protocol_version(mut self, version: SslVersion) -> Self {
        self.max_proto_version = Some(version);
        self
    }

    pub fn with_allowed_cipher_suites(mut self, allowed_cipher_suites: &str) -> Self {
        self.allowed_cipher_suites = Some(allowed_cipher_suites.to_string());
        self
    }

    /// The list of allowed values for TLS 1.3 can be found in https://tools.ietf.org/html/rfc8446#appendix-B.3.1.3
    pub fn with_allowed_signature_algorithms(mut self, allowed_signature_algorithms: &str) -> Self {
        self.allowed_signature_algorithms = Some(allowed_signature_algorithms.to_string());
        self
    }

    pub fn expect_error(mut self, expected_error: &str) -> Self {
        self.expected_error = Some(expected_error.to_string());
        self
    }

    pub fn build_with_default_server_cert(
        self,
        server_node: NodeId,
        trusted_client_certs: Vec<X509PublicKeyCert>,
    ) -> CustomServer {
        let cert = CertWithPrivateKey::builder()
            .cn(server_node.to_string())
            .build_ed25519();
        self.build(cert, trusted_client_certs)
    }

    pub fn build(
        self,
        server_cert: CertWithPrivateKey,
        trusted_client_certs: Vec<X509PublicKeyCert>,
    ) -> CustomServer {
        let max_proto_version = self.max_proto_version.unwrap_or(DEFAULT_MAX_PROTO_VERSION);
        let allowed_cipher_suites = self
            .allowed_cipher_suites
            .unwrap_or_else(|| DEFAULT_ALLOWED_CIPHER_SUITES.to_string());
        let allowed_signature_algorithms = self
            .allowed_signature_algorithms
            .unwrap_or_else(|| DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS.to_string());
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        CustomServer {
            listener,
            server_cert,
            trusted_client_certs,
            max_proto_version,
            allowed_cipher_suites,
            allowed_signature_algorithms,
            expected_error: self.expected_error,
        }
    }
}

/// A custom, configurable TLS server that does not rely on the crypto
/// implementation. It is purely for testing the client.
pub struct CustomServer {
    listener: std::net::TcpListener,
    server_cert: CertWithPrivateKey,
    trusted_client_certs: Vec<X509PublicKeyCert>,
    max_proto_version: SslVersion,
    allowed_cipher_suites: String,
    allowed_signature_algorithms: String,
    expected_error: Option<String>,
}

#[allow(unused)]
impl CustomServer {
    pub fn builder() -> CustomServerBuilder {
        CustomServerBuilder {
            max_proto_version: None,
            allowed_cipher_suites: None,
            allowed_signature_algorithms: None,
            expected_error: None,
        }
    }

    /// Run this client asynchronously. This allows a client to connect.
    pub async fn run(self) {
        let mut tokio_tcp_listener = TcpListener::from_std(self.listener.try_clone().unwrap())
            .expect("failed to create tokio TcpListener");
        let (tcp_stream, _peer_address) = tokio_tcp_listener
            .accept()
            .await
            .expect("failed to accept connection");

        let tls_acceptor = self.tls_acceptor();
        let result = tokio_openssl::accept(&tls_acceptor, tcp_stream).await;

        if let Some(expected_error) = self.expected_error {
            let error = result.err().expect("expected error");
            if !error.to_string().contains(&expected_error) {
                panic!(
                    "expected the server error to contain \"{}\" but got error: {:?}",
                    expected_error, error
                )
            }
        } else if let Some(error) = result.err() {
            panic!(
                "expected the server result to be ok but got error: {}",
                error
            )
        }
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
        X509PublicKeyCert {
            certificate_der: self
                .server_cert
                .x509()
                .to_der()
                .expect("failed to DER encode server cert"),
        }
    }

    /// Returns the PEM encoded server certificate.
    pub fn cert_pem(&self) -> Vec<u8> {
        self.server_cert
            .x509()
            .to_pem()
            .expect("failed to PEM encode server cert")
    }

    fn tls_acceptor(&self) -> SslAcceptor {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .expect("Failed to initialize the acceptor.");
        self.restrict_tls_version_and_cipher_suites_and_sig_algs(&mut builder);
        let trusted_client_certs = self
            .trusted_client_certs
            .iter()
            .map(|c| X509::from_der(&c.certificate_der).expect("unable to parse client cert"))
            .collect();
        set_peer_verification_cert_store(trusted_client_certs, &mut builder);
        builder.set_verify_depth(0);
        builder
            .set_private_key(&self.server_cert.key_pair())
            .expect("Failed to set the private key.");
        builder
            .set_certificate(&self.server_cert.x509())
            .expect("Failed to set the server certificate.");
        builder
            .check_private_key()
            .expect("Inconsistent private key and certificate.");
        builder.build()
    }

    fn restrict_tls_version_and_cipher_suites_and_sig_algs(&self, builder: &mut SslContextBuilder) {
        builder
            .set_max_proto_version(Some(self.max_proto_version))
            .expect("Failed to set the maximum protocol version.");
        builder
            .set_ciphersuites(self.allowed_cipher_suites.as_str())
            .expect("Failed to set the ciphersuites.");
        builder
            .set_sigalgs_list(self.allowed_signature_algorithms.as_str())
            .expect("Failed to set the sigalgs list.");
    }
}
