//! A custom, configurable TLS client that does not rely on the crypto
//! implementation. It is purely for testing the server.
#![allow(clippy::unwrap_used)]
use crate::tls::set_peer_verification_cert_store;
use crate::tls::x509_certificates::CertWithPrivateKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::NodeId;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{ConnectConfiguration, SslConnector, SslContextBuilder, SslMethod, SslVersion};
use openssl::x509::X509;
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

const DEFAULT_MAX_PROTO_VERSION: SslVersion = SslVersion::TLS1_3;
const DEFAULT_ALLOWED_CIPHER_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
const DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS: &str = "ed25519";

/// A builder that allows to configure and build a `CustomClient` using a fluent
/// API.
pub struct CustomClientBuilder {
    max_proto_version: Option<SslVersion>,
    allowed_cipher_suites: Option<String>,
    allowed_signature_algorithms: Option<String>,
    expected_error: Option<String>,
    client_auth_data: Option<(PKey<Private>, X509)>,
    extra_chain_certs: Option<Vec<X509>>,
    msg_expected_from_server: Option<String>,
}

impl CustomClientBuilder {
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

    pub fn with_default_client_auth(self, client_node: NodeId) -> Self {
        self.with_client_auth(
            CertWithPrivateKey::builder()
                .cn(client_node.to_string())
                .build_ed25519(),
        )
    }

    pub fn with_client_auth(mut self, cert: CertWithPrivateKey) -> Self {
        self.client_auth_data = Some((cert.key_pair(), cert.x509()));
        self
    }

    pub fn without_client_auth(mut self) -> Self {
        self.client_auth_data = None;
        self
    }

    pub fn with_extra_chain_certs(mut self, extra_chain_certs: Vec<X509>) -> Self {
        self.extra_chain_certs = Some(extra_chain_certs);
        self
    }

    pub fn expect_msg_from_server(mut self, msg: &str) -> Self {
        self.msg_expected_from_server = Some(msg.to_string());
        self
    }

    pub fn build(self, server_cert: X509PublicKeyCert) -> CustomClient {
        let max_proto_version = self.max_proto_version.unwrap_or(DEFAULT_MAX_PROTO_VERSION);
        let allowed_cipher_suites = self
            .allowed_cipher_suites
            .unwrap_or_else(|| DEFAULT_ALLOWED_CIPHER_SUITES.to_string());
        let allowed_signature_algorithms = self
            .allowed_signature_algorithms
            .unwrap_or_else(|| DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS.to_string());
        let server_cert =
            X509::from_der(&server_cert.certificate_der).expect("Unable to parse server cert.");
        CustomClient {
            client_auth_data: self.client_auth_data,
            extra_chain_certs: self.extra_chain_certs,
            server_cert,
            max_proto_version,
            allowed_cipher_suites,
            allowed_signature_algorithms,
            expected_error: self.expected_error,
            msg_expected_from_server: self.msg_expected_from_server,
        }
    }
}

/// A custom, configurable TLS client that does not rely on the crypto
/// implementation. It is purely for testing the server.
pub struct CustomClient {
    client_auth_data: Option<(PKey<Private>, X509)>,
    extra_chain_certs: Option<Vec<X509>>,
    server_cert: X509,
    max_proto_version: SslVersion,
    allowed_cipher_suites: String,
    allowed_signature_algorithms: String,
    expected_error: Option<String>,
    msg_expected_from_server: Option<String>,
}

#[allow(unused)]
impl CustomClient {
    pub fn builder() -> CustomClientBuilder {
        CustomClientBuilder {
            max_proto_version: None,
            allowed_cipher_suites: None,
            allowed_signature_algorithms: None,
            expected_error: None,
            client_auth_data: None,
            extra_chain_certs: None,
            msg_expected_from_server: None,
        }
    }

    /// Run this client asynchronously. This tries to connect to the configured
    /// server.
    pub async fn run(self, server_port: u16) {
        let tcp_stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("failed to connect");
        let tls_connector = self.tls_connector();
        let result = tokio_openssl::connect(
            tls_connector,
            "domain is irrelevant, because hostname verification is disabled",
            tcp_stream,
        )
        .await;

        if let Some(expected_error) = self.expected_error {
            let error = result.err().expect("expected error");
            if !error.to_string().contains(&expected_error) {
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
                Ok(stream) => {
                    let (mut tls_read_half, tls_write_half) = tokio::io::split(stream);
                    self.expect_msg_from_server_if_configured(&mut tls_read_half)
                        .await;
                }
            }
        }
    }

    fn tls_connector(&self) -> ConnectConfiguration {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .expect("Failed to initialize connector.");
        self.restrict_tls_version_and_cipher_suites_and_sig_algs(&mut builder);
        set_peer_verification_cert_store(vec![self.server_cert.clone()], &mut builder);
        builder.set_verify_depth(0);
        if let Some((private_key, cert)) = &self.client_auth_data {
            builder
                .set_private_key(private_key)
                .expect("Failed to set the private key.");
            builder
                .set_certificate(cert)
                .expect("Failed to set the client certificate.");
            builder
                .check_private_key()
                .expect("Inconsistent private key and certificate.");
        }
        if let Some(extra_chain_certs) = &self.extra_chain_certs {
            for extra_chain_cert in extra_chain_certs {
                builder.add_extra_chain_cert(extra_chain_cert.clone());
            }
        }
        let mut connect_config = builder
            .build()
            .configure()
            .expect("Failed to build the connector configuration.");
        connect_config.set_verify_hostname(false);
        connect_config
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

    /// Returns the certificate used for client authentication.
    pub fn client_auth_cert(&self) -> X509PublicKeyCert {
        if let Some((_, cert)) = &self.client_auth_data {
            return X509PublicKeyCert {
                certificate_der: cert.to_der().expect("failed to DER encode client_cert"),
            };
        }
        panic!("no certificate since client auth is disabled")
    }

    async fn expect_msg_from_server_if_configured(
        &self,
        tls_read_half: &mut ReadHalf<SslStream<TcpStream>>,
    ) {
        if let Some(msg_expected_from_server) = &self.msg_expected_from_server {
            let mut bytes_from_server = Vec::new();
            tls_read_half
                .read_to_end(&mut bytes_from_server)
                .await
                .expect("error in read_to_end");
            let msg_from_server = String::from_utf8(bytes_from_server.to_vec()).unwrap();
            assert_eq!(msg_from_server, msg_expected_from_server.clone());
        }
    }
}
