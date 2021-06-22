use context::*;
use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptorBuilder, SslConnectorBuilder, SslContextBuilder, SslVersion};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::{
    pkey::{PKey, Private},
    ssl::{ConnectConfiguration, SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};

pub use acceptor::{tls_acceptor, ClientAuthentication, CreateTlsAcceptorError};
pub use connector::{tls_connector, CreateTlsConnectorError};

const MIN_PROTOCOL_VERSION: Option<SslVersion> = Some(SslVersion::TLS1_3);
const ALLOWED_CIPHER_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
const ALLOWED_SIGNATURE_ALGORITHMS: &str = "ed25519";

#[cfg(test)]
mod tests;

mod acceptor {
    use super::*;

    pub enum ClientAuthentication {
        /// No client authentication is performed. The server does not request a
        /// certificate from the client.
        NoAuthentication,
        /// Client authentication is optional. If the client presents a
        /// certificate, the handshake only succeeds if the client's certificate
        /// can be verified against 'trusted_client_certs'.
        OptionalAuthentication { trusted_client_certs: Vec<X509> },
    }

    /// Builds a TLS acceptor to establish TLS connections on the server side.
    ///
    /// For the exact configuration details, see the documentation of the
    /// `TlsHandshake` trait in the `ic-crypto-tls-interfaces` crate.
    ///
    /// # Errors
    /// * `CreateTlsAcceptorError` if the creation of the acceptor failed
    pub fn tls_acceptor(
        private_key: &PKey<Private>,
        server_cert: &X509,
        client_auth: ClientAuthentication,
    ) -> Result<SslAcceptor, CreateTlsAcceptorError> {
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
            .expect("Failed to initialize the acceptor.");

        restrict_tls_version_and_cipher_suites_and_sig_algs(&mut builder);

        match client_auth {
            ClientAuthentication::NoAuthentication => {
                prohibit_client_authentication(&mut builder);
            }
            ClientAuthentication::OptionalAuthentication {
                trusted_client_certs,
            } => {
                ensure_root_self_signed_sigs_verified(&mut builder);
                ensure_trusted_client_certs_not_empty(&trusted_client_certs)?;
                allow_but_dont_enforce_client_authentication(&mut builder);
                set_peer_verification_cert_store(trusted_client_certs, &mut builder)?;
                set_maximum_number_of_intermediate_ca_certificates(1, &mut builder);
            }
        }

        set_private_key(private_key, server_cert, &mut builder)?;
        set_certificate(server_cert, &mut builder)?;
        check_private_key(server_cert, &mut builder)?;
        Ok(builder.build())
    }

    fn ensure_trusted_client_certs_not_empty(
        trusted_client_certs: &[X509],
    ) -> Result<(), CreateTlsAcceptorError> {
        if trusted_client_certs.is_empty() {
            return Err(CreateTlsAcceptorError {
                description: "The trusted client certs must not be empty.".to_string(),
                cert_der: None,
                internal_error: None,
            });
        }
        Ok(())
    }

    fn allow_but_dont_enforce_client_authentication(builder: &mut SslAcceptorBuilder) {
        // We do not set the `FAIL_IF_NO_PEER_CERT` flag since client authentication
        // should be allowed, but not enforced.
        builder.set_verify(SslVerifyMode::PEER);
    }

    fn prohibit_client_authentication(builder: &mut SslAcceptorBuilder) {
        builder.set_verify(SslVerifyMode::NONE);
    }

    /// A TLS acceptor couldn't be created.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CreateTlsAcceptorError {
        pub description: String,
        pub cert_der: Option<Vec<u8>>,
        pub internal_error: Option<String>,
    }

    impl From<CreateTlsContextError> for CreateTlsAcceptorError {
        fn from(error: CreateTlsContextError) -> Self {
            CreateTlsAcceptorError {
                description: error.description,
                cert_der: error.cert_der,
                internal_error: Some(error.internal_error),
            }
        }
    }
}

mod connector {
    use super::*;

    /// Builds a TLS connector to establish TLS connections on the client side.
    ///
    /// For the exact configuration details, see the documentation of the
    /// `TlsHandshake` trait in the `ic-crypto-tls-interfaces` crate.
    ///
    /// # Errors
    /// * `CreateTlsConnectorError` if the creation of the connector failed
    pub fn tls_connector(
        private_key: &PKey<Private>,
        client_cert: &X509,
        trusted_server_cert: &X509,
    ) -> Result<ConnectConfiguration, CreateTlsConnectorError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .expect("Failed to initialize connector.");
        restrict_tls_version_and_cipher_suites_and_sig_algs(&mut builder);
        ensure_root_self_signed_sigs_verified(&mut builder);
        set_peer_verification_cert_store(vec![trusted_server_cert.clone()], &mut builder)?;
        set_most_restrictive_certificate_verification_depth(&mut builder);
        set_private_key(private_key, client_cert, &mut builder)?;
        set_certificate(client_cert, &mut builder)?;
        check_private_key(client_cert, &mut builder)?;
        let mut connect_config =
            build_connect_configuration(builder, &client_cert, &trusted_server_cert)?;
        connect_config.set_verify_hostname(false);
        Ok(connect_config)
    }

    fn build_connect_configuration(
        builder: SslConnectorBuilder,
        client_cert: &X509,
        trusted_server_cert: &X509,
    ) -> Result<ConnectConfiguration, CreateTlsConnectorError> {
        builder.build().configure().map_err(|e| {
            CreateTlsConnectorError::new(
                "Failed to build the connector configuration.",
                client_cert,
                trusted_server_cert,
                e,
            )
        })
    }

    /// A TLS connector couldn't be created.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CreateTlsConnectorError {
        pub description: String,
        pub client_cert_der: Option<Vec<u8>>,
        pub server_cert_der: Option<Vec<u8>>,
        pub internal_error: String,
    }

    impl CreateTlsConnectorError {
        fn new(
            description: &str,
            client_cert: &X509,
            server_cert: &X509,
            internal_error: ErrorStack,
        ) -> Self {
            Self {
                description: description.to_string(),
                client_cert_der: client_cert.to_der().map(Some).unwrap_or(None),
                server_cert_der: server_cert.to_der().map(Some).unwrap_or(None),
                internal_error: format!("{}", internal_error),
            }
        }
    }

    impl From<CreateTlsContextError> for CreateTlsConnectorError {
        fn from(error: CreateTlsContextError) -> Self {
            CreateTlsConnectorError {
                description: error.description,
                client_cert_der: error.cert_der,
                server_cert_der: None,
                internal_error: error.internal_error,
            }
        }
    }
}

mod context {
    use super::*;

    pub fn restrict_tls_version_and_cipher_suites_and_sig_algs(builder: &mut SslContextBuilder) {
        // The following calls are on hard-coded input and so we panic:
        builder
            .set_min_proto_version(MIN_PROTOCOL_VERSION)
            .expect("Failed to set the minimum protocol version.");
        builder
            .set_ciphersuites(ALLOWED_CIPHER_SUITES)
            .expect("Failed to set the ciphersuites.");
        // The list of allowed values for TLS 1.3 can be found in https://tools.ietf.org/html/rfc8446#appendix-B.3.1.3
        builder
            .set_sigalgs_list(ALLOWED_SIGNATURE_ALGORITHMS)
            .expect("Failed to set the sigalgs list.");
    }

    pub fn ensure_root_self_signed_sigs_verified(builder: &mut SslContextBuilder) {
        // This instructs OpenSSL to check the signature on the peer's self-signed
        // certificate. Cf. [the OpenSSL
        // docs](https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_flags.html).
        //
        // Nb. this isn't strictly necessary, as ownership of the private key is already
        // checked during the handshake (CertificateVerify message) and the
        // self-signed cert is already part of our trust store.
        // However, we do it here for completeness and surprise-minimization.
        builder
            .verify_param_mut()
            .set_flags(openssl::x509::verify::X509VerifyFlags::CHECK_SS_SIGNATURE)
            .expect("Failed to require checking of self-signed certificate signatures");
    }

    pub fn set_private_key(
        private_key: &PKey<Private>,
        cert: &X509,
        builder: &mut SslContextBuilder,
    ) -> Result<(), CreateTlsContextError> {
        builder
            .set_private_key(private_key)
            .map_err(|e| CreateTlsContextError::new("Failed to set the private key.", cert, e))
    }

    pub fn set_certificate(
        cert: &X509,
        builder: &mut SslContextBuilder,
    ) -> Result<(), CreateTlsContextError> {
        builder
            .set_certificate(cert)
            .map_err(|e| CreateTlsContextError::new("Failed to set the self certificate.", cert, e))
    }

    pub fn check_private_key(
        cert: &X509,
        builder: &mut SslContextBuilder,
    ) -> Result<(), CreateTlsContextError> {
        builder.check_private_key().map_err(|e| {
            CreateTlsContextError::new("Inconsistent private key and certificate.", cert, e)
        })
    }

    pub fn set_most_restrictive_certificate_verification_depth(builder: &mut SslContextBuilder) {
        set_maximum_number_of_intermediate_ca_certificates(0, builder);
    }

    pub fn set_maximum_number_of_intermediate_ca_certificates(
        max_number_of_intermediate_ca_certificates: u32,
        builder: &mut SslContextBuilder,
    ) {
        // The depth supplied to `set_verify_depth` represents the number of allowed
        // intermediate CA certificates because neither the leaf (aka end-entity) nor
        // the root certificate (aka trust-anchor) count against the depth. See the
        // OpenSSL docs: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_verify_depth.html
        builder.set_verify_depth(max_number_of_intermediate_ca_certificates);
    }

    pub fn set_peer_verification_cert_store(
        certs: Vec<X509>,
        builder: &mut SslContextBuilder,
    ) -> Result<(), CreateTlsContextError> {
        // `SslConnector::builder` calls `set_default_verify_paths`, automatically
        // adding many CA certificates to the context's `cert_store`. This would be a
        // security vulnerability. Thus, we overwrite the cert_store with an empty one:
        set_empty_cert_store(builder);
        let store = cert_store(certs)?;
        builder
            .set_verify_cert_store(store)
            .map_err(|e| CreateTlsContextError {
                description: "Failed to set the verify_cert_store.".to_string(),
                cert_der: None,
                internal_error: format!("{}", e),
            })
    }

    fn set_empty_cert_store(builder: &mut SslContextBuilder) {
        let empty_cert_store = X509StoreBuilder::new()
            .expect("Failed to init X509 store builder.")
            .build();
        builder.set_cert_store(empty_cert_store);
    }

    fn cert_store(certs: Vec<X509>) -> Result<X509Store, CreateTlsContextError> {
        // The following call is on hard-coded input and so we panic:
        let mut cert_store_builder =
            X509StoreBuilder::new().expect("Failed to init X509 store builder.");
        for cert in certs {
            cert_store_builder.add_cert(cert.clone()).map_err(|e| {
                CreateTlsContextError::new(
                    "Failed to add the certificate to the cert_store.",
                    &cert,
                    e,
                )
            })?;
        }
        Ok(cert_store_builder.build())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CreateTlsContextError {
        pub description: String,
        pub cert_der: Option<Vec<u8>>,
        pub internal_error: String,
    }

    impl CreateTlsContextError {
        fn new(description: &str, cert: &X509, internal_error: ErrorStack) -> Self {
            Self {
                description: description.to_string(),
                cert_der: cert.to_der().map(Some).unwrap_or(None),
                internal_error: format!("{}", internal_error),
            }
        }
    }
}
