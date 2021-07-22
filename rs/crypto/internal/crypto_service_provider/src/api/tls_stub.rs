use crate::api::tls_stub::tls_errors::{CspTlsClientHandshakeError, CspTlsServerHandshakeError};
use crate::tls_stub::cert_chain::CspCertificateChain;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::TlsStream;
use std::collections::HashSet;
use tokio::net::TcpStream;

pub mod tls_errors;

/// A trait that exposes TLS server-side handshaking
#[async_trait]
pub trait CspTlsServerHandshake {
    /// Transforms a TCP stream into a TLS stream by performing a TLS server
    /// handshake. This allows to set up a TLS connection as a server.
    ///
    /// The `self_cert` is used as server certificate and the corresponding
    /// private key must be in the secret key store.  The client may
    /// authenticate using a certificate. If the client presents a certificate,
    /// the server will only connect to a client that can present one of the
    /// `trusted_client_certs` in the TLS handshake.
    ///
    /// For the handshake, the server uses the following configuration:
    /// * Minimum protocol version: TLS 1.3
    /// * Supported signature algorithms: ed25519
    /// * Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    /// * Client authentication: optional, with ed25519 certificate
    ///
    /// The given `tcp_stream` is consumed. If an error is returned, the TCP
    /// connection is therefore dropped.
    ///
    /// The TLS stream is returned in a form that does not allow for extracting
    /// the private key corresponding to `self_cert` or the TLS session keys.
    ///
    /// Returns the TLS stream, together with an optional certificate chain. If
    /// the client presented a certificate and successfully authenticated, the
    /// respective certificate chain is returned (in `Some`). If the handshake
    /// was successful and the client did not present a certificate, the
    /// returned certificate chain is `None`.
    ///
    /// # Errors
    /// * CspTlsServerHandshakeError::CreateAcceptorError if there is a problem
    ///   configuring the server for accepting connections from clients.
    /// * CspTlsServerHandshakeError::HandshakeError if there is an error during
    ///   the TLS handshake, or the handshake fails.
    /// * CspTlsServerHandshakeError::SecretKeyNotFound if the secret key
    ///   corresponding to `self_cert` cannot be found in the secret key store.
    /// * CspTlsServerHandshakeError::MalformedSecretKey if the secret key
    ///   corresponding to `self_cert` is malformed in the secret key store.
    /// * CspTlsServerHandshakeError::WrongSecretKeyType if the secret key
    ///   corresponding to `self_cert` has the wrong type in the secret key
    ///   store.
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
        trusted_client_certs: HashSet<TlsPublicKeyCert>,
    ) -> Result<(TlsStream, Option<CspCertificateChain>), CspTlsServerHandshakeError>;

    /// Transforms a TCP stream into a TLS stream by performing a TLS server
    /// handshake. This allows to set up a TLS connection as a server.
    ///
    /// The `self_cert` is used as server certificate and the corresponding
    /// private key must be in the secret key store.
    ///
    /// For the handshake, the server uses the following configuration:
    /// * Minimum protocol version: TLS 1.3
    /// * Supported signature algorithms: ed25519
    /// * Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    /// * Client authentication: no client authentication is performed
    ///
    /// The given `tcp_stream` is consumed. If an error is returned, the TCP
    /// connection is therefore dropped.
    ///
    /// The TLS stream is returned in a form that does not allow for extracting
    /// the private key corresponding to `self_cert` or the TLS session keys.
    ///
    /// Returns the TLS stream.
    ///
    /// # Errors
    /// * CspTlsServerHandshakeError::CreateAcceptorError if there is a problem
    ///   configuring the server for accepting connections from clients.
    /// * CspTlsServerHandshakeError::HandshakeError if there is an error during
    ///   the TLS handshake, or the handshake fails.
    /// * CspTlsServerHandshakeError::SecretKeyNotFound if the secret key
    ///   corresponding to `self_cert` cannot be found in the secret key store.
    /// * CspTlsServerHandshakeError::MalformedSecretKey if the secret key
    ///   corresponding to `self_cert` is malformed in the secret key store.
    /// * CspTlsServerHandshakeError::WrongSecretKeyType if the secret key
    ///   corresponding to `self_cert` has the wrong type in the secret key
    ///   store.
    /// * CspTlsServerHandshakeError::MalformedClientCertificate if any
    ///   certificate in the chain offered by the client is malformed.
    async fn perform_tls_server_handshake_without_client_auth(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
    ) -> Result<TlsStream, CspTlsServerHandshakeError>;
}

/// A trait that exposes TLS client-side handshaking
#[async_trait]
pub trait CspTlsClientHandshake {
    /// Transforms a TCP stream into a TLS stream by performing a TLS
    /// client handshake. This allows to set up a TLS connection as a client.
    ///
    /// The `self_cert` is used as client certificate for mutual SSL and
    /// the corresponding private key must be in the secret key store. The
    /// client will only connect to a server that presents the
    /// `trusted_server_cert` in the TLS handshake.
    ///
    /// Hostname verification will _not_ be performed during the handshake.
    ///
    /// The given `tcp_stream` is consumed. If an error is returned, the TCP
    /// connection is therefore dropped.
    ///
    /// The TLS stream is returned in a form that does not allow for extracting
    /// the private key corresponding to `self_cert` or the TLS session keys.
    ///
    /// # Errors
    /// * CspTlsClientHandshakeError::CreateConnectorError if there is a problem
    ///   configuring the TLS client for performing the handshake.
    /// * CspTlsClientHandshakeError::HandshakeError if there is an error during
    ///   the TLS handshake, or the handshake fails.
    /// * CspTlsClientHandshakeError::SecretKeyNotFound if the secret key
    ///   corresponding to `self_cert` cannot be found in the secret key store.
    /// * CspTlsClientHandshakeError::MalformedSecretKey if the secret key
    ///   corresponding to `self_cert` is malformed in the secret key store.
    /// * CspTlsClientHandshakeError::WrongSecretKeyType if the secret key
    ///   corresponding to `self_cert` has the wrong type in the secret key
    ///   store.
    /// * CspTlsClientHandshakeError::MalformedServerCertificate if the
    ///   certificate offered by the server is malformed.
    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
        trusted_server_cert: TlsPublicKeyCert,
    ) -> Result<(TlsStream, TlsPublicKeyCert), CspTlsClientHandshakeError>;
}
