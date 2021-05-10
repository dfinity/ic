//! Public interface for running a TLS handshake as a client
use super::*;
use ic_crypto_internal_tls::{tls_connector, CreateTlsConnectorError};
use ic_crypto_tls_interfaces::TlsStream;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_openssl::HandshakeError;

/// Transforms a TCP stream into a TLS stream by performing a TLS client
/// handshake.
///
/// This client authenticates its connection using the `client_cert` and the
/// corresponding `client_private_key`. The client only connects if the server
/// presents `trusted_server_cert` as certificate during the handshake.
///
/// For the handshake, the client uses the following configuration:
/// * Minimum protocol version: TLS 1.3
/// * Supported signature algorithms: ed25519
/// * Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
/// * Server authentication: mandatory, with ed25519 certificate
///
/// The given `tcp_stream` is consumed. If an error is returned, the TCP
/// connection is therefore dropped.
///
/// # Arguments
/// * `tcp_stream` is the TCP connection over which to run the TLS handshake
/// * `client_cert` is the caller's X.509 certificate
/// * `client_private_key` is the private key corresponding to `client_cert`
/// * `trusted_server_cert` is the X.509 certificate of the intended peer
///
/// # Returns
/// `Ok(TlsStream)` if the handshake was successful,
/// `TlsClientHandshakeError` otherwise
///
/// # Errors
/// * `TlsClientHandshakeError::CreateConnectorError` if the key or certs fail
///   to parse or there is an error creating the configuration
/// * `TlsClientHandshakeError::HandshakeError` if the handshake fails
pub async fn perform_tls_client_handshake(
    tcp_stream: TcpStream,
    client_cert: TlsPublicKeyCert,
    client_private_key: TlsPrivateKey,
    trusted_server_cert: TlsPublicKeyCert,
) -> Result<TlsStream, TlsClientHandshakeError> {
    let tls_connector = tls_connector(
        client_private_key.as_pkey(),
        client_cert.as_x509(),
        trusted_server_cert.as_x509(),
    )?;
    let tls_stream = tokio_openssl::connect(
        tls_connector,
        "domain is irrelevant, because hostname verification is disabled",
        tcp_stream,
    )
    .await?;
    Ok(TlsStream::new(tls_stream))
}

#[derive(Error, Clone, Debug, PartialEq, Eq)]
/// The TLS client handshake failed.
pub enum TlsClientHandshakeError {
    #[error("{description}: {internal_error}")]
    CreateConnectorError {
        description: String,
        client_cert_der: Option<Vec<u8>>,
        server_cert_der: Option<Vec<u8>>,
        internal_error: String,
    },
    #[error("handshake failed: {internal_error}")]
    HandshakeError { internal_error: String },
}

impl From<CreateTlsConnectorError> for TlsClientHandshakeError {
    fn from(clib_create_tls_connector_error: CreateTlsConnectorError) -> Self {
        TlsClientHandshakeError::CreateConnectorError {
            description: clib_create_tls_connector_error.description,
            client_cert_der: clib_create_tls_connector_error.client_cert_der,
            server_cert_der: clib_create_tls_connector_error.server_cert_der,
            internal_error: clib_create_tls_connector_error.internal_error,
        }
    }
}

impl From<HandshakeError<TcpStream>> for TlsClientHandshakeError {
    fn from(handshake_error: HandshakeError<TcpStream>) -> Self {
        TlsClientHandshakeError::HandshakeError {
            internal_error: format!(
                "Handshake failed in tokio_openssl:connect: {}",
                handshake_error
            ),
        }
    }
}
