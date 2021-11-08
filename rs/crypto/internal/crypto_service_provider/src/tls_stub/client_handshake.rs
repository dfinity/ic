use crate::api::tls_errors::CspTlsClientHandshakeError;
use crate::api::CspTlsClientHandshake;
use crate::secret_key_store::SecretKeyStore;
use crate::tls_stub::{key_from_secret_key_store, peer_cert_from_stream, CspTlsSecretKeyError};
use crate::Csp;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::TlsStream;
use openssl::ssl::ConnectConfiguration;
use rand::{CryptoRng, Rng};
use std::pin::Pin;
use tokio::net::TcpStream;

#[cfg(test)]
mod tests;

#[async_trait]
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> CspTlsClientHandshake
    for Csp<R, S, C>
{
    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
        trusted_server_cert: TlsPublicKeyCert,
    ) -> Result<(TlsStream, TlsPublicKeyCert), CspTlsClientHandshakeError> {
        let tls_connector = self.tls_connector(self_cert, trusted_server_cert)?;

        let mut tls_stream = unconnected_tls_stream(
            tls_connector,
            "domain is irrelevant, because hostname verification is disabled",
            tcp_stream,
        )?;
        Pin::new(&mut tls_stream).connect().await.map_err(|e| {
            CspTlsClientHandshakeError::HandshakeError {
                internal_error: format!("Handshake failed in tokio_openssl:connect: {}", e),
            }
        })?;

        let peer_cert = peer_cert_from_stream(&tls_stream)?.ok_or(
            CspTlsClientHandshakeError::HandshakeError {
                internal_error: "Missing server certificate during handshake.".to_string(),
            },
        )?;

        Ok((TlsStream::new(tls_stream), peer_cert))
    }
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> Csp<R, S, C> {
    /// Creates a Connector for TLS. This allows to set up a TLS connection as a
    /// client. The `self_cert` is used as client certificate for mutual SSL and
    /// the corresponding private key must be in the secret key store. The
    /// client will only connect to a server that presents the
    /// `trusted_server_cert` in the TLS handshake.
    fn tls_connector(
        &self,
        self_cert: TlsPublicKeyCert,
        trusted_server_cert: TlsPublicKeyCert,
    ) -> Result<ConnectConfiguration, CspTlsClientHandshakeError> {
        Ok(ic_crypto_internal_tls::tls_connector(
            &key_from_secret_key_store(&*self.sks_read_lock(), &self_cert)?,
            self_cert.as_x509(),
            trusted_server_cert.as_x509(),
        )?)
    }
}

fn unconnected_tls_stream(
    tls_connector: ConnectConfiguration,
    domain: &str,
    tcp_stream: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>, CspTlsClientHandshakeError> {
    let tls_state = tls_connector.into_ssl(domain).map_err(|e| {
        CspTlsClientHandshakeError::CreateConnectorError {
            description: "failed to convert TLS connector to state object".to_string(),
            internal_error: format!("{}", e),
            client_cert_der: None,
            server_cert_der: None,
        }
    })?;
    let tls_stream = tokio_openssl::SslStream::new(tls_state, tcp_stream).map_err(|e| {
        CspTlsClientHandshakeError::CreateConnectorError {
            description: "failed to create tokio_openssl::SslStream".to_string(),
            internal_error: format!("{}", e),
            client_cert_der: None,
            server_cert_der: None,
        }
    })?;
    Ok(tls_stream)
}

impl From<CspTlsSecretKeyError> for CspTlsClientHandshakeError {
    fn from(secret_key_error: CspTlsSecretKeyError) -> Self {
        match secret_key_error {
            CspTlsSecretKeyError::SecretKeyNotFound => {
                CspTlsClientHandshakeError::SecretKeyNotFound
            }
            CspTlsSecretKeyError::MalformedSecretKey => {
                CspTlsClientHandshakeError::MalformedSecretKey
            }
            CspTlsSecretKeyError::WrongSecretKeyType => {
                CspTlsClientHandshakeError::WrongSecretKeyType
            }
        }
    }
}
