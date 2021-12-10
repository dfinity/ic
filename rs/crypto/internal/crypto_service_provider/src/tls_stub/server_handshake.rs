use crate::api::tls_errors::CspTlsServerHandshakeError;
use crate::api::CspTlsServerHandshake;
use crate::secret_key_store::SecretKeyStore;
use crate::tls_stub::cert_chain::CspCertificateChain;
use crate::tls_stub::{
    key_from_secret_key_store, peer_cert_chain_from_stream, CspTlsSecretKeyError,
};
use crate::Csp;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::TlsStream;
use openssl::ssl::{Ssl, SslAcceptor};
use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;

#[cfg(test)]
mod tests;

#[async_trait]
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> CspTlsServerHandshake
    for Csp<R, S, C>
{
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
        trusted_client_certs: HashSet<TlsPublicKeyCert>,
    ) -> Result<(TlsStream, Option<CspCertificateChain>), CspTlsServerHandshakeError> {
        let tls_acceptor = self.tls_acceptor(self_cert, Some(trusted_client_certs.clone()))?;

        let mut tls_stream = unconnected_tls_stream(tls_acceptor, tcp_stream)?;
        Pin::new(&mut tls_stream).accept().await.map_err(|e| {
            CspTlsServerHandshakeError::HandshakeError {
                internal_error: format!("Handshake failed in tokio_openssl:accept: {}", e),
            }
        })?;

        let peer_cert_chain = peer_cert_chain_from_stream(&tls_stream)?;
        Ok((TlsStream::new(tls_stream), peer_cert_chain))
    }

    async fn perform_tls_server_handshake_without_client_auth(
        &self,
        tcp_stream: TcpStream,
        self_cert: TlsPublicKeyCert,
    ) -> Result<TlsStream, CspTlsServerHandshakeError> {
        let tls_acceptor = self.tls_acceptor(self_cert, None)?;

        let mut tls_stream = unconnected_tls_stream(tls_acceptor, tcp_stream)?;
        Pin::new(&mut tls_stream).accept().await.map_err(|e| {
            CspTlsServerHandshakeError::HandshakeError {
                internal_error: format!("Handshake failed in tokio_openssl:accept: {}", e),
            }
        })?;

        Ok(TlsStream::new(tls_stream))
    }
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> Csp<R, S, C> {
    /// Creates an Acceptor for TLS. This allows to set up a TLS connection as a
    /// server. The `self_cert` is used as server certificate and the
    /// corresponding private key must be in the secret key store.

    /// The server can be configured to require client authentication.
    /// If trusted_client_certs is Some then the non-empty set will
    /// list the client certificates that will be accepted. If it is None,
    /// then no client authentication will be performed.
    fn tls_acceptor(
        &self,
        self_cert: TlsPublicKeyCert,
        trusted_client_certs: Option<HashSet<TlsPublicKeyCert>>,
    ) -> Result<SslAcceptor, CspTlsServerHandshakeError> {
        use ic_crypto_internal_tls::{tls_acceptor, ClientAuthentication};

        let trusted_client_certs_x509 = match trusted_client_certs {
            Some(c) => ClientAuthentication::OptionalAuthentication {
                trusted_client_certs: c.iter().map(TlsPublicKeyCert::as_x509).cloned().collect(),
            },
            None => ClientAuthentication::NoAuthentication,
        };
        Ok(tls_acceptor(
            &key_from_secret_key_store(Arc::clone(&self.csp_vault), &self_cert)?,
            self_cert.as_x509(),
            trusted_client_certs_x509,
        )?)
    }
}

fn unconnected_tls_stream(
    tls_acceptor: SslAcceptor,
    tcp_stream: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>, CspTlsServerHandshakeError> {
    let tls_state = Ssl::new(tls_acceptor.context()).map_err(|e| {
        CspTlsServerHandshakeError::CreateAcceptorError {
            description: "failed to convert TLS acceptor to state object".to_string(),
            internal_error: Some(format!("{}", e)),
            cert_der: None,
        }
    })?;
    let tls_stream = tokio_openssl::SslStream::new(tls_state, tcp_stream).map_err(|e| {
        CspTlsServerHandshakeError::CreateAcceptorError {
            description: "failed to create tokio_openssl::SslStream".to_string(),
            internal_error: Some(format!("{}", e)),
            cert_der: None,
        }
    })?;
    Ok(tls_stream)
}

impl From<CspTlsSecretKeyError> for CspTlsServerHandshakeError {
    fn from(secret_key_error: CspTlsSecretKeyError) -> Self {
        match secret_key_error {
            CspTlsSecretKeyError::SecretKeyNotFound => {
                CspTlsServerHandshakeError::SecretKeyNotFound
            }
            CspTlsSecretKeyError::MalformedSecretKey => {
                CspTlsServerHandshakeError::MalformedSecretKey
            }
            CspTlsSecretKeyError::WrongSecretKeyType => {
                CspTlsServerHandshakeError::WrongSecretKeyType
            }
        }
    }
}
