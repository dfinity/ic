use crate::api::tls_errors::{CspMalformedPeerCertificateError, CspTlsServerHandshakeError};
use crate::api::CspTlsServerHandshake;
use crate::secret_key_store::SecretKeyStore;
use crate::tls_stub::cert_chain::CspCertificateChain;
use crate::tls_stub::{
    key_from_secret_key_store, peer_cert_chain_from_stream, CspTlsSecretKeyError,
};
use crate::Csp;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::TlsStream;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use openssl::ssl::SslAcceptor;
use openssl::x509::X509;
use rand::{CryptoRng, Rng};
use tokio::net::TcpStream;

#[cfg(test)]
mod tests;

#[async_trait]
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore> CspTlsServerHandshake for Csp<R, S> {
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: X509PublicKeyCert,
        trusted_client_certs: Vec<X509PublicKeyCert>,
    ) -> Result<(TlsStream, Option<CspCertificateChain>), CspTlsServerHandshakeError> {
        let tls_acceptor = self.tls_acceptor(self_cert, trusted_client_certs.clone())?;

        let tls_stream = tokio_openssl::accept(&tls_acceptor, tcp_stream)
            .await
            .map_err(|e| CspTlsServerHandshakeError::HandshakeError {
                internal_error: format!("Handshake failed in tokio_openssl:accept: {}", e),
            })?;

        let peer_cert_chain = peer_cert_chain_from_stream(&tls_stream)?;
        Ok((TlsStream::new(tls_stream), peer_cert_chain))
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    /// Creates an Acceptor for TLS. This allows to set up a TLS connection as a
    /// server. The `self_cert` is used as server certificate and the
    /// corresponding private key must be in the secret key store. The
    /// server will only allow TLS connections from clients that
    /// authenticate with a client certificate in `trusted_client_certs`.
    fn tls_acceptor(
        &self,
        self_cert: X509PublicKeyCert,
        trusted_client_certs: Vec<X509PublicKeyCert>,
    ) -> Result<SslAcceptor, CspTlsServerHandshakeError> {
        let self_cert_x509 = self_cert_x509(&self_cert)?;
        let trusted_client_certs_x509 = trusted_client_certs_x509(trusted_client_certs)?;
        Ok(ic_crypto_internal_tls::tls_acceptor(
            &key_from_secret_key_store(&*self.sks_read_lock(), &self_cert)?,
            &self_cert_x509,
            trusted_client_certs_x509,
        )?)
    }
}

fn self_cert_x509(self_cert: &X509PublicKeyCert) -> Result<X509, CspTlsServerHandshakeError> {
    X509::from_der(&self_cert.certificate_der).map_err(|e| {
        CspTlsServerHandshakeError::MalformedSelfCertificate {
            internal_error: format!("{}", e),
        }
    })
}

fn trusted_client_certs_x509(
    trusted_client_certs: Vec<X509PublicKeyCert>,
) -> Result<Vec<X509>, CspTlsServerHandshakeError> {
    trusted_client_certs
        .into_iter()
        .map(|cert| {
            X509::from_der(&cert.certificate_der).map_err(|e| {
                CspTlsServerHandshakeError::MalformedClientCertificate(
                    CspMalformedPeerCertificateError {
                        internal_error: format!("{}", e),
                    },
                )
            })
        })
        .collect()
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
