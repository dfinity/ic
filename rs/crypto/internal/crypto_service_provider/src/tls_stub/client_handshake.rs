use crate::api::tls_errors::{CspMalformedPeerCertificateError, CspTlsClientHandshakeError};
use crate::api::CspTlsClientHandshake;
use crate::secret_key_store::SecretKeyStore;
use crate::tls_stub::{key_from_secret_key_store, peer_cert_from_stream, CspTlsSecretKeyError};
use crate::Csp;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::TlsStream;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use openssl::ssl::ConnectConfiguration;
use openssl::x509::X509;
use rand::{CryptoRng, Rng};
use tokio::net::TcpStream;

#[cfg(test)]
mod tests;

#[async_trait]
impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore> CspTlsClientHandshake for Csp<R, S> {
    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        self_cert: X509PublicKeyCert,
        trusted_server_cert: X509PublicKeyCert,
    ) -> Result<(TlsStream, X509), CspTlsClientHandshakeError> {
        let tls_connector = self.tls_connector(self_cert, trusted_server_cert)?;

        let tls_stream = tokio_openssl::connect(
            tls_connector,
            "domain is irrelevant, because hostname verification is disabled",
            tcp_stream,
        )
        .await
        .map_err(|e| CspTlsClientHandshakeError::HandshakeError {
            internal_error: format!("Handshake failed in tokio_openssl:connect: {}", e),
        })?;

        // The type of `peer_cert` (X509) is currently different from the cert types
        // used for `self_cert` and `trusted_server_cert`. This will be cleaned up
        // as part of moving the cert equality check from the IDKM to the CSP, which
        // will remove the `peer_cert` return value entirely:
        // TODO (CRP-772): Remove the X509 from the result
        let peer_cert = peer_cert_from_stream(&tls_stream)?.ok_or(
            CspTlsClientHandshakeError::HandshakeError {
                internal_error: "Missing server certificate during handshake.".to_string(),
            },
        )?;

        Ok((TlsStream::new(tls_stream), peer_cert))
    }
}

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore> Csp<R, S> {
    /// Creates a Connector for TLS. This allows to set up a TLS connection as a
    /// client. The `self_cert` is used as client certificate for mutual SSL and
    /// the corresponding private key must be in the secret key store. The
    /// client will only connect to a server that presents the
    /// `trusted_server_cert` in the TLS handshake.
    fn tls_connector(
        &self,
        self_cert: X509PublicKeyCert,
        trusted_server_cert: X509PublicKeyCert,
    ) -> Result<ConnectConfiguration, CspTlsClientHandshakeError> {
        let self_cert_x509 = self_cert_x509(&self_cert)?;
        let trusted_server_cert_x509 = trusted_server_cert_x509(trusted_server_cert)?;
        Ok(ic_crypto_internal_tls::tls_connector(
            &key_from_secret_key_store(&*self.sks_read_lock(), &self_cert)?,
            &self_cert_x509,
            &trusted_server_cert_x509,
        )?)
    }
}

fn self_cert_x509(self_cert: &X509PublicKeyCert) -> Result<X509, CspTlsClientHandshakeError> {
    X509::from_der(&self_cert.certificate_der).map_err(|e| {
        CspTlsClientHandshakeError::MalformedSelfCertificate {
            internal_error: format!("{}", e),
        }
    })
}

fn trusted_server_cert_x509(
    trusted_server_cert: X509PublicKeyCert,
) -> Result<X509, CspTlsClientHandshakeError> {
    X509::from_der(&trusted_server_cert.certificate_der).map_err(|e| {
        CspTlsClientHandshakeError::MalformedServerCertificate(CspMalformedPeerCertificateError {
            internal_error: format!("{}", e),
        })
    })
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
