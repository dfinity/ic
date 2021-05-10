//! TLS utilities

use crate::api::tls_errors::{CspTlsClientHandshakeError, CspTlsServerHandshakeError};
use crate::keygen::tls_registry_cert_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::tls_stub::cert_chain::CspCertificateChainCreationError;
use crate::types::CspSecretKey;
use cert_chain::CspCertificateChain;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509VerifyResult, X509};
use std::convert::TryFrom;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

pub mod cert_chain;
mod client_handshake;
mod server_handshake;

#[cfg(test)]
mod test_utils;

fn key_from_secret_key_store<S: SecretKeyStore>(
    secret_key_store: &S,
    self_cert: &X509PublicKeyCert,
) -> Result<PKey<Private>, CspTlsSecretKeyError> {
    let secret_key: CspSecretKey = secret_key_store
        .get(&tls_registry_cert_hash_as_key_id(self_cert.clone()))
        .ok_or_else(|| CspTlsSecretKeyError::SecretKeyNotFound)?;
    let secret_key_der_bytes = match secret_key {
        CspSecretKey::TlsEd25519(secret_key_der_bytes) => Ok(secret_key_der_bytes),
        _ => Err(CspTlsSecretKeyError::WrongSecretKeyType),
    }?;
    // Note: we don't want to expose *any* info about the secret key,
    // so just ignore the openssl error.
    PKey::private_key_from_der(&secret_key_der_bytes.bytes)
        .map_err(|_| CspTlsSecretKeyError::MalformedSecretKey)
}

enum CspTlsSecretKeyError {
    SecretKeyNotFound,
    MalformedSecretKey,
    WrongSecretKeyType,
}

fn peer_cert_from_stream(
    tls_stream: &SslStream<TcpStream>,
) -> Result<Option<X509>, CspPeerCertFromStreamError> {
    let peer_cert = tls_stream.ssl().peer_certificate();
    if peer_cert.is_some() && tls_stream.ssl().verify_result() != X509VerifyResult::OK {
        return Err(CspPeerCertFromStreamError::PeerCertificateNotVerified);
    }
    Ok(peer_cert)
}

#[derive(Debug)]
enum CspPeerCertFromStreamError {
    PeerCertificateNotVerified,
}

impl From<CspPeerCertFromStreamError> for CspTlsClientHandshakeError {
    fn from(peer_cert_error: CspPeerCertFromStreamError) -> Self {
        match peer_cert_error {
            CspPeerCertFromStreamError::PeerCertificateNotVerified => {
                CspTlsClientHandshakeError::HandshakeError {
                    internal_error: "The server certificate was not verified during the handshake."
                        .to_string(),
                }
            }
        }
    }
}

impl From<CspPeerCertFromStreamError> for CspTlsServerHandshakeError {
    fn from(peer_cert_error: CspPeerCertFromStreamError) -> Self {
        match peer_cert_error {
            CspPeerCertFromStreamError::PeerCertificateNotVerified => {
                CspTlsServerHandshakeError::HandshakeError {
                    internal_error: "The client certificate was not verified during the handshake."
                        .to_string(),
                }
            }
        }
    }
}

fn peer_cert_chain_from_stream(
    tls_stream: &SslStream<TcpStream>,
) -> Result<Option<CspCertificateChain>, CspPeerCertChainFromStreamError> {
    let peer_cert_chain = tls_stream.ssl().verified_chain();
    let verify_result_is_ok = tls_stream.ssl().verify_result() == X509VerifyResult::OK;
    // Note: the result of `verified_chain` must not be used if the `verify_result`
    // is not OK because the chain may be incomplete or invalid.
    match (peer_cert_chain, verify_result_is_ok) {
        (None, _) => Ok(None),
        (Some(verified_chain), true) => {
            let cert_chain = CspCertificateChain::try_from(verified_chain)?;
            ensure_chain_leaf_consistency(&cert_chain, &tls_stream.ssl().peer_certificate())?;
            Ok(Some(cert_chain))
        }
        (Some(_), false) => Err(CspPeerCertChainFromStreamError::UnverifiedCertChain),
    }
}

fn ensure_chain_leaf_consistency(
    cert_chain: &CspCertificateChain,
    peer_cert: &Option<X509>,
) -> Result<(), CspPeerCertChainFromStreamError> {
    let peer_cert = peer_cert.as_ref().ok_or_else(|| {
        CspPeerCertChainFromStreamError::CertChainLeafInconsistency(
            "missing peer certificate".to_string(),
        )
    })?;
    let peer_cert_digest = peer_cert.digest(MessageDigest::sha256()).map_err(|e| {
        CspPeerCertChainFromStreamError::CertChainLeafInconsistency(format!(
            "failed to create digest for peer cert: {}",
            e
        ))
    })?;
    let cert_chain_leaf_digest =
        cert_chain
            .leaf()
            .digest(MessageDigest::sha256())
            .map_err(|e| {
                CspPeerCertChainFromStreamError::CertChainLeafInconsistency(format!(
                    "failed to create digest for cert chain leaf: {}",
                    e
                ))
            })?;
    if *peer_cert_digest != *cert_chain_leaf_digest {
        return Err(CspPeerCertChainFromStreamError::CertChainLeafInconsistency(
            "leaf of peer certificate chain is inconsistent with peer certificate".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum CspPeerCertChainFromStreamError {
    UnverifiedCertChain,
    EmptyCertChain,
    CertChainLeafInconsistency(String),
}

impl From<CspCertificateChainCreationError> for CspPeerCertChainFromStreamError {
    fn from(cert_chain_creation_error: CspCertificateChainCreationError) -> Self {
        match cert_chain_creation_error {
            CspCertificateChainCreationError::ChainEmpty => {
                CspPeerCertChainFromStreamError::EmptyCertChain
            }
        }
    }
}

impl From<CspPeerCertChainFromStreamError> for CspTlsServerHandshakeError {
    fn from(peer_cert_chain_error: CspPeerCertChainFromStreamError) -> Self {
        match peer_cert_chain_error {
            CspPeerCertChainFromStreamError::UnverifiedCertChain => {
                CspTlsServerHandshakeError::HandshakeError {
                    internal_error:
                        "The client certificate chain was not verified during the handshake."
                            .to_string(),
                }
            }
            CspPeerCertChainFromStreamError::EmptyCertChain => {
                CspTlsServerHandshakeError::HandshakeError {
                    internal_error:
                        "The client certificate chain was present but empty during the handshake."
                            .to_string(),
                }
            }
            CspPeerCertChainFromStreamError::CertChainLeafInconsistency(internal_error) => {
                CspTlsServerHandshakeError::HandshakeError {
                    internal_error: format!(
                        "Chain leaf consistency check failed: {}",
                        internal_error
                    ),
                }
            }
        }
    }
}
