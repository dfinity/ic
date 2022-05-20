//! TLS error types

#[cfg(test)]
mod tests;

use ic_crypto_internal_tls::{CreateTlsAcceptorError, CreateTlsConnectorError};
use ic_crypto_tls_interfaces::{
    MalformedPeerCertificateError, TlsClientHandshakeError, TlsServerHandshakeError,
};

use std::fmt;

/// Errors occurring during a TLS handshake
#[derive(Clone, PartialEq, Eq)]
pub enum CspTlsClientHandshakeError {
    MalformedServerCertificate(CspMalformedPeerCertificateError),
    CreateConnectorError {
        description: String,
        client_cert_der: Option<Vec<u8>>,
        server_cert_der: Option<Vec<u8>>,
        internal_error: String,
    },
    HandshakeError {
        internal_error: String,
    },
    SecretKeyNotFound,
    MalformedSecretKey,
    WrongSecretKeyType,
}
impl fmt::Debug for CspTlsClientHandshakeError {
    /// Prints in a developer-friendly format.
    ///
    /// The standard rust encoding is used for all fields except DER
    /// certificates, which are printed as base64 rather than arrays of
    /// integers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CspTlsClientHandshakeError::*;
        match self {
            MalformedServerCertificate(cert) => write!(
                f,
                "CspTlsClientHandshakeError::MalformedServerCertificate({:?})",
                cert
            ),
            CreateConnectorError {
                description,
                client_cert_der,
                server_cert_der,
                internal_error,
            } => {
                write!(f, "CspTlsClientHandshakeError::CreateConnectorError{{ description: {}, client_cert_der: {:?}, server_cert_der: {:?}, internal_error: {}}}",
                          description,
                          client_cert_der.as_ref().map(|der| base64::encode(&der)),
                          server_cert_der.as_ref().map(|der| base64::encode(&der)),
                          internal_error)
            }
            HandshakeError { internal_error } => write!(
                f,
                "CspTlsClientHandshakeError::HandshakeError{{ internal_error: {} }}",
                internal_error
            ),
            SecretKeyNotFound => write!(f, "CspTlsClientHandshakeError::SecretKeyNotFound"),
            MalformedSecretKey => write!(f, "CspTlsClientHandshakeError::MalformedSecretKey"),
            WrongSecretKeyType => write!(f, "CspTlsClientHandshakeError::WrongSecretKeyType"),
        }
    }
}

/// The TLS peer certificate was malformed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspMalformedPeerCertificateError {
    pub internal_error: String,
}

impl From<CspTlsClientHandshakeError> for TlsClientHandshakeError {
    fn from(csp_tls_client_handshake_error: CspTlsClientHandshakeError) -> Self {
        let panic_prefix = "CSP TLS client handshake error: ";
        match csp_tls_client_handshake_error {
            CspTlsClientHandshakeError::MalformedServerCertificate(csp_error) => {
                TlsClientHandshakeError::MalformedServerCertificate(MalformedPeerCertificateError {
                    internal_error: csp_error.internal_error,
                })
            }
            CspTlsClientHandshakeError::CreateConnectorError {
                description,
                client_cert_der,
                server_cert_der,
                internal_error,
            } => TlsClientHandshakeError::CreateConnectorError {
                description,
                client_cert_der,
                server_cert_der,
                internal_error,
            },
            CspTlsClientHandshakeError::HandshakeError { internal_error } => {
                TlsClientHandshakeError::HandshakeError { internal_error }
            }
            CspTlsClientHandshakeError::SecretKeyNotFound => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key was not found", panic_prefix);
            }
            CspTlsClientHandshakeError::MalformedSecretKey => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key is malformed", panic_prefix);
            }
            CspTlsClientHandshakeError::WrongSecretKeyType => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key has the wrong type", panic_prefix);
            }
        }
    }
}

impl From<CreateTlsConnectorError> for CspTlsClientHandshakeError {
    fn from(clib_create_tls_connector_error: CreateTlsConnectorError) -> Self {
        CspTlsClientHandshakeError::CreateConnectorError {
            description: clib_create_tls_connector_error.description,
            client_cert_der: clib_create_tls_connector_error.client_cert_der,
            server_cert_der: clib_create_tls_connector_error.server_cert_der,
            internal_error: clib_create_tls_connector_error.internal_error,
        }
    }
}

/// TLS handshake failed (server side)
#[derive(Clone, PartialEq, Eq)]
pub enum CspTlsServerHandshakeError {
    MalformedClientCertificate(CspMalformedPeerCertificateError),
    CreateAcceptorError {
        description: String,
        cert_der: Option<Vec<u8>>,
        internal_error: Option<String>,
    },
    HandshakeError {
        internal_error: String,
    },
    SecretKeyNotFound,
    MalformedSecretKey,
    WrongSecretKeyType,
}
impl fmt::Debug for CspTlsServerHandshakeError {
    /// Prints in a developer-friendly format.
    ///
    /// The standard rust encoding is used for all fields except DER
    /// certificates, which are printed as base64 rather than arrays of
    /// integers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CspTlsServerHandshakeError::*;
        match self {
            MalformedClientCertificate(error) => write!(f, "CspTlsServerHandshakeError::MalformedClientCertificate({:?})", error),
            CreateAcceptorError{description, cert_der, internal_error} => write!(f, "CspTlsServerHandshakeError::CreateAcceptorError{{ description: {}, cert_der: {:?}, internal_error: {:?}}}",
                                                                                 description,
                                                                                 cert_der.as_ref().map(|der| base64::encode(&der[..])),
                                                                                 internal_error),
            HandshakeError{internal_error} => write!(f, "CspTlsServerHandshakeError::HandshakeError{{ internal_error: {} }}", internal_error),
            SecretKeyNotFound => write!(f, "CspTlsServerHandshakeError::SecretKeyNotFound"),
            MalformedSecretKey => write!(f, "CspTlsServerHandshakeError::MalformedSecretKey"),
            WrongSecretKeyType => write!(f, "CspTlsServerHandshakeError::WrongSecretKeyType"),
        }
    }
}

impl From<CspTlsServerHandshakeError> for TlsServerHandshakeError {
    fn from(csp_tls_server_handshake_error: CspTlsServerHandshakeError) -> Self {
        let panic_prefix = "CSP TLS server handshake error: ";
        match csp_tls_server_handshake_error {
            CspTlsServerHandshakeError::MalformedClientCertificate(csp_error) => {
                TlsServerHandshakeError::MalformedClientCertificate(MalformedPeerCertificateError {
                    internal_error: csp_error.internal_error,
                })
            }
            CspTlsServerHandshakeError::CreateAcceptorError {
                description,
                cert_der,
                internal_error,
            } => TlsServerHandshakeError::CreateAcceptorError {
                description,
                cert_der,
                internal_error,
            },
            CspTlsServerHandshakeError::HandshakeError { internal_error } => {
                TlsServerHandshakeError::HandshakeError { internal_error }
            }
            CspTlsServerHandshakeError::SecretKeyNotFound => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key was not found", panic_prefix);
            }
            CspTlsServerHandshakeError::MalformedSecretKey => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key is malformed", panic_prefix);
            }
            CspTlsServerHandshakeError::WrongSecretKeyType => {
                // This would be a problem in the node's setup, so we panic:
                panic!("{}The secret key has the wrong type", panic_prefix);
            }
        }
    }
}

impl From<CreateTlsAcceptorError> for CspTlsServerHandshakeError {
    fn from(clib_create_tls_acceptor_error: CreateTlsAcceptorError) -> Self {
        CspTlsServerHandshakeError::CreateAcceptorError {
            description: clib_create_tls_acceptor_error.description,
            cert_der: clib_create_tls_acceptor_error.cert_der,
            internal_error: clib_create_tls_acceptor_error.internal_error,
        }
    }
}
