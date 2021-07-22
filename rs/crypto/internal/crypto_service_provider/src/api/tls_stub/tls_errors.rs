//! TLS error types

use ic_crypto_internal_tls::{CreateTlsAcceptorError, CreateTlsConnectorError};
use ic_crypto_tls_interfaces::{
    MalformedPeerCertificateError, TlsClientHandshakeError, TlsServerHandshakeError,
};

/// Errors occurring during a TLS handshake
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
