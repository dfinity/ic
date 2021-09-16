//! Tests for the TLS error types

use super::*;

/// Verifies that debug() works for CspTlsClientHandshakeError without
/// panicking.
#[test]
fn csp_tls_client_handshake_error_debug() {
    let samples = &[
       (CspTlsClientHandshakeError::MalformedServerCertificate(CspMalformedPeerCertificateError{ internal_error: "Foo".to_string() }), "CspTlsClientHandshakeError::MalformedServerCertificate(CspMalformedPeerCertificateError { internal_error: \"Foo\" })"),
       (CspTlsClientHandshakeError::CreateConnectorError {
        description: "desc".to_string(),
        client_cert_der: Some(vec![1,2,3,4,5,6,7,8,9]),
        server_cert_der: None,
        internal_error: "err".to_string(),
    }, "CspTlsClientHandshakeError::CreateConnectorError{ description: desc, client_cert_der: Some(\"AQIDBAUGBwgJ\"), server_cert_der: None, internal_error: err}"),
    (CspTlsClientHandshakeError::HandshakeError{internal_error: "bat\"man".to_string()}, "CspTlsClientHandshakeError::HandshakeError{ internal_error: bat\"man }"),
    (CspTlsClientHandshakeError::SecretKeyNotFound, "CspTlsClientHandshakeError::SecretKeyNotFound"),
    (CspTlsClientHandshakeError::MalformedSecretKey, "CspTlsClientHandshakeError::MalformedSecretKey"),
    (CspTlsClientHandshakeError::WrongSecretKeyType, "CspTlsClientHandshakeError::WrongSecretKeyType")
    ];
    for (value, formatted) in samples {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}
