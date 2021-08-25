//! Offers TLS functionality with self-managed keys.
//!
//! As opposed to the `CryptoComponent` that manages the TLS private keys
//! itself, this module allows the caller to manage the private keys. This can
//! e.g. be used by parties that need to connect to Internet Computer nodes via
//! TLS.
//!
//! # Security Warning
//! Since the private keys are self-managed, it is the
//! responsibility of the caller to keep the private key material secure!

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use openssl::pkey::{PKey, Private};
use std::fmt;

pub use client_handshake::{perform_tls_client_handshake, TlsClientHandshakeError};
pub use keygen::generate_tls_keys;

mod client_handshake;
mod keygen;

#[allow(unused)]
#[derive(Clone)]
/// TLS private key
pub struct TlsPrivateKey {
    private_key: PKey<Private>,
}

#[allow(unused)]
impl TlsPrivateKey {
    /// Creates a private key from a PEM encoding
    pub fn new_from_pem(private_key_pem: Vec<u8>) -> Result<Self, TlsPemParsingError> {
        // nb. Make sure we don't leak sensitive info in the error message.
        let private_key =
            PKey::private_key_from_pem(&private_key_pem).map_err(|_| TlsPemParsingError {
                internal_error: "Error parsing PEM via OpenSSL".to_string(),
            })?;
        Ok(Self { private_key })
    }

    /// Creates a private key from an existing OpenSSL struct
    fn new_from_pkey(private_key: PKey<Private>) -> Self {
        Self { private_key }
    }

    /// Returns the private key in PEM encoding
    pub fn to_pem(&self) -> Result<Vec<u8>, TlsEncodingError> {
        self.private_key
            .private_key_to_pem_pkcs8()
            .map_err(|_| TlsEncodingError {
                internal_error: "Error encoding PEM via OpenSSL".to_string(),
            })
    }

    /// Returns the private key as an OpenSSL struct
    fn as_pkey(&self) -> &PKey<Private> {
        &self.private_key
    }
}

impl fmt::Debug for TlsPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, Eq)]
/// A PEM string could not be parsed.
pub struct TlsPemParsingError {
    pub internal_error: String,
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, Eq)]
/// A TLS struct couldn't be encoded (as PEM or DER).
pub struct TlsEncodingError {
    pub internal_error: String,
}
