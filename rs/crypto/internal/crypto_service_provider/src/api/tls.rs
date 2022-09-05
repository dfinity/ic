use crate::TlsHandshakeCspVault;
use std::sync::Arc;

/// Provides an `Arc` to an implementation of a trait that can generate the
/// signature needed for performing a TLS handshake.
pub trait CspTlsHandshakeSignerProvider: Send + Sync {
    fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault>;
}
