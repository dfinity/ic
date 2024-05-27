use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::vault::api::CspTlsSignError;
use ic_crypto_internal_csp::TlsHandshakeCspVault;
use rustls::{self, Error as TLSError, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// An implementation of Rustls' `rustls::sign::SigningKey` that returns a
/// `CspServerEd25519Signer` in `choose_scheme`. The signing operation is
/// delegated to the `TlsHandshakeCspServer` which may perform the signing
/// operation in a separate process or remotely on an HSM.
pub struct CspServerEd25519SigningKey {
    signer: CspServerEd25519Signer,
}

impl CspServerEd25519SigningKey {
    /// Creates a `CspServerEd25519SigningKey` that uses `tls_csp_vault` to
    /// create signatures. The `key_id` indicates which secret key is used for signing.
    pub fn new(key_id: KeyId, tls_csp_vault: Arc<dyn TlsHandshakeCspVault>) -> Self {
        Self {
            signer: CspServerEd25519Signer {
                key_id,
                tls_csp_vault,
            },
        }
    }
}

impl rustls::sign::SigningKey for CspServerEd25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if !offered.contains(&SignatureScheme::ED25519) {
            return None;
        }

        Some(Box::new(self.signer.clone()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

/// An implementation of Rustls' `rustls::sign::Signer` that delegates the
/// `sign` operation to a `TlsHandshakeCspServer` which may perform the signing
/// operation in a separate process or remotely on an HSM. Currently, the only
/// scheme that is supported is Ed25519.
#[derive(Clone)]
struct CspServerEd25519Signer {
    key_id: KeyId,
    tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
}

impl rustls::sign::Signer for CspServerEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let csp_signature = self
            .tls_csp_vault
            .tls_sign(message.to_vec(), self.key_id)
            .map_err(|e| match e {
                CspTlsSignError::SecretKeyNotFound { .. }
                | CspTlsSignError::WrongSecretKeyType { .. }
                | CspTlsSignError::MalformedSecretKey { .. }
                | CspTlsSignError::SigningFailed { .. }
                | CspTlsSignError::TransientInternalError { .. } => TLSError::General(format!(
                    "Failed to create signature during \
                     TLS handshake by means of the CspServerEd25519Signer: {:?}",
                    e
                )),
            })?;
        match csp_signature {
            CspSignature::Ed25519(signature_bytes) => Ok(signature_bytes.0.to_vec()),
            _ => Err(TLSError::General(
                "Signature created during TLS handshake did not have the expected type Ed25519."
                    .to_string(),
            )),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
