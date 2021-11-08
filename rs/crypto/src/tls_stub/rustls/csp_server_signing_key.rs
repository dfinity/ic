use ic_crypto_internal_csp::keygen::tls_cert_hash_as_key_id;
use ic_crypto_internal_csp::types::CspSignature;
use ic_crypto_internal_csp::TlsHandshakeCspServer;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::KeyId;
use std::sync::Arc;
use tokio_rustls::rustls::internal::msgs::enums::SignatureAlgorithm;
use tokio_rustls::rustls::sign::{Signer, SigningKey};
use tokio_rustls::rustls::{SignatureScheme, TLSError};

#[cfg(test)]
mod tests;

#[allow(unused)]
pub struct CspServerEd25519SigningKey {
    signer: CspServerEd25519Signer,
}

#[allow(unused)]
impl CspServerEd25519SigningKey {
    pub fn new(
        self_cert: &TlsPublicKeyCert,
        tls_csp_server: Arc<dyn TlsHandshakeCspServer>,
    ) -> Self {
        Self {
            signer: CspServerEd25519Signer {
                key_id: tls_cert_hash_as_key_id(self_cert),
                tls_csp_server,
            },
        }
    }
}

impl SigningKey for CspServerEd25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if !offered.contains(&SignatureScheme::ED25519) {
            return None;
        }

        Some(Box::new(self.signer.clone()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

#[allow(unused)]
#[derive(Clone)]
struct CspServerEd25519Signer {
    key_id: KeyId,
    tls_csp_server: Arc<dyn TlsHandshakeCspServer>,
}

impl Signer for CspServerEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let csp_signature = self
            .tls_csp_server
            .sign(message, &self.key_id)
            .map_err(|e| {
                TLSError::General(format!(
                    "Failed to create signature during \
                     TLS handshake by means of the CspServerEd25519Signer: {:?}",
                    e
                ))
            })?;
        match csp_signature {
            CspSignature::Ed25519(signature_bytes) => Ok(signature_bytes.0.to_vec()),
            _ => Err(TLSError::General(
                "Signature created during TLS handshake did not have the expected type Ed25519."
                    .to_string(),
            )),
        }
    }

    fn get_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
