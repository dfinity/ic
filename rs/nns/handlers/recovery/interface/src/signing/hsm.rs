use std::sync::Arc;

use crate::RecoveryError;

use super::{ed25519::EdwardsCurve, k256::Secp256k1, p256::Prime256v1, Signer, Verifier};

// From ic-admin
pub type SignBytes =
    Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> + Send + Sync>;

pub struct Hsm {
    inner_pub_key: Arc<dyn Verifier>,
    sign_func: Option<SignBytes>,
}

impl Verifier for Hsm {
    fn verify_payload(&self, payload: &[u8], signature: &[u8]) -> crate::Result<()> {
        self.inner_pub_key.verify_payload(payload, signature)
    }

    fn to_public_key_der(&self) -> crate::Result<Vec<u8>> {
        self.inner_pub_key.to_public_key_der()
    }

    fn to_public_key_pem(&self) -> crate::Result<String> {
        self.inner_pub_key.to_public_key_pem()
    }
}

impl Signer for Hsm {
    fn sign_payload(&self, payload: &[u8]) -> crate::Result<Vec<u8>> {
        if let Some(sign_func) = &self.sign_func {
            sign_func(payload).map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
        } else {
            Err(RecoveryError::InvalidIdentity(
                "Missing sing func".to_string(),
            ))
        }
    }
}

impl Hsm {
    pub fn from_public_key_der(pub_key_der: &[u8]) -> crate::Result<Self> {
        if let Ok(edwards) = EdwardsCurve::from_public_key_der(pub_key_der) {
            return Ok(Self::from_verifier(Arc::new(edwards)));
        }

        if let Ok(secp256) = Secp256k1::from_public_key_der(pub_key_der) {
            return Ok(Self::from_verifier(Arc::new(secp256)));
        }

        if let Ok(prime) = Prime256v1::from_public_key_der(pub_key_der) {
            return Ok(Self::from_verifier(Arc::new(prime)));
        }

        Err(RecoveryError::InvalidPubKey(
            "Key stored on hsm implements an unknown algorithm".to_string(),
        ))
    }

    fn from_verifier(verifier: Arc<dyn Verifier>) -> Self {
        Self {
            sign_func: None,
            inner_pub_key: verifier,
        }
    }

    pub fn new(pub_key_der: &[u8], sign_func: SignBytes) -> crate::Result<Self> {
        let from_pub_key_der = Self::from_public_key_der(pub_key_der)?;

        Ok(Self {
            sign_func: Some(sign_func),
            ..from_pub_key_der
        })
    }
}
