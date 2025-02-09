use ic_secp256k1::{PrivateKey, PublicKey};

use crate::RecoveryError;

pub struct Secp256k1 {
    private_key: Option<PrivateKey>,
    public_key: PublicKey,
}

impl super::Verifier for Secp256k1 {
    fn verify_payload(&self, payload: &[u8], signature: &[u8]) -> crate::Result<()> {
        match self.public_key.verify_ecdsa_signature(payload, signature) {
            true => Ok(()),
            false => Err(RecoveryError::InvalidSignature(
                "Invalid signature".to_string(),
            )),
        }
    }

    fn to_public_key_der(&self) -> crate::Result<Vec<u8>> {
        Ok(self.public_key.serialize_der())
    }
}

impl super::Signer for Secp256k1 {
    fn sign_payload(&self, payload: &[u8]) -> crate::Result<Vec<u8>> {
        let private_key = self
            .private_key
            .clone()
            .ok_or(RecoveryError::InvalidIdentity(
                "Signing key missing".to_string(),
            ))?;

        let signature = private_key.sign_message_with_ecdsa(payload);

        Ok(signature.to_vec())
    }
}

impl Secp256k1 {
    pub fn from_public_key_der(public_key_der: &[u8]) -> crate::Result<Self> {
        let public_key = PublicKey::deserialize_der(public_key_der)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        Ok(Self {
            private_key: None,
            public_key,
        })
    }

    pub fn from_public_key(public_key: &[u8]) -> crate::Result<Self> {
        let public_key = PublicKey::deserialize_sec1(public_key)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        Ok(Self {
            private_key: None,
            public_key,
        })
    }

    pub fn new(private_key: PrivateKey) -> Self {
        Self {
            public_key: private_key.public_key(),
            private_key: Some(private_key),
        }
    }

    pub fn from_pem(path: &str) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;
        let private_key = PrivateKey::deserialize_rfc5915_pem(&contents)
            .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;

        Ok(Self::new(private_key))
    }
}
