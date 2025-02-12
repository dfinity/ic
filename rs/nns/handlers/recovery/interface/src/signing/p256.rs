use k256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};

use crate::RecoveryError;

pub struct Prime256v1 {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl super::Verifier for Prime256v1 {
    fn verify_payload(&self, payload: &[u8], signature: &[u8]) -> crate::Result<()> {
        let signature = Signature::from_slice(signature)
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        self.verifying_key
            .verify(payload, &signature)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
    }

    fn to_public_key_der(&self) -> crate::Result<Vec<u8>> {
        self.verifying_key
            .to_public_key_der()
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))
            .map(|document| document.into_vec())
    }

    fn to_public_key_pem(&self) -> crate::Result<String> {
        self.verifying_key
            .to_public_key_pem(k256::pkcs8::LineEnding::LF)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))
    }
}

impl super::Signer for Prime256v1 {
    fn sign_payload(&self, payload: &[u8]) -> crate::Result<Vec<u8>> {
        let signing_key = self
            .signing_key
            .clone()
            .ok_or(RecoveryError::InvalidIdentity(
                "Signing key missing".to_string(),
            ))?;

        let signature: Signature = signing_key
            .try_sign(payload)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))?;

        let r = signature.r().to_bytes().to_vec();
        let s = signature.s().to_bytes().to_vec();

        Ok(r.into_iter().chain(s).collect())
    }
}

impl Prime256v1 {
    pub fn from_public_key_der(public_key_der: &[u8]) -> crate::Result<Self> {
        let verifying_key = VerifyingKey::from_public_key_der(public_key_der)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        Ok(Self {
            signing_key: None,
            verifying_key,
        })
    }

    pub fn from_public_key(public_key: &[u8]) -> crate::Result<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        Ok(Self {
            signing_key: None,
            verifying_key,
        })
    }

    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            verifying_key: *signing_key.verifying_key(),
            signing_key: Some(signing_key),
        }
    }

    pub fn from_pem(path: &str) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;

        let signing_key = SigningKey::from_pkcs8_pem(&contents)
            .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;
        Ok(Self::new(signing_key))
    }
}
