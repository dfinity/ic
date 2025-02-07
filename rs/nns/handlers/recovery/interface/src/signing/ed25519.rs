use ed25519_dalek::{pkcs8::EncodePublicKey, Signature, Signer, SigningKey, VerifyingKey};
use spki::{DecodePublicKey, Document, SubjectPublicKeyInfoRef};

use crate::RecoveryError;

pub struct EdwardsCurve {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl super::Signer for EdwardsCurve {
    fn sign_payload(&self, payload: &[u8]) -> crate::Result<Vec<u8>> {
        let signing_key = self
            .signing_key
            .clone()
            .ok_or(RecoveryError::InvalidIdentity(
                "Signing key missing".to_string(),
            ))?;

        let signature = signing_key.sign(&payload);
        Ok(signature.to_vec())
    }
}

impl TryInto<Vec<u8>> for EdwardsCurve {
    type Error = RecoveryError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.verifying_key
            .to_public_key_der()
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))
            .map(|document| document.into_vec())
    }
}

impl super::Verifier for EdwardsCurve {
    fn verify_payload(&self, payload: &[u8], signature: &[u8]) -> crate::Result<()> {
        let signature = Signature::from_slice(&signature)
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        self.verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for EdwardsCurve {
    type Error = RecoveryError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let document: Document = Document::from_public_key_der(&value)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        let info: SubjectPublicKeyInfoRef = document
            .decode_msg()
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

        let verifying_key: VerifyingKey = info
            .try_into()
            .map_err(|e: spki::Error| RecoveryError::InvalidPubKey(e.to_string()))?;

        Ok(Self {
            signing_key: None,
            verifying_key,
        })
    }
}
