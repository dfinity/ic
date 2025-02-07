use p256::ecdsa::{signature::SignerMut, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use spki::{DecodePublicKey, Document, SubjectPublicKeyInfoRef};

use crate::RecoveryError;

pub struct Prime256 {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl super::Signer for Prime256 {
    fn sign_payload(&self, payload: &Vec<u8>) -> crate::Result<Vec<u8>> {
        let mut signing_key = self
            .signing_key
            .clone()
            .ok_or(RecoveryError::InvalidIdentity(
                "Signing key missing".to_string(),
            ))?;

        let signature: Signature = signing_key
            .try_sign(&payload)
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        let r = signature.r().to_bytes().to_vec();
        let s = signature.s().to_bytes().to_vec();
        Ok(r.into_iter().chain(s.into_iter()).collect())
    }
}

impl TryInto<Vec<u8>> for Prime256 {
    type Error = RecoveryError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.verifying_key
            .to_public_key_der()
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))
            .map(|document| document.into_vec())
    }
}

impl super::Verifier for Prime256 {
    fn verify_payload(&self, payload: &Vec<u8>, signature: &Vec<u8>) -> crate::Result<()> {
        let signature = Signature::from_slice(&signature)
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        self.verifying_key
            .verify(payload, &signature)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for Prime256 {
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
