use super::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SecurityMetadata {
    pub signature: [[u8; 32]; 2],
    pub payload: Vec<u8>,
    pub pub_key: [u8; 32],
}

impl SecurityMetadata {
    pub fn empty() -> Self {
        Self {
            signature: [[0; 32]; 2],
            payload: vec![],
            pub_key: [0; 32],
        }
    }

    pub fn validate_metadata(&self, caller: &Principal) -> Result<()> {
        self.principal_matches_public_key(caller)?;
        self.verify()
    }

    pub fn verify(&self) -> Result<()> {
        let loaded_public_key = VerifyingKey::from_bytes(&self.pub_key)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;
        let signature = Signature::from_slice(self.signature.as_flattened())
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        loaded_public_key
            .verify_strict(&self.payload, &signature)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
    }

    pub fn principal_matches_public_key(&self, principal: &Principal) -> Result<()> {
        let loaded_principal = Principal::self_authenticating(self.pub_key);

        match loaded_principal.eq(principal) {
            true => Ok(()),
            false => Err(RecoveryError::PrincipalPublicKeyMismatch(format!(
                "Expected {}, got {}",
                loaded_principal, principal,
            ))),
        }
    }
}
