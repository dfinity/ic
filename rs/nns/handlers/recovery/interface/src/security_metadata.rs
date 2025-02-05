use super::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Clone, Debug, CandidType, Deserialize)]
/// Wrapper struct containing information regarding integrity.
pub struct SecurityMetadata {
    /// Represents an outcome of a cryptographic operation
    /// that includes a private key (also known as signing key)
    /// and a payload that is being signed.
    ///
    /// Should be verified with a corresponding public key (also
    /// known as verifying key).
    pub signature: [[u8; 32]; 2],
    /// What is being signed.
    ///
    /// In context of recovery canister proposal it includes
    /// all fields in a proposal except the ballots of node operators
    /// serialized as vector of bytes.
    pub payload: Vec<u8>,
    /// Verifying key.
    ///
    /// It is used to verify the authenticity of a signature.
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

    /// Verify the authenticity of a whole vote on a recovery canister proposal.
    pub fn validate_metadata(&self, caller: &Principal) -> Result<()> {
        self.principal_matches_public_key(caller)?;
        self.verify_signature()
    }

    /// Verifies the signature authenticity of security metadata.
    pub fn verify_signature(&self) -> Result<()> {
        let loaded_public_key = VerifyingKey::from_bytes(&self.pub_key)
            .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;
        let signature = Signature::from_slice(self.signature.as_flattened())
            .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

        loaded_public_key
            .verify_strict(&self.payload, &signature)
            .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
    }

    /// Verifies if the passed principal is derived from a given public key (also known as
    /// verifying key).
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
