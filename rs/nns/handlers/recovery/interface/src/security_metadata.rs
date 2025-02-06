use super::*;
use candid::{CandidType, Principal};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use spki::{Document, SubjectPublicKeyInfoRef};

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
    /// Der encoded public key.
    ///
    /// It is used to verify the authenticity of a signature.
    pub pub_key_der: Vec<u8>,
}

impl SecurityMetadata {
    pub fn empty() -> Self {
        Self {
            signature: [[0; 32]; 2],
            payload: vec![],
            pub_key_der: vec![],
        }
    }

    /// Verify the authenticity of a whole vote on a recovery canister proposal.
    pub fn validate_metadata(&self, caller: &Principal) -> Result<()> {
        self.principal_matches_public_key(caller)?;
        self.verify_signature()
    }

    /// Verifies the signature authenticity of security metadata.
    pub fn verify_signature(&self) -> Result<()> {
        valid_signature(
            &self.pub_key_der,
            self.signature.as_flattened(),
            &self.payload,
        )
    }

    /// Verifies if the passed principal is derived from a given public key (also known as
    /// verifying key).
    pub fn principal_matches_public_key(&self, principal: &Principal) -> Result<()> {
        let loaded_principal = Principal::self_authenticating(&self.pub_key_der);

        match loaded_principal.eq(principal) {
            true => Ok(()),
            false => Err(RecoveryError::PrincipalPublicKeyMismatch(format!(
                "Expected {}, got {}",
                loaded_principal, principal,
            ))),
        }
    }
}

fn valid_signature(pub_key_der: &Vec<u8>, signature: &[u8], payload: &Vec<u8>) -> Result<()> {
    let document: Document = Document::from_public_key_der(&pub_key_der)
        .map_err(|e| RecoveryError::InvalidPubKey(e.to_string()))?;

    let info: SubjectPublicKeyInfoRef = document.decode_msg().unwrap();

    let maybe_ed25519: Result<ed25519_dalek::VerifyingKey> = info
        .clone()
        .try_into()
        .map_err(|e: spki::Error| RecoveryError::InvalidPubKey(e.to_string()));
    let maybe_p256: Result<p256::ecdsa::VerifyingKey> = info
        .try_into()
        .map_err(|e: spki::Error| RecoveryError::InvalidPubKey(e.to_string()));

    match (maybe_ed25519, maybe_p256) {
        (Ok(k), _) => {
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

            k.verify_strict(&payload, &signature)
                .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
        }
        (_, Ok(k)) => {
            let signature = p256::ecdsa::Signature::from_slice(&signature)
                .map_err(|e| RecoveryError::InvalidSignatureFormat(e.to_string()))?;

            k.verify(payload, &signature)
                .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))
        }
        _ => Err(RecoveryError::InvalidPubKey(
            "Unknown der format".to_string(),
        )),
    }
}
