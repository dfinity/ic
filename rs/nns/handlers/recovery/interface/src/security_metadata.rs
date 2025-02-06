use super::*;
use candid::{CandidType, Principal};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use simple_asn1::{
    oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, Sequence},
};

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
        let loaded_public_key = VerifyingKey::from_bytes(&self.decode_der_pub_key())
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
        let loaded_principal = Principal::self_authenticating(&self.pub_key_der);

        match loaded_principal.eq(principal) {
            true => Ok(()),
            false => Err(RecoveryError::PrincipalPublicKeyMismatch(format!(
                "Expected {}, got {}",
                loaded_principal, principal,
            ))),
        }
    }

    fn decode_der_pub_key(&self) -> [u8; 32] {
        // TODO: Logic for reversing other keys
        let mut key = [0; 32];
        key.copy_from_slice(&self.pub_key_der[self.pub_key_der.len() - 32..]);
        key
    }
}

// Copied from agent-rs
pub fn der_encode_public_key(public_key: Vec<u8>) -> Vec<u8> {
    // see Section 4 "SubjectPublicKeyInfo" in https://tools.ietf.org/html/rfc8410

    let id_ed25519 = oid!(1, 3, 101, 112);
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, id_ed25519)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info).unwrap()
}
