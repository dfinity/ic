use crate::signing::verify_payload_naive;

use super::*;
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
/// Wrapper struct containing information regarding integrity.
pub struct SecurityMetadata {
    /// Represents an outcome of a cryptographic operation
    /// that includes a private key (also known as signing key)
    /// and a payload that is being signed.
    ///
    /// Should be verified with a corresponding public key (also
    /// known as verifying key).
    #[serde(serialize_with = "base64_serde::serialize")]
    pub signature: Vec<u8>,
    /// What is being signed.
    ///
    /// In context of recovery canister proposal it includes
    /// all fields in a proposal except the ballots of node operators
    /// serialized as vector of bytes.
    #[serde(serialize_with = "base64_serde::serialize")]
    pub payload: Vec<u8>,
    /// Der encoded public key.
    ///
    /// It is used to verify the authenticity of a signature.
    #[serde(serialize_with = "pub_key_serde::serialize")]
    pub pub_key_der: Vec<u8>,
}

impl SecurityMetadata {
    pub fn empty() -> Self {
        Self {
            signature: vec![],
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
        verify_payload_naive(&self.pub_key_der, &self.payload, &self.signature)
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

mod base64_serde {
    use serde::Serializer;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::encode(bytes);
        serializer.serialize_str(&encoded)
    }
}

mod pub_key_serde {
    use serde::Serializer;

    pub fn serialize<S>(_bytes: &Vec<u8>, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("Outout omitted")
    }
}
