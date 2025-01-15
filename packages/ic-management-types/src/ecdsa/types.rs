use candid::CandidType;
use serde::{Deserialize, Serialize};

use super::super::main::CanisterId;

/// Argument type of [ecdsa_public_key](super::ecdsa_public_key).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaPublicKeyArgument {
    /// Canister id, default to the canister id of the caller if None.
    pub canister_id: Option<CanisterId>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [EcdsaKeyId].
    pub key_id: EcdsaKeyId,
}

/// Response Type of [ecdsa_public_key](super::ecdsa_public_key).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaPublicKeyResponse {
    /// An ECDSA public key encoded in SEC1 compressed form.
    pub public_key: Vec<u8>,
    /// Can be used to deterministically derive child keys of the public_key.
    pub chain_code: Vec<u8>,
}

/// Argument type of [sign_with_ecdsa](super::sign_with_ecdsa).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithEcdsaArgument {
    /// Hash of the message with length of 32 bytes.
    pub message_hash: Vec<u8>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [EcdsaKeyId].
    pub key_id: EcdsaKeyId,
}

/// Response type of [sign_with_ecdsa](super::sign_with_ecdsa).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithEcdsaResponse {
    /// Encoded as the concatenation of the SEC1 encodings of the two values r and s.
    pub signature: Vec<u8>,
}

/// ECDSA KeyId.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaKeyId {
    /// See [EcdsaCurve].
    pub curve: EcdsaCurve,
    /// Name.
    pub name: String,
}

/// ECDSA Curve.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub enum EcdsaCurve {
    /// secp256k1
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl Default for EcdsaCurve {
    fn default() -> Self {
        Self::Secp256k1
    }
}
