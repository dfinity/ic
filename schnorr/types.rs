use candid::CandidType;
use serde::{Deserialize, Serialize};

use super::super::main::CanisterId;

/// Argument Type of [schnorr_public_key](super::schnorr_public_key).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrPublicKeyArgument {
    /// Canister id, default to the canister id of the caller if None.
    pub canister_id: Option<CanisterId>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [SchnorrKeyId].
    pub key_id: SchnorrKeyId,
}

/// Response Type of [schnorr_public_key](super::schnorr_public_key).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrPublicKeyResponse {
    /// An Schnorr public key encoded in SEC1 compressed form.
    pub public_key: Vec<u8>,
    /// Can be used to deterministically derive child keys of the public_key.
    pub chain_code: Vec<u8>,
}

/// Argument Type of [sign_with_schnorr](super::sign_with_schnorr).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithSchnorrArgument {
    /// Message to be signed.
    pub message: Vec<u8>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [SchnorrKeyId].
    pub key_id: SchnorrKeyId,
}

/// Response Type of [sign_with_schnorr](super::sign_with_schnorr).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithSchnorrResponse {
    /// The encoding of the signature depends on the key ID's algorithm.
    pub signature: Vec<u8>,
}

/// Schnorr KeyId.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrKeyId {
    /// See [SchnorrAlgorithm].
    pub algorithm: SchnorrAlgorithm,
    /// Name.
    pub name: String,
}

/// Schnorr Algorithm.
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum SchnorrAlgorithm {
    /// BIP-340 secp256k1.
    #[serde(rename = "bip340secp256k1")]
    #[default]
    Bip340secp256k1,
    /// ed25519.
    #[serde(rename = "ed25519")]
    Ed25519,
}
