//! Internet Computer Canister Signature Algorithm (ICCSA) types
use ic_crypto_tree_hash::MixedHashTree;
use ic_types::messages::Blob;
use ic_types::CanisterId;
use serde::{Deserialize, Serialize};

mod conversions;

/// An ICCSA signature encoded as a bytestring
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Container for an ICCSA public key _without_ the DER-wrapping.
/// The byte representation may be invalid and needs to be parsed
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// A decoded ICCSA signature
#[derive(Deserialize)]
pub struct Signature {
    pub certificate: Blob,
    pub tree: MixedHashTree,
}

/// A ICCSA public key that was successfully parsed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    signing_canister_id: CanisterId,
    #[serde(with = "serde_bytes")]
    seed: Vec<u8>,
}

impl PublicKey {
    /// Create a new ICCSA PublicKey instance
    pub fn new(signing_canister_id: CanisterId, seed: Vec<u8>) -> Self {
        PublicKey {
            signing_canister_id,
            seed,
        }
    }

    pub fn signing_canister_id(&self) -> CanisterId {
        self.signing_canister_id
    }

    /// Return a reference to the seed
    pub fn seed(&self) -> &[u8] {
        &self.seed[..]
    }

    /// Return the seed, consuming self
    pub fn into_seed(self) -> Vec<u8> {
        self.seed
    }
}
