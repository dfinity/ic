//! Internet Computer Canister Signature Algorithm (ICCSA) types
use ic_crypto_tree_hash::MixedHashTree;
use ic_types::messages::Blob;
use ic_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

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

// Methods used for testing: they are not #[cfg(test)]
// because they are used outside of the crate.
impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let canister_id_principal_bytes = self.signing_canister_id.get_ref().as_slice();
        let mut buf = vec![];
        buf.push(u8::try_from(canister_id_principal_bytes.len()).expect("u8 too small"));
        buf.extend_from_slice(canister_id_principal_bytes);
        buf.extend_from_slice(&self.seed);
        buf
    }
}
