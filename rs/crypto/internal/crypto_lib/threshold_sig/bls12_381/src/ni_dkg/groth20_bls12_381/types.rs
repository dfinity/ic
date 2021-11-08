//! Types for the Groth20-BLS12-381 implementation of Non-interactive
//! Distributed Key Generation.

use ic_crypto_internal_types::curves::bls12_381::{Fr as FrBytes, G1 as G1Bytes, G2 as G2Bytes};
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPok, FsEncryptionPop, FsEncryptionPublicKey,
};
use serde::{Deserialize, Serialize};

use std::fmt;
use zeroize::Zeroize;

#[cfg(test)]
pub mod arbitrary;

#[cfg(test)]
mod tests;

/// Forward secure encryption secret key used in Groth20.
///
/// Note: This is the CBOR serialised form of a linked list.  Given that the
/// list is bounded in size we could use a fixed size representation.  We
/// may also want to expose the data structure here, depending on the
/// strategic decisions regarding CBOR and protobufs.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsEncryptionSecretKey {
    pub bte_nodes: Vec<BTENode>,
}
impl Zeroize for FsEncryptionSecretKey {
    fn zeroize(&mut self) {
        for node in self.bte_nodes.iter_mut() {
            node.zeroize();
        }
    }
}
impl fmt::Debug for FsEncryptionSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // this prints no secret key parts since Debug for BTENode is redacted:
        write!(f, "bte_nodes: {}", format!("{:?}", self.bte_nodes))
    }
}

/// Library-independent representation of binary tree encryption leaf keys.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BTENode {
    // Notation from section 7.2.
    #[serde(with = "serde_bytes")]
    pub tau: Vec<u8>,
    pub a: G1Bytes,
    pub b: G2Bytes,
    pub d_t: Vec<G2Bytes>,
    pub d_h: Vec<G2Bytes>,
    pub e: G2Bytes,
}

impl Zeroize for BTENode {
    fn zeroize(&mut self) {
        // tau is not secret.  It is a common parameter and doesn't need to be zeroed.
        self.a.zeroize();
        self.b.zeroize();
        for node in self.d_t.iter_mut() {
            node.zeroize();
        }
        for node in self.d_h.iter_mut() {
            node.zeroize();
        }
        self.e.zeroize();
    }
}

impl fmt::Debug for BTENode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tau: {}, a: REDACTED, b: REDACTED, d_t: REDACTED, d_h: REDACTED, e: REDACTED",
            format!("{:?}", base64::encode(&self.tau))
        )
    }
}

/// (deprecated) Forward-secure encryption public key, secret key, and
/// proof-of-knowledge.
//CRP-900: Remove the following type
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsEncryptionKeySet {
    pub public_key: FsEncryptionPublicKey,
    pub pok: FsEncryptionPok,
    pub secret_key: FsEncryptionSecretKey,
}
impl Zeroize for FsEncryptionKeySet {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Forward-secure encryption public key, secret key, and proof-of-possession.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsEncryptionKeySetWithPop {
    pub public_key: FsEncryptionPublicKey,
    pub pop: FsEncryptionPop,
    pub secret_key: FsEncryptionSecretKey,
}
impl Zeroize for FsEncryptionKeySetWithPop {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Converts an old `FsEncryptionKeySet` to a `FsEncryptionKeySetWithPop`.
///
/// The old `FsEncrptionPok` is formatted as a `FsEncryptionPop` as follows:
/// * The `blinder` of the PoK is written as the `pop_key` value in the PoP
/// * The `challenge` of the proof of possession is set equal to `0`.
/// * The `response` of the Pok is written as the `response` value in the PoP,
///
/// # Security Notice
/// The reformatted PoK **does not** constitute a valid PoP.
/// This function must be used for compatibility purposes only and it will be
/// removed as part of CRP-923.
pub fn convert_keyset_to_keyset_with_pop(key_set: FsEncryptionKeySet) -> FsEncryptionKeySetWithPop {
    FsEncryptionKeySetWithPop {
        public_key: key_set.public_key,
        pop: FsEncryptionPop {
            pop_key: key_set.pok.blinder,
            challenge: FrBytes([0; FrBytes::SIZE]),
            response: key_set.pok.response,
        },
        secret_key: key_set.secret_key,
    }
}
