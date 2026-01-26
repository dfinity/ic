//! Types for the Groth20-BLS12-381 implementation of Non-interactive
//! Distributed Key Generation.

// TODO: Remove after https://github.com/rust-lang/rust/issues/147648 is fixed
#![allow(unused_assignments)]

use ic_crypto_internal_types::curves::bls12_381::{G1Bytes, G2Bytes};
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPop, FsEncryptionPublicKey,
};
use serde::{Deserialize, Serialize};

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct FsEncryptionSecretKey {
    pub bte_nodes: Vec<BTENodeBytes>,
}

impl fmt::Debug for FsEncryptionSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // this prints no secret key parts since Debug for BTENodeBytes is redacted:
        write!(f, "bte_nodes: {:?}", self.bte_nodes)
    }
}

/// Library-independent representation of binary tree encryption leaf keys.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct BTENodeBytes {
    // Notation from section 7.2.
    #[serde(with = "serde_bytes")]
    #[zeroize(skip)] // tau is public and does not need to be zeroized
    pub tau: Vec<u8>,
    pub a: G1Bytes,
    pub b: G2Bytes,
    pub d_t: Vec<G2Bytes>,
    pub d_h: Vec<G2Bytes>,
    pub e: G2Bytes,
}

impl fmt::Debug for BTENodeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tau: {}, a: REDACTED, b: REDACTED, d_t: REDACTED, d_h: REDACTED, e: REDACTED",
            base64::encode(&self.tau)
        )
    }
}

/// Forward-secure encryption public key, secret key, and proof-of-possession.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct FsEncryptionKeySetWithPop {
    #[zeroize(skip)]
    pub public_key: FsEncryptionPublicKey,
    #[zeroize(skip)]
    pub pop: FsEncryptionPop,
    pub secret_key: FsEncryptionSecretKey,
}
