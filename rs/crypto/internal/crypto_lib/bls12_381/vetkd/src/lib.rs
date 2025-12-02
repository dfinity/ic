//! Verifiably Encrypted Threshold Key Derivation
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, PairingInvalidPoint, Scalar};
use ic_crypto_internal_bls12_381_type::{G2Prepared, Gt, LagrangeCoefficients, NodeIndices};

use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

/// The index of a node
pub type NodeIndex = u32;

/// The derivation context
#[derive(Clone)]
pub struct DerivationContext {
    canister_id: Vec<u8>,
    /// The user-provided context string, if any
    context: Option<Vec<u8>>,
}

// Prefix-freeness is not required, as the domain separator is used with XMD,
// which includes the domain separator's length as a distinct input.
const DERIVATION_CANISTER_DST: &[u8; 33] = b"ic-vetkd-bls12-381-g2-canister-id";

const DERIVATION_CONTEXT_DST: &[u8; 29] = b"ic-vetkd-bls12-381-g2-context";

impl DerivationContext {
    /// Create a new derivation context
    pub fn new(canister_id: &[u8], context: &[u8]) -> Self {
        Self {
            canister_id: canister_id.to_vec(),
            context: if context.is_empty() {
                None
            } else {
                Some(context.to_vec())
            },
        }
    }

    fn hash_to_scalar(input1: &[u8], input2: &[u8], domain_sep: &'static [u8]) -> Scalar {
        let combined_input = {
            let mut c = Vec::with_capacity(2 * 8 + input1.len() + input2.len());
            c.extend_from_slice(&(input1.len() as u64).to_be_bytes());
            c.extend_from_slice(input1);
            c.extend_from_slice(&(input2.len() as u64).to_be_bytes());
            c.extend_from_slice(input2);
            c
        };

        Scalar::hash(domain_sep, &combined_input)
    }

    fn derive_key(&self, master_pk: &G2Affine) -> (G2Affine, Scalar) {
        let mut offset = Self::hash_to_scalar(
            &master_pk.serialize(),
            &self.canister_id,
            DERIVATION_CANISTER_DST,
        );

        let canister_key = G2Affine::generator() * &offset + master_pk;

        if let Some(context) = &self.context {
            let context_offset =
                Self::hash_to_scalar(&canister_key.serialize(), context, DERIVATION_CONTEXT_DST);
            let canister_key_with_context = G2Affine::generator() * &context_offset + canister_key;
            offset += context_offset;
            (G2Affine::from(canister_key_with_context), offset)
        } else {
            (G2Affine::from(canister_key), offset)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Error indicating that deserializing a transport public key failed
pub enum TransportPublicKeyDeserializationError {
    /// Error indicating the public key was not a valid elliptic curve point
    InvalidPublicKey,
}

#[derive(Clone, Debug)]
/// A transport public key
pub struct TransportPublicKey {
    public_key: G1Affine,
}

impl TransportPublicKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = G1Affine::BYTES;

    /// Serialize this public key to a bytestring
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        self.public_key.serialize()
    }

    /// Deserialize a previously serialized public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransportPublicKeyDeserializationError> {
        let public_key = G1Affine::deserialize(&bytes)
            .map_err(|_| TransportPublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { public_key })
    }

    fn point(&self) -> &G1Affine {
        &self.public_key
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Error indicating that deserializing a derived public key failed
pub enum PublicKeyDeserializationError {
    /// The public point was not a valid encoding
    InvalidPublicKey,
}

#[derive(Clone, Debug)]
/// A derived public key
pub struct DerivedPublicKey {
    pt: G2Affine,
}

impl DerivedPublicKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = G2Affine::BYTES;

    /// Derive a public key relative to another public key and a derivation context
    pub fn derive_sub_key(pk: &G2Affine, context: &DerivationContext) -> Self {
        let (pt, _delta) = context.derive_key(pk);
        Self { pt }
    }

    /// Serialize a derived public key
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        self.pt.serialize()
    }

    /// Return the derived point in G2
    pub fn point(&self) -> &G2Affine {
        &self.pt
    }

    /// Deserialize a previously serialized derived public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserializationError> {
        let pt = G2Affine::deserialize(&bytes)
            .map_err(|_| PublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { pt })
    }
}

/// Check the validity of an encrypted key or encrypted key share
///
/// The only difference in handling is when checking a share, the
/// master and verification public keys will be different.
fn check_validity(
    c1: &G1Affine,
    c2: &G2Affine,
    c3: &G1Affine,
    tpk: &TransportPublicKey,
    verification_pk: &G2Affine,
    msg: &G1Affine,
) -> bool {
    let neg_g2_g = G2Prepared::neg_generator();
    let c2_prepared = G2Prepared::from(c2);

    // check e(c1,g2) == e(g1, c2)
    let c1_c2 = Gt::multipairing(&[(c1, neg_g2_g), (G1Affine::generator(), &c2_prepared)]);
    if !c1_c2.is_identity() {
        return false;
    }

    let verification_key_prepared = G2Prepared::from(verification_pk);

    // check e(c3, g2) == e(tpk, c2) * e(msg, dpki)
    let c3_c2_msg = Gt::multipairing(&[
        (c3, neg_g2_g),
        (tpk.point(), &c2_prepared),
        (msg, &verification_key_prepared),
    ]);

    if !c3_c2_msg.is_identity() {
        return false;
    }

    true
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Error indicating that deserializing an encrypted key failed
pub enum EncryptedKeyDeserializationError {
    /// Error indicating one or more of the points was invalid
    InvalidEncryptedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Error indicating that combining shares into an encrypted key failed
pub enum EncryptedKeyCombinationError {
    /// There were insufficient shares to perform combination
    InsufficientShares,
    /// Not enough valid shares
    InsufficientValidKeyShares,
    /// Some of the key shares are invalid
    InvalidShares,
    /// The reconstruction threshold was invalid
    ReconstructionFailed,
}

#[derive(Clone, Eq, PartialEq, Debug)]
/// An encrypted key
pub struct EncryptedKey {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

impl EncryptedKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = 2 * G1Affine::BYTES + G2Affine::BYTES;

    /// Combine, unchecked.
    /// The returned key may be invalid.
    fn combine_unchecked(
        nodes: &BTreeMap<NodeIndex, EncryptedKeyShare>,
        reconstruction_threshold: usize,
    ) -> Result<Self, EncryptedKeyCombinationError> {
        if nodes.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientShares);
        }

        let l = LagrangeCoefficients::at_zero(&NodeIndices::from_map(nodes));

        let c1 = l
            .interpolate_g1(&nodes.iter().map(|i| &i.1.c1).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");
        let c2 = l
            .interpolate_g2(&nodes.iter().map(|i| &i.1.c2).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");
        let c3 = l
            .interpolate_g1(&nodes.iter().map(|i| &i.1.c3).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");

        Ok(Self { c1, c2, c3 })
    }

    /// Combines all the given shares into an encrypted key.
    ///
    /// If the result is Ok(), the returned key is guaranteed to be valid.
    /// Returns the combined key, if it is valid.
    /// Does not take the nodes' individual public keys as input.
    pub fn combine_all(
        nodes: &BTreeMap<NodeIndex, EncryptedKeyShare>,
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        context: &DerivationContext,
        input: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        let c = Self::combine_unchecked(nodes, reconstruction_threshold)?;
        if c.is_valid(master_pk, context, input, tpk) {
            Ok(c)
        } else {
            Err(EncryptedKeyCombinationError::InvalidShares)
        }
    }

    /// Filters the valid shares from the given ones, and combines them into a valid key, if possible.
    /// The returned key is guaranteed to be valid.
    /// Returns an error if not sufficient shares are given or if not sufficient valid shares are given.
    /// Takes also the nodes' individual public keys as input, which means the individual public keys
    /// must be available: calculating them is comparatively expensive. Note that combine_all does not
    /// take the individual public keys as input.
    pub fn combine_valid_shares(
        nodes: &BTreeMap<NodeIndex, (G2Affine, EncryptedKeyShare)>,
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        context: &DerivationContext,
        input: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        if nodes.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientShares);
        }

        // Take the first reconstruction_threshold shares which pass validity check
        let mut valid_shares = BTreeMap::new();

        for (node_index, (node_pk, node_eks)) in nodes.iter() {
            if node_eks.is_valid(master_pk, node_pk, context, input, tpk) {
                valid_shares.insert(*node_index, node_eks.clone());

                // Have we collected enough shares?
                // If so stop verifying and proceed with reconstruction
                if valid_shares.len() >= reconstruction_threshold {
                    break;
                }
            }
        }

        if valid_shares.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientValidKeyShares);
        }

        let c = Self::combine_unchecked(&valid_shares, reconstruction_threshold)?;

        // If sufficient shares are available, and all were valid (which we already checked)
        // then the resulting signature should always be valid as well.
        //
        // This check is mostly to catch the case where the reconstruction_threshold was
        // somehow incorrect.
        if c.is_valid(master_pk, context, input, tpk) {
            Ok(c)
        } else {
            Err(EncryptedKeyCombinationError::ReconstructionFailed)
        }
    }

    /// Check if this encrypted key is valid with respect to the provided derivation input and context
    pub fn is_valid(
        &self,
        master_pk: &G2Affine,
        context: &DerivationContext,
        input: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let dpk = DerivedPublicKey::derive_sub_key(master_pk, context);
        let msg = G1Affine::augmented_hash(&dpk.pt, input);
        check_validity(&self.c1, &self.c2, &self.c3, tpk, &dpk.pt, &msg)
    }

    /// Deserialize an encrypted key
    pub fn deserialize(val: &[u8]) -> Result<Self, EncryptedKeyDeserializationError> {
        if val.len() != Self::BYTES {
            return Err(EncryptedKeyDeserializationError::InvalidEncryptedKey);
        }
        let c2_start = G1Affine::BYTES;
        let c3_start = G1Affine::BYTES + G2Affine::BYTES;

        let c1_bytes: &[u8] = &val[..c2_start];
        let c2_bytes: &[u8] = &val[c2_start..c3_start];
        let c3_bytes: &[u8] = &val[c3_start..];

        let c1 = G1Affine::deserialize(&c1_bytes);
        let c2 = G2Affine::deserialize(&c2_bytes);
        let c3 = G1Affine::deserialize(&c3_bytes);

        match (c1, c2, c3) {
            (Ok(c1), Ok(c2), Ok(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedKeyDeserializationError::InvalidEncryptedKey),
        }
    }

    /// Serialize an encrypted key
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        let mut output = [0u8; Self::BYTES];

        let c2_start = G1Affine::BYTES;
        let c3_start = G1Affine::BYTES + G2Affine::BYTES;

        output[..c2_start].copy_from_slice(&self.c1.serialize());
        output[c2_start..c3_start].copy_from_slice(&self.c2.serialize());
        output[c3_start..].copy_from_slice(&self.c3.serialize());

        output
    }

    /// Return the c1 element
    pub fn c1(&self) -> &G1Affine {
        &self.c1
    }

    /// Return the c2 element
    pub fn c2(&self) -> &G2Affine {
        &self.c2
    }

    /// Return the c3 element
    pub fn c3(&self) -> &G1Affine {
        &self.c3
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
/// A share of an encrypted key
pub struct EncryptedKeyShare {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Error indicating that deserialization of an encrypted key share failed
pub enum EncryptedKeyShareDeserializationError {
    /// One or more of the share points were not valid
    InvalidEncryptedKeyShare,
}

impl EncryptedKeyShare {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = 2 * G1Affine::BYTES + G2Affine::BYTES;

    /// Create a new encrypted key share.
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        master_pk: &G2Affine,
        node_sk: &Scalar,
        transport_pk: &TransportPublicKey,
        context: &DerivationContext,
        input: &[u8],
    ) -> Self {
        let (dpk, delta) = context.derive_key(master_pk);

        let dsk = delta + node_sk;

        let r = Scalar::random(rng);

        let msg = G1Affine::augmented_hash(&dpk, input);

        let c1 = G1Affine::from(G1Affine::generator() * &r);
        let c2 = G2Affine::from(G2Affine::generator() * &r);
        let c3 = G1Affine::from(transport_pk.point() * &r + msg * &dsk);

        Self { c1, c2, c3 }
    }

    /// Check if this encrypted key share is valid
    pub fn is_valid(
        &self,
        master_pk: &G2Affine,
        node_pk: &G2Affine,
        context: &DerivationContext,
        input: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let (dpk, offset) = context.derive_key(master_pk);

        let derived_node_key = G2Affine::from(G2Affine::generator().mul_vartime(&offset) + node_pk);

        let msg = G1Affine::augmented_hash(&dpk, input);

        check_validity(&self.c1, &self.c2, &self.c3, tpk, &derived_node_key, &msg)
    }

    /// Deserialize an encrypted key share
    pub fn deserialize(val: &[u8]) -> Result<Self, EncryptedKeyShareDeserializationError> {
        if val.len() != Self::BYTES {
            return Err(EncryptedKeyShareDeserializationError::InvalidEncryptedKeyShare);
        }
        let c2_start = G1Affine::BYTES;
        let c3_start = G1Affine::BYTES + G2Affine::BYTES;

        let c1_bytes: &[u8] = &val[..c2_start];
        let c2_bytes: &[u8] = &val[c2_start..c3_start];
        let c3_bytes: &[u8] = &val[c3_start..];

        let c1 = G1Affine::deserialize(&c1_bytes);
        let c2 = G2Affine::deserialize(&c2_bytes);
        let c3 = G1Affine::deserialize(&c3_bytes);

        match (c1, c2, c3) {
            (Ok(c1), Ok(c2), Ok(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedKeyShareDeserializationError::InvalidEncryptedKeyShare),
        }
    }

    /// Serialize an encrypted key share
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        let mut output = [0u8; Self::BYTES];

        let c2_start = G1Affine::BYTES;
        let c3_start = G1Affine::BYTES + G2Affine::BYTES;

        output[..c2_start].copy_from_slice(&self.c1.serialize());
        output[c2_start..c3_start].copy_from_slice(&self.c2.serialize());
        output[c3_start..].copy_from_slice(&self.c3.serialize());

        output
    }
}
