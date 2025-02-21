//! Verifiably Encrypted Threshold Key Derivation
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, PairingInvalidPoint, Scalar};
use ic_crypto_internal_bls12_381_type::{G2Prepared, Gt, LagrangeCoefficients};

use rand::{CryptoRng, RngCore};

/// The index of a node
pub type NodeIndex = u32;

/// The derivation domain
#[derive(Clone)]
pub struct DerivationDomain {
    delta: Scalar,
}

// Prefix-freeness is not required, as the domain separator is used with XMD,
// which includes the domain separator's length as a distinct input.
const DERIVATION_DOMAIN_DST: &[u8; 39] = b"ic-vetkd-bls12-381-g2-derivation-domain";

impl DerivationDomain {
    /// Create a new derivation domain
    pub fn new(canister_id: &[u8], domain: &[u8]) -> Self {
        let mut input = vec![];
        input.extend_from_slice(&(canister_id.len() as u64).to_be_bytes()); // 8 bytes length
        input.extend_from_slice(canister_id);

        let mut delta = Scalar::hash(DERIVATION_DOMAIN_DST, &input);

        if !domain.is_empty() {
            let mut input = vec![];
            input.extend_from_slice(&(domain.len() as u64).to_be_bytes()); // 8 bytes length
            input.extend_from_slice(domain.as_ref());

            delta += Scalar::hash(DERIVATION_DOMAIN_DST, &input);
        }

        Self { delta }
    }

    fn delta(&self) -> &Scalar {
        &self.delta
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
pub enum DerivedPublicKeyDeserializationError {
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

    /// Derive a public key relative to another public key and a derivation domain
    pub fn compute_derived_key(pk: &G2Affine, derivation_domain: &DerivationDomain) -> Self {
        let pt = G2Affine::from(G2Affine::generator() * derivation_domain.delta() + pk);
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
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DerivedPublicKeyDeserializationError> {
        let pt = G2Affine::deserialize(&bytes)
            .map_err(|_| DerivedPublicKeyDeserializationError::InvalidPublicKey)?;
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
    /// Two shares had the same node index
    DuplicateNodeIndex,
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
        nodes: &[(NodeIndex, EncryptedKeyShare)],
        reconstruction_threshold: usize,
    ) -> Result<Self, EncryptedKeyCombinationError> {
        if nodes.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientShares);
        }

        let l = LagrangeCoefficients::at_zero(&nodes.iter().map(|i| i.0).collect::<Vec<_>>())
            .map_err(|_| EncryptedKeyCombinationError::DuplicateNodeIndex)?;

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
        nodes: &[(NodeIndex, EncryptedKeyShare)],
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        derivation_domain: &DerivationDomain,
        did: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        let c = Self::combine_unchecked(nodes, reconstruction_threshold)?;
        if c.is_valid(master_pk, derivation_domain, did, tpk) {
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
        nodes: &[(NodeIndex, G2Affine, EncryptedKeyShare)],
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        derivation_domain: &DerivationDomain,
        did: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        if nodes.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientShares);
        }

        // Take the first reconstruction_threshold shares which pass validity check
        let mut valid_shares = Vec::with_capacity(reconstruction_threshold);

        for (node_index, node_pk, node_eks) in nodes.iter() {
            if node_eks.is_valid(master_pk, node_pk, derivation_domain, did, tpk) {
                valid_shares.push((*node_index, node_eks.clone()));

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
        if c.is_valid(master_pk, derivation_domain, did, tpk) {
            Ok(c)
        } else {
            Err(EncryptedKeyCombinationError::ReconstructionFailed)
        }
    }

    /// Check if this encrypted key is valid with respect to the provided derivation domain
    pub fn is_valid(
        &self,
        master_pk: &G2Affine,
        derivation_domain: &DerivationDomain,
        did: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let dpk = DerivedPublicKey::compute_derived_key(master_pk, derivation_domain);
        let msg = G1Affine::augmented_hash(&dpk.pt, did);
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
        derivation_domain: &DerivationDomain,
        did: &[u8],
    ) -> Self {
        let delta = derivation_domain.delta();

        let dsk = delta + node_sk;
        let dpk = G2Affine::from(G2Affine::generator() * delta + master_pk);

        let r = Scalar::random(rng);

        let msg = G1Affine::augmented_hash(&dpk, did);

        let c1 = G1Affine::from(G1Affine::generator() * &r);
        let c2 = G2Affine::from(G2Affine::generator() * &r);
        let c3 = G1Affine::from(transport_pk.point() * &r + msg * &dsk);

        Self { c1, c2, c3 }
    }

    /// Check if this encrypted key share is valid
    pub fn is_valid(
        &self,
        master_pk: &G2Affine,
        master_pki: &G2Affine,
        derivation_domain: &DerivationDomain,
        did: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let dpki = DerivedPublicKey::compute_derived_key(master_pki, derivation_domain);
        let dpk = DerivedPublicKey::compute_derived_key(master_pk, derivation_domain);

        let msg = G1Affine::augmented_hash(&dpk.pt, did);

        check_validity(&self.c1, &self.c2, &self.c3, tpk, &dpki.pt, &msg)
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
