//! Verifiably Encrypted Threshold Key Derivation
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub use ic_crypto_internal_bls12_381_type::*;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod ro;

/// The index of a node
pub type NodeIndex = u32;

/// The derivation path
#[derive(Clone)]
pub struct DerivationPath {
    delta: Scalar,
}

impl DerivationPath {
    /// Create a new derivation path
    pub fn new<U: AsRef<[u8]>>(canister_id: &[u8], extra_paths: &[U]) -> Self {
        let mut ro = ro::RandomOracle::new("ic-crypto-vetkd-bls12-381-derivation-path");

        ro.update_bin(canister_id);

        for path in extra_paths {
            ro.update_bin(path.as_ref());
        }

        let delta = ro.finalize_to_scalar();
        Self { delta }
    }

    fn delta(&self) -> &Scalar {
        &self.delta
    }
}

#[derive(Copy, Clone, Debug)]
/// Deserialization of a transport secret key failed
pub enum TransportSecretKeyDeserializationError {
    /// Error indicating the key was not a valid scalar
    InvalidSecretKey,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key of the transport key pair
pub struct TransportSecretKey {
    secret_key: Scalar,
}

impl TransportSecretKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = Scalar::BYTES;

    /// Create a new transport secret key
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = Scalar::random(rng);
        Self { secret_key }
    }

    /// Serialize the transport secret key to a bytestring
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        self.secret_key.serialize()
    }

    /// Deserialize a previously serialized transport secret key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransportSecretKeyDeserializationError> {
        let secret_key = Scalar::deserialize(&bytes)
            .map_err(|_| TransportSecretKeyDeserializationError::InvalidSecretKey)?;
        Ok(Self { secret_key })
    }

    /// Return the public key associated with this secret key
    pub fn public_key(&self) -> TransportPublicKey {
        let public_key = G1Affine::generator() * &self.secret_key;
        TransportPublicKey::new(public_key.to_affine())
    }

    fn secret(&self) -> &Scalar {
        &self.secret_key
    }

    /// Decrypt an encrypted key
    ///
    /// Returns None if decryption failed
    pub fn decrypt(
        &self,
        ek: &EncryptedKey,
        dpk: &DerivedPublicKey,
        did: &[u8],
    ) -> Option<G1Affine> {
        let msg = augmented_hash_to_g1(&dpk.pt, did);

        let k = G1Affine::from(G1Projective::from(&ek.c3) - &ek.c1 * self.secret());

        let dpk_prep = G2Prepared::from(&dpk.pt);
        let k_is_valid_sig =
            Gt::multipairing(&[(&k, G2Prepared::neg_generator()), (&msg, &dpk_prep)]).is_identity();

        if k_is_valid_sig {
            Some(k)
        } else {
            None
        }
    }

    /// Decrypt an encrypted key, and hash it to a symmetric key
    ///
    /// Returns None if decryption failed
    ///
    /// The output length can be arbitrary and is specified by the caller
    ///
    /// The `symmetric_key_associated_data` field should include information about
    /// the protocol and cipher that this key will be used for
    pub fn decrypt_and_hash(
        &self,
        ek: &EncryptedKey,
        dpk: &DerivedPublicKey,
        did: &[u8],
        symmetric_key_bytes: usize,
        symmetric_key_associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        match self.decrypt(ek, dpk, did) {
            None => None,
            Some(k) => {
                let mut ro = ro::RandomOracle::new(&format!(
                    "ic-crypto-vetkd-bls12-381-create-secret-key-{}-bytes",
                    symmetric_key_bytes
                ));
                ro.update_bin(symmetric_key_associated_data);
                ro.update_bin(&k.serialize());
                Some(ro.finalize_to_vec(symmetric_key_bytes))
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
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

    fn new(public_key: G1Affine) -> Self {
        Self { public_key }
    }

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

#[derive(Copy, Clone, Debug)]
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

    /// Derive a public key relative to another public key and a derivation path
    pub fn compute_derived_key(pk: &G2Affine, derivation_path: &DerivationPath) -> Self {
        let pt = G2Affine::from(G2Affine::generator() * derivation_path.delta() + pk);
        Self { pt }
    }

    /// Serialize a derived public key
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        self.pt.serialize()
    }

    /// Deserialize a previously serialized derived public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DerivedPublicKeyDeserializationError> {
        let pt = G2Affine::deserialize(&bytes)
            .map_err(|_| DerivedPublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { pt })
    }
}

/// See draft-irtf-cfrg-bls-signature-01 §4.2.2 for details on BLS augmented signatures
fn augmented_hash_to_g1(pk: &G2Affine, data: &[u8]) -> G1Affine {
    let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

    let mut signature_input = vec![];
    signature_input.extend_from_slice(&pk.serialize());
    signature_input.extend_from_slice(data);
    G1Affine::hash(domain_sep, &signature_input)
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

#[derive(Copy, Clone, Debug)]
/// Error indicating that deserializing an encrypted key failed
pub enum EncryptedKeyDeserializationError {
    /// Error indicating one or more of the points was invalid
    InvalidEncryptedKey,
}

#[derive(Clone, Debug)]
/// Error indicating that combining shares into an encrypted key failed
pub enum EncryptedKeyCombinationError {
    /// Two shares had the same node index
    DuplicateNodeIndex,
    /// There were insufficient shares to perform combination
    InsufficientShares,
    /// Some of the key shares are invalid; the Vec contains the list of
    /// node indexes whose shares were malformed
    InvalidKeyShares(Vec<NodeIndex>),
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

    /// Combine several shares into an encrypted key
    pub fn combine(
        nodes: &[(NodeIndex, G2Affine, EncryptedKeyShare)],
        reconstruction_threshold: usize,
        master_pk: &G2Affine,
        tpk: &TransportPublicKey,
        derivation_path: &DerivationPath,
        did: &[u8],
    ) -> Result<Self, EncryptedKeyCombinationError> {
        if nodes.len() < reconstruction_threshold {
            return Err(EncryptedKeyCombinationError::InsufficientShares);
        }

        let l = LagrangeCoefficients::at_zero(&nodes.iter().map(|i| i.0).collect::<Vec<_>>())
            .map_err(|_| EncryptedKeyCombinationError::DuplicateNodeIndex)?;

        let c1 = l
            .interpolate_g1(&nodes.iter().map(|i| &i.2.c1).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");
        let c2 = l
            .interpolate_g2(&nodes.iter().map(|i| &i.2.c2).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");
        let c3 = l
            .interpolate_g1(&nodes.iter().map(|i| &i.2.c3).collect::<Vec<_>>())
            .expect("Number of nodes and shares guaranteed equal");

        let c = Self { c1, c2, c3 };

        if !c.is_valid(master_pk, derivation_path, did, tpk) {
            // Detect and return the invalid share id(s)
            let mut invalid = vec![];

            for (node_id, node_pk, node_eks) in nodes {
                if !node_eks.is_valid(master_pk, node_pk, derivation_path, did, tpk) {
                    invalid.push(*node_id);
                }
            }

            return Err(EncryptedKeyCombinationError::InvalidKeyShares(invalid));
        }

        Ok(c)
    }

    /// Check if this encrypted key is valid with respect to the provided derivation path
    pub fn is_valid(
        &self,
        master_pk: &G2Affine,
        derivation_path: &DerivationPath,
        did: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let dpk = DerivedPublicKey::compute_derived_key(master_pk, derivation_path);
        let msg = augmented_hash_to_g1(&dpk.pt, did);
        check_validity(&self.c1, &self.c2, &self.c3, tpk, &dpk.pt, &msg)
    }

    /// Deserialize an encrypted key
    pub fn deserialize(val: [u8; Self::BYTES]) -> Result<Self, EncryptedKeyDeserializationError> {
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
}

#[derive(Clone, Eq, PartialEq, Debug)]
/// A share of an encrypted key
pub struct EncryptedKeyShare {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

#[derive(Copy, Clone, Debug)]
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
        derivation_path: &DerivationPath,
        did: &[u8],
    ) -> Self {
        let delta = derivation_path.delta();

        let dsk = delta + node_sk;
        let dpk = G2Affine::from(G2Affine::generator() * delta + master_pk);

        let r = Scalar::random(rng);

        let msg = augmented_hash_to_g1(&dpk, did);

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
        derivation_path: &DerivationPath,
        did: &[u8],
        tpk: &TransportPublicKey,
    ) -> bool {
        let dpki = DerivedPublicKey::compute_derived_key(master_pki, derivation_path);
        let dpk = DerivedPublicKey::compute_derived_key(master_pk, derivation_path);

        let msg = augmented_hash_to_g1(&dpk.pt, did);

        check_validity(&self.c1, &self.c2, &self.c3, tpk, &dpki.pt, &msg)
    }

    /// Deserialize an encrypted key share
    pub fn deserialize(
        val: [u8; Self::BYTES],
    ) -> Result<Self, EncryptedKeyShareDeserializationError> {
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
