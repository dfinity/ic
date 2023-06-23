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

#[derive(Debug, Clone)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
/// An encrypted key
pub struct EncryptedKey {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

impl EncryptedKey {
    /// The length of the serialized encoding of this type
    pub const BYTES: usize = 2 * G1Affine::BYTES + G2Affine::BYTES;

    /// Combinine several shares into an encrypted key
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

    ///
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

#[derive(Copy, Clone, Debug)]
/// Error during interpolation
pub enum LagrangeError {
    /// Error during interpolation, usually duplicated node index
    InterpolationError,
}

/// Lagrange interpolation
pub struct LagrangeCoefficients {
    coefficients: Vec<Scalar>,
}

impl LagrangeCoefficients {
    fn new(coefficients: Vec<Scalar>) -> Result<Self, LagrangeError> {
        if coefficients.is_empty() {
            return Err(LagrangeError::InterpolationError);
        }

        Ok(Self { coefficients })
    }

    /// Return the Lagrange coefficients
    pub fn coefficients(&self) -> &[Scalar] {
        &self.coefficients
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g1<T: AsRef<G1Affine>>(&self, y: &[T]) -> Result<G1Affine, LagrangeError> {
        if y.len() != self.coefficients.len() {
            return Err(LagrangeError::InterpolationError);
        }

        Ok(G1Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g2<T: AsRef<G2Affine>>(&self, y: &[T]) -> Result<G2Affine, LagrangeError> {
        if y.len() != self.coefficients.len() {
            return Err(LagrangeError::InterpolationError);
        }

        Ok(G2Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }

    /// Check for duplicate dealer indexes
    ///
    /// Since these are public we don't need to worry about the lack of constant
    /// time behavior from HashSet
    fn check_for_duplicates(node_index: &[NodeIndex]) -> Result<(), LagrangeError> {
        let mut set = std::collections::HashSet::new();

        for i in node_index {
            if !set.insert(i) {
                return Err(LagrangeError::InterpolationError);
            }
        }

        Ok(())
    }

    /// Computes Lagrange polynomials evaluated at zero
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0) * (x_1) * ... * (x_(i-1)) *(x_(i+1)) * ... *(x_n)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_zero(samples: &[NodeIndex]) -> Result<Self, LagrangeError> {
        Self::at_value(&Scalar::zero(), samples)
    }

    /// Computes Lagrange polynomials evaluated at a given value.
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0-value) * (x_1-value) * ... * (x_(i-1)-value) *(x_(i+1)-value) * ... *(x_n-value)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_value(value: &Scalar, samples: &[NodeIndex]) -> Result<Self, LagrangeError> {
        // This is not strictly required but for our usage it simplifies matters
        if samples.is_empty() {
            return Err(LagrangeError::InterpolationError);
        }

        if samples.len() == 1 {
            return Self::new(vec![Scalar::one()]);
        }

        Self::check_for_duplicates(samples)?;

        let samples: Vec<Scalar> = samples
            .iter()
            .map(|s| Scalar::from_node_index(*s))
            .collect();

        let mut numerator = Vec::with_capacity(samples.len());
        let mut tmp = Scalar::one();
        numerator.push(tmp.clone());
        for x in samples.iter().take(samples.len() - 1) {
            tmp *= x - value;
            numerator.push(tmp.clone());
        }

        tmp = Scalar::one();
        for (i, x) in samples[1..].iter().enumerate().rev() {
            tmp *= x - value;
            numerator[i] *= &tmp;
        }

        for (lagrange_i, x_i) in numerator.iter_mut().zip(&samples) {
            // Compute the value at 0 of the i-th Lagrange polynomial that is `0` at the
            // other data points but `1` at `x_i`.
            let mut denom = Scalar::one();
            for x_j in samples.iter().filter(|x_j| *x_j != x_i) {
                denom *= x_j - x_i;
            }

            let inv = match denom.inverse() {
                None => return Err(LagrangeError::InterpolationError),
                Some(inv) => inv,
            };

            *lagrange_i *= inv;
        }
        Self::new(numerator)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An IBE (identity based encryption) ciphertext
pub struct IBECiphertext {
    c1: G2Affine,
    c2: [u8; Self::SEED_BYTES],
    c3: Vec<u8>,
}

impl IBECiphertext {
    const SEED_BYTES: usize = 32;

    /// Serialize this IBE ciphertext
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(G2Affine::BYTES + Self::SEED_BYTES + self.c3.len());

        output.extend_from_slice(&self.c1.serialize());
        output.extend_from_slice(&self.c2);
        output.extend_from_slice(&self.c3);

        output
    }

    /// Deserialize an IBE ciphertext
    ///
    /// Returns None if the encoding is not valid
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < G2Affine::BYTES + Self::SEED_BYTES {
            return None;
        }

        let c1 = match G2Affine::deserialize(&bytes[0..G2Affine::BYTES].as_ref()) {
            Ok(pt) => pt,
            Err(_) => return None,
        };

        let mut c2 = [0u8; Self::SEED_BYTES];
        c2.clone_from_slice(&bytes[G2Affine::BYTES..(G2Affine::BYTES + Self::SEED_BYTES)]);

        let c3 = bytes[G2Affine::BYTES + Self::SEED_BYTES..].to_vec();

        Some(Self { c1, c2, c3 })
    }

    fn hash_to_mask(seed: &[u8; Self::SEED_BYTES], msg: &[u8]) -> Scalar {
        let mut ro = ro::RandomOracle::new("ic-crypto-vetkd-bls12-381-ibe-hash-to-mask");
        ro.update_bin(seed);
        ro.update_bin(msg);
        ro.finalize_to_scalar()
    }

    fn mask_seed(seed: &[u8; Self::SEED_BYTES], t: &Gt) -> [u8; Self::SEED_BYTES] {
        let mut ro = ro::RandomOracle::new("ic-crypto-vetkd-bls12-381-ibe-mask-seed");
        ro.update_bin(&t.tag());

        let mut mask = ro.finalize_to_array::<{ Self::SEED_BYTES }>();
        for i in 0..Self::SEED_BYTES {
            mask[i] ^= seed[i];
        }
        mask
    }

    fn mask_msg(msg: &[u8], seed: &[u8; Self::SEED_BYTES]) -> Vec<u8> {
        let mut ro = ro::RandomOracle::new("ic-crypto-vetkd-bls12-381-ibe-mask-msg");
        ro.update_bin(seed);

        let mut mask = ro.finalize_to_vec(msg.len());

        for i in 0..msg.len() {
            mask[i] ^= msg[i];
        }

        mask
    }

    /// Encrypt a message using IBE
    pub fn encrypt<R: CryptoRng + RngCore>(
        dpk: &DerivedPublicKey,
        did: &[u8],
        msg: &[u8],
        rng: &mut R,
    ) -> Self {
        let mut seed = [0u8; Self::SEED_BYTES];
        rng.fill_bytes(&mut seed);

        let t = Self::hash_to_mask(&seed, msg);
        let tsig = Gt::pairing(&augmented_hash_to_g1(&dpk.pt, did), &dpk.pt) * &t;

        let c1 = G2Affine::from(G2Affine::generator() * &t);
        let c2 = Self::mask_seed(&seed, &tsig);
        let c3 = Self::mask_msg(msg, &seed);

        Self { c1, c2, c3 }
    }

    /// Decrypt an IBE ciphertext
    ///
    /// Returns the plaintext, or None if decryption failed
    pub fn decrypt(&self, k: &G1Affine) -> Option<Vec<u8>> {
        let t = Gt::pairing(k, &self.c1);

        let seed = Self::mask_seed(&self.c2, &t);

        let msg = Self::mask_msg(&self.c3, &seed);

        let t = Self::hash_to_mask(&seed, &msg);

        let g_t = G2Affine::from(G2Affine::generator() * &t);

        if self.c1 == g_t {
            Some(msg)
        } else {
            None
        }
    }
}
