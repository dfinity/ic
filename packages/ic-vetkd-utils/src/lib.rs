//! Verifiably Encrypted Threshold Key Derivation Utilities
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]
#![warn(future_incompatible)]

use ic_bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod ro;

#[cfg(feature = "js")]
use wasm_bindgen::prelude::*;

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

const G1AFFINE_BYTES: usize = 48; // Size of compressed form
const G2AFFINE_BYTES: usize = 96; // Size of compressed form

#[cfg_attr(feature = "js", wasm_bindgen)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key of the transport key pair
pub struct TransportSecretKey {
    secret_key: Scalar,
}

#[cfg_attr(feature = "js", wasm_bindgen)]
impl TransportSecretKey {
    #[cfg_attr(feature = "js", wasm_bindgen(constructor))]
    /// Creates a transport secret key from a 32-byte seed.
    pub fn from_seed(seed: Vec<u8>) -> Result<TransportSecretKey, String> {
        let seed_32_bytes: [u8; 32] = seed.try_into().map_err(|_e| "seed not 32 bytes")?;
        let rng = &mut ChaCha20Rng::from_seed(seed_32_bytes);
        use pairing::group::ff::Field;
        let secret_key = Scalar::random(rng);
        Ok(Self { secret_key })
    }

    /// Returns the serialized public key associated with this secret key
    pub fn public_key(&self) -> Vec<u8> {
        let public_key = G1Affine::generator() * self.secret_key;
        use pairing::group::Curve;
        public_key.to_affine().to_compressed().to_vec()
    }

    /// Decrypts and verifies an encrypted key, and hashes it to a symmetric key
    ///
    /// The output length can be arbitrary and is specified by the caller
    ///
    /// The `symmetric_key_associated_data` field should include information about
    /// the protocol and cipher that this key will be used for.
    pub fn decrypt_and_hash(
        &self,
        encrypted_key_bytes: Vec<u8>,
        derived_public_key_bytes: Vec<u8>,
        derivation_id: &[u8],
        symmetric_key_bytes: usize,
        symmetric_key_associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted_key = EncryptedKey::from_bytes_vec(encrypted_key_bytes)?;
        let derived_public_key = DerivedPublicKey::from_bytes_vec(derived_public_key_bytes)
            .map_err(|e| format!("failed to deserialize public key: {:?}", e))?;
        let key = encrypted_key.decrypt_and_verify(self, derived_public_key, derivation_id)?;

        let mut ro = ro::RandomOracle::new(&format!(
            "ic-crypto-vetkd-bls12-381-create-secret-key-{}-bytes",
            symmetric_key_bytes
        ));
        ro.update_bin(symmetric_key_associated_data);
        ro.update_bin(&key.to_compressed());
        let hash = ro.finalize_to_vec(symmetric_key_bytes);

        Ok(hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DerivedPublicKey {
    point: G2Affine,
}

impl From<DerivedPublicKey> for G2Affine {
    fn from(public_key: DerivedPublicKey) -> Self {
        public_key.point
    }
}

#[derive(Copy, Clone, Debug)]
enum DerivedPublicKeyDeserializationError {
    InvalidPublicKey,
}

impl DerivedPublicKey {
    const BYTES: usize = G2AFFINE_BYTES;

    fn from_bytes_vec(bytes: Vec<u8>) -> Result<Self, DerivedPublicKeyDeserializationError> {
        let dpk_bytes: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_e| DerivedPublicKeyDeserializationError::InvalidPublicKey)?;
        let dpk = option_from_ctoption(G2Affine::from_compressed(&dpk_bytes))
            .ok_or(DerivedPublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating that deserializing an encrypted key failed
enum EncryptedKeyDeserializationError {
    /// Error indicating one or more of the points was invalid
    InvalidEncryptedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An encrypted key
struct EncryptedKey {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

impl EncryptedKey {
    /// The length of the serialized encoding of this type
    const BYTES: usize = 2 * G1AFFINE_BYTES + G2AFFINE_BYTES;

    /// Decrypts and verifies an encrypted key
    fn decrypt_and_verify(
        &self,
        tsk: &TransportSecretKey,
        derived_public_key: DerivedPublicKey,
        derivation_id: &[u8],
    ) -> Result<G1Affine, String> {
        let k = G1Affine::from(G1Projective::from(&self.c3) - self.c1 * tsk.secret_key);

        let msg = augmented_hash_to_g1(&derived_public_key.point, derivation_id);
        let dpk_prep = G2Prepared::from(G2Affine::from(derived_public_key));
        use pairing::group::Group;
        let is_valid = gt_multipairing(&[(&k, &G2PREPARED_NEG_G), (&msg, &dpk_prep)]).is_identity();
        if bool::from(is_valid) {
            Ok(k)
        } else {
            Err("invalid encrypted key: verification failed".to_string())
        }
    }

    /// Deserializes an encrypted key from a byte vector
    fn from_bytes_vec(bytes: Vec<u8>) -> Result<EncryptedKey, String> {
        let ek_bytes: [u8; Self::BYTES] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!("key not {} bytes but {}", Self::BYTES, bytes.len())
        })?;
        Self::from_bytes(&ek_bytes).map_err(|e| format!("{:?}", e))
    }

    /// Deserializes an encrypted key from a byte array
    fn from_bytes(val: &[u8; Self::BYTES]) -> Result<Self, EncryptedKeyDeserializationError> {
        let c2_start = G1AFFINE_BYTES;
        let c3_start = G1AFFINE_BYTES + G2AFFINE_BYTES;

        let c1_bytes: &[u8; G1AFFINE_BYTES] = &val[..c2_start]
            .try_into()
            .map_err(|_e| EncryptedKeyDeserializationError::InvalidEncryptedKey)?;
        let c2_bytes: &[u8; G2AFFINE_BYTES] = &val[c2_start..c3_start]
            .try_into()
            .map_err(|_e| EncryptedKeyDeserializationError::InvalidEncryptedKey)?;
        let c3_bytes: &[u8; G1AFFINE_BYTES] = &val[c3_start..]
            .try_into()
            .map_err(|_e| EncryptedKeyDeserializationError::InvalidEncryptedKey)?;

        let c1 = option_from_ctoption(G1Affine::from_compressed(c1_bytes));
        let c2 = option_from_ctoption(G2Affine::from_compressed(c2_bytes));
        let c3 = option_from_ctoption(G1Affine::from_compressed(c3_bytes));

        match (c1, c2, c3) {
            (Some(c1), Some(c2), Some(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedKeyDeserializationError::InvalidEncryptedKey),
        }
    }
}

fn augmented_hash_to_g1(pk: &G2Affine, data: &[u8]) -> G1Affine {
    let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

    let mut signature_input = Vec::with_capacity(G2AFFINE_BYTES + data.len());
    signature_input.extend_from_slice(&pk.to_compressed());
    signature_input.extend_from_slice(data);

    let pt = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        signature_input,
        domain_sep,
    );
    G1Affine::from(pt)
}

fn gt_multipairing(terms: &[(&G1Affine, &G2Prepared)]) -> Gt {
    ic_bls12_381::multi_miller_loop(terms).final_exponentiation()
}

fn option_from_ctoption<T>(ctoption: subtle::CtOption<T>) -> Option<T> {
    if bool::from(ctoption.is_some()) {
        Some(ctoption.unwrap())
    } else {
        None
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    feature = "js",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    feature = "js",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
