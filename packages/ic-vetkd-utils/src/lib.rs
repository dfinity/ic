//! Verifiably Encrypted Threshold Key Derivation Utilities
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]
#![warn(future_incompatible)]
#![allow(clippy::mem_forget)]

use ic_bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::array::TryFromSliceError;
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "js")]
use wasm_bindgen::prelude::*;

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

const G1AFFINE_BYTES: usize = 48; // Size of compressed form
const G2AFFINE_BYTES: usize = 96; // Size of compressed form

/// Derive a symmetric key using HKDF-SHA256
pub fn derive_symmetric_key(input: &[u8], domain_sep: &str, len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, input);
    let mut okm = vec![0u8; len];
    hk.expand(domain_sep.as_bytes(), &mut okm)
        .expect("Unsupported output length for HKDF");
    okm
}

fn hash_to_scalar(input: &[u8], domain_sep: &str) -> ic_bls12_381::Scalar {
    use ic_bls12_381::hash_to_curve::HashToField;

    let mut s = [ic_bls12_381::Scalar::zero()];
    <ic_bls12_381::Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
        input,
        domain_sep.as_bytes(),
        &mut s,
    );
    s[0]
}

fn prefix_with_len(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

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

    /// Serialize this transport secret key to a bytestring
    pub fn serialize(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    /// Serialize this transport secret key to a bytestring
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "TransportSecretKey must be exactly 32 bytes not {}",
                bytes.len()
            ));
        }

        let bytes: [u8; 32] = bytes.try_into().expect("Length already checked");

        if let Some(s) = Scalar::from_bytes(&bytes).into_option() {
            Ok(Self { secret_key: s })
        } else {
            Err("Invalid TransportSecretKey bytes".to_string())
        }
    }
}

/// Return true iff the argument is a valid encoding of a transport public key
pub fn is_valid_transport_public_key_encoding(bytes: &[u8]) -> bool {
    match bytes.try_into() {
        Ok(bytes) => option_from_ctoption(G1Affine::from_compressed(&bytes)).is_some(),
        Err(_) => false,
    }
}

#[cfg_attr(feature = "js", wasm_bindgen)]
#[derive(Clone, Debug, Eq, PartialEq)]
/// A derived public key
pub struct DerivedPublicKey {
    point: G2Affine,
}

impl From<DerivedPublicKey> for G2Affine {
    fn from(public_key: DerivedPublicKey) -> Self {
        public_key.point
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating deserializing a derived public key failed
pub enum DerivedPublicKeyDeserializationError {
    /// The public key is invalid
    InvalidPublicKey,
}

impl DerivedPublicKey {
    const BYTES: usize = G2AFFINE_BYTES;

    /// Deserializes a (derived) public key.
    ///
    /// Only compressed points are supported.
    ///
    /// Normally the bytes provided here will have been returned by the
    /// Internet Computer's `vetkd_public_key`` management canister interface.
    ///
    /// Returns an error if the key is invalid (e.g., it has invalid length,
    /// i.e., not 96 bytes, it is not in compressed format, is is not a point
    /// on the curve, it is not torsion-free).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DerivedPublicKeyDeserializationError> {
        let dpk_bytes: &[u8; Self::BYTES] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            DerivedPublicKeyDeserializationError::InvalidPublicKey
        })?;
        let dpk = option_from_ctoption(G2Affine::from_compressed(dpk_bytes))
            .ok_or(DerivedPublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }

    /// Perform second-stage derivation of a public key
    ///
    /// To create the derived public key in VetKD, a two step derivation is performed. The first step
    /// creates a key that is specific to the canister that is making VetKD requests to the
    /// management canister, sometimes called canister master key. The second step incorporates the
    /// "derivation context" value provided to the `vetkd_public_key` management canister interface.
    ///
    /// If `vetkd_public_key` is invoked with an empty derivation context, it simply returns the
    /// canister master key. Then the second derivation step can be done offline, using this
    /// function. This is useful if you wish to derive multiple keys without having to interact with
    /// the IC each time.
    pub fn derive_sub_key(&self, context: &[u8]) -> Self {
        if context.is_empty() {
            return self.clone();
        }

        let dst = "ic-vetkd-bls12-381-g2-context";

        let offset = hash_to_scalar(&prefix_with_len(context), dst);

        let derived_key = G2Affine::from(self.point + G2Affine::generator() * offset);
        Self { point: derived_key }
    }

    /// Return the byte encoding of this derived public key
    pub fn serialize(&self) -> Vec<u8> {
        self.point.to_compressed().to_vec()
    }
}

/// A verifiably encrypted threshold key derived by the VetKD protocol
///
/// A VetKey is a valid BLS signature created for an input specified
/// by the user
///
#[cfg_attr(feature = "js", wasm_bindgen)]
#[derive(Clone)]
pub struct VetKey {
    pt: G1Affine,
    pt_bytes: [u8; 48],
}

impl VetKey {
    fn new(pt: G1Affine) -> Self {
        Self {
            pt,
            pt_bytes: pt.to_compressed(),
        }
    }

    /**
     * Return the VetKey bytes, aka the BLS signature
     *
     * Use the raw bytes only if your design makes use of the fact that VetKeys
     * are BLS signatures (eg for random beacon or threshold BLS signature
     * generation). If you are using VetKD for key distribution, instead use
     * derive_symmetric_key
     */
    pub fn signature_bytes(&self) -> &[u8; 48] {
        &self.pt_bytes
    }

    /**
     * Derive a symmetric key of the requested length from the VetKey
     *
     * The `domain_sep` parameter should be a string unique to your application and
     * also your usage of the resulting key. For example say your application
     * "my-app" is deriving two keys, one for usage "foo" and the other for
     * "bar". You might use as domain separators "my-app-foo" and "my-app-bar".
     */
    pub fn derive_symmetric_key(&self, domain_sep: &str, output_len: usize) -> Vec<u8> {
        derive_symmetric_key(&self.pt_bytes, domain_sep, output_len)
    }

    /**
     * Deserialize a VetKey from the byte encoding
     *
     * Typically this would have been created using [`VetKey::signature_bytes`]
     */
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        let bytes48: [u8; 48] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            format!("Vetkey is unexpected length {}", bytes.len())
        })?;

        if let Some(pt) = option_from_ctoption(G1Affine::from_compressed(&bytes48)) {
            Ok(Self {
                pt,
                pt_bytes: bytes48,
            })
        } else {
            Err("Invalid VetKey".to_string())
        }
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating that deserializing an encrypted key failed
pub enum EncryptedVetKeyDeserializationError {
    /// Error indicating one or more of the points was invalid
    InvalidEncryptedVetKey,
}

/// An encrypted VetKey
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedVetKey {
    c1: G1Affine,
    c2: G2Affine,
    c3: G1Affine,
}

impl EncryptedVetKey {
    /// The length of the serialized encoding of this type
    const BYTES: usize = 2 * G1AFFINE_BYTES + G2AFFINE_BYTES;

    /// Decrypts and verifies the VetKey
    pub fn decrypt_and_verify(
        &self,
        tsk: &TransportSecretKey,
        derived_public_key: &DerivedPublicKey,
        input: &[u8],
    ) -> Result<VetKey, String> {
        // Check that c1 and c2 have the same discrete logarithm

        let c2_prep = G2Prepared::from(self.c2);

        let c1_c2 = gt_multipairing(&[
            (&self.c1, &G2PREPARED_NEG_G),
            (&G1Affine::generator(), &c2_prep),
        ]);

        if !bool::from(c1_c2.is_identity()) {
            return Err("invalid encrypted key: c1 inconsistent with c2".to_string());
        }

        // Recover the purported VetKey
        let k = G1Affine::from(G1Projective::from(&self.c3) - self.c1 * tsk.secret_key);

        // Check that the VetKey is a valid BLS signature
        let msg = augmented_hash_to_g1(&derived_public_key.point, input);
        let dpk_prep = G2Prepared::from(derived_public_key.point);

        use pairing::group::Group;
        let is_valid = gt_multipairing(&[(&k, &G2PREPARED_NEG_G), (&msg, &dpk_prep)]).is_identity();
        if bool::from(is_valid) {
            Ok(VetKey::new(k))
        } else {
            Err("invalid encrypted key: verification failed".to_string())
        }
    }

    /// Deserializes an encrypted key from a byte vector
    pub fn deserialize(bytes: &[u8]) -> Result<EncryptedVetKey, String> {
        let ek_bytes: &[u8; Self::BYTES] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            format!("key not {} bytes but {}", Self::BYTES, bytes.len())
        })?;
        Self::deserialize_array(ek_bytes).map_err(|e| format!("{:?}", e))
    }

    /// Deserializes an encrypted key from a byte array
    pub fn deserialize_array(
        val: &[u8; Self::BYTES],
    ) -> Result<Self, EncryptedVetKeyDeserializationError> {
        let c2_start = G1AFFINE_BYTES;
        let c3_start = G1AFFINE_BYTES + G2AFFINE_BYTES;

        let c1_bytes: &[u8; G1AFFINE_BYTES] = &val[..c2_start]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c2_bytes: &[u8; G2AFFINE_BYTES] = &val[c2_start..c3_start]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c3_bytes: &[u8; G1AFFINE_BYTES] = &val[c3_start..]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;

        let c1 = option_from_ctoption(G1Affine::from_compressed(c1_bytes));
        let c2 = option_from_ctoption(G2Affine::from_compressed(c2_bytes));
        let c3 = option_from_ctoption(G1Affine::from_compressed(c3_bytes));

        match (c1, c2, c3) {
            (Some(c1), Some(c2), Some(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey),
        }
    }
}

const IBE_SEED_BYTES: usize = 32;

const IBE_HEADER_BYTES: usize = 8;
const IBE_HEADER: [u8; IBE_HEADER_BYTES] = [b'I', b'C', b' ', b'I', b'B', b'E', 0x00, 0x01];

#[derive(Clone, Debug, Eq, PartialEq)]
/// An IBE (identity based encryption) ciphertext
#[cfg_attr(feature = "js", wasm_bindgen)]
pub struct IBECiphertext {
    header: Vec<u8>,
    c1: G2Affine,
    c2: [u8; IBE_SEED_BYTES],
    c3: Vec<u8>,
}

enum IBEDomainSep {
    HashToMask,
    MaskSeed,
    MaskMsg(usize),
}

impl IBEDomainSep {
    #[allow(clippy::inherent_to_string)]
    fn to_string(&self) -> String {
        match self {
            Self::HashToMask => "ic-vetkd-bls12-381-ibe-hash-to-mask".to_owned(),
            Self::MaskSeed => "ic-vetkd-bls12-381-ibe-mask-seed".to_owned(),
            // Zero prefix the length up to 20 digits, which is sufficient to be fixed
            // length for any 64-bit length. This ensures all of the MaskMsg domain
            // separators are of equal length. With how we use the domain separators, this
            // padding isn't required - we only need uniquness - but having variable
            // length domain separators is generally not considered a good practice and is
            // easily avoidable here.
            Self::MaskMsg(len) => format!("ic-vetkd-bls12-381-ibe-mask-msg-{:020}", len),
        }
    }
}

#[cfg_attr(feature = "js", wasm_bindgen)]
impl IBECiphertext {
    /// Serialize this IBE ciphertext
    pub fn serialize(&self) -> Vec<u8> {
        let mut output =
            Vec::with_capacity(self.header.len() + G2AFFINE_BYTES + IBE_SEED_BYTES + self.c3.len());

        output.extend_from_slice(&self.header);
        output.extend_from_slice(&self.c1.to_compressed());
        output.extend_from_slice(&self.c2);
        output.extend_from_slice(&self.c3);

        output
    }

    /// Deserialize an IBE ciphertext
    ///
    /// Returns Err if the encoding is not valid
    pub fn deserialize(bytes: &[u8]) -> Result<IBECiphertext, String> {
        if bytes.len() < IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES {
            return Err("IBECiphertext too short to be valid".to_string());
        }

        let header = bytes[0..IBE_HEADER_BYTES].to_vec();
        let c1 = deserialize_g2(&bytes[IBE_HEADER_BYTES..(IBE_HEADER_BYTES + G2AFFINE_BYTES)])?;

        let mut c2 = [0u8; IBE_SEED_BYTES];
        c2.copy_from_slice(
            &bytes[IBE_HEADER_BYTES + G2AFFINE_BYTES
                ..(IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES)],
        );

        let c3 = bytes[IBE_HEADER_BYTES + G2AFFINE_BYTES + IBE_SEED_BYTES..].to_vec();

        if header != IBE_HEADER {
            return Err("IBECiphertext has unknown header".to_string());
        }

        Ok(Self { header, c1, c2, c3 })
    }

    fn hash_to_mask(header: &[u8], seed: &[u8; IBE_SEED_BYTES], msg: &[u8]) -> Scalar {
        let domain_sep = IBEDomainSep::HashToMask;
        let mut ro_input = Vec::with_capacity(seed.len() + msg.len());
        ro_input.extend_from_slice(header);
        ro_input.extend_from_slice(seed);
        ro_input.extend_from_slice(msg);

        hash_to_scalar(&ro_input, &domain_sep.to_string())
    }

    fn mask_seed(seed: &[u8; IBE_SEED_BYTES], t: &Gt) -> [u8; IBE_SEED_BYTES] {
        let domain_sep = IBEDomainSep::MaskSeed;
        let mask = derive_symmetric_key(&t.to_bytes(), &domain_sep.to_string(), IBE_SEED_BYTES);

        let mut masked_seed = [0u8; IBE_SEED_BYTES];
        for i in 0..IBE_SEED_BYTES {
            masked_seed[i] = mask[i] ^ seed[i];
        }
        masked_seed
    }

    fn mask_msg(msg: &[u8], seed: &[u8; IBE_SEED_BYTES]) -> Vec<u8> {
        fn derive_ibe_ctext_mask(seed: &[u8], msg_len: usize) -> Vec<u8> {
            use sha3::{
                digest::{ExtendableOutputReset, Update, XofReader},
                Shake256,
            };

            let mut shake = Shake256::default();
            shake.update(seed);

            let mut xof = shake.finalize_xof_reset();
            let mut mask = vec![0u8; msg_len];
            xof.read(&mut mask);
            mask
        }

        let domain_sep = IBEDomainSep::MaskMsg(msg.len());

        let shake_seed = derive_symmetric_key(seed, &domain_sep.to_string(), 32);

        let mut mask = derive_ibe_ctext_mask(&shake_seed, msg.len());

        for i in 0..msg.len() {
            mask[i] ^= msg[i];
        }

        mask
    }

    /// Encrypt a message using IBE
    ///
    /// The message can be of arbitrary length
    ///
    /// The seed must be exactly 256 bits (32 bytes) long and should be
    /// generated with a cryptographically secure random number generator. Do
    /// not reuse the seed for encrypting another message or any other purpose.
    ///
    /// To decrypt this message requires using the VetKey associated with the
    /// provided derived public key (ie the same master key and context string),
    /// and with an `input` equal to the provided `identity` parameter.
    pub fn encrypt(
        dpk: &DerivedPublicKey,
        identity: &[u8],
        msg: &[u8],
        seed: &[u8],
    ) -> Result<IBECiphertext, String> {
        let seed: &[u8; IBE_SEED_BYTES] = seed
            .try_into()
            .map_err(|_e| format!("Provided seed must be {} bytes long ", IBE_SEED_BYTES))?;

        let header = IBE_HEADER.to_vec();

        let t = Self::hash_to_mask(&header, seed, msg);

        let pt = augmented_hash_to_g1(&dpk.point, identity);

        let tsig = ic_bls12_381::pairing(&pt, &dpk.point) * t;

        let c1 = G2Affine::from(G2Affine::generator() * t);
        let c2 = Self::mask_seed(seed, &tsig);
        let c3 = Self::mask_msg(msg, seed);

        Ok(Self { header, c1, c2, c3 })
    }

    /// Decrypt an IBE ciphertext
    ///
    /// The VetKey provided must be the VetKey produced by a request to the IC
    /// for a given `identity` (aka `input`) and `context` both matching the
    /// values used during encryption.
    ///
    /// Returns the plaintext, or Err if decryption failed
    pub fn decrypt(&self, vetkey: &VetKey) -> Result<Vec<u8>, String> {
        let t = ic_bls12_381::pairing(&vetkey.pt, &self.c1);

        let seed = Self::mask_seed(&self.c2, &t);

        let msg = Self::mask_msg(&self.c3, &seed);

        let t = Self::hash_to_mask(&self.header, &seed, &msg);

        let g_t = G2Affine::from(G2Affine::generator() * t);

        if self.c1 == g_t {
            Ok(msg)
        } else {
            Err("decryption failed".to_string())
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

fn deserialize_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    let bytes: &[u8; G2AFFINE_BYTES] = bytes
        .try_into()
        .map_err(|_| "Invalid length for G2".to_string())?;

    let pt = G2Affine::from_compressed(bytes);
    if bool::from(pt.is_some()) {
        Ok(pt.unwrap())
    } else {
        Err("Invalid G2 elliptic curve point".to_string())
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
