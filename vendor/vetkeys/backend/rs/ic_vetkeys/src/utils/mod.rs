//! Verifiably Encrypted Threshold Key Derivation Utilities
//!
//! See the ePrint paper <https://eprint.iacr.org/2023/616> for protocol details

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]

use hex_literal::hex;
use ic_bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar,
};
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::array::TryFromSliceError;
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MASTER_PUBLIC_KEY_BYTES_KEY_1 : [u8; 96] = hex!("a9caf9ae8af0c7c7272f8a122133e2e0c7c0899b75e502bda9e109ca8193ded3ef042ed96db1125e1bdaad77d8cc60d917e122fe2501c45b96274f43705edf0cfd455bc66c3c060faa2fcd15486e76351edf91fecb993797273bbc8beaa47404");

const MASTER_PUBLIC_KEY_BYTES_TEST_KEY_1 : [u8; 96] = hex!("ad86e8ff845912f022a0838a502d763fdea547c9948f8cb20ea7738dd52c1c38dcb4c6ca9ac29f9ac690fc5ad7681cb41922b8dffbd65d94bff141f5fb5b6624eccc03bf850f222052df888cf9b1e47203556d7522271cbb879b2ef4b8c2bfb1");

const POCKETIC_MASTER_PUBLIC_KEY_BYTES_KEY_1 : [u8; 96] = hex!("8c800b5cff00463d26e8167369168827f1e48f4d8d60f71dd6a295580f65275b5f5f8e6a792c876b2c72492136530d0710a27522ee63977a76216c3cef9e70bfcb45b88736fc62142e7e0737848ce06cbb1f45a4a6a349b142ae5cf7853561e0");

const POCKETIC_MASTER_PUBLIC_KEY_BYTES_TEST_KEY_1 : [u8; 96] = hex!("9069b82c7aae418cef27678291e7f2cb1a008a500eceba7199bffca12421b07c158987c6a22618af3d1958738b2835691028801f7663d311799733286c557c8979184bb62cb559a4d582fca7d2e48b860f08ed6641aef66a059ec891889a6218");

const POCKETIC_MASTER_PUBLIC_KEY_BYTES_DFX_TEST_KEY : [u8; 96] = hex!("b181c14cf9d04ba45d782c0067a44b0aaa9fc2acf94f1a875f0dae801af4f80339a7e6bf8b09fcf993824c8df3080b3f1409b688ca08cbd44d2cb28db9899f4aa3b5f06b9174240448e10be2f01f9f80079ea5431ce2d11d1c8d1c775333315f");

fn decode_g2_mpk(bytes: &[u8; 96]) -> G2Affine {
    G2Affine::from_compressed(bytes).expect("Hardcoded master public key not a valid point")
}

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();

    static ref PROD_G2_KEY_1: G2Affine = decode_g2_mpk(&MASTER_PUBLIC_KEY_BYTES_KEY_1);
    static ref PROD_G2_TEST_KEY_1: G2Affine = decode_g2_mpk(&MASTER_PUBLIC_KEY_BYTES_TEST_KEY_1);

    static ref POCKETIC_G2_KEY_1: G2Affine = decode_g2_mpk(&POCKETIC_MASTER_PUBLIC_KEY_BYTES_KEY_1);
    static ref POCKETIC_G2_TEST_KEY_1: G2Affine = decode_g2_mpk(&POCKETIC_MASTER_PUBLIC_KEY_BYTES_TEST_KEY_1);
    static ref POCKETIC_G2_DFX_TEST_KEY: G2Affine = decode_g2_mpk(&POCKETIC_MASTER_PUBLIC_KEY_BYTES_DFX_TEST_KEY);
}

const G1AFFINE_BYTES: usize = 48; // Size of compressed form
const G2AFFINE_BYTES: usize = 96; // Size of compressed form

struct G2PrecomputedTable {
    tbl: Vec<G2Affine>,
}

impl G2PrecomputedTable {
    /// The size of the windows
    ///
    /// This algorithm uses just `SUBGROUP_BITS/WINDOW_BITS` additions in
    /// the online phase, at the cost of storing a table of size
    /// `(SUBGROUP_BITS + WINDOW_BITS - 1)/WINDOW_BITS * (1 << WINDOW_BITS - 1)`
    ///
    /// This constant is configurable and can take values between 1 and 7
    /// (inclusive)
    ///
    /// | WINDOW_BITS | TABLE_SIZE | online additions |
    /// | ----------- | ---------- | ---------------- |
    /// |           1 |       255  |              255 |
    /// |           2 |       384  |              128 |
    /// |           3 |       595  |               85 |
    /// |           4 |       960  |               64 |
    /// |           5 |      1581  |               51 |
    /// |           6 |      2709  |               43 |
    /// |           7 |      4699  |               37 |
    ///
    const WINDOW_BITS: usize = 4;

    /// The bit length of the BLS12-381 subgroup
    const SUBGROUP_BITS: usize = 255;

    // A bitmask of all 1s that is WINDOW_BITS long
    const WINDOW_MASK: u8 = (1 << Self::WINDOW_BITS) - 1;

    // The total number of windows in a scalar
    const WINDOWS: usize = Self::SUBGROUP_BITS.div_ceil(Self::WINDOW_BITS);

    // We must select from 2^WINDOW_BITS elements in each table
    // group. However one element of the table group is always the
    // identity, and so can be omitted, which is the reason for the
    // subtraction by 1 here.
    const WINDOW_ELEMENTS: usize = (1 << Self::WINDOW_BITS) - 1;

    // The total size of the table we will use
    const TABLE_SIZE: usize = Self::WINDOW_ELEMENTS * Self::WINDOWS;

    /// Precompute a table for fast multiplication
    fn new(pt: &G2Affine) -> Self {
        let mut ptbl = vec![ic_bls12_381::G2Projective::identity(); Self::TABLE_SIZE];

        let mut accum = ic_bls12_381::G2Projective::from(pt);

        for i in 0..Self::WINDOWS {
            let tbl_i = &mut ptbl[Self::WINDOW_ELEMENTS * i..Self::WINDOW_ELEMENTS * (i + 1)];

            tbl_i[0] = accum;
            for j in 1..Self::WINDOW_ELEMENTS {
                // Our table indexes are off by one due to the omitted
                // identity element. So here we are checking if we are
                // about to compute a point that is a doubling of a point
                // we have previously computed. If so we can compute it
                // using a (faster) doubling rather than using addition.

                tbl_i[j] = if j % 2 == 1 {
                    tbl_i[j / 2].double()
                } else {
                    tbl_i[j - 1] + tbl_i[0]
                };
            }

            // move on to the next power
            accum = tbl_i[Self::WINDOW_ELEMENTS / 2].double();
        }

        // batch convert the table to affine form, so we can use mixed addition
        // in the online phase.
        let mut tbl = vec![ic_bls12_381::G2Affine::identity(); Self::TABLE_SIZE];
        ic_bls12_381::G2Projective::batch_normalize(&ptbl, &mut tbl);

        Self { tbl }
    }

    /// Perform variable-time scalar multiplication using the precomputed table plus extra addition
    fn mul_vartime(&self, scalar: &Scalar, extra_add: Option<&G2Affine>) -> ic_bls12_381::G2Affine {
        let s = {
            let mut s = scalar.to_bytes();
            s.reverse(); // zkcrypto/bls12_381 uses little-endian
            s
        };

        let mut accum = if let Some(add) = extra_add {
            ic_bls12_381::G2Projective::from(add)
        } else {
            ic_bls12_381::G2Projective::identity()
        };

        for i in 0..Self::WINDOWS {
            let tbl_for_i = &self.tbl[Self::WINDOW_ELEMENTS * i..Self::WINDOW_ELEMENTS * (i + 1)];

            let b = Self::get_window(&s, Self::WINDOW_BITS * i);
            if b > 0 {
                accum += tbl_for_i[b as usize - 1];
            }
        }

        G2Affine::from(accum)
    }

    /// Perform scalar multiplication using the precomputed table
    fn mul(&self, scalar: &Scalar) -> ic_bls12_381::G2Affine {
        let s = {
            let mut s = scalar.to_bytes();
            s.reverse(); // zkcrypto/bls12_381 uses little-endian
            s
        };

        let mut accum = ic_bls12_381::G2Projective::identity();

        for i in 0..Self::WINDOWS {
            let tbl_for_i = &self.tbl[Self::WINDOW_ELEMENTS * i..Self::WINDOW_ELEMENTS * (i + 1)];

            let b = Self::get_window(&s, Self::WINDOW_BITS * i);
            accum += Self::ct_select(tbl_for_i, b as usize);
        }

        G2Affine::from(accum)
    }

    // Extract a WINDOW_BITS sized window out of s, depending on offset.
    #[inline(always)]
    fn get_window(s: &[u8], offset: usize) -> u8 {
        const BITS_IN_BYTE: usize = 8;

        let shift = offset % BITS_IN_BYTE;
        let byte_offset = s.len() - 1 - (offset / BITS_IN_BYTE);

        let w0 = s[byte_offset];

        let single_byte_window = shift <= (BITS_IN_BYTE - Self::WINDOW_BITS) || byte_offset == 0;

        let bits = if single_byte_window {
            // If we can get the window out of single byte, do so
            w0 >> shift
        } else {
            // Otherwise we must join two bytes and extract the result
            let w1 = s[byte_offset - 1];
            (w0 >> shift) | (w1 << (BITS_IN_BYTE - shift))
        };

        bits & Self::WINDOW_MASK
    }

    // Constant time table lookup
    //
    // This version is specifically adapted to this algorithm. If
    // index is zero, then it returns the identity element. Otherwise
    // it returns from[index-1].
    #[inline(always)]
    fn ct_select(from: &[ic_bls12_381::G2Affine], index: usize) -> ic_bls12_381::G2Affine {
        use subtle::{ConditionallySelectable, ConstantTimeEq};

        let mut val = ic_bls12_381::G2Affine::identity();

        let index = index.wrapping_sub(1);
        for (idx, v) in from.iter().enumerate() {
            val.conditional_assign(v, usize::ct_eq(&idx, &index));
        }

        val
    }
}

lazy_static::lazy_static! {
    static ref G2_MUL_TABLE: G2PrecomputedTable = G2PrecomputedTable::new(&G2Affine::generator());
}

/// Derive a symmetric key using HKDF-SHA256
fn hkdf(okm: &mut [u8], input: &[u8], domain_sep: &str) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, input);
    hk.expand(domain_sep.as_bytes(), okm)
        .expect("Unsupported output length for HKDF");
}

/// Derive a symmetric key using HKDF-SHA256
///
/// The `input` parameter should be a sufficiently long random input generated
/// in a secure way. 256 bits (32 bytes) or longer is preferable.
///
/// The `domain_sep` should be a string that uniquely identifies the
/// context for which this key is used.
///
/// The returned vector will be `len` bytes long.
pub fn derive_symmetric_key(input: &[u8], domain_sep: &str, len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    hkdf(&mut okm, input, domain_sep);
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

fn extend_with_length_prefix(vec: &mut Vec<u8>, data: &[u8]) {
    vec.extend_from_slice(&(data.len() as u64).to_be_bytes());
    vec.extend(data);
}

fn hash_to_scalar_two_inputs(
    input1: &[u8],
    input2: &[u8],
    domain_sep: &str,
) -> ic_bls12_381::Scalar {
    let combined_input = {
        let mut c = Vec::with_capacity(2 * 8 + input1.len() + input2.len());
        extend_with_length_prefix(&mut c, input1);
        extend_with_length_prefix(&mut c, input2);
        c
    };

    hash_to_scalar(&combined_input, domain_sep)
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key of the transport key pair
pub struct TransportSecretKey {
    // Note that we Box the value here
    //
    // This is done because in Rust, even if the type does not derive Copy, any
    // object can be moved, and Rust assumes that memcpy is sufficient to move
    // any object. This move effectively creates a copy on the stack that we do
    // not know about and which will not be zeroized.
    //
    // By putting the value into a Box, the object can still be moved, but the move
    // will happen by copying the pointer value of the Box rather than the secret itself.
    //
    // See the zeroize docs (<https://docs.rs/zeroize/1.8.1/zeroize/#stackheap-zeroing-notes>)
    // for further information about this issue.
    secret_key: Box<Scalar>,
}

impl TransportSecretKey {
    /// Creates a transport secret key from a 32-byte seed.
    pub fn from_seed(seed: Vec<u8>) -> Result<TransportSecretKey, String> {
        let seed_32_bytes: [u8; 32] = seed.try_into().map_err(|_e| "seed not 32 bytes")?;
        let rng = &mut ChaCha20Rng::from_seed(seed_32_bytes);
        use pairing::group::ff::Field;
        let secret_key = Box::new(Scalar::random(rng));
        Ok(Self { secret_key })
    }

    /// Returns the serialized public key associated with this secret key
    pub fn public_key(&self) -> Vec<u8> {
        let public_key = G1Affine::generator() * (*self.secret_key);
        use pairing::group::Curve;
        public_key.to_affine().to_compressed().to_vec()
    }

    /// Serialize this transport secret key to a bytestring
    pub fn serialize(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    /// Deserialize this transport secret key from a bytestring
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "TransportSecretKey must be exactly 32 bytes not {}",
                bytes.len()
            ));
        }

        let bytes: [u8; 32] = bytes.try_into().expect("Length already checked");

        if let Some(s) = Scalar::from_bytes(&bytes).into_option() {
            Ok(Self {
                secret_key: Box::new(s),
            })
        } else {
            Err("Invalid TransportSecretKey bytes".to_string())
        }
    }
}

/// Return true iff the argument is a valid encoding of a transport public key
pub fn is_valid_transport_public_key_encoding(bytes: &[u8]) -> bool {
    match bytes.try_into() {
        Ok(bytes) => G1Affine::from_compressed(&bytes).into_option().is_some(),
        Err(_) => false,
    }
}

#[derive(Copy, Clone, Debug)]
/// Error indicating deserializing a derived public key failed
pub enum PublicKeyDeserializationError {
    /// The public key is invalid
    InvalidPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A master VetKD public key
pub struct MasterPublicKey {
    point: G2Affine,
}

impl MasterPublicKey {
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
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserializationError> {
        let dpk_bytes: &[u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_e: TryFromSliceError| PublicKeyDeserializationError::InvalidPublicKey)?;
        let dpk = G2Affine::from_compressed(dpk_bytes)
            .into_option()
            .ok_or(PublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }

    /// Perform first-stage derivation of a canister public key from the master public key
    ///
    /// To create the derived public key in VetKD, a two step derivation is performed;
    ///
    /// - The first step creates a canister public key, sometimes called canister master key.
    ///   This step is implemented by the `derive_canister_key` method.
    ///
    /// - The second step derives a canister sub-key which incorporates the "context" value provided to the
    ///   `vetkd_public_key` management canister interface. This step is implemented by the
    ///   `DerivedPublicKey::derive_sub_key` method.
    pub fn derive_canister_key(&self, canister_id: &[u8]) -> DerivedPublicKey {
        let dst = "ic-vetkd-bls12-381-g2-canister-id";

        let offset = hash_to_scalar_two_inputs(&self.serialize(), canister_id, dst);

        let derived_key = G2_MUL_TABLE.mul_vartime(&offset, Some(&self.point));
        DerivedPublicKey { point: derived_key }
    }

    /// Return the byte encoding of this master public key
    pub fn serialize(&self) -> Vec<u8> {
        self.point.to_compressed().to_vec()
    }

    /// Return the hardcoded master public key used on IC
    ///
    /// This allows performing public key derivation offline
    ///
    /// Returns None if the provided key_id is not known
    pub fn for_mainnet_key(key_id: &VetKDKeyId) -> Option<Self> {
        match (key_id.curve, key_id.name.as_str()) {
            (VetKDCurve::Bls12_381_G2, "key_1") => Some(Self::new(*PROD_G2_KEY_1)),
            (VetKDCurve::Bls12_381_G2, "test_key_1") => Some(Self::new(*PROD_G2_TEST_KEY_1)),
            (_, _) => None,
        }
    }

    /// Return the hardcoded master public key used for testing in PocketIC
    ///
    /// Returns None if the provided key_id is not known
    pub fn for_pocketic_key(key_id: &VetKDKeyId) -> Option<Self> {
        match (key_id.curve, key_id.name.as_str()) {
            (VetKDCurve::Bls12_381_G2, "key_1") => Some(Self::new(*POCKETIC_G2_KEY_1)),
            (VetKDCurve::Bls12_381_G2, "test_key_1") => Some(Self::new(*POCKETIC_G2_TEST_KEY_1)),
            (VetKDCurve::Bls12_381_G2, "dfx_test_key") => {
                Some(Self::new(*POCKETIC_G2_DFX_TEST_KEY))
            }
            (_, _) => None,
        }
    }

    fn new(point: G2Affine) -> Self {
        Self { point }
    }
}

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
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PublicKeyDeserializationError> {
        let dpk_bytes: &[u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_e: TryFromSliceError| PublicKeyDeserializationError::InvalidPublicKey)?;
        let dpk = G2Affine::from_compressed(dpk_bytes)
            .into_option()
            .ok_or(PublicKeyDeserializationError::InvalidPublicKey)?;
        Ok(Self { point: dpk })
    }

    /// Perform second-stage derivation of a public key from a canister public key
    ///
    /// To create the derived public key in VetKD, a two step derivation is performed;
    ///
    /// - The first step creates a canister public key, sometimes called canister master key. This step is implemented
    ///   by the `MasterKey::derive_canister_key` method.
    /// - The second step derives a canister sub-key which incorporates the "context" value provided to the
    ///   `vetkd_public_key` management canister interface. This step is implemented by the `derive_sub_key` method.
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

        let offset = hash_to_scalar_two_inputs(&self.serialize(), context, dst);

        let derived_key = G2_MUL_TABLE.mul_vartime(&offset, Some(&self.point));
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
#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VetKey {
    // See the comment regarding Boxing in the definition of TransportSecretKey
    vetkey: Box<(G1Affine, [u8; 48])>,
}

impl VetKey {
    fn new(pt: G1Affine) -> Self {
        let vetkey = Box::new((pt, pt.to_compressed()));
        Self { vetkey }
    }

    /**
     * Return the VetKey bytes, aka the BLS signature
     *
     * Use the raw bytes only if your design makes use of the fact that VetKeys
     * are BLS signatures (eg for random beacon or threshold BLS signature
     * generation). If you are using VetKD for key distribution, instead use
     * [`derive_symmetric_key`]
     */
    pub fn signature_bytes(&self) -> &[u8; 48] {
        &self.vetkey.1
    }

    /**
     * Serialize the VetKey to a byte string
     *
     * The return value here is the VetKey itself which in most uses is a
     * secret value.
     */
    pub fn serialize(&self) -> &[u8; 48] {
        &self.vetkey.1
    }

    pub(crate) fn point(&self) -> &G1Affine {
        &self.vetkey.0
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
        derive_symmetric_key(self.serialize(), domain_sep, output_len)
    }

    /**
     * Return a DerivedKeyMaterial
     *
     * This class allows further key derivation and encryption but the underlying
     * secret key cannot be extracted.
     */
    pub fn as_derived_key_material(&self) -> DerivedKeyMaterial {
        let key = self.derive_symmetric_key("ic-vetkd-bls12-381-g2-derived-key-material", 32);
        DerivedKeyMaterial {
            key,
            raw_vetkey: self.vetkey.1.to_vec(),
        }
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

        if let Some(pt) = G1Affine::from_compressed(&bytes48).into_option() {
            Ok(Self::new(pt))
        } else {
            Err("Invalid VetKey".to_string())
        }
    }
}

/// Key material derived from a VetKey
///
/// This struct allows deriving further keys from the VetKey without
/// allowing direct access to the VetKey secret key, preventing it
/// from being reused inappropriately.
///
/// As a convenience this struct also offers AES-GCM encryption/decryption
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeyMaterial {
    key: Vec<u8>,
    raw_vetkey: Vec<u8>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
/// An error while encrypting
pub enum EncryptionError {
    /// The provided message was too long to be encrypted
    PlaintextTooLong,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
/// An error while decrypting
pub enum DecryptionError {
    /// The ciphertext was too short to possibly be valid
    MessageTooShort,
    /// The GCM tag did not validate
    InvalidCiphertext,
    /// The expected message header did not appear in the ciphertext
    ///
    /// Either the ciphertext was invalid, or possibly the decrypting side
    /// needs to be upgraded to support a new format
    UnknownHeader,
}

impl DerivedKeyMaterial {
    const GCM_KEY_SIZE: usize = 32;
    const GCM_TAG_SIZE: usize = 16;
    const GCM_NONCE_SIZE: usize = 12;

    const GCM_HEADER_VERSION: u8 = 2;
    const GCM_HEADER_SIZE: usize = 8;
    const GCM_HEADER: [u8; Self::GCM_HEADER_SIZE] = *b"IC GCMv2";

    /// Derive a new key for AES-GCM
    ///
    /// Note that the domain separator provided by the user is prefixed
    /// with `ic-vetkd-bls12-381-g2-aes-gcm-`
    fn derive_aes_gcm_key(&self, domain_sep: &str, version: u8) -> Vec<u8> {
        derive_symmetric_key(
            &self.key,
            &format!("ic-vetkd-bls12-381-g2-aes-gcm-v{version}-{domain_sep}"),
            Self::GCM_KEY_SIZE,
        )
    }

    /// Encrypt a message
    ///
    /// The decryption used here is interoperable with the TypeScript
    /// library ic_vetkeys function `DerivedKeyMaterial.decryptMessage`
    ///
    /// The domain separator should be unique for this usage, for example
    /// by including the identities of the sender and receiver.
    ///
    /// The associated data field is information which will be authenticated
    /// but not included in the ciphertext. This can be useful for binding
    /// additional contextual data (eg a protocol identifier) or information
    /// which should be authenticated but does not need to be encrypted.
    /// If not needed, it can be left empty or an application-specific constant
    /// value can be used,
    ///
    /// The format of the returned message is, in order
    ///  * 8 byte header
    ///  * 12 byte nonce
    ///  * Ciphertext of length equal to the message length
    ///  * 16 byte GCM authentication tag
    ///
    pub fn encrypt_message<R: rand::RngCore + rand::CryptoRng>(
        &self,
        message: &[u8],
        domain_sep: &str,
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{aead::Aead, aead::AeadCore, Aes256Gcm, Key, KeyInit};
        let key = self.derive_aes_gcm_key(domain_sep, Self::GCM_HEADER_VERSION);
        let key = Key::<Aes256Gcm>::from_slice(&key);
        // aes_gcm::Aes256Gcm only supports/uses 12 byte nonces
        let nonce = Aes256Gcm::generate_nonce(rng);
        assert_eq!(nonce.len(), Self::GCM_NONCE_SIZE);
        let gcm = Aes256Gcm::new(key);

        // Unfortunately aes_gcm does not allow a vector of AAD inputs
        // so we have to allocate a copy. Typically associated data is short
        let prefixed_aad = {
            let mut r = Vec::with_capacity(Self::GCM_HEADER.len() + associated_data.len());
            r.extend_from_slice(&Self::GCM_HEADER); // assumed fixed length
            r.extend_from_slice(associated_data);
            r
        };

        let msg = aes_gcm::aead::Payload {
            msg: message,
            aad: &prefixed_aad,
        };

        // The function returns an opaque `Error` with no details, but upon
        // examination, the only way it can fail is if the plaintext is larger
        // than GCM's maximum input length of 2^36 bytes.
        let ctext = gcm
            .encrypt(&nonce, msg)
            .map_err(|_| EncryptionError::PlaintextTooLong)?;

        let mut res = vec![];
        res.extend_from_slice(&Self::GCM_HEADER);
        res.extend_from_slice(nonce.as_slice());
        res.extend_from_slice(ctext.as_slice());
        Ok(res)
    }

    /// Decrypt a message
    ///
    /// The decryption used here is interoperable with the TypeScript
    /// library ic_vetkeys function `DerivedKeyMaterial.encryptMessage`
    pub fn decrypt_message(
        &self,
        ctext: &[u8],
        domain_sep: &str,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};

        // Minimum possible length is 8 byte header + 12 bytes nonce + 16 bytes GCM tag
        if ctext.len() < Self::GCM_HEADER_SIZE + Self::GCM_NONCE_SIZE + Self::GCM_TAG_SIZE {
            return Err(DecryptionError::MessageTooShort);
        }

        // If multiple versions are ever supported in the future, and we
        // must retain backward compatability, then this would need to be
        // extended to check for multiple different headers and process
        // the ciphertext accordingly.
        if ctext[0..Self::GCM_HEADER_SIZE] != Self::GCM_HEADER {
            if associated_data.is_empty() {
                // Try decrypting using the old headerless format which did not
                // support associated data

                let key = derive_symmetric_key(&self.raw_vetkey, domain_sep, Self::GCM_KEY_SIZE);

                let nonce = aes_gcm::Nonce::from_slice(&ctext[0..Self::GCM_NONCE_SIZE]);
                let gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

                let ptext = gcm
                    .decrypt(nonce, &ctext[Self::GCM_NONCE_SIZE..])
                    .map_err(|_| DecryptionError::InvalidCiphertext)?;

                return Ok(ptext.as_slice().to_vec());
            } else {
                return Err(DecryptionError::UnknownHeader);
            }
        }

        let key = self.derive_aes_gcm_key(domain_sep, Self::GCM_HEADER_VERSION);
        let key = Key::<Aes256Gcm>::from_slice(&key);

        let nonce = aes_gcm::Nonce::from_slice(
            &ctext[Self::GCM_HEADER_SIZE..Self::GCM_HEADER_SIZE + Self::GCM_NONCE_SIZE],
        );
        let gcm = Aes256Gcm::new(key);

        let prefixed_aad = {
            let mut r = Vec::with_capacity(Self::GCM_HEADER.len() + associated_data.len());
            r.extend_from_slice(&ctext[0..Self::GCM_HEADER_SIZE]);
            r.extend_from_slice(associated_data);
            r
        };

        let msg = aes_gcm::aead::Payload {
            msg: &ctext[Self::GCM_HEADER_SIZE + Self::GCM_NONCE_SIZE..],
            aad: &prefixed_aad,
        };

        let ptext = gcm
            .decrypt(nonce, msg)
            .map_err(|_| DecryptionError::InvalidCiphertext)?;

        Ok(ptext.as_slice().to_vec())
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

    const C2_OFFSET: usize = G1AFFINE_BYTES;
    const C3_OFFSET: usize = G1AFFINE_BYTES + G2AFFINE_BYTES;

    /// Decrypts and verifies the VetKey
    pub fn decrypt_and_verify(
        &self,
        tsk: &TransportSecretKey,
        derived_public_key: &DerivedPublicKey,
        input: &[u8],
    ) -> Result<VetKey, String> {
        use pairing::group::Group;

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
        let k = G1Affine::from(G1Projective::from(&self.c3) - self.c1 * (*tsk.secret_key));

        // Check that the VetKey is a valid BLS signature
        if verify_bls_signature_pt(derived_public_key, input, &k) {
            Ok(VetKey::new(k))
        } else {
            Err("invalid encrypted key: verification failed".to_string())
        }
    }

    /// Serialize the encrypted VetKey
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.c1.to_compressed());
        result.extend_from_slice(&self.c2.to_compressed());
        result.extend_from_slice(&self.c3.to_compressed());

        result
    }

    /// Deserializes an encrypted key from a byte vector
    pub fn deserialize(bytes: &[u8]) -> Result<EncryptedVetKey, String> {
        let ek_bytes: &[u8; Self::BYTES] = bytes.try_into().map_err(|_e: TryFromSliceError| {
            format!("key not {} bytes but {}", Self::BYTES, bytes.len())
        })?;
        Self::deserialize_array(ek_bytes).map_err(|e| format!("{e:?}"))
    }

    /// Deserializes an encrypted key from a byte array
    pub fn deserialize_array(
        val: &[u8; Self::BYTES],
    ) -> Result<Self, EncryptedVetKeyDeserializationError> {
        let c1_bytes: &[u8; G1AFFINE_BYTES] = &val[..Self::C2_OFFSET]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c2_bytes: &[u8; G2AFFINE_BYTES] = &val[Self::C2_OFFSET..Self::C3_OFFSET]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;
        let c3_bytes: &[u8; G1AFFINE_BYTES] = &val[Self::C3_OFFSET..]
            .try_into()
            .map_err(|_e| EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey)?;

        let c1 = G1Affine::from_compressed(c1_bytes).into_option();
        let c2 = G2Affine::from_compressed(c2_bytes).into_option();
        let c3 = G1Affine::from_compressed(c3_bytes).into_option();

        match (c1, c2, c3) {
            (Some(c1), Some(c2), Some(c3)) => Ok(Self { c1, c2, c3 }),
            (_, _, _) => Err(EncryptedVetKeyDeserializationError::InvalidEncryptedVetKey),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An identity, used for identity based encryption (IBE)
///
/// As far as the IBE scheme goes this is simply an opauqe bytestring
/// We provide a type to make code using the IBE a bit easier to understand
pub struct IbeIdentity {
    val: Vec<u8>,
}

impl IbeIdentity {
    /// Create an identity from a byte string
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            val: bytes.to_vec(),
        }
    }

    /// Create an identity from a UTF8 string
    pub fn from_string(str: &str) -> Self {
        Self::from_bytes(str.as_bytes())
    }

    /// Create an identity from a Principal
    pub fn from_principal(principal: &candid::Principal) -> Self {
        Self::from_bytes(principal.as_slice())
    }

    /// Return the bytestring of this identity
    pub fn value(&self) -> &[u8] {
        &self.val
    }
}

/*
* Amount of randomness generated during the IBE encryption process
*/
const IBE_SEED_BYTES: usize = 32;

/// A random seed, used for identity based encryption
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IbeSeed {
    // See the comment regarding Boxing in the definition of TransportSecretKey
    val: Box<[u8; IBE_SEED_BYTES]>,
}

impl IbeSeed {
    /// Create a random seed for IBE encryption
    pub fn random<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        use rand::Rng;
        Self {
            val: Box::new(rng.gen::<[u8; IBE_SEED_BYTES]>()),
        }
    }

    /// Create a seed for IBE encryption from a byte string
    ///
    /// This input should be randomly chosen by a secure random number generator.
    /// If the seed is not securely generated the IBE scheme will be insecure.
    ///
    /// At least 128 bits (16 bytes) must be provided.
    ///
    /// If the input is exactly 256 bits it is used directly. Otherwise the input
    /// is hashed with HKDF to produce a 256 bit seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 16 {
            return Err("Insufficient input material for IbeSeed derivation".to_string());
        }

        let mut val = Box::new([0u8; IBE_SEED_BYTES]);
        if bytes.len() == IBE_SEED_BYTES {
            val.copy_from_slice(bytes)
        } else {
            let hkdf =
                derive_symmetric_key(bytes, "ic-vetkd-bls12-381-ibe-hash-seed", IBE_SEED_BYTES);
            val.copy_from_slice(&hkdf);
        }

        Ok(Self { val })
    }

    fn value(&self) -> &[u8; IBE_SEED_BYTES] {
        &self.val
    }
}

/*
 * IBE ciphertexts are prefixed with a header to identity the protocol and provide
 * an extension point if needed in the future eg for changing to a different cipher.
 *
 * The header consists of "IC IBE" (ASCII) plus two bytes 0x00 and 0x01 which
 * here are just fixed and effectively arbitrary values, but could be used to
 * indicate for example a version in the future should we need to support multiple
 * variants of the IBE scheme.
*/
const IBE_HEADER: [u8; 8] = [b'I', b'C', b' ', b'I', b'B', b'E', 0x00, 0x01];

const IBE_HEADER_BYTES: usize = IBE_HEADER.len();

const IBE_OVERHEAD: usize = IBE_HEADER_BYTES + IBE_SEED_BYTES + G2AFFINE_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
/// An IBE (identity based encryption) ciphertext
pub struct IbeCiphertext {
    header: Vec<u8>,
    c1: G2Affine,
    c2: [u8; IBE_SEED_BYTES],
    c3: Vec<u8>,
}

enum IbeDomainSep {
    HashToMask,
    MaskSeed,
    MaskMsg(usize),
}

impl IbeDomainSep {
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
            Self::MaskMsg(len) => format!("ic-vetkd-bls12-381-ibe-mask-msg-{len:020}"),
        }
    }
}

impl IbeCiphertext {
    /// Serialize this IBE ciphertext
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(IBE_OVERHEAD + self.c3.len());

        output.extend_from_slice(&self.header);
        output.extend_from_slice(&self.c1.to_compressed());
        output.extend_from_slice(&self.c2);
        output.extend_from_slice(&self.c3);

        output
    }

    /// Deserialize an IBE ciphertext
    ///
    /// Returns Err if the encoding is not valid
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < IBE_OVERHEAD {
            return Err("IbeCiphertext too short to be valid".to_string());
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
            return Err("IbeCiphertext has unknown header".to_string());
        }

        Ok(Self { header, c1, c2, c3 })
    }

    fn hash_to_mask(header: &[u8], seed: &[u8; IBE_SEED_BYTES], msg: &[u8]) -> Scalar {
        /*
        It would have been better to instead use the SHA-256 of the message instead of the
        message directly, since that would avoid having to allocate an extra buffer of
        length proportional to the message. If in the future any change is made to the
        IBE scheme, consider also changing this.
        */

        let domain_sep = IbeDomainSep::HashToMask;
        let mut ro_input = Vec::with_capacity(seed.len() + msg.len());
        ro_input.extend_from_slice(header);
        ro_input.extend_from_slice(seed);
        ro_input.extend_from_slice(msg);

        hash_to_scalar(&ro_input, &domain_sep.to_string())
    }

    fn mask_seed(seed: &[u8; IBE_SEED_BYTES], t: &Gt) -> [u8; IBE_SEED_BYTES] {
        let domain_sep = IbeDomainSep::MaskSeed;
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

        let domain_sep = IbeDomainSep::MaskMsg(msg.len());

        let mut shake_seed = derive_symmetric_key(seed, &domain_sep.to_string(), IBE_SEED_BYTES);

        let mut mask = derive_ibe_ctext_mask(&shake_seed, msg.len());
        shake_seed.zeroize();

        for i in 0..msg.len() {
            mask[i] ^= msg[i];
        }

        mask
    }

    /// Encrypt a message using IBE
    ///
    /// There is no fixed upper bound on the size of the message that can be encrypted using
    /// this scheme. However, internally during the encryption process several heap allocations
    /// are performed which are approximately the same length as the message itself, so
    /// encrypting or decrypting very large messages may result in memory allocation errors.
    ///
    /// If you anticipate using IBE to encrypt very large messages, consider using IBE just to
    /// encrypt a symmetric key, and then using a standard cipher such as AES-GCM to encrypt the
    /// data.
    ///
    /// The seed should be generated with a cryptographically secure random
    /// number generator. Do not reuse the seed for encrypting another message
    /// or any other purpose.
    ///
    /// To decrypt this message requires using the VetKey associated with the
    /// provided derived public key (ie the same master key and context string),
    /// and with an `input` equal to the provided `identity` parameter.
    pub fn encrypt(
        dpk: &DerivedPublicKey,
        identity: &IbeIdentity,
        msg: &[u8],
        seed: &IbeSeed,
    ) -> Self {
        let header = IBE_HEADER.to_vec();

        let t = Self::hash_to_mask(&header, seed.value(), msg);

        let pt = augmented_hash_to_g1(&dpk.point, identity.value());

        let tsig = ic_bls12_381::pairing(&pt, &dpk.point) * t;

        let c1 = G2_MUL_TABLE.mul(&t);
        let c2 = Self::mask_seed(seed.value(), &tsig);
        let c3 = Self::mask_msg(msg, seed.value());

        Self { header, c1, c2, c3 }
    }

    /// Decrypt an IBE ciphertext
    ///
    /// There is no fixed upper bound on the size of the message that can be encrypted using
    /// this scheme. However, internally during the encryption process several heap allocations
    /// are performed which are approximately the same length as the message itself, so
    /// encrypting or decrypting very large messages may result in memory allocation errors.
    ///
    /// The VetKey provided must be the VetKey produced by a request to the IC
    /// for a given `identity` (aka `input`) and `context` both matching the
    /// values used during encryption.
    ///
    /// Returns the plaintext, or Err if decryption failed
    pub fn decrypt(&self, vetkey: &VetKey) -> Result<Vec<u8>, String> {
        let tsig = ic_bls12_381::pairing(vetkey.point(), &self.c1);

        let seed = Self::mask_seed(&self.c2, &tsig);

        let msg = Self::mask_msg(&self.c3, &seed);

        let t = Self::hash_to_mask(&self.header, &seed, &msg);

        let g_t = G2_MUL_TABLE.mul(&t);

        if self.c1 == g_t {
            Ok(msg)
        } else {
            Err("decryption failed".to_string())
        }
    }

    /// Helper function for determining the size of an IBE ciphertext in bytes.
    pub fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + IBE_OVERHEAD
    }

    /// Helper function for determining the size of an IBE plaintext in bytes.
    ///
    /// Returns None if the indicated length would be a ciphertext
    /// that is not possibly valid (due to missing required elements)
    pub fn plaintext_size(ciphertext_size: usize) -> Option<usize> {
        if ciphertext_size >= IBE_OVERHEAD {
            Some(ciphertext_size - IBE_OVERHEAD)
        } else {
            None
        }
    }
}

/// An error occured while decoding or checking a VrfOutput
#[derive(Copy, Clone, Debug)]
pub enum InvalidVrfOutput {
    /// The serialization has an incorrect/impossible length
    UnexpectedLength,
    /// The serialization contains invalid data
    InvalidData,
    /// The VRF proof was invalid
    InvalidProof,
}

/// VRF (Verifiable Random Function) Output
///
/// VetKD can be used to construct a VRF, which is a public key version of a
/// keyed hash. Like a standard keyed hash, it takes an input string and produces
/// a output string which is indistinguishable from random. The difference
/// between a VRF and a normal keyed hash is that a VRF can only be computed
/// by someone with access to the VRF secret key, while the VRF output can be verified
/// by any party with access to the public key.
///
/// For some general background on VRFs consult [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html)
///
/// Create a new [`VrfOutput`] using [`management_canister::compute_vrf`]
#[derive(Eq, PartialEq)]
pub struct VrfOutput {
    proof: VetKey,
    dpk: DerivedPublicKey,
    output: [u8; Self::VRF_BYTES],
    input: Vec<u8>,
}

impl VrfOutput {
    /// The size of the hashed VRF
    pub const VRF_BYTES: usize = 32;

    fn compute_vrf_hash(
        vetkey: &VetKey,
        dpk: &DerivedPublicKey,
        input: &[u8],
    ) -> [u8; Self::VRF_BYTES] {
        /*
        We instantiate the VRF by hashing with HKDF the prefix-free concatenation of

        - The vetKey (ie the BLS signature)
        - The compressed serialization of the derived public key
        - The input that was used to construct the signature

        Strictly speaking only the vetKey itself is required but binding all available
        context is generally considered a good practice.
         */
        let mut ro_input =
            Vec::with_capacity(G1AFFINE_BYTES + G2AFFINE_BYTES + input.len() + 3 * 8);
        extend_with_length_prefix(&mut ro_input, vetkey.serialize());
        extend_with_length_prefix(&mut ro_input, &dpk.serialize());
        extend_with_length_prefix(&mut ro_input, input);

        let mut output = [0u8; Self::VRF_BYTES];
        hkdf(&mut output, &ro_input, "ic-vetkd-bls12-381-g2-vrf");
        output
    }

    /// Create a new VrfOutput from a VetKey
    ///
    /// The provided input and derived public key must be the same values
    /// which were used to create the VetKey.
    pub(crate) fn create(
        proof: VetKey,
        input: Vec<u8>,
        dpk: DerivedPublicKey,
    ) -> Result<Self, InvalidVrfOutput> {
        if !verify_bls_signature_pt(&dpk, &input, proof.point()) {
            return Err(InvalidVrfOutput::InvalidProof);
        }

        let output = Self::compute_vrf_hash(&proof, &dpk, &input);
        Ok(Self {
            proof,
            dpk,
            output,
            input,
        })
    }

    /// Serialize the VrfOutput
    pub fn serialize(&self) -> Vec<u8> {
        // Note that we do not include the VRF output here - instead we rederive it
        //
        // The first two outputs are fixed length so the encoding here is unambigious
        let mut output = Vec::with_capacity(G1AFFINE_BYTES + G2AFFINE_BYTES + self.input.len());
        output.extend_from_slice(self.proof.serialize());
        output.extend_from_slice(&self.dpk.serialize());
        output.extend_from_slice(&self.input);
        output
    }

    /// Deserialize and verify a VrfOutput
    ///
    /// Note this verifies the VrfOutput with respect to the derived public key
    /// and VRF input which are included in the struct. It is the responsibility
    /// of the application to examine the return value of [`VrfOutput::public_key`]
    /// and [`VrfOutput::input`] and ensure these values make sense in the context
    /// where this VRF is being used.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, InvalidVrfOutput> {
        if bytes.len() < G1AFFINE_BYTES + G2AFFINE_BYTES {
            return Err(InvalidVrfOutput::UnexpectedLength);
        }

        let proof = VetKey::deserialize(&bytes[0..G1AFFINE_BYTES])
            .map_err(|_| InvalidVrfOutput::InvalidData)?;

        let dpk =
            DerivedPublicKey::deserialize(&bytes[G1AFFINE_BYTES..G1AFFINE_BYTES + G2AFFINE_BYTES])
                .map_err(|_| InvalidVrfOutput::InvalidData)?;

        let input = bytes[G1AFFINE_BYTES + G2AFFINE_BYTES..].to_vec();

        if !verify_bls_signature_pt(&dpk, &input, proof.point()) {
            return Err(InvalidVrfOutput::InvalidProof);
        }

        let output = Self::compute_vrf_hash(&proof, &dpk, &input);

        Ok(Self {
            proof,
            dpk,
            output,
            input,
        })
    }

    /// Return the input that was used to create this VRF output
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Return the key under which this VRF output was derived
    pub fn public_key(&self) -> &DerivedPublicKey {
        &self.dpk
    }

    /// Return the VRF output
    ///
    /// This is a random-looking value which was provably generated by some party with
    /// access to the VRF secret key.
    ///
    /// If your application needs more than [`Self::VRF_BYTES`] of randomness, the easiest
    /// approach would be to derive a longer value using a KDF, for example using
    /// [`derive_symmetric_key`].
    ///
    /// Another option would be to seed a PRNG ([`ChaCha20Rng::from_seed`]) and then
    /// invoke the RNG to generate outputs as required.
    pub fn output(&self) -> &[u8; Self::VRF_BYTES] {
        &self.output
    }
}

/// Verify an augmented BLS signature
///
/// Augmented BLS signatures include the public key as part of the input, and
/// "under the hood" a vetKey is an augmented BLS signature. This function allows
/// verifying, for example, that a vetKey used as a VRF output is in fact a valid
/// signature.
///
/// See <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#name-message-augmentation>
/// for more details on BLS message augmentation.
///
/// Returns true if and only if the provided signature is valid with respect to
/// the provided public key and input
pub fn verify_bls_signature(dpk: &DerivedPublicKey, input: &[u8], signature: &[u8]) -> bool {
    let signature: G1Affine = match <[u8; 48]>::try_from(signature) {
        Ok(bytes) => match G1Affine::from_compressed(&bytes).into_option() {
            Some(pt) => pt,
            None => return false,
        },
        Err(_) => return false,
    };

    verify_bls_signature_pt(dpk, input, &signature)
}

/// Verify an augmented BLS signature
///
/// Returns true if and only if the provided signature is valid with respect to
/// the provided public key and input
fn verify_bls_signature_pt(dpk: &DerivedPublicKey, input: &[u8], signature: &G1Affine) -> bool {
    if dpk.point.is_identity().into() {
        return false;
    }

    let msg = augmented_hash_to_g1(&dpk.point, input);
    let dpk_prep = G2Prepared::from(dpk.point);

    // Check that `e(sig, G2) == e(msg, dpk)` using a multipairing

    use pairing::group::Group;
    let is_valid =
        gt_multipairing(&[(signature, &G2PREPARED_NEG_G), (&msg, &dpk_prep)]).is_identity();
    bool::from(is_valid)
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

/// This module contains functions for calling the ICP management canister's `vetkd_derive_key` endpoint from within a canister.
pub mod management_canister {
    use ic_cdk::{call::CallResult, management_canister::VetKDPublicKeyArgs};

    use crate::types::CanisterId;

    use super::*;

    /// Derives an unencrypted vetKey.
    ///
    /// Because the vetKey returned by this function is unencrypted, it is public to the canister and ICP nodes. Using this function is equivalent to decrypting the vetKey directly by the canister itself.
    /// Therefore, this function shall only be used if the vetKey is used as public information by the canister, e.g., when it is used as BLS signature, for timelock encryption, or for producing verifiable randomness.
    ///
    /// **Warning**: A vetKey produced by this function is *insecure* to use as a private key by a user.
    ///
    /// A public vetKey is derived by calling the ICP management canister's `vetkd_derive_key` endpoint with a **fixed public transport key** that produces an **unencrypted vetKey**.
    /// Therefore, this function is more efficient than actually retrieving the encrypted vetKey and calling [`EncryptedVetKey::decrypt_and_verify`].
    ///
    /// # Arguments
    /// * `input` - corresponds to `input` in `vetkd_derive_key`
    /// * `context` - corresponds to `context` in `vetkd_derive_key`
    /// * `key_id` - corresponds to `key_id` in `vetkd_derive_key`
    ///
    /// # Returns
    /// * `Ok(VetKey)` - The derived vetKey on success
    /// * `Err(DeriveUnencryptedVetkeyError)` - If derivation fails due to unsupported curve or canister call error
    async fn derive_unencrypted_vetkey(
        input: Vec<u8>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<Vec<u8>, VetKDDeriveKeyCallError> {
        if key_id.curve != VetKDCurve::Bls12_381_G2 {
            return Err(VetKDDeriveKeyCallError::UnsupportedCurve);
        }

        let request = VetKDDeriveKeyArgs {
            input,
            context,
            key_id,
            // Encryption with the G1 identity element produces unencrypted vetKeys
            transport_public_key: G1Affine::identity().to_compressed().to_vec(),
        };

        let reply = ic_cdk::management_canister::vetkd_derive_key(&request)
            .await
            .map_err(VetKDDeriveKeyCallError::CallFailed)?;

        if reply.encrypted_key.len() != EncryptedVetKey::BYTES {
            return Err(VetKDDeriveKeyCallError::InvalidReply);
        }

        Ok(reply.encrypted_key
            [EncryptedVetKey::C3_OFFSET..EncryptedVetKey::C3_OFFSET + G1AFFINE_BYTES]
            .to_vec())
    }

    #[derive(Debug)]
    /// Errors that can occur when deriving an unencrypted vetKey
    pub enum VetKDDeriveKeyCallError {
        /// The curve is currently not supported
        UnsupportedCurve,
        /// The canister call failed
        CallFailed(ic_cdk::management_canister::SignCallError),
        /// Invalid reply from the management canister
        InvalidReply,
    }

    /// Creates a threshold BLS12-381 signature for the given `message`.
    ///
    /// The `context` parameter defines signer's identity.
    /// The returned signature can be verified with the public key retrieved via [`bls_public_key`] with the same `context` and `key_id`.
    /// Having the public key, message, and signature, we now can verify that the signature is valid.
    /// For that, we can call [`verify_bls_signature`] from this crate in Rust or `verifyBlsSignature` from the `@dfinity/vetkeys` package in TypeScript/JavaScript.
    ///
    /// This function will use `ic0_cost_vetkd_derive_key` to calculate the precise number of cycles to attach.
    ///
    /// # Arguments
    /// * `message` - the message to be signed
    /// * `context` - the identity of the signer
    /// * `key_id` - the key ID of the threshold key deployed on the Internet Computer
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The signature on success
    /// * `Err(VetKDDeriveKeyCallError)` - If derivation fails due to unsupported curve or canister call error
    pub async fn sign_with_bls(
        message: Vec<u8>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<Vec<u8>, VetKDDeriveKeyCallError> {
        derive_unencrypted_vetkey(message, context, key_id).await
    }

    /// Returns the public key of a threshold BLS12-381 key.
    /// Signatures produced with [`sign_with_bls`] are verifiable under a public key returned by this method iff the public key is for the correct `canister_id` and the same `context` and `key_id` was used.
    ///
    /// # Arguments
    /// * `canister_id` - the canister ID that the public key is computed for. If `canister_id` is `None`, it will default to the canister id of the caller.
    /// * `context` - the identity of the signer
    /// * `key_id` - the key ID of the threshold key deployed on the Internet Computer
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The public key on success
    /// * `Err(ic_cdk::call::Error)` - If the canister call fails
    pub async fn bls_public_key(
        canister_id: Option<CanisterId>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> CallResult<Vec<u8>> {
        ic_cdk::management_canister::vetkd_public_key(&VetKDPublicKeyArgs {
            canister_id,
            context,
            key_id,
        })
        .await
        .map(|r| r.public_key)
    }

    /// Creates a VRF output for the provided input
    ///
    /// This function will use `ic0_cost_vetkd_derive_key` to calculate the precise number of cycles to attach.
    ///
    /// # Arguments
    /// * `context` - a string identifying the context in which this VRF output
    ///   will be used, for example the application
    /// * `input` - a value that should be unique to a particular situation
    /// * `key_id` - the key ID of the threshold key deployed on the Internet Computer
    ///
    /// # Examples
    ///
    /// Examples of possible `(input,context)` pairs in various VRF settings
    ///
    /// * Lottery: `context` "My Verifiably Random Lottery v1", `input` "Drawing Jan 1, 2028",
    ///   "Drawing Jan 2, 2028", ...
    /// * Leader Election: "FooProtocol Random Leader Election", `input` "Leader Election #1",
    ///   "Leader Election #2", ...
    ///
    /// # Returns
    /// * `Ok(VrfOutput)` - The VRF output structure
    /// * `Err(VetKDDeriveKeyCallError)` - If derivation fails due to unsupported curve or canister call error
    pub async fn compute_vrf(
        input: Vec<u8>,
        context: Vec<u8>,
        key_id: VetKDKeyId,
    ) -> Result<VrfOutput, VetKDDeriveKeyCallError> {
        let vetkey_bytes =
            derive_unencrypted_vetkey(input.clone(), context.clone(), key_id.clone())
                .await
                .map_err(|_| VetKDDeriveKeyCallError::InvalidReply)?;

        let vetkey = VetKey::deserialize(&vetkey_bytes)
            .map_err(|_| VetKDDeriveKeyCallError::InvalidReply)?;
        let canister_id = ic_cdk::api::canister_self();

        let dpk = match MasterPublicKey::for_mainnet_key(&key_id) {
            Some(mk) => mk
                .derive_canister_key(canister_id.as_slice())
                .derive_sub_key(&context),
            None => {
                // If the key id is not known we must instead perform an online query
                // for the relevant key
                let dpk_bytes =
                    ic_cdk::management_canister::vetkd_public_key(&VetKDPublicKeyArgs {
                        canister_id: Some(canister_id),
                        context,
                        key_id,
                    })
                    .await
                    .map_err(|_| VetKDDeriveKeyCallError::InvalidReply)?;

                DerivedPublicKey::deserialize(&dpk_bytes.public_key)
                    .map_err(|_| VetKDDeriveKeyCallError::InvalidReply)?
            }
        };

        VrfOutput::create(vetkey, input, dpk).map_err(|_| VetKDDeriveKeyCallError::InvalidReply)
    }
}
