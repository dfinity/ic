#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]
#![forbid(unsafe_code)]

//! A crate for creating and verifying Ed25519 signatures

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Digest, Sha512};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hex_literal::hex;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

pub use ic_principal::Principal as CanisterId;

/// An error if a private key cannot be decoded
#[derive(Clone, Debug, Error)]
pub enum PrivateKeyDecodingError {
    /// The outer PEM encoding is invalid
    #[error("The outer PEM encoding is invalid: {0}")]
    InvalidPemEncoding(String),
    /// The PEM label was not the expected value
    #[error("The PEM label was not the expected value: {0}")]
    UnexpectedPemLabel(String),
    /// The private key seems invalid in some way; the string contains details
    #[error("The private key seems invalid in some way: {0}")]
    InvalidKeyEncoding(String),
}

/// An Ed25519 secret key
#[derive(Clone, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PrivateKey {
    sk: SigningKey,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key().serialize_raw())
            .finish_non_exhaustive() // avoids printing secret information
    }
}

/*
The ring crate, in versions prior to 0.17 has an unfortunate bug that
it both requires that Ed25519 private keys be conveyed using the PKCS8 V2
encoding AND it has a bug such that it does not accept the actual (correct)
PKCS8 V2 encoding.
*/

const BUGGY_RING_V2_DER_PREFIX: [u8; 16] = [
    48, 83, // A sequence of 83 bytes follows.
    2, 1, // An integer denoting version
    1, // 0 if secret key only, 1 if public key is also present
    48, 5, // An element of 5 bytes follows
    6, 3, 43, 101, 112, // The OID
    4, 34, // An octet string of 34 bytes follows.
    4, 32, // An octet string of 32 bytes follows.
];

const BUGGY_RING_V2_DER_PK_PREFIX: [u8; 5] = [
    161,
    35, // An explicitly tagged with 35 bytes. (This is the bug; this should be an implicit tag)
    3, 33, // A bitstring of 33 bytes follows.
    0,  // The bitstring (32 bytes) is divisible by 8
];

const BUGGY_RING_V2_LEN: usize = BUGGY_RING_V2_DER_PREFIX.len()
    + PrivateKey::BYTES
    + BUGGY_RING_V2_DER_PK_PREFIX.len()
    + PublicKey::BYTES;

/// Specifies a private key encoding format
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PrivateKeyFormat {
    /// PKCS #8 v1: most common version, implemented by for example OpenSSL
    Pkcs8v1,
    /// PKCS #8 v2: newer format which includes the public key.
    ///
    /// # Warning
    ///
    /// Many libraries including OpenSSL cannot parse PKCS8 v2 formatting
    Pkcs8v2,
    /// PKCS #8 v2 emulating a bug that makes it compatible with
    /// versions of the ring cryptography library prior to 0.17
    ///
    /// # Warning
    ///
    /// The only libraries that can parse this format are ring,
    /// or libraries (such as this crate) that go out of their way
    /// to be compatible with ring's buggy format.
    Pkcs8v2WithRingBug,
}

impl PrivateKey {
    /// The length in bytes of the raw private key
    pub const BYTES: usize = 32;

    /// Create a new random secret Ed25519 key
    #[cfg(feature = "rand")]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_using_rng(&mut rng)
    }

    /// Create a new random secret Ed25519 key using specified RNG
    #[cfg(feature = "rand")]
    pub fn generate_using_rng<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        let sk = SigningKey::generate(rng);
        Self { sk }
    }

    /// Generate a key using an input seed
    ///
    /// # Warning
    ///
    /// For security the seed should be at least 256 bits and
    /// randomly generated
    pub fn generate_from_seed(seed: &[u8]) -> Self {
        let digest: [u8; 32] = {
            let mut sha2 = Sha512::new();
            sha2.update(seed);
            let digest: [u8; 64] = sha2.finalize().into();
            let mut truncated = [0u8; 32];
            truncated.copy_from_slice(&digest[..32]);
            truncated
        };

        Self {
            sk: SigningKey::from_bytes(&digest),
        }
    }

    /// Sign a message and return a signature
    ///
    /// This is the non-prehashed variant of Ed25519
    pub fn sign_message(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).into()
    }

    /// Return the public key associated with this secret key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.sk.verifying_key())
    }

    /// Serialize the Ed25519 secret key
    ///
    /// This returns the 32-byte encoding of the seed value
    /// which is used to derive the secret scalar
    pub fn serialize_raw(&self) -> [u8; Self::BYTES] {
        self.sk.to_bytes()
    }

    /// Deserialize an Ed25519 private key from raw format
    ///
    /// This is just the plain 32 byte random seed from which the
    /// internal key material is derived
    ///
    /// This corresponds with the format used by PrivateKey::serialize_raw
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PrivateKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes).map_err(|_| {
            PrivateKeyDecodingError::InvalidKeyEncoding(format!(
                "Expected key of exactly {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;

        Ok(Self::deserialize_raw_32(&bytes))
    }

    /// Deserialize an Ed25519 private key from raw format
    ///
    /// This is just the plain 32 byte random seed from which the
    /// internal key material is derived
    ///
    /// This corresponds with the format used by PrivateKey::serialize_raw
    pub fn deserialize_raw_32(bytes: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(bytes);
        Self { sk }
    }

    /// Serialize the Ed25519 secret key in PKCS8 format
    ///
    /// The details of the formatting are specified using the argument
    pub fn serialize_pkcs8(&self, format: PrivateKeyFormat) -> Vec<u8> {
        let sk_bytes = self.serialize_raw();
        let pk_bytes = self.public_key().serialize_raw();

        fn to_pkcs8<T: EncodePrivateKey>(v: &T) -> Vec<u8> {
            let pkcs8 = v.to_pkcs8_der();

            // Key encoding with the pkcs8 crate can fail, largely to allow for
            // fallible encoding on the part of the algorithm specific code.  But
            // logically speaking, as long as the key is valid (which we've already
            // checked) then there is no reason for encoding to ever fail outside of
            // memory allocation errors. None of the error types that to_pkcs8_der
            // can return have any relevance to encoding. And the dalek encoding
            // functions themselves do not have any error cases.

            pkcs8.expect("PKCS8 encoding failed").to_bytes().to_vec()
        }

        match format {
            PrivateKeyFormat::Pkcs8v1 => {
                let kp = ed25519_dalek::pkcs8::KeypairBytes {
                    secret_key: sk_bytes,
                    public_key: None,
                };

                to_pkcs8(&kp)
            }
            PrivateKeyFormat::Pkcs8v2 => {
                let kp = ed25519_dalek::pkcs8::KeypairBytes {
                    secret_key: sk_bytes,
                    public_key: Some(ed25519_dalek::pkcs8::PublicKeyBytes(pk_bytes)),
                };

                to_pkcs8(&kp)
            }
            PrivateKeyFormat::Pkcs8v2WithRingBug => {
                let mut ringv2 = Vec::with_capacity(BUGGY_RING_V2_LEN);

                ringv2.extend_from_slice(&BUGGY_RING_V2_DER_PREFIX);
                ringv2.extend_from_slice(&sk_bytes);
                ringv2.extend_from_slice(&BUGGY_RING_V2_DER_PK_PREFIX);
                ringv2.extend_from_slice(&pk_bytes);

                ringv2
            }
        }
    }

    /// Deserialize an Ed25519 private key from PKCS8 format
    ///
    /// Both v1 and v2 PKCS8 encodings are accepted. The only difference is
    /// that v2 includes the public key as well. This also accepts the buggy
    /// format used by ring 0.16.
    ///
    /// This corresponds with the format used by PrivateKey::serialize_pkcs8
    pub fn deserialize_pkcs8(bytes: &[u8]) -> Result<Self, PrivateKeyDecodingError> {
        if bytes.len() == BUGGY_RING_V2_LEN && bytes.starts_with(&BUGGY_RING_V2_DER_PREFIX) {
            let sk_offset = BUGGY_RING_V2_DER_PREFIX.len();
            Self::deserialize_raw(&bytes[sk_offset..sk_offset + Self::BYTES])
        } else {
            let sk = SigningKey::from_pkcs8_der(bytes)
                .map_err(|e| PrivateKeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
            Ok(Self { sk })
        }
    }

    /// Serialize the Ed25519 secret key in PKCS8 v2 format with PEM encoding
    ///
    /// The details of the formatting are specified using the argument
    pub fn serialize_pkcs8_pem(&self, format: PrivateKeyFormat) -> String {
        let pkcs8 = self.serialize_pkcs8(format);

        pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8))
    }

    /// Deserialize an Ed25519 private key from PKCS8 PEM format
    ///
    /// Both v1 and v2 PKCS8 encodings are accepted
    ///
    /// This corresponds with the format used by PrivateKey::serialize_pkcs8_pem
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, PrivateKeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| PrivateKeyDecodingError::InvalidPemEncoding(format!("{e:?}")))?;
        if der.tag() != "PRIVATE KEY" {
            return Err(PrivateKeyDecodingError::UnexpectedPemLabel(
                der.tag().to_string(),
            ));
        }

        Self::deserialize_pkcs8(der.contents())
    }

    /// Derive a private key from this private key using a derivation path
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold Ed25519
    ///
    /// Note that this function returns a DerivedPrivateKey rather than Self,
    /// and that DerivedPrivateKey can sign messages but cannot be serialized.
    /// This is due to the definition of Ed25519 private keys, which is
    /// incompatible with additive derivation.
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (DerivedPrivateKey, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a private key from this private key using a derivation path
    /// and chain code
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold Ed25519
    ///
    /// Note that this function returns a DerivedPrivateKey rather than Self,
    /// and that DerivedPrivateKey can sign messages but cannot be serialized.
    /// This is due to the definition of Ed25519 private keys, which is
    /// incompatible with additive derivation.
    ///
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (DerivedPrivateKey, [u8; 32]) {
        let sk_scalar = self.sk.to_scalar();
        let pt = EdwardsPoint::mul_base(&sk_scalar);

        let (pt, sum, chain_code) = derivation_path.derive_offset(pt, chain_code);

        let derived_scalar = sk_scalar + sum;

        let derived_hash_prefix = {
            // Hash the new derived key and chain code with SHA-512 to derive
            // the new hash prefix
            let mut sha2 = Sha512::new();
            sha2.update(derived_scalar.to_bytes());
            sha2.update(chain_code);
            let hash: [u8; 64] = sha2.finalize().into();
            let mut truncated = [0u8; 32];
            truncated.copy_from_slice(&hash[..32]);
            truncated
        };

        let dpk = DerivedPrivateKey::new(derived_scalar, derived_hash_prefix, pt);
        (dpk, chain_code)
    }
}

/// A private key derived via the IC's derivation mechanism
///
/// Due to oddities in Ed25519's secret key format, a derived private
/// key cannot be treated the same way as an ordinary private key.
/// In particular, it cannot be serialized.
pub struct DerivedPrivateKey {
    // ExpandedSecretKey has a Drop impl which will zeroize the key
    esk: ed25519_dalek::hazmat::ExpandedSecretKey,
    vk: ed25519_dalek::VerifyingKey,
}

impl DerivedPrivateKey {
    fn new(scalar: Scalar, hash_prefix: [u8; 32], pk: EdwardsPoint) -> Self {
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
            scalar,
            hash_prefix,
        };

        let vk = ed25519_dalek::VerifyingKey::from(pk);

        Self { esk, vk }
    }

    /// Sign a message and return a signature
    ///
    /// This is the non-prehashed variant of Ed25519
    pub fn sign_message(&self, msg: &[u8]) -> [u8; 64] {
        ed25519_dalek::hazmat::raw_sign::<Sha512>(&self.esk, msg, &self.vk).to_bytes()
    }

    /// Return the public key associated with this private key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.vk)
    }

    /// Derive a private key from this private key using a derivation path
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold Ed25519
    ///
    /// Note that this function returns a DerivedPrivateKey rather than Self,
    /// and that DerivedPrivateKey can sign messages but cannot be serialized.
    /// This is due to the definition of Ed25519 private keys, which is
    /// incompatible with additive derivation.
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (DerivedPrivateKey, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a private key from this private key using a derivation path
    /// and chain code
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold Ed25519
    ///
    /// Note that this function returns a DerivedPrivateKey rather than Self,
    /// and that DerivedPrivateKey can sign messages but cannot be serialized.
    /// This is due to the definition of Ed25519 private keys, which is
    /// incompatible with additive derivation.
    ///
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (DerivedPrivateKey, [u8; 32]) {
        let sk_scalar = self.esk.scalar;
        let pt = EdwardsPoint::mul_base(&sk_scalar);

        let (pt, sum, chain_code) = derivation_path.derive_offset(pt, chain_code);

        let derived_scalar = sk_scalar + sum;

        let derived_hash_prefix = {
            // Hash the new derived key and chain code with SHA-512 to derive
            // the new hash prefix
            let mut sha2 = Sha512::new();
            sha2.update(derived_scalar.to_bytes());
            sha2.update(chain_code);
            let hash: [u8; 64] = sha2.finalize().into();
            let mut truncated = [0u8; 32];
            truncated.copy_from_slice(&hash[..32]);
            truncated
        };

        let dpk = DerivedPrivateKey::new(derived_scalar, derived_hash_prefix, pt);
        (dpk, chain_code)
    }
}

/// An invalid key was encountered
#[derive(Clone, Debug, Error)]
pub enum PublicKeyDecodingError {
    /// The outer PEM encoding is invalid
    #[error("The outer PEM encoding is invalid: {0}")]
    InvalidPemEncoding(String),
    /// The PEM label was not the expected value
    #[error("The PEM label was not the expected value: {0}")]
    UnexpectedPemLabel(String),
    /// The encoding of the public key is invalid, the string contains details
    #[error("The encoding of the public key is invalid: {0}")]
    InvalidKeyEncoding(String),
}

/// An Ed25519 signature (not a public API)
struct Signature {
    r: EdwardsPoint,
    r_bytes: [u8; 32], // potentially non-canonical
    s: Scalar,
}

impl Signature {
    fn from_slice(signature: &[u8]) -> Result<Self, SignatureError> {
        if signature.len() != 64 {
            return Err(SignatureError::InvalidLength);
        }

        let (r, r_bytes) = {
            let mut r_bytes = [0u8; 32];
            r_bytes.copy_from_slice(&signature[..32]);
            let r = CompressedEdwardsY(r_bytes)
                .decompress()
                .ok_or(SignatureError::InvalidSignature)?;

            (r, r_bytes)
        };

        let s = {
            let mut s_bytes = [0u8; 32];
            s_bytes.copy_from_slice(&signature[32..]);
            Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
                .ok_or(SignatureError::InvalidSignature)?
        };

        Ok(Self { r, r_bytes, s })
    }

    pub fn r_bytes(&self) -> &[u8; 32] {
        &self.r_bytes
    }

    pub fn r(&self) -> &EdwardsPoint {
        &self.r
    }

    pub fn s(&self) -> &Scalar {
        &self.s
    }
}

/// An identifier for the mainnet production key
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MasterPublicKeyId {
    /// The production master key
    Key1,
    /// The test master key
    TestKey1,
}

/// An identifier for the hardcoded keys used in PocketIC
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PocketIcMasterPublicKeyId {
    /// The PocketIC hardcoded key "key_1"
    Key1,
    /// The PocketIC hardcoded key "test_key_1"
    TestKey1,
    /// The PocketIC hardcoded key "dfx_test_key"
    DfxTestKey,
}

/// An Ed25519 public key
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PublicKey {
    pk: VerifyingKey,
}

/// An error that occurs when verifying signatures or batches of signatures
#[derive(Copy, Clone, Debug, Error)]
pub enum SignatureError {
    /// The signature had an invalid length, and cannot possibly be valid
    #[error("The signature had an invalid length, and cannot possibly be valid")]
    InvalidLength,
    /// The batch was invalid (e.g., due to length mismatch between number of
    /// messages and number of signatures)
    #[error(
        "The batch was invalid (e.g., due to length mismatch between number of 
        messages and number of signatures)"
    )]
    InvalidBatch,
    /// A signature was invalid
    #[error("A signature was invalid")]
    InvalidSignature,
}

impl PublicKey {
    /// The number of bytes in the raw public key
    pub const BYTES: usize = 32;

    /// Internal constructor
    ///
    /// # Warning
    ///
    /// This does not verify that the key is within the prime order
    /// subgroup, or that the public key is canonical. To check these
    /// properties, use is_torsion_free and is_canonical
    fn new(pk: VerifyingKey) -> Self {
        Self { pk }
    }

    /// Return true if and only if the key is contained within the prime
    /// order subgroup
    pub fn is_torsion_free(&self) -> bool {
        // We don't need to call is_weak here since that is subsumed by the
        // test that the point is torsion free - is_weak just checks if the
        // point is within the size-8 cofactor group.
        self.pk.to_edwards().is_torsion_free()
    }

    /// Return true if and only if the public key uses a canonical encoding
    pub fn is_canonical(&self) -> bool {
        self.pk.to_bytes() == self.pk.to_edwards().compress().0
    }

    /// Convert a raw Ed25519 public key (32 bytes) to the DER encoding
    ///
    /// # Warning
    ///
    /// This performs no validity check on the public key aside from verifying
    /// that it is exactly 32 bytes long. If you pass an invalid key (ie a
    /// encoding of a point not in the prime order subgroup), then the DER
    /// encoding of that invalid key will be returned.
    pub fn convert_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, PublicKeyDecodingError> {
        // We continue to check the length, since otherwise the DER
        // encoding itself would be invalid and unparsable.
        if raw.len() != Self::BYTES {
            return Err(PublicKeyDecodingError::InvalidKeyEncoding(format!(
                "Expected key of exactly {} bytes, got {}",
                Self::BYTES,
                raw.len()
            )));
        };

        const DER_PREFIX: [u8; 12] = [
            48, 42, // A sequence of 42 bytes follows
            48, 5, // An sequence of 5 bytes follows
            6, 3, 43, 101, 112, // The OID (1.3.101.112)
            3, 33, // A bitstring of 33 bytes follows
            0,  // The bitstring has no unused bits
        ];

        let mut der_enc = Vec::with_capacity(DER_PREFIX.len() + Self::BYTES);
        der_enc.extend_from_slice(&DER_PREFIX);
        der_enc.extend_from_slice(raw);
        Ok(der_enc)
    }

    /// Serialize this public key in raw format
    ///
    /// This is just the 32 byte encoding of the public point
    pub fn serialize_raw(&self) -> [u8; Self::BYTES] {
        *self.pk.as_bytes()
    }

    /// Deserialize a public key in raw format
    ///
    /// This is just the 32 byte encoding of the public point,
    /// cooresponding to Self::serialize_raw
    ///
    /// # Warning
    ///
    /// This does not verify that the key is within the prime order
    /// subgroup, or that the public key is canonical. To check these
    /// properties, use is_torsion_free and is_canonical
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes).map_err(|_| {
            PublicKeyDecodingError::InvalidKeyEncoding(format!(
                "Expected key of exactly {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;
        let pk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| PublicKeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;

        Ok(Self::new(pk))
    }

    /// Serialize this public key as a DER encoded structure
    ///
    /// See RFC 8410 for details on the format
    pub fn serialize_rfc8410_der(&self) -> Vec<u8> {
        let der = self.pk.to_public_key_der();

        // See comment in serialize_pkcs8 regarding this expect
        der.expect("Encoding public key as DER failed")
            .as_bytes()
            .to_vec()
    }

    /// Serialize this public key as a PEM encoded structure
    ///
    /// See RFC 8410 for details on the format
    ///
    /// This returns a Vec<u8> instead of a String for accidental/historical reasons
    pub fn serialize_rfc8410_pem(&self) -> Vec<u8> {
        let der = self.serialize_rfc8410_der();
        pem::encode(&pem::Pem::new("PUBLIC KEY", der)).into()
    }

    /// Deserialize the DER encoded public key
    ///
    /// See RFC 8410 for details on the format. This cooresponds to
    /// Self::serialize_rfc8410_der
    ///
    /// # Warning
    ///
    /// This does not verify that the key is within the prime order
    /// subgroup, or that the public key is canonical. To check these
    /// properties, use is_torsion_free and is_canonical
    pub fn deserialize_rfc8410_der(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let pk = VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| PublicKeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
        Ok(Self::new(pk))
    }

    /// Deserialize the PEM encoded public key
    ///
    /// See RFC 8410 for details on the format. This cooresponds to
    /// Self::serialize_rfc8410_pem
    ///
    /// # Warning
    ///
    /// This does not verify that the key is within the prime order
    /// subgroup, or that the public key is canonical. To check these
    /// properties, use is_torsion_free and is_canonical
    pub fn deserialize_rfc8410_pem(pem: &str) -> Result<Self, PublicKeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| PublicKeyDecodingError::InvalidPemEncoding(format!("{e:?}")))?;
        if der.tag() != "PUBLIC KEY" {
            return Err(PublicKeyDecodingError::UnexpectedPemLabel(
                der.tag().to_string(),
            ));
        }

        Self::deserialize_rfc8410_der(der.contents())
    }

    /// Helper function for computing H(R || A || M)
    fn compute_challenge(sig: &Signature, pk: &Self, msg: &[u8]) -> Scalar {
        let mut sha512 = Sha512::new();
        sha512.update(sig.r_bytes());
        // VerifyingKey::as_bytes returns the original encoding which may be non-canonical;
        // this is exactly what we need under ZIP215
        sha512.update(pk.pk.as_bytes());
        sha512.update(msg);
        Scalar::from_hash(sha512)
    }

    /// Verify a Ed25519 signature
    ///
    /// Returns Ok if the signature is valid, or Err otherwise
    ///
    /// This verification follows ZIP215 validation rules
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let signature = Signature::from_slice(signature)?;

        let k = Self::compute_challenge(&signature, self, msg);
        let minus_a = -self.pk.to_edwards();
        let recomputed_r =
            EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &minus_a, signature.s());

        use curve25519_dalek::traits::IsIdentity;

        if (recomputed_r - signature.r())
            .mul_by_cofactor()
            .is_identity()
        {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }

    /// Verify a batch of signatures
    ///
    /// Returns Ok if the signatures are all valid, or Err otherwise
    ///
    /// Note that this does not indicate which of the signature(s) are invalid;
    /// if batch verification fails you must then test serially to find the
    /// valid signatures (if any).
    ///
    /// This verification follows ZIP215 validation rules
    #[cfg(feature = "rand")]
    pub fn batch_verify<R: rand::CryptoRng + rand::Rng>(
        messages: &[&[u8]],
        signatures: &[&[u8]],
        keys: &[Self],
        rng: &mut R,
    ) -> Result<(), SignatureError> {
        if messages.len() != signatures.len() || signatures.len() != keys.len() {
            return Err(SignatureError::InvalidBatch);
        }

        use curve25519_dalek::{
            constants::ED25519_BASEPOINT_POINT, traits::IsIdentity, traits::VartimeMultiscalarMul,
        };
        use std::iter::once;

        let signatures = signatures
            .iter()
            .map(|s| Signature::from_slice(s))
            .collect::<Result<Vec<_>, _>>()?;

        let n = signatures.len();

        let hrams = (0..n)
            .map(|i| Self::compute_challenge(&signatures[i], &keys[i], messages[i]))
            .collect::<Vec<_>>();

        // Select a random Scalar for each signature.
        let zs: Vec<Scalar> = (0..n).map(|_| Scalar::from(rng.r#gen::<u128>())).collect();

        let b_coefficient: Scalar = signatures
            .iter()
            .zip(zs.iter())
            .map(|(sig, z)| sig.s() * z)
            .sum();

        let zhrams = hrams.iter().zip(zs.iter()).map(|(hram, z)| hram * z);

        let r = signatures.iter().map(|sig| *sig.r());
        let pk = keys.iter().map(|pk| pk.pk.to_edwards());

        let id = EdwardsPoint::vartime_multiscalar_mul(
            once(-b_coefficient).chain(zs.iter().cloned()).chain(zhrams),
            once(ED25519_BASEPOINT_POINT).chain(r).chain(pk),
        )
        .mul_by_cofactor();

        if id.is_identity() {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }

    /// Return the public master keys used in the production mainnet
    pub fn mainnet_key(key_id: MasterPublicKeyId) -> Self {
        match key_id {
            MasterPublicKeyId::Key1 => Self::deserialize_raw(&hex!(
                "476374d9df3a8af28d3164dc2422cff894482eadd1295290b6d9ad92b2eeaa5c"
            ))
            .expect("Hardcoded master key was rejected"),
            MasterPublicKeyId::TestKey1 => Self::deserialize_raw(&hex!(
                "6c0824beb37621bcca6eecc237ed1bc4e64c9c59dcb85344aa7f9cc8278ee31f"
            ))
            .expect("Hardcoded master key was rejected"),
        }
    }

    /// Return the public master keys used by PocketIC
    ///
    /// Note that the secret keys for these public keys are known, and these keys
    /// should only be used for offline testing with PocketIC
    pub fn pocketic_key(key_id: PocketIcMasterPublicKeyId) -> Self {
        match key_id {
            PocketIcMasterPublicKeyId::Key1 => Self::deserialize_raw(&hex!(
                "db415b8eb85bd5127b0984723e0448054042cf40e7a9c262ed0cc87ecea98349"
            ))
            .expect("Hardcoded master key was rejected"),
            PocketIcMasterPublicKeyId::TestKey1 => Self::deserialize_raw(&hex!(
                "6ed9121ecf701b9e301fce17d8a65214888984e8211225691b089d6b219ec144"
            ))
            .expect("Hardcoded master key was rejected"),
            PocketIcMasterPublicKeyId::DfxTestKey => Self::deserialize_raw(&hex!(
                "7124afcb1be5927cac0397a7447b9c3cda2a4099af62d9bc0a2c2fe42d33efe1"
            ))
            .expect("Hardcoded master key was rejected"),
        }
    }

    /// Derive a public key from the mainnet parameters
    ///
    /// This is an offline equivalent to the `schnorr_public_key` management canister call
    pub fn derive_mainnet_key(
        key_id: MasterPublicKeyId,
        canister_id: &CanisterId,
        derivation_path: &[Vec<u8>],
    ) -> (Self, [u8; 32]) {
        let mk = PublicKey::mainnet_key(key_id);
        mk.derive_subkey(&DerivationPath::from_canister_id_and_path(
            canister_id.as_slice(),
            derivation_path,
        ))
    }

    /// Derive a public key as is done on PocketIC
    ///
    /// This is an offline equivalent to the `schnorr_public_key` management canister call
    /// when running on PocketIC
    pub fn derive_pocketic_key(
        key_id: PocketIcMasterPublicKeyId,
        canister_id: &CanisterId,
        derivation_path: &[Vec<u8>],
    ) -> (Self, [u8; 32]) {
        let mk = PublicKey::pocketic_key(key_id);
        mk.derive_subkey(&DerivationPath::from_canister_id_and_path(
            canister_id.as_slice(),
            derivation_path,
        ))
    }

    /// Derive a public key from this public key using a derivation path
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for Ed25519
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (Self, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a public key from this public key using a derivation path
    /// and chain code
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for Ed25519
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        // TODO(CRP-2412) Use VerifyingKey::to_edwards once available

        let pt = CompressedEdwardsY(self.pk.to_bytes()).decompress().unwrap();

        let (pt, _sum, chain_code) = derivation_path.derive_offset(pt, chain_code);

        let key = Self::new(VerifyingKey::from(pt));

        (key, chain_code)
    }
}

/// A component of a derivation path
#[derive(Clone, Debug)]
pub struct DerivationIndex(pub Vec<u8>);

/// Derivation Path
///
/// A derivation path is simply a sequence of DerivationIndex
#[derive(Clone, Debug)]
pub struct DerivationPath {
    path: Vec<DerivationIndex>,
}

impl DerivationPath {
    /// Create a BIP32-style derivation path
    pub fn new_bip32(bip32: &[u32]) -> Self {
        let mut path = Vec::with_capacity(bip32.len());
        for n in bip32 {
            path.push(DerivationIndex(n.to_be_bytes().to_vec()));
        }
        Self::new(path)
    }

    /// Create a free-form derivation path
    pub fn new(path: Vec<DerivationIndex>) -> Self {
        Self { path }
    }

    /// Create a path from a canister ID and a user provided path
    pub fn from_canister_id_and_path(canister_id: &[u8], path: &[Vec<u8>]) -> Self {
        let mut vpath = Vec::with_capacity(1 + path.len());
        vpath.push(DerivationIndex(canister_id.to_vec()));

        for n in path {
            vpath.push(DerivationIndex(n.to_vec()));
        }
        Self::new(vpath)
    }

    /// Return the length of this path
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Return if this path is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the components of the derivation path
    pub fn path(&self) -> &[DerivationIndex] {
        &self.path
    }

    fn derive_offset(
        &self,
        mut pt: EdwardsPoint,
        chain_code: &[u8; 32],
    ) -> (EdwardsPoint, Scalar, [u8; 32]) {
        let mut chain_code = *chain_code;
        let mut sum = Scalar::ZERO;

        for idx in self.path() {
            let mut ikm = Vec::with_capacity(PublicKey::BYTES + idx.0.len());
            ikm.extend_from_slice(&pt.compress().0);
            ikm.extend_from_slice(&idx.0);

            let hkdf = hkdf::Hkdf::<Sha512>::new(Some(&chain_code), &ikm);

            let mut okm = [0u8; 96];
            hkdf.expand(b"Ed25519", &mut okm)
                .expect("96 is a valid length for HKDF-SHA-512");

            let mut offset = [0u8; 64];
            offset.copy_from_slice(&okm[0..64]);
            offset.reverse(); // dalek uses little endian
            let offset = Scalar::from_bytes_mod_order_wide(&offset);

            pt += EdwardsPoint::mul_base(&offset);
            sum += offset;
            chain_code.copy_from_slice(&okm[64..]);
        }

        (pt, sum, chain_code)
    }
}
