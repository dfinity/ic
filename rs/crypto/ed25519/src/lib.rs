#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]
#![forbid(unsafe_code)]

//! A crate for creating and verifying Ed25519 signatures

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{verify_batch, Signature, Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

/// An error if a private key cannot be decoded
#[derive(Clone, Debug)]
pub enum PrivateKeyDecodingError {
    /// The private key seems invalid in some way; the string contains details
    InvalidKeyEncoding(String),
}

/// An Ed25519 secret key
#[derive(Clone, ZeroizeOnDrop, Eq, PartialEq)]
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

impl PrivateKey {
    /// The length in bytes of the raw private key
    pub const BYTES: usize = 32;

    /// Create a new random secret Ed25519 key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_using_rng(&mut rng)
    }

    /// Create a new random secret Ed25519 key using specified RNG
    pub fn generate_using_rng<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let sk = SigningKey::generate(rng);
        Self { sk }
    }

    /// Sign a message and return a signature
    ///
    /// This is the non-prehashed variant of Ed25519
    pub fn sign_message(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign(msg).to_vec()
    }

    /// Return the public key associated with this secret key
    pub fn public_key(&self) -> PublicKey {
        let pk = self.sk.verifying_key();
        PublicKey { pk }
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
    /// This corresponds with the format used by PrivateKey::serialize
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PrivateKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes).map_err(|_| {
            PrivateKeyDecodingError::InvalidKeyEncoding(format!(
                "Expected key of exactly {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;

        let sk = SigningKey::from_bytes(&bytes);
        Ok(Self { sk })
    }

    /// Serialize the Ed25519 secret key in PKCS8 v2 format
    ///
    /// This is the v2 PKCS8 format, which includes the public key
    ///
    /// # Warning
    ///
    /// Some software, notably OpenSSL, does not understand the v2 PKCS8 format.
    pub fn serialize_pkcs8(&self) -> Vec<u8> {
        let pkcs8 = self.sk.to_pkcs8_der();

        // Key encoding with the pkcs8 crate can fail, largely to allow for
        // falliable encoding on the part of the algorithm specific code.  But
        // logically speaking, as long as the key is valid (which we've already
        // checked) then there is no reason for encoding to ever fail outside of
        // memory allocation errors. None of the error types that to_pkcs8_der
        // can return have any relevance to encoding. And the dalek encoding
        // functions themselves do not have any error cases.
        pkcs8
            .expect("Failed to encode key as PKCS8")
            .to_bytes()
            .to_vec()
    }

    /// Serialize the Ed25519 secret key in PKCS8 v1 format
    ///
    /// This is the v1 PKCS8 format, which omits the public key
    ///
    /// Use this only if required to interop with software which does
    /// not understand the v2 PKCS8 format
    pub fn serialize_pkcs8_v1(&self) -> Vec<u8> {
        const DER_PREFIX: [u8; 16] = [
            48, 46, // A sequence of 46 bytes follows.
            2, 1, // An integer denoting version
            0, // 0 if secret key only, 1 if public key is also present
            48, 5, // An element of 5 bytes follows
            6, 3, 43, 101, 112, // Object ID (6), length 3, value 1.3.101.112
            4, 34, // An octet string of 34 bytes follows.
            4, 32, // An octet string of 32 bytes follows.
        ];

        let mut pkcs8v1 = Vec::with_capacity(DER_PREFIX.len() + Self::BYTES);

        pkcs8v1.extend_from_slice(&DER_PREFIX);
        pkcs8v1.extend_from_slice(&self.serialize_raw());

        pkcs8v1
    }

    /// Deserialize an Ed25519 private key from PKCS8 format
    ///
    /// Both v1 and v2 PKCS8 encodings are accepted. The only difference is
    /// that v2 includes the public key as well.
    ///
    /// This corresponds with the format used by PrivateKey::serialize_pkcs8
    pub fn deserialize_pkcs8(bytes: &[u8]) -> Result<Self, PrivateKeyDecodingError> {
        let sk = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| PrivateKeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { sk })
    }

    /// Serialize the Ed25519 secret key in PKCS8 v2 format with PEM encoding
    ///
    /// This is the v2 PKCS8 format which includes the public key
    ///
    /// # Warning
    ///
    /// Some software, notably OpenSSL, does not understand the v2 PKCS8 format.
    pub fn serialize_pkcs8_pem(&self) -> String {
        let pkcs8 = self.sk.to_pkcs8_pem(Default::default());

        // See comment in serialize_pkcs8 regarding this expect
        pkcs8.expect("Failed to encode key as PKCS8").to_string()
    }

    /// Deserialize an Ed25519 private key from PKCS8 PEM format
    ///
    /// Both v1 and v2 PKCS8 encodings are accepted
    ///
    /// This corresponds with the format used by PrivateKey::serialize_pkcs8_pem
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, PrivateKeyDecodingError> {
        let sk = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| PrivateKeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { sk })
    }
}

/// An invalid key was encountered
#[derive(Clone, Debug)]
pub enum PublicKeyDecodingError {
    /// The encoding of the public key is invalid, the string contains details
    InvalidKeyEncoding(String),
    /// The public key had a valid encoding, but contains elements of the torsion
    /// subgroup. This should never happen with a non-malicious peer.
    KeyNotTorsionFree,
}

/// An Ed25519 public key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PublicKey {
    pk: VerifyingKey,
}

/// An error that occurs when verifying signatures or batches of signatures
#[derive(Copy, Clone, Debug)]
pub enum SignatureError {
    /// The signature had an invalid length, and cannot possibly be valid
    InvalidLength,
    /// The batch was invalid (eg due to length mismatch between number of
    /// messages and number of signatures)
    InvalidBatch,
    /// A signature was invalid
    InvalidSignature,
}

impl PublicKey {
    /// The number of bytes in the raw public key
    pub const BYTES: usize = 32;

    /// Internal constructor
    ///
    /// Checks the point for validity before returning
    fn new(pk: VerifyingKey) -> Result<Self, PublicKeyDecodingError> {
        // TODO(CRP-2412) This can be changed to `pk.to_edwards().is_torsion_free()` once
        // https://github.com/dalek-cryptography/curve25519-dalek/issues/624
        // makes it into a release
        if !curve25519_dalek::edwards::CompressedEdwardsY(pk.to_bytes())
            .decompress()
            .unwrap()
            .is_torsion_free()
        {
            return Err(PublicKeyDecodingError::KeyNotTorsionFree);
        }

        // We don't need to call is_weak here since that is subsumed by the
        // test that the point is torsion free - is_weak just checks if the
        // point is within the size-8 cofactor group.

        Ok(Self { pk })
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
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes).map_err(|_| {
            PublicKeyDecodingError::InvalidKeyEncoding(format!(
                "Expected key of exactly {} bytes, got {}",
                Self::BYTES,
                bytes.len()
            ))
        })?;
        let pk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| PublicKeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;

        Self::new(pk)
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

    /// Deserialize the DER encoded public key
    ///
    /// See RFC 8410 for details on the format. This cooresponds to
    /// Self::serialize_rfc8410_der
    pub fn deserialize_rfc8410_der(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let pk = VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| PublicKeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Self::new(pk)
    }

    /// Verify a Ed25519 signature
    ///
    /// Returns Ok if the signature is valid, or Err otherwise
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| SignatureError::InvalidLength)?;

        // We use the batch verification API also for single signatures to ensure
        // there is no discrepency between batch and single signature verification;
        // Ed25519 generally has problems with this; see
        // https://hdevalence.ca/blog/2020-10-04-its-25519am
        verify_batch(&[msg], &[signature], &[self.pk]).map_err(|_| SignatureError::InvalidSignature)
    }

    /// Verify a batch of signatures
    ///
    /// Returns Ok if the signatures are all valid, or Err otherwise
    ///
    /// Note that this does not indicate which of the signature(s) are invalid;
    /// if batch verification fails you must then test serially to find the
    /// valid signatures (if any).
    pub fn batch_verify(
        messages: &[&[u8]],
        signatures: &[&[u8]],
        keys: &[Self],
    ) -> Result<(), SignatureError> {
        if messages.len() != signatures.len() || signatures.len() != keys.len() {
            return Err(SignatureError::InvalidBatch);
        }

        let signatures = signatures
            .iter()
            .map(|s| Signature::from_slice(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SignatureError::InvalidLength)?;

        // We could use std::slice::from_raw_parts to avoid these copies, but
        // we'd rather avoid unsafe unless strictly necessary.
        //
        // unsafe { std::slice::from_raw_parts(keys.as_ptr() as *const VerifyingKey, keys.len()) };
        let keys = keys.iter().map(|k| k.pk).collect::<Vec<_>>();

        verify_batch(messages, &signatures, &keys).map_err(|_| SignatureError::InvalidSignature)
    }
}
