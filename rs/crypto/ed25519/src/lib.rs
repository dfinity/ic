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
    /// The outer PEM encoding is invalid
    InvalidPemEncoding(String),
    /// The PEM label was not the expected value
    UnexpectedPemLabel(String),
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
    161, 35, // An explicitly tagged with 35 bytes.
    3, 33, // A bitstring of 33 bytes follows.
    0,  // The bitstring (32 bytes) is divisible by 8
];

const BUGGY_RING_V2_LEN: usize = BUGGY_RING_V2_DER_PREFIX.len()
    + PrivateKey::BYTES
    + BUGGY_RING_V2_DER_PK_PREFIX.len()
    + PublicKey::BYTES;

/// Specifies a private key encoding format
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    pub fn sign_message(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).into()
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
                .map_err(|e| PrivateKeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
            Ok(Self { sk })
        }
    }

    /// Serialize the Ed25519 secret key in PKCS8 v2 format with PEM encoding
    ///
    /// The details of the formatting are specified using the argument
    pub fn serialize_pkcs8_pem(&self, format: PrivateKeyFormat) -> String {
        let pkcs8 = self.serialize_pkcs8(format);

        pem::encode(&pem::Pem {
            tag: "PRIVATE KEY".to_string(),
            contents: pkcs8,
        })
    }

    /// Deserialize an Ed25519 private key from PKCS8 PEM format
    ///
    /// Both v1 and v2 PKCS8 encodings are accepted
    ///
    /// This corresponds with the format used by PrivateKey::serialize_pkcs8_pem
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, PrivateKeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| PrivateKeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != "PRIVATE KEY" {
            return Err(PrivateKeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_pkcs8(&der.contents)
    }
}

/// An invalid key was encountered
#[derive(Clone, Debug)]
pub enum PublicKeyDecodingError {
    /// The outer PEM encoding is invalid
    InvalidPemEncoding(String),
    /// The PEM label was not the expected value
    UnexpectedPemLabel(String),
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

    /// Serialize this public key as a PEM encoded structure
    ///
    /// See RFC 8410 for details on the format
    pub fn serialize_rfc8410_pem(&self) -> Vec<u8> {
        pem::encode(&pem::Pem {
            tag: "PUBLIC KEY".to_string(),
            contents: self.serialize_rfc8410_der(),
        })
        .into()
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

    /// Deserialize the PEM encoded public key
    ///
    /// See RFC 8410 for details on the format. This cooresponds to
    /// Self::serialize_rfc8410_pem
    pub fn deserialize_rfc8410_pem(pem: &str) -> Result<Self, PublicKeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| PublicKeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != "PUBLIC KEY" {
            return Err(PublicKeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_rfc8410_der(&der.contents)
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
