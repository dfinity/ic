use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{verify_batch, Signature, Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

#[derive(Copy, Clone, Debug)]
pub enum SecretKeyDecodingError {
    IncorrectLength,
    InvalidKeyEncoding,
}

/// An Ed25519 secret key
#[derive(Clone, ZeroizeOnDrop, Eq, PartialEq)]
pub struct SecretKey {
    sk: SigningKey,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key().serialize_raw())
            .finish_non_exhaustive() // avoids printing secret information
    }
}

impl SecretKey {
    /// The length in bytes of the raw private key
    pub const BYTES: usize = 32;

    /// Create a new random secret Ed25519 key
    pub fn generate_key<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let sk = SigningKey::generate(rng);
        Self { sk }
    }

    /// Deserialize an Ed25519 key from raw format
    ///
    /// This is just the plain 32 byte random seed from which the
    /// internal key material is derived
    ///
    /// This corresponds with the format used by SecretKey::serialize
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, SecretKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes)
            .map_err(|_| SecretKeyDecodingError::IncorrectLength)?;
        let sk = SigningKey::from_bytes(&bytes);
        Ok(Self { sk })
    }

    /// Deserialize an Ed25519 key from PKCS8 format
    ///
    /// This corresponds with the format used by SecretKey::serialize_pkcs8
    pub fn deserialize_pkcs8(bytes: &[u8]) -> Result<Self, SecretKeyDecodingError> {
        let sk = SigningKey::from_pkcs8_der(bytes)
            .map_err(|_| SecretKeyDecodingError::InvalidKeyEncoding)?;
        Ok(Self { sk })
    }

    /// Deserialize an Ed25519 key from PKCS8 PEM format
    ///
    /// This corresponds with the format used by SecretKey::serialize_pkcs8
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, SecretKeyDecodingError> {
        let sk = SigningKey::from_pkcs8_pem(pem)
            .map_err(|_| SecretKeyDecodingError::InvalidKeyEncoding)?;
        Ok(Self { sk })
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

    /// Serialize the Ed25519 secret key in PKCS8 format
    ///
    /// This is the "v2" PKCS8 format which includes the public key
    pub fn serialize_pkcs8(&self) -> Vec<u8> {
        self.sk
            .to_pkcs8_der()
            .expect("Failed to encode key as PKCS8")
            .to_bytes()
            .to_vec()
    }

    /// Serialize the Ed25519 secret key in PKCS8 format with PEM encoding
    pub fn serialize_pkcs8_pem(&self) -> String {
        self.sk
            .to_pkcs8_pem(Default::default())
            .expect("Failed to encode key as PKCS8")
            .to_string()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum PublicKeyDecodingError {
    InvalidLength,
    InvalidPublicKey,
    KeyNotTorsionFree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PublicKey {
    pk: VerifyingKey,
}

#[derive(Copy, Clone, Debug)]
pub enum SignatureError {
    InvalidLength,
    InvalidBatch,
    InvalidSignature,
}

impl PublicKey {
    pub const BYTES: usize = 32;

    /// Internal constructor
    ///
    /// Checks the point for validity before returning
    fn new(pk: VerifyingKey) -> Result<Self, PublicKeyDecodingError> {
        // TODO(CRP-2412) This can be changed to `to_edwards().is_torsion_free()` once
        // https://github.com/dalek-cryptography/curve25519-dalek/issues/624
        // makes it into a release
        if !pk.to_montgomery().to_edwards(0).unwrap().is_torsion_free() {
            return Err(PublicKeyDecodingError::KeyNotTorsionFree)?;
        }

        // We don't need to call is_weak here since that is subsumed by the
        // test that the point is torsion free - is_weak just checks if the
        // point is within the size-8 cofactor group.

        Ok(Self { pk })
    }

    /// Deserialize a public key in raw format
    ///
    /// This is just the 32 byte encoding of the public point
    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let bytes = <[u8; Self::BYTES]>::try_from(bytes)
            .map_err(|_| PublicKeyDecodingError::InvalidLength)?;
        let pk = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| PublicKeyDecodingError::InvalidPublicKey)?;

        Self::new(pk)
    }

    /// Serialize this public key in raw format
    ///
    /// This is just the 32 byte encoding of the public point
    pub fn serialize_raw(&self) -> [u8; Self::BYTES] {
        *self.pk.as_bytes()
    }

    /// Serialize this public key as a DER encoded structure
    ///
    /// See RFC 8410 for details on the format
    pub fn serialize_rfc8410_der(&self) -> Vec<u8> {
        self.pk
            .to_public_key_der()
            .expect("Encoding public key as DER failed")
            .as_bytes()
            .to_vec()
    }

    /// Serialize this public key as a DER encoded structure
    ///
    /// See RFC 8410 for details on the format
    pub fn deserialize_rfc8410_der(bytes: &[u8]) -> Result<Self, PublicKeyDecodingError> {
        let pk = VerifyingKey::from_public_key_der(bytes)
            .map_err(|_| PublicKeyDecodingError::InvalidPublicKey)?;
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

        // This is safe because Self is a repr(transparent) wrapper around VerifyingKey
        //
        // Alternate approach, at the cost of copying all of the keys
        // let keys = keys.iter().map(|k| k.pk).collect::<Vec<_>>();
        let keys =
            unsafe { std::slice::from_raw_parts(keys.as_ptr() as *const VerifyingKey, keys.len()) };

        verify_batch(messages, &signatures, keys).map_err(|_| SignatureError::InvalidSignature)
    }
}
