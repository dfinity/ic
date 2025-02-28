#![forbid(unsafe_code)]
#![forbid(missing_docs)]

//! Public Key Encryption Utility
//!
//! This crate offers functionality for encrypting messages using a public key.
//! First a key is created using the recipients public key (and, if source
//! authentication is being used, also the senders private key). Then the message
//! is encrypted and authenticated using a standard cipher.
//!
//! All binary strings produced by this crate include a protocol/version
//! identifiers, which will allow algorithm rotation in the future should this
//! be necessary (for example to support a post quantum scheme)
//!
//! Two different modes are offered, namely non-authenticated and authenticated.
//!
//! A non-authenticated message encrypts the message to the public key, but does not
//! provide any kind of source authentication. Thus the receiver can decrypt the message,
//! but does not have any idea who it came from; anyone can encrypt a message to the
//! recipients public key.
//!
//! When sending an authenticated message, the sender also uses their private key.
//! Decrypting the message takes as input both the recipients private key and the
//! purported senders public key. Decryption will only succeed if the sender of that
//! ciphertext did in fact have access to the associated private key.
//!
//! Both modes can make use of an associated_data parameter. The associated_data field is
//! information which is not encrypted, nor is it included in the returned ciphertext
//! blob. However it is implicitly authenticated by a successful decryption; that is, if
//! the decrypting side uses the same associated_data parameter during decryption, then
//! decryption will succeed and the decryptor knows that the associated_data field they
//! used is also authentic, and is associated with the ciphertext message. If the
//! encryptor and decryptor disagree on the associated_data field, then decryption will
//! fail. If not needed, associated_data can be set to an empty slice.
//!
//! # Example (Non-Authenticated Encryption)
//!
//! ```
//! let mut rng = rand::rngs::OsRng;
//!
//! // perform key generation:
//! let sk = ic_hpke::PrivateKey::generate(&mut rng);
//! let sk_bytes = sk.serialize();
//! // save sk_bytes to secure storage...
//! let pk_bytes = sk.public_key().serialize();
//! // publish pk_bytes
//!
//! // Now someone can encrypt a message to your key:
//! let msg = b"attack at dawn";
//! let associated_data = b"example-protocol-v1";
//! let pk = ic_hpke::PublicKey::deserialize(&pk_bytes).unwrap();
//! let ctext = pk.encrypt_noauth(msg, associated_data, &mut rng).unwrap();
//!
//! // Upon receipt, decrypt the ciphertext:
//! let recovered_msg = sk.decrypt_noauth(&ctext, associated_data).unwrap();
//! assert_eq!(recovered_msg, msg, "decryption worked");
//!
//! // If associated data is incorrect decryption fails
//! assert!(sk.decrypt_noauth(&ctext, b"wrong-associated-data").is_err());
//! ```
//!
//! # Example (Authenticated Encryption)
//!
//! ```
//! let mut rng = rand::rngs::OsRng;
//!
//! let a_sk = ic_hpke::PrivateKey::generate(&mut rng);
//! let a_pk = a_sk.public_key();
//!
//! let b_sk = ic_hpke::PrivateKey::generate(&mut rng);
//! let b_pk = b_sk.public_key();
//!
//! // We assume the two public keys can be exchanged in a trusted way beforehand
//!
//! let msg = b"this is only a test";
//! let associated_data = b"example-protocol-v2-with-auth";
//!
//! let ctext = a_pk.encrypt(msg, associated_data, &b_sk, &mut rng).unwrap();
//!
//! let recovered_msg = a_sk.decrypt(&ctext, associated_data, &b_pk).unwrap();
//! assert_eq!(recovered_msg, msg, "decryption worked");
//!
//! // If recipient accidentally tries to decrypt noauth, it does not work
//! assert!(a_sk.decrypt_noauth(&ctext, associated_data).is_err());
//! // If associated data is incorrect decryption fails
//! assert!(a_sk.decrypt(&ctext, b"wrong-associated-data", &b_pk).is_err());
//! // If the wrong public key is used decryption fails
//! assert!(a_sk.decrypt(&ctext, associated_data, &a_pk).is_err());
//! ```

use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha384, kem::DhP384HkdfSha384, Deserializable, Kem, Serializable,
};

/*
 * All artifacts produced by this crate - public keys, private keys, and
 * ciphertexts, are prefixed with a header.
 *
 * The header starts with a 56 bit long "magic" field. This makes the values
 * easy to identity - someone searching for this hex string will likely find
 * this crate right away. It also ensures that values we accept were intended
 * specifically for us. This is the first 56 bits of the SHA-256 of the string
 * "Internet Computer HPKE".
 *
 * The next part is a 8 bit version field. This is currently 1; we only
 * implement this one version. The field allows us extensibility in the future if
 * needed, eg to handle a transition to post-quantum.
 */

// An arbitrary magic number that is prefixed to all artifacts to identify them
// plus our initial version (01)
const MAGIC: u64 = 0x64e4f9efb76abc01;

// Current header is just the magic + version field
const HEADER_SIZE: usize = 8;

type V1Kem = DhP384HkdfSha384;
type V1Kdf = HkdfSha384;
type V1Aead = AesGcm256;

type V1PublicKey = <V1Kem as hpke::Kem>::PublicKey;
type V1PrivateKey = <V1Kem as hpke::Kem>::PrivateKey;

#[derive(Copy, Clone, Debug)]
/// An error occured while deserializing a key
pub enum KeyDeserializationError {
    /// The protocol identifier/version field did not match
    UnknownMagic,
    /// The key was of a length that is not possibly valid
    InvalidLength,
    /// The header was valid but the key was invalid
    InvalidKey,
}

#[derive(Copy, Clone, Debug)]
/// An error occurred during encryption
///
/// Logically there is no reason for encryption to fail in this
/// context, but unfortunately some of the implementation has
/// falliable interfaces. Rather than unwrapping and risking
/// a panic, we pass this falliability onto the caller
pub enum EncryptionError {
    /// Some error occurred during encryption
    InternalError,
}

#[derive(Clone)]
/// A public key usable for encryption
pub struct PublicKey {
    pk: V1PublicKey,
}

impl PublicKey {
    /// Encrypt a message without sender authentication
    ///
    /// This encrypts a message to the public key such that whoever
    /// knows the associated private key can decrypt the message.
    ///
    /// The associated_data field is information which is not encrypted, nor is
    /// it included in the returned blob. However it is implicitly authenticated
    /// by a successful decryption; that is, if the decrypting side uses the
    /// same associated_data parameter during decryption, then decryption will
    /// succeed and the decryptor knows that this field is also authentic.  If
    /// the encryptor and decryptor disagree on the associated_data field, then
    /// decryption will fail. If not needed, associated_data can be set to an
    /// empty slice.
    ///
    /// This function provides no guarantees to the recipient about who sent it;
    /// anyone can encrypt a message with this function.
    pub fn encrypt_noauth<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EncryptionError> {
        let opmode = hpke::OpModeS::<V1Kem>::Base;
        self._v1_encrypt(&opmode, msg, associated_data, rng)
    }

    /// Encrypt a message with sender authentication
    ///
    /// This encrypts a message using the recipients public key
    ///
    /// This encrypts a message to the public key such that whoever
    /// knows the associated private key can decrypt the message.
    ///
    /// The associated_data field is information which is not encrypted, nor is
    /// it included in the returned blob. However it is implicitly authenticated
    /// by a successful decryption; that is, if the decrypting side uses the
    /// same associated_data parameter during decryption, then decryption will
    /// succeed and the decryptor knows that this field is also authentic.  If
    /// the encryptor and decryptor disagree on the associated_data field, then
    /// decryption will fail. If not needed, associated_data can be set to an
    /// empty slice
    ///
    /// This function also authenticates the message using the provided private key.
    /// The decrypting side must know the recipients public key in order to decrypt
    /// the message.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        associated_data: &[u8],
        sender: &PrivateKey,
        rng: &mut R,
    ) -> Result<Vec<u8>, EncryptionError> {
        let opmode = hpke::OpModeS::<V1Kem>::Auth((sender.sk.clone(), sender.pk.clone()));
        self._v1_encrypt(&opmode, msg, associated_data, rng)
    }

    fn _v1_encrypt<R: RngCore + CryptoRng>(
        &self,
        opmode: &hpke::OpModeS<V1Kem>,
        msg: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut buf = vec![];
        buf.extend_from_slice(&MAGIC.to_be_bytes());

        // Note that &buf, containing the header, is passed as the "info"
        // parameter; this is then used during the HKDF expansion, ensuring this
        // ciphertext can only be decrypted in this context and not, for example,
        // under a different version
        //
        // An alternative, had the info parameter not been available, would be to
        // concatenate the user-provided associated data and the header
        // together. However this separation is neater and avoids having to
        // allocate and copy the associated data.

        let (hpke_key, hpke_ctext) = hpke::single_shot_seal::<V1Aead, V1Kdf, V1Kem, R>(
            opmode,
            &self.pk,
            &buf,
            msg,
            associated_data,
            rng,
        )
        .map_err(|_| EncryptionError::InternalError)?;

        buf.extend_from_slice(&hpke_key.to_bytes());
        buf.extend_from_slice(&hpke_ctext);

        Ok(buf)
    }

    /// Serialize the public key to a bytestring
    pub fn serialize(&self) -> Vec<u8> {
        let len = <V1PublicKey as Serializable>::size();
        let mut buf = vec![0u8; HEADER_SIZE + len];
        buf[0..HEADER_SIZE].copy_from_slice(&MAGIC.to_be_bytes());
        self.pk.write_exact(&mut buf[HEADER_SIZE..]);
        buf
    }

    /// Deserialize a public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, KeyDeserializationError> {
        if bytes.len() < HEADER_SIZE {
            return Err(KeyDeserializationError::InvalidLength);
        }

        let magic = u64::from_be_bytes(
            bytes[0..HEADER_SIZE]
                .try_into()
                .expect("Conversion cannot fail"),
        );
        if magic != MAGIC {
            return Err(KeyDeserializationError::UnknownMagic);
        }

        let len = <V1PublicKey as Serializable>::size();
        if bytes.len() != HEADER_SIZE + len {
            return Err(KeyDeserializationError::InvalidLength);
        }

        match V1PublicKey::from_bytes(&bytes[HEADER_SIZE..]) {
            Ok(pk) => Ok(Self { pk }),
            Err(_) => Err(KeyDeserializationError::InvalidKey),
        }
    }

    fn new(pk: V1PublicKey) -> Self {
        Self { pk }
    }
}

#[derive(Copy, Clone, Debug)]
/// An error occured while decrypting a message
pub enum DecryptionError {
    /// The protocol identifier/version field did not match
    UnknownMagic,
    /// The length was wrong
    InvalidLength,
    /// The header was valid but the decryption failed
    InvalidCiphertext,
}

#[derive(Clone)]
/// A private key usable for decryption
pub struct PrivateKey {
    sk: V1PrivateKey,
    pk: V1PublicKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut ikm = vec![0; 64];
        rng.fill_bytes(&mut ikm);
        let (sk, pk) = <V1Kem as Kem>::derive_keypair(&ikm);
        Self { sk, pk }
    }

    /// Decrypt a message without sender authentication
    ///
    /// This is the counterpart to [`PublicKey::encrypt_noauth`]
    pub fn decrypt_noauth(
        &self,
        msg: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let opmode = hpke::OpModeR::<V1Kem>::Base;
        self._v1_decrypt(&opmode, msg, associated_data)
    }

    /// Decrypt a message with sender authentication
    ///
    /// This is the counterpart to [`PublicKey::encrypt`]
    ///
    /// This function provides sender authentication; if decryption succeeds
    /// then it is mathematically guaranteed that the sender had access
    /// to the secret key associated with `sender`
    pub fn decrypt(
        &self,
        msg: &[u8],
        associated_data: &[u8],
        sender: &PublicKey,
    ) -> Result<Vec<u8>, DecryptionError> {
        let opmode = hpke::OpModeR::<V1Kem>::Auth(sender.pk.clone());
        self._v1_decrypt(&opmode, msg, associated_data)
    }

    fn _v1_decrypt(
        &self,
        opmode: &hpke::OpModeR<V1Kem>,
        msg: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        if msg.len() < HEADER_SIZE {
            return Err(DecryptionError::InvalidLength);
        }

        let header = &msg[0..HEADER_SIZE];

        let magic = u64::from_be_bytes(
            msg[0..HEADER_SIZE]
                .try_into()
                .expect("Conversion cannot fail"),
        );
        if magic != MAGIC {
            return Err(DecryptionError::UnknownMagic);
        }

        let encap_key_len = <V1Kem as Kem>::EncappedKey::size();

        if msg.len() < HEADER_SIZE + encap_key_len {
            return Err(DecryptionError::InvalidLength);
        }

        let encap_key_bytes = &msg[HEADER_SIZE..HEADER_SIZE + encap_key_len];
        let encap_key = <V1Kem as Kem>::EncappedKey::from_bytes(encap_key_bytes)
            .map_err(|_| DecryptionError::InvalidCiphertext)?;

        let ciphertext = &msg[HEADER_SIZE + encap_key_len..];

        match hpke::single_shot_open::<V1Aead, V1Kdf, V1Kem>(
            opmode,
            &self.sk,
            &encap_key,
            header,
            ciphertext,
            associated_data,
        ) {
            Ok(ptext) => Ok(ptext),
            Err(_) => Err(DecryptionError::InvalidCiphertext),
        }
    }

    /// Return the associated public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.pk.clone())
    }

    /// Serialize this private key
    pub fn serialize(&self) -> Vec<u8> {
        let len = <V1PrivateKey as Serializable>::size();
        let mut buf = vec![0u8; HEADER_SIZE + len];
        buf[0..HEADER_SIZE].copy_from_slice(&MAGIC.to_be_bytes());
        self.sk.write_exact(&mut buf[HEADER_SIZE..]);
        buf
    }

    /// Deserialize a private key previously serialized with [`PrivateKey::serialize`]
    pub fn deserialize(bytes: &[u8]) -> Result<Self, KeyDeserializationError> {
        let len = <V1PrivateKey as Serializable>::size();

        if bytes.len() < HEADER_SIZE {
            return Err(KeyDeserializationError::InvalidLength);
        }

        let magic = u64::from_be_bytes(
            bytes[0..HEADER_SIZE]
                .try_into()
                .expect("Conversion cannot fail"),
        );
        if magic != MAGIC {
            return Err(KeyDeserializationError::UnknownMagic);
        }

        if bytes.len() != HEADER_SIZE + len {
            return Err(KeyDeserializationError::InvalidLength);
        }

        match V1PrivateKey::from_bytes(&bytes[HEADER_SIZE..]) {
            Ok(sk) => {
                let pk = <V1Kem as Kem>::sk_to_pk(&sk);
                Ok(Self { sk, pk })
            }
            Err(_) => Err(KeyDeserializationError::InvalidKey),
        }
    }
}
