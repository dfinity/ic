#![forbid(unsafe_code)]
#![forbid(missing_docs)]

//! Public Key Encryption Utility
//!
//! This crate offers functionality for encrypting messages using a public key,
//! with optional sender authentication.
//!
//! All binary strings produced by this crate include protocol and version
//! identifiers, which will allow algorithm rotation in the future should this
//! be necessary (for example to support a post quantum scheme)
//!
//! Two different modes are offered, namely authenticated and non-authenticated.
//!
//! When sending an authenticated message, the sender also uses their private key.
//! Decrypting the message takes as input both the recipients private key and the
//! purported senders public key. Decryption will only succeed if the sender of that
//! ciphertext did in fact have access to the associated private key.
//!
//! A non-authenticated message encrypts the message to the public key, but does not
//! provide any kind of source authentication. Thus the receiver can decrypt the message,
//! but does not have any idea who it came from; anyone can encrypt a message to the
//! recipients public key.
//!
//! Both modes can make use of an `associated_data` parameter. The `associated_data` field is
//! information which is not encrypted, nor is it included in the returned ciphertext
//! blob. However it is implicitly authenticated by a successful decryption; that is, if
//! the decrypting side uses the same `associated_data` parameter during decryption, then
//! decryption will succeed and the decryptor knows that the `associated_data` field they
//! used is also authentic, and is associated with that ciphertext message. If the
//! encryptor and decryptor disagree on the `associated_data` field, then decryption will
//! fail. Commonly, the `associated_data` is used to bind additional information about the
//! context which both the sender and receiver will know, for example a protocol identifer.
//! If no such information is available, the associated data can be set to an empty slice.
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
//! assert_eq!(recovered_msg, msg, "failed to decrypt message");
//!
//! // If recipient accidentally tries to decrypt without authentication, decryption fails
//! assert!(a_sk.decrypt_noauth(&ctext, associated_data).is_err());
//! // If associated data is incorrect, decryption fails
//! assert!(a_sk.decrypt(&ctext, b"wrong-associated-data", &b_pk).is_err());
//! // If the wrong public key is used, decryption fails
//! assert!(a_sk.decrypt(&ctext, associated_data, &a_pk).is_err());
//! ```
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
//! assert_eq!(recovered_msg, msg, "failed to decrypt message");
//!
//! // If associated data is incorrect, decryption fails
//! assert!(sk.decrypt_noauth(&ctext, b"wrong-associated-data").is_err());
//! ```

use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{
    Deserializable, Kem, Serializable, aead::AesGcm256, kdf::HkdfSha384, kem::DhP384HkdfSha384,
};

/*
 * All artifacts produced by this crate - public keys, private keys, and
 * ciphertexts, are prefixed with a header.
 *
 * The header starts with a 56 bit long "magic" field. This makes the values
 * easy to identity - someone searching for this hex string will likely find
 * this crate right away. It also ensures that values we accept were intended
 * specifically for us. The string is the ASCII bytes of "IC HPKE".
 *
 * The next part is a 8 bit version field. This is currently 1; we only
 * implement this one version. The field allows us extensibility in the future if
 * needed, eg to handle a transition to post-quantum.
 */

// An arbitrary magic number that is prefixed to all artifacts to identify them
// plus our initial version (01)
const MAGIC: u64 = 0x49432048504b4501;

// Current header is just the magic + version field
const HEADER_SIZE: usize = 8;

/*
 * V1 KEM
 * ========
 *
 * The V1 kem uses HPKE from RFC 9180 using P-384 with HKDF-SHA-384
 * and AES-256 in GCM mode.
 */
type V1Kem = DhP384HkdfSha384;
type V1Kdf = HkdfSha384;
type V1Aead = AesGcm256;

// The amount of random material which is used to derive a secret key
//
// RFC 9180 requires this be at least 48 bytes (for P-384), we somewhat arbitrarily use 64
const V1_IKM_LENGTH: usize = 64;

type V1PublicKey = <V1Kem as hpke::Kem>::PublicKey;
type V1PrivateKey = <V1Kem as hpke::Kem>::PrivateKey;

/*
 * A helper macro for reading the header and optionally checking the length
 */
macro_rules! check_header {
    (@common $err:ty, $val:expr_2021) => {
        if $val.len() < HEADER_SIZE {
            Err(<$err>::InvalidLength)
        } else {
            let magic = u64::from_be_bytes(
                <[u8; 8]>::try_from(&$val[0..HEADER_SIZE]).expect("Conversion cannot fail"),
            );
            if magic != MAGIC {
                Err(<$err>::UnknownMagic)
            } else {
                Ok($val.len() - HEADER_SIZE)
            }
        }
    };
    ($err:ty, $val:expr_2021) => {
        check_header!(@common $err, $val)
    };
    ($err:ty, $val:expr_2021, $req_len:expr_2021) => {
        match check_header!(@common $err, $val) {
            Ok(len) => {
                if len == $req_len {
                    Ok(())
                } else {
                    Err(<$err>::InvalidLength)
                }
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// An error occured while deserializing a key
pub enum KeyDeserializationError {
    /// The protocol identifier or version field was unknown to us
    UnknownMagic,
    /// The key was of a length that is not possibly valid
    InvalidLength,
    /// The header was valid but the key was invalid
    InvalidKey,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
        let len = <V1PublicKey as Serializable>::size();

        check_header!(KeyDeserializationError, bytes, len)?;

        match V1PublicKey::from_bytes(&bytes[HEADER_SIZE..]) {
            Ok(pk) => Ok(Self { pk }),
            Err(_) => Err(KeyDeserializationError::InvalidKey),
        }
    }

    /// Encrypt a message with sender authentication
    ///
    /// This encrypts a message using the recipients public key, and
    /// additionally authenticates the message using the provided private key.
    /// The decrypting side must know the recipients public key in order to
    /// decrypt the message.
    ///
    /// The `associated_data` field is information which is not encrypted, nor is
    /// it included in the returned blob. However it is implicitly authenticated
    /// by a successful decryption; that is, if the decrypting side uses the
    /// same `associated_data` parameter during decryption, then decryption will
    /// succeed and the decryptor knows that this field is also authentic.  If
    /// the encryptor and decryptor disagree on the `associated_data` field, then
    /// decryption will fail. If not needed, `associated_data` can be set to an
    /// empty slice
    ///
    /// The recipient must use [`PrivateKey::decrypt`] to decrypt
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

    /// Encrypt a message without sender authentication
    ///
    /// This encrypts a message to the public key such that whoever
    /// knows the associated private key can decrypt the message.
    ///
    /// The `associated_data` field is information which is not encrypted, nor is
    /// it included in the returned blob. However it is implicitly authenticated
    /// by a successful decryption; that is, if the decrypting side uses the
    /// same `associated_data` parameter during decryption, then decryption will
    /// succeed and the decryptor knows that this field is also authentic.  If
    /// the encryptor and decryptor disagree on the `associated_data` field, then
    /// decryption will fail. If not needed, `associated_data` can be set to an
    /// empty slice.
    ///
    /// This function provides no guarantees to the recipient about who sent it;
    /// anyone can encrypt a message with this function.
    ///
    /// The recipient must use [`PrivateKey::decrypt_noauth`] to decrypt
    pub fn encrypt_noauth<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EncryptionError> {
        let opmode = hpke::OpModeS::<V1Kem>::Base;
        self._v1_encrypt(&opmode, msg, associated_data, rng)
    }

    fn new(pk: V1PublicKey) -> Self {
        Self { pk }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
        let mut ikm = [0; V1_IKM_LENGTH];
        rng.fill_bytes(&mut ikm);
        let (sk, pk) = <V1Kem as Kem>::derive_keypair(&ikm);
        Self { sk, pk }
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

        check_header!(KeyDeserializationError, bytes, len)?;

        match V1PrivateKey::from_bytes(&bytes[HEADER_SIZE..]) {
            Ok(sk) => {
                let pk = <V1Kem as Kem>::sk_to_pk(&sk);
                Ok(Self { sk, pk })
            }
            Err(_) => Err(KeyDeserializationError::InvalidKey),
        }
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

    /// Decrypt a message without sender authentication
    ///
    /// This is the counterpart to [`PublicKey::encrypt_noauth`]
    ///
    /// This function *cannot* decrypt messages created using [`PublicKey::encrypt`]
    ///
    /// # Warning
    ///
    /// Remember that without sender authentication there is no guarantee that the message
    /// you decrypt was sent by anyone in particular. Using this function safely requires
    /// some out of band authentication mechanism.
    pub fn decrypt_noauth(
        &self,
        msg: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let opmode = hpke::OpModeR::<V1Kem>::Base;
        self._v1_decrypt(&opmode, msg, associated_data)
    }

    fn _v1_decrypt(
        &self,
        opmode: &hpke::OpModeR<V1Kem>,
        msg: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let encap_key_len = <V1Kem as Kem>::EncappedKey::size();

        if check_header!(DecryptionError, msg)? < encap_key_len {
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
            &msg[0..HEADER_SIZE],
            ciphertext,
            associated_data,
        ) {
            Ok(ptext) => Ok(ptext),
            Err(_) => Err(DecryptionError::InvalidCiphertext),
        }
    }
}
