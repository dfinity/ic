#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]

//! A crate with handling of ECDSA keys over the secp256r1 curve

use p256::{
    elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        Curve,
    },
    NistP256,
};
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

/// An error indicating that decoding a key failed
#[derive(Clone, Debug)]
pub enum KeyDecodingError {
    /// The key encoding was invalid in some way
    InvalidKeyEncoding(String),
    /// The PEM encoding was invalid
    InvalidPemEncoding(String),
    /// The PEM encoding had an unexpected label
    UnexpectedPemLabel(String),
}

lazy_static::lazy_static! {

    /// See RFC 3279 section 2.3.5
    static ref ECDSA_OID: simple_asn1::OID = simple_asn1::oid!(1, 2, 840, 10045, 2, 1);

    /// See RFC 5759 section 3.2
    static ref SECP256R1_OID: simple_asn1::OID = simple_asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
}

/// DER encode the public point into a SubjectPublicKeyInfo
///
/// The public_point can be either the compressed or uncompressed format
fn der_encode_ecdsa_spki_pubkey(public_point: &[u8]) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256r1_oid = ASN1Block::ObjectIdentifier(0, SECP256R1_OID.clone());
    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256r1_oid]);

    let key_bytes = ASN1Block::BitString(0, public_point.len() * 8, public_point.to_vec());

    let blocks = vec![alg_id, key_bytes];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

fn der_encode_rfc5915_privatekey(secret_key: &[u8]) -> Vec<u8> {
    use simple_asn1::*;
    use std::str::FromStr;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let ecdsa_version = ASN1Block::Integer(0, BigInt::from_str("1").expect("One is an integer"));
    let key_bytes = ASN1Block::OctetString(0, secret_key.to_vec());
    let key_blocks = vec![ecdsa_version, key_bytes];

    to_der(&ASN1Block::Sequence(0, key_blocks))
        .expect("Failed to encode ECDSA private key as RFC 5915 DER")
}

fn der_encode_pkcs8_rfc5208_private_key(secret_key: &[u8]) -> Vec<u8> {
    use simple_asn1::*;
    use std::str::FromStr;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let pkcs8_version = ASN1Block::Integer(0, BigInt::from_str("0").expect("Zero is an integer"));
    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256r1_oid = ASN1Block::ObjectIdentifier(0, SECP256R1_OID.clone());

    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256r1_oid]);

    let octet_string = ASN1Block::OctetString(0, der_encode_rfc5915_privatekey(secret_key));

    let blocks = vec![pkcs8_version, alg_id, octet_string];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

fn pem_encode(raw: &[u8], label: &'static str) -> String {
    pem::encode(&pem::Pem {
        tag: label.to_string(),
        contents: raw.to_vec(),
    })
}

/// An ECDSA private key
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    key: p256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_using_rng(&mut rng)
    }

    /// Generate an INSECURE key usable for testing
    pub fn generate_insecure_key_for_testing(seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        Self::generate_using_rng(&mut rng)
    }

    /// Generate a new random private key using some provided RNG
    pub fn generate_using_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = p256::ecdsa::SigningKey::random(rng);
        Self { key }
    }

    /// Deserialize a private key encoded in SEC1 format
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let byte_array: [u8; <NistP256 as Curve>::FieldBytesSize::USIZE] =
            bytes.try_into().map_err(|_e| {
                KeyDecodingError::InvalidKeyEncoding(format!("invalid key size = {}.", bytes.len()))
            })?;

        let key = p256::ecdsa::SigningKey::from_bytes(&GenericArray::from(byte_array))
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in PKCS8 format
    pub fn deserialize_pkcs8_der(der: &[u8]) -> Result<Self, KeyDecodingError> {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in PKCS8 format with PEM encoding
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != "PRIVATE KEY" {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_pkcs8_der(&der.contents)
    }

    /// Serialize the private key to a simple bytestring
    ///
    /// This uses the SEC1 encoding, which is just the representation
    /// of the secret integer in a 32-byte array, encoding it using
    /// big-endian notation.
    pub fn serialize_sec1(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// Serialize the private key as PKCS8 format in DER encoding
    pub fn serialize_pkcs8_der(&self) -> Vec<u8> {
        der_encode_pkcs8_rfc5208_private_key(&self.serialize_sec1())
    }

    /// Serialize the private key as PKCS8 format in PEM encoding
    pub fn serialize_pkcs8_pem(&self) -> String {
        pem_encode(&self.serialize_pkcs8_der(), "PRIVATE KEY")
    }

    /// Sign a message
    ///
    /// The message is hashed with SHA-256
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Return the public key cooresponding to this private key
    pub fn public_key(&self) -> PublicKey {
        let key = self.key.verifying_key();
        PublicKey { key: *key }
    }
}

/// An ECDSA public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: p256::ecdsa::VerifyingKey,
}

impl PublicKey {
    /// Deserialize a public key stored in SEC1 format
    ///
    /// This is just the encoding of the point. Both compressed and uncompressed
    /// points are accepted
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in DER SubjectPublicKeyInfo format
    pub fn deserialize_der(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        use p256::pkcs8::DecodePublicKey;
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in PEM SubjectPublicKeyInfo format
    pub fn deserialize_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != "PUBLIC KEY" {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_der(&der.contents)
    }

    /// Serialize a public key in SEC1 format
    ///
    /// The point can optionally be compressed
    pub fn serialize_sec1(&self, compressed: bool) -> Vec<u8> {
        self.key.to_encoded_point(compressed).to_bytes().to_vec()
    }

    /// Serialize a public key in DER as a SubjectPublicKeyInfo
    pub fn serialize_der(&self) -> Vec<u8> {
        der_encode_ecdsa_spki_pubkey(&self.serialize_sec1(false))
    }

    /// Serialize a public key in PEM encoding of a SubjectPublicKeyInfo
    pub fn serialize_pem(&self) -> String {
        pem_encode(&self.serialize_der(), "PUBLIC KEY")
    }

    /// Verify a (message,signature) pair
    ///
    /// Be aware that this verification does not ensure non-malleability
    ///
    /// Some usages of ECDSA rely on non-malleability properties of ECDSA.  This
    /// particularly arises in the context of crypto currencies of various
    /// types. ECDSA signatures are usually malleable, in that if (r,s) is a
    /// valid signature, then (r,-s) is also valid. To avoid this malleability,
    /// some systems require that s be "normalized" to the smallest value.
    ///
    /// This normalization is quite common on secp256k1, but is virtually
    /// unknown and unimplemented for secp256r1. The vast majority of secp256r1
    /// signatures will not be normalized. Thus this verification *does not*
    /// ensure any non-malleability properties.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        let signature = match p256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        self.key.verify(message, &signature).is_ok()
    }
}
