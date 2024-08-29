mod secp256k1_conversions;
#[cfg(test)]
mod tests;

use ic_base_types::PrincipalId;
use ic_types::crypto::DOMAIN_IC_REQUEST;
use ic_types::messages::MessageId;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{error::Error, sync::Arc};

// TODO: migrate the two closures to async closures when supported by Rust.
// The closures are called within async context. So putting the signing function in
// an async closure signals the intent that the duration of running the closure
// should be small - O(milliseconds).
pub type SignBytes = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;
pub type SignMessageId = Arc<dyn Fn(&MessageId) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;

/// A secp256k1 key pair
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    sk: ic_crypto_secp256k1::PrivateKey,
    /// The public key bytes only.
    pk: ic_crypto_secp256k1::PublicKey,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ed25519KeyPair {
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Ed25519KeyPair {
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut rng = ChaCha20Rng::from_seed(rng.gen());
        let key = ic_crypto_ed25519::PrivateKey::generate_using_rng(&mut rng);
        Self {
            secret_key: key.serialize_raw(),
            public_key: key.public_key().serialize_raw(),
        }
    }

    /// Parses an Ed25519KeyPair from a PEM string.
    pub fn from_pem(pem: &str) -> Result<Self, ic_crypto_ed25519::PrivateKeyDecodingError> {
        let key = ic_crypto_ed25519::PrivateKey::deserialize_pkcs8_pem(pem)?;
        Ok(Ed25519KeyPair {
            secret_key: key.serialize_raw(),
            public_key: key.public_key().serialize_raw(),
        })
    }

    pub fn to_pem(&self) -> String {
        let key = ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&self.secret_key);
        key.serialize_pkcs8_pem(ic_crypto_ed25519::PrivateKeyFormat::Pkcs8v2WithRingBug)
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let key = ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&self.secret_key);
        key.sign_message(msg)
    }
}

impl Secp256k1KeyPair {
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign_message_with_ecdsa(msg).to_vec()
    }
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut rng = ChaCha20Rng::from_seed(rng.gen());
        let sk = ic_crypto_secp256k1::PrivateKey::generate_using_rng(&mut rng);
        let pk = sk.public_key();
        Self { sk, pk }
    }
    pub fn get_public_key(&self) -> ic_crypto_secp256k1::PublicKey {
        self.pk.clone()
    }
}

#[derive(Clone)]
pub enum SigKeys {
    Ed25519(Ed25519KeyPair),
    EcdsaSecp256k1(Secp256k1KeyPair),
}

impl SigKeys {
    /// Parses a key pair from a PEM file.
    pub fn from_pem(pem: &str) -> Result<Self, &'static str> {
        if let Ok(secp_key) = Secp256k1KeyPair::from_pem(pem) {
            Ok(SigKeys::EcdsaSecp256k1(secp_key))
        } else if let Ok(ed25519_key) = Ed25519KeyPair::from_pem(pem) {
            Ok(SigKeys::Ed25519(ed25519_key))
        } else {
            Err("unsupported or malformed secret key pem")
        }
    }
}

/// Represents the identity of the sender.
#[derive(Clone)]
pub enum Sender {
    /// The sender is defined as a public/private keypair of a signature scheme,
    /// not bound to a specific scheme.
    SigKeys(SigKeys),

    /// The sender is authenticated via an external HSM devices and the
    /// signature mechanism is specified through the provided function
    /// reference.
    ExternalHsm {
        /// DER encoded public key
        pub_key: Vec<u8>,
        /// Function that abstracts the external HSM.
        sign: SignBytes,
    },
    /// The anonymous sender is used (no signature).
    Anonymous,
    /// Principal ID (no signature)
    PrincipalId(PrincipalId),
    /// Signed from the node itself, with its key.
    Node {
        /// DER encoded public key
        pub_key: Vec<u8>,
        /// Function that signs the message id
        sign: SignMessageId,
    },
}

impl Sender {
    pub fn from_keypair(kp: &Ed25519KeyPair) -> Self {
        Self::from_ed25519_key_pair(*kp)
    }

    pub fn from_ed25519_key_pair(keys: Ed25519KeyPair) -> Self {
        Sender::SigKeys(SigKeys::Ed25519(keys))
    }

    pub fn from_secp256k1_keys(
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<Self, ic_crypto_secp256k1::KeyDecodingError> {
        let pk = ic_crypto_secp256k1::PublicKey::deserialize_sec1(pk_bytes)?;
        let sk = ic_crypto_secp256k1::PrivateKey::deserialize_sec1(sk_bytes)?;
        Ok(Sender::SigKeys(SigKeys::EcdsaSecp256k1(Secp256k1KeyPair {
            sk,
            pk,
        })))
    }

    pub fn from_external_hsm(pub_key: Vec<u8>, sign: SignBytes) -> Self {
        Sender::ExternalHsm { pub_key, sign }
    }

    pub fn from_principal_id(principal_id: PrincipalId) -> Self {
        Sender::PrincipalId(principal_id)
    }

    pub fn get_principal_id(&self) -> PrincipalId {
        match self {
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::Ed25519(key_pair) => PrincipalId::new_self_authenticating(
                    &ed25519_public_key_to_der(key_pair.public_key.to_vec()),
                ),
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    PrincipalId::new_self_authenticating(&key_pair.pk.serialize_der())
                }
            },
            Self::ExternalHsm { pub_key, .. } => PrincipalId::new_self_authenticating(pub_key),
            Self::Anonymous => PrincipalId::new_anonymous(),
            Self::PrincipalId(id) => *id,
            Self::Node { pub_key, .. } => {
                PrincipalId::new_self_authenticating(&ed25519_public_key_to_der(pub_key.clone()))
            }
        }
    }

    pub fn sign_message_id(&self, msg_id: &MessageId) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        match self {
            // When signing from the node the domain separator is added by the signing function.
            Self::Node { sign, .. } => sign(msg_id).map(Some),
            _ => self.sign_with_ic_domain_separator(msg_id.as_bytes()),
        }
    }

    fn sign_with_ic_domain_separator(
        &self,
        raw_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut msg = vec![];
        msg.extend_from_slice(DOMAIN_IC_REQUEST);
        msg.extend_from_slice(raw_msg);
        match self {
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::Ed25519(key_pair) => Ok(Some(key_pair.sign(&msg).to_vec())),
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    Ok(Some(key_pair.sk.sign_message_with_ecdsa(&msg).to_vec()))
                }
            },
            Self::ExternalHsm { sign, .. } => sign(&msg).map(Some),
            Self::Anonymous => Ok(None),
            Self::PrincipalId(_) => Ok(None),
            Self::Node { .. } => unreachable!("Wrong case of agent.sign()"),
        }
    }

    pub fn sender_pubkey_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::Ed25519(key_pair) => {
                    Some(ed25519_public_key_to_der(key_pair.public_key.to_vec()))
                }
                SigKeys::EcdsaSecp256k1(key_pair) => Some(key_pair.pk.serialize_der()),
            },
            Self::ExternalHsm { pub_key, .. } => Some(pub_key.clone()),
            Self::Anonymous => None,
            Self::PrincipalId(_) => None,
            Self::Node { pub_key, .. } => Some(ed25519_public_key_to_der(pub_key.clone())),
        }
    }
}

/// This is a minimal implementation of DER-encoding for Ed25519, as the keys
/// are constant-length. The format is an ASN.1 SubjectPublicKeyInfo, whose
/// header contains the OID for Ed25519, as specified in RFC 8410:
/// https://tools.ietf.org/html/rfc8410
pub fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    // The constant is the prefix of the DER encoding of the ASN.1
    // SubjectPublicKeyInfo data structure. It can be read as follows:
    // 0x30 0x2A: Sequence of length 42 bytes
    //   0x30 0x05: Sequence of length 5 bytes
    //     0x06 0x03 0x2B 0x65 0x70: OID of length 3 bytes, 1.3.101.112 (where 43 =
    //              1 * 40 + 3)
    //   0x03 0x21: Bit string of length 33 bytes
    //     0x00 [raw key]: No padding [raw key]
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    encoded.append(&mut key);
    encoded
}

pub fn ed25519_public_key_from_der(mut key_der: Vec<u8>) -> Vec<u8> {
    assert!(key_der.len() > 12);
    key_der.drain(0..12);
    key_der
}
