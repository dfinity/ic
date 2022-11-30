mod secp256k1_conversions;
#[cfg(test)]
mod tests;

use ic_base_types::PrincipalId;
use ic_crypto_internal_types::sign::eddsa::ed25519::SecretKey as Ed25519SecretKey;
use ic_crypto_sha::Sha256;
use ic_crypto_utils_basic_sig::conversions::Ed25519PemParseError;
use ic_crypto_utils_basic_sig::conversions::Ed25519SecretKeyConversions;
use ic_types::crypto::DOMAIN_IC_REQUEST;
use ic_types::messages::MessageId;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{error::Error, sync::Arc};

pub type SignBytes = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;
pub type SignMessageId = Arc<dyn Fn(&MessageId) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;

/// A secp256k1 key pair
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    /// The DER encoded secret key and the curve parameters.
    ///
    /// The data structure expected downstream is that used by
    /// [https://www.openssl.org/docs/man1.0.2/man3/d2i_ECPrivate_key.html]()
    /// so while sk doesn't match the ed25519 structure below, it is what
    /// is needed.
    ///
    /// TODO: Check with downstream developers; perhaps we can add a "der" field
    /// with the current data and keep just the 32 byes of the key itself in sk.
    sk: ecdsa_secp256k1::types::SecretKeyBytes,
    /// The public key bytes only.
    pk: ecdsa_secp256k1::types::PublicKeyBytes,
}

#[derive(Copy, Clone, Debug)]
pub struct Ed25519KeyPair {
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Ed25519KeyPair {
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let rng = ChaCha20Rng::from_seed(rng.gen());
        let signing_key = ed25519_consensus::SigningKey::new(rng);
        Self {
            secret_key: signing_key.to_bytes(),
            public_key: signing_key.verification_key().to_bytes(),
        }
    }

    /// Parses an Ed25519KeyPair from a PEM string.
    pub fn from_pem(pem: &str) -> Result<Self, Ed25519PemParseError> {
        let (secret_key, public_key) = Ed25519SecretKey::from_pem(pem)?;
        Ok(Ed25519KeyPair {
            secret_key: secret_key.0,
            public_key: public_key.0,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let signing_key = ed25519_consensus::SigningKey::from(self.secret_key);
        signing_key.sign(msg).to_bytes()
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

    pub fn from_secp256k1_keys(sk_bytes: &[u8], pk_bytes: &[u8]) -> Self {
        let pk = ecdsa_secp256k1::types::PublicKeyBytes::from(pk_bytes.to_vec());
        let sk = ecdsa_secp256k1::api::secret_key_from_components(sk_bytes, &pk).unwrap();
        Sender::SigKeys(SigKeys::EcdsaSecp256k1(Secp256k1KeyPair { sk, pk }))
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
                SigKeys::EcdsaSecp256k1(key_pair) => PrincipalId::new_self_authenticating(
                    &ecdsa_secp256k1::api::public_key_to_der(&key_pair.pk).unwrap(),
                ),
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
                    // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
                    // in ECDSA), so we do it here with SHA256, which is the only
                    // supported hash currently.
                    let msg_hash = Sha256::hash(&msg);
                    Ok(Some(
                        ecdsa_secp256k1::api::sign(&msg_hash, &key_pair.sk)
                            .expect("ECDSA-secp256k1 signing failed")
                            .0
                            .to_vec(),
                    ))
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
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    Some(ecdsa_secp256k1::api::public_key_to_der(&key_pair.pk).unwrap())
                }
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
