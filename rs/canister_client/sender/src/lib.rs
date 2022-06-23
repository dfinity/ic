use ed25519_dalek::{Keypair, Signer, KEYPAIR_LENGTH};
use ic_crypto_sha::Sha256;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_types::{messages::MessageId, PrincipalId};
use std::{error::Error, sync::Arc};

/// A version of Keypair with a clone instance.
/// Originally this was done with a reference, but I'm avoiding them in async
/// testing because it makes the tests much harder to write.
/// This is a little inefficient, but it's only used for testing
#[derive(Clone, Copy)]
pub struct ClonableKeyPair {
    bytes: [u8; KEYPAIR_LENGTH],
}

impl ClonableKeyPair {
    fn new(kp: &Keypair) -> Self {
        ClonableKeyPair {
            bytes: kp.to_bytes(),
        }
    }

    fn get(&self) -> Keypair {
        Keypair::from_bytes(&self.bytes).unwrap()
    }
}

pub type SignF = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;
pub type SignFID = Arc<dyn Fn(&MessageId) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;

#[derive(Clone)]
pub struct Secp256k1KeyPair {
    sk: ecdsa_secp256k1::types::SecretKeyBytes,
    pk: ecdsa_secp256k1::types::PublicKeyBytes,
}

#[derive(Clone)]
pub enum SigKeys {
    EcdsaSecp256k1(Secp256k1KeyPair),
}

/// Represents the identity of the sender.
#[derive(Clone)]
pub enum Sender {
    /// The sender is defined as public/private keypair.
    KeyPair(ClonableKeyPair),

    /// The sender is defined as a public/private keypair of a signature scheme,
    /// not bound to a specific scheme.
    /// TODO: add handling of Ed25519-keys, and remove `KeyPair`-variant above
    SigKeys(SigKeys),

    /// The sender is authenticated via an external HSM devices and the
    /// signature mechanism is specified through the provided function
    /// reference.
    ExternalHsm {
        /// DER encoded public key
        pub_key: Vec<u8>,
        /// Function that abstracts the external HSM.
        sign: SignF,
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
        sign: SignFID,
    },
}

impl Sender {
    pub fn from_keypair(kp: &Keypair) -> Self {
        Sender::KeyPair(ClonableKeyPair::new(kp))
    }

    pub fn from_secp256k1_keys(sk_bytes: &[u8], pk_bytes: &[u8]) -> Self {
        let pk = ecdsa_secp256k1::types::PublicKeyBytes::from(pk_bytes.to_vec());
        let sk = ecdsa_secp256k1::api::secret_key_from_components(sk_bytes, &pk).unwrap();
        Sender::SigKeys(SigKeys::EcdsaSecp256k1(Secp256k1KeyPair { sk, pk }))
    }

    pub fn from_external_hsm(pub_key: Vec<u8>, sign: SignF) -> Self {
        Sender::ExternalHsm { pub_key, sign }
    }

    pub fn from_principal_id(principal_id: PrincipalId) -> Self {
        Sender::PrincipalId(principal_id)
    }

    pub fn get_principal_id(&self) -> PrincipalId {
        match self {
            Self::KeyPair(keypair) => PrincipalId::new_self_authenticating(
                &ed25519_public_key_to_der(keypair.get().public.to_bytes().to_vec()),
            ),
            Self::SigKeys(sig_keys) => match sig_keys {
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
            Self::Node { sign, .. } => sign(msg_id).map(Some),
            _ => {
                let mut sig_data = vec![];
                sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
                sig_data.extend_from_slice(msg_id.as_bytes());
                self.sign(&sig_data)
            }
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        match self {
            Self::KeyPair(keypair) => Ok(Some(keypair.get().sign(msg).to_bytes().to_vec())),
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
                    // in ECDSA), so we do it here with SHA256, which is the only
                    // supported hash currently.
                    let msg_hash = Sha256::hash(msg);
                    Ok(Some(
                        ecdsa_secp256k1::api::sign(&msg_hash, &key_pair.sk)
                            .expect("ECDSA-secp256k1 signing failed")
                            .0
                            .to_vec(),
                    ))
                }
            },
            Self::ExternalHsm { sign, .. } => sign(msg).map(Some),
            Self::Anonymous => Ok(None),
            Self::PrincipalId(_) => Ok(None),
            Self::Node { .. } => unreachable!("Wrong case of agent.sign()"),
        }
    }

    pub fn sender_pubkey_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::KeyPair(keypair) => Some(ed25519_public_key_to_der(
                keypair.get().public.to_bytes().to_vec(),
            )),
            Self::SigKeys(sig_keys) => match sig_keys {
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
