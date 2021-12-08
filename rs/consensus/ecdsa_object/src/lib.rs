//! Definitions for the ECDSA objects that are stored in the ECDSA artifact
//! pool.

use ic_crypto::crypto_hash;
use ic_interfaces::crypto::CryptoHashable;
use ic_types::consensus::ecdsa::{
    EcdsaDealing, EcdsaDealingSupport, EcdsaMessage, EcdsaMessageHash, EcdsaSigShare,
};
use ic_types::crypto::CryptoHashOf;

/// EcdsaObject should be implemented by types that go into the artifact pool.
/// EcdsaObject represents the objects that go into the EcdsaObjectPool
/// (i.e) the inner message variants in EdsaMessage like EcdsaDealing,
/// EcdsaDealingSupport, etc.
pub trait EcdsaObject: CryptoHashable + Clone + Sized {
    /// Returns crypto hash of the object used as key.
    fn key(&self) -> CryptoHashOf<Self> {
        crypto_hash(self)
    }

    /// Returns the EcdsaMessageHash(EcdsaMessageId) for this object.
    fn outer_hash(&self) -> EcdsaMessageHash;

    /// Converts the inner object to the outer EcdsaMessage.
    fn into_outer(self) -> EcdsaMessage;

    /// Extracts the individual crypto hash from the EcdsaMessageHash.
    fn key_from_outer_hash(hash: &EcdsaMessageHash) -> CryptoHashOf<Self>;

    /// Converts the individual crypto hash to EcdsaMessageHash.
    fn key_to_outer_hash(inner_hash: &CryptoHashOf<Self>) -> EcdsaMessageHash;
}

impl EcdsaObject for EcdsaDealing {
    fn into_outer(self) -> EcdsaMessage {
        EcdsaMessage::EcdsaDealing(self)
    }

    fn outer_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaDealing(self.key())
    }

    fn key_from_outer_hash(hash: &EcdsaMessageHash) -> CryptoHashOf<Self> {
        if let EcdsaMessageHash::EcdsaDealing(hash) = hash {
            hash.clone()
        } else {
            panic!(
                "EcdsaDealing::key_from_outer_hash(): unexpected type: {:?}",
                hash
            );
        }
    }

    fn key_to_outer_hash(inner_hash: &CryptoHashOf<Self>) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaDealing(inner_hash.clone())
    }
}

impl EcdsaObject for EcdsaDealingSupport {
    fn into_outer(self) -> EcdsaMessage {
        EcdsaMessage::EcdsaDealingSupport(self)
    }

    fn outer_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaDealingSupport(self.key())
    }

    fn key_from_outer_hash(hash: &EcdsaMessageHash) -> CryptoHashOf<Self> {
        if let EcdsaMessageHash::EcdsaDealingSupport(hash) = hash {
            hash.clone()
        } else {
            panic!(
                "EcdsaDealingSupport::key_from_outer_hash(): unexpected type: {:?}",
                hash
            );
        }
    }

    fn key_to_outer_hash(inner_hash: &CryptoHashOf<Self>) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaDealingSupport(inner_hash.clone())
    }
}

impl EcdsaObject for EcdsaSigShare {
    fn into_outer(self) -> EcdsaMessage {
        EcdsaMessage::EcdsaSigShare(self)
    }

    fn outer_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaSigShare(self.key())
    }

    fn key_from_outer_hash(hash: &EcdsaMessageHash) -> CryptoHashOf<Self> {
        if let EcdsaMessageHash::EcdsaSigShare(hash) = hash {
            hash.clone()
        } else {
            panic!(
                "EcdsaSigShare::key_from_outer_hash(): unexpected type: {:?}",
                hash
            );
        }
    }

    fn key_to_outer_hash(inner_hash: &CryptoHashOf<Self>) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaSigShare(inner_hash.clone())
    }
}

pub fn ecdsa_msg_hash(msg: &EcdsaMessage) -> EcdsaMessageHash {
    match msg {
        EcdsaMessage::EcdsaDealing(object) => object.outer_hash(),
        EcdsaMessage::EcdsaDealingSupport(object) => object.outer_hash(),
        EcdsaMessage::EcdsaSigShare(object) => object.outer_hash(),
    }
}
