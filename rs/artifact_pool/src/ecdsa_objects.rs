//! Definitions for the ECDSA objects that are stored in the ECDSA artifact
//! pool.

use ic_crypto::crypto_hash;
use ic_interfaces::crypto::CryptoHashable;
use ic_types::consensus::ecdsa::{
    EcdsaDealing, EcdsaDealingSupport, EcdsaMessage, EcdsaMessageHash,
};
use ic_types::crypto::CryptoHashOf;

/// EcdsaObject should be implemented by types that go into the artifact pool.
/// EcdsaObject represents the objects that go into the EcdsaObjectPool
/// (i.e) the inner message variants in EdsaMessage like EcdsaDealing,
/// EcdsaDealingSupport, etc.
pub(crate) trait EcdsaObject: CryptoHashable + Clone + Sized {
    /// Returns crypto hash of the object used as key.
    fn key(&self) -> CryptoHashOf<Self> {
        crypto_hash(self)
    }

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
