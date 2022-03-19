//! Definitions for the ECDSA objects that are stored in the ECDSA artifact
//! pool.

use ic_crypto_hash::crypto_hash;
use ic_interfaces::crypto::CryptoHashable;
use ic_types::consensus::ecdsa::{
    EcdsaComplaint, EcdsaDealingSupport, EcdsaMessage, EcdsaMessageHash, EcdsaOpening,
    EcdsaSigShare, EcdsaSignedDealing,
};

/// EcdsaObject should be implemented by the ECDSA message types
/// (e.g) EcdsaSignedDealing, EcdsaDealingSupport, etc
pub trait EcdsaObject: CryptoHashable + Clone + Sized {
    /// Returns EcdsaMessageHash of the object used as key.
    fn message_hash(&self) -> EcdsaMessageHash;
}

impl EcdsaObject for EcdsaSignedDealing {
    fn message_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaSignedDealing(crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaDealingSupport {
    fn message_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaDealingSupport(crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaSigShare {
    fn message_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaSigShare(crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaComplaint {
    fn message_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaComplaint(crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaOpening {
    fn message_hash(&self) -> EcdsaMessageHash {
        EcdsaMessageHash::EcdsaOpening(crypto_hash(self))
    }
}

pub fn ecdsa_msg_hash(msg: &EcdsaMessage) -> EcdsaMessageHash {
    match msg {
        EcdsaMessage::EcdsaSignedDealing(object) => object.message_hash(),
        EcdsaMessage::EcdsaDealingSupport(object) => object.message_hash(),
        EcdsaMessage::EcdsaSigShare(object) => object.message_hash(),
        EcdsaMessage::EcdsaComplaint(object) => object.message_hash(),
        EcdsaMessage::EcdsaOpening(object) => object.message_hash(),
    }
}
