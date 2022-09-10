//! Definitions for the ECDSA objects that are stored in the ECDSA artifact
//! pool.

use ic_types::consensus::ecdsa::{
    complaint_prefix, dealing_prefix, dealing_support_prefix, opening_prefix, sig_share_prefix,
    EcdsaArtifactId, EcdsaComplaint, EcdsaMessage, EcdsaOpening, EcdsaPrefixOf, EcdsaSigShare,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};
use ic_types::crypto::crypto_hash;
use ic_types::crypto::CryptoHashable;

/// EcdsaObject should be implemented by the ECDSA message types
/// (e.g) EcdsaSignedDealing, EcdsaDealingSupport, etc
pub trait EcdsaObject: CryptoHashable + Clone + Sized {
    /// Returns the artifact prefix.
    fn message_prefix(&self) -> EcdsaPrefixOf<Self>;

    /// Returns the artifact Id.
    fn message_id(&self) -> EcdsaArtifactId;
}

impl EcdsaObject for SignedIDkgDealing {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        dealing_prefix(&self.idkg_dealing().transcript_id, &self.dealer_id())
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Dealing(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for IDkgDealingSupport {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        dealing_support_prefix(&self.transcript_id, &self.dealer_id, &self.sig_share.signer)
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::DealingSupport(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaSigShare {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        sig_share_prefix(&self.request_id, &self.signer_id)
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::SigShare(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaComplaint {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        complaint_prefix(
            &self.content.idkg_complaint.transcript_id,
            &self.content.idkg_complaint.dealer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Complaint(self.message_prefix(), crypto_hash(self))
    }
}

impl EcdsaObject for EcdsaOpening {
    fn message_prefix(&self) -> EcdsaPrefixOf<Self> {
        opening_prefix(
            &self.content.idkg_opening.transcript_id,
            &self.content.idkg_opening.dealer_id,
            &self.content.complainer_id,
            &self.signature.signer,
        )
    }

    fn message_id(&self) -> EcdsaArtifactId {
        EcdsaArtifactId::Opening(self.message_prefix(), crypto_hash(self))
    }
}

pub fn ecdsa_msg_id(msg: &EcdsaMessage) -> EcdsaArtifactId {
    match msg {
        EcdsaMessage::EcdsaSignedDealing(object) => object.message_id(),
        EcdsaMessage::EcdsaDealingSupport(object) => object.message_id(),
        EcdsaMessage::EcdsaSigShare(object) => object.message_id(),
        EcdsaMessage::EcdsaComplaint(object) => object.message_id(),
        EcdsaMessage::EcdsaOpening(object) => object.message_id(),
    }
}
