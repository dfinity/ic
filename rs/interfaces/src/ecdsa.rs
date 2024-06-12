//! ECDSA related public interfaces.

use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::idkg::{
    EcdsaComplaint, EcdsaMessage, EcdsaOpening, EcdsaPrefixOf, EcdsaSigShare, EcdsaStats,
    SchnorrSigShare, SigShare,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};

// TODO: purge/remove from validated
#[derive(Debug)]
pub enum EcdsaChangeAction {
    AddToValidated(EcdsaMessage),
    MoveToValidated(EcdsaMessage),
    RemoveValidated(EcdsaMessageId),
    RemoveUnvalidated(EcdsaMessageId),
    HandleInvalid(EcdsaMessageId, String),
}

pub type EcdsaChangeSet = Vec<EcdsaChangeAction>;

#[derive(Debug, Clone)]
pub enum EcdsaPoolSectionOp {
    Insert(EcdsaMessage),
    Remove(EcdsaMessageId),
}

#[derive(Clone, Debug, Default)]
pub struct EcdsaPoolSectionOps {
    pub ops: Vec<EcdsaPoolSectionOp>,
}

impl EcdsaPoolSectionOps {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn insert(&mut self, message: EcdsaMessage) {
        self.ops.push(EcdsaPoolSectionOp::Insert(message));
    }

    pub fn remove(&mut self, id: EcdsaMessageId) {
        self.ops.push(EcdsaPoolSectionOp::Remove(id));
    }
}

/// The validated/unvalidated parts of the artifact pool.
pub trait EcdsaPoolSection: Send + Sync {
    /// Checks if the artifact present in the pool.
    fn contains(&self, msg_id: &EcdsaMessageId) -> bool;

    /// Looks up an artifact by the Id.
    fn get(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage>;

    /// Iterator for signed dealing objects.
    fn signed_dealings(&self)
        -> Box<dyn Iterator<Item = (EcdsaMessageId, SignedIDkgDealing)> + '_>;

    /// Iterator for signed dealing objects matching the prefix.
    fn signed_dealings_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, SignedIDkgDealing)> + '_> {
        unimplemented!()
    }

    /// Iterator for dealing support objects.
    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, IDkgDealingSupport)> + '_>;

    /// Iterator for dealing support objects matching the prefix.
    fn dealing_support_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<IDkgDealingSupport>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, IDkgDealingSupport)> + '_> {
        unimplemented!()
    }

    /// Iterator for signature share objects.
    fn ecdsa_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSigShare)> + '_>;

    /// Iterator for signature share objects matching the prefix.
    fn ecdsa_signature_shares_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaSigShare>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSigShare)> + '_> {
        unimplemented!()
    }

    /// Iterator for signature share objects.
    fn schnorr_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, SchnorrSigShare)> + '_>;

    /// Iterator for signature share objects matching the prefix.
    fn schnorr_signature_shares_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<SchnorrSigShare>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, SchnorrSigShare)> + '_> {
        unimplemented!()
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, SigShare)> + '_>;

    /// Iterator for complaint objects.
    fn complaints(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaComplaint)> + '_>;

    /// Iterator for complaint objects matching the prefix.
    fn complaints_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaComplaint>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaComplaint)> + '_> {
        unimplemented!()
    }

    /// Iterator for opening objects.
    fn openings(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaOpening)> + '_>;

    /// Iterator for opening objects matching the prefix.
    fn openings_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaOpening>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaOpening)> + '_> {
        unimplemented!()
    }
}

/// The mutable interface for validated/unvalidated parts of the artifact pool.
pub trait MutableEcdsaPoolSection: Send + Sync {
    /// Applies the changes to the pool.
    fn mutate(&mut self, ops: EcdsaPoolSectionOps);

    /// Get the immutable handle.
    fn as_pool_section(&self) -> &dyn EcdsaPoolSection;
}

/// Artifact pool for the ECDSA messages (query interface)
pub trait EcdsaPool: Send + Sync {
    /// Return a reference to the validated PoolSection.
    fn validated(&self) -> &dyn EcdsaPoolSection;

    /// Return a reference to the unvalidated PoolSection.
    fn unvalidated(&self) -> &dyn EcdsaPoolSection;

    /// Returns reference to the stats. The stats are not persisted.
    fn stats(&self) -> &dyn EcdsaStats;
}
