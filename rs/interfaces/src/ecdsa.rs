//! ECDSA related public interfaces.

use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::idkg::{
    EcdsaComplaint, EcdsaOpening, EcdsaPrefixOf, EcdsaSigShare, EcdsaStats, IDkgMessage,
    SchnorrSigShare, SigShare,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};

// TODO: purge/remove from validated
#[derive(Debug)]
pub enum EcdsaChangeAction {
    AddToValidated(IDkgMessage),
    MoveToValidated(IDkgMessage),
    RemoveValidated(IDkgMessageId),
    RemoveUnvalidated(IDkgMessageId),
    HandleInvalid(IDkgMessageId, String),
}

pub type EcdsaChangeSet = Vec<EcdsaChangeAction>;

#[derive(Debug, Clone)]
pub enum EcdsaPoolSectionOp {
    Insert(IDkgMessage),
    Remove(IDkgMessageId),
}

#[derive(Clone, Debug, Default)]
pub struct EcdsaPoolSectionOps {
    pub ops: Vec<EcdsaPoolSectionOp>,
}

impl EcdsaPoolSectionOps {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn insert(&mut self, message: IDkgMessage) {
        self.ops.push(EcdsaPoolSectionOp::Insert(message));
    }

    pub fn remove(&mut self, id: IDkgMessageId) {
        self.ops.push(EcdsaPoolSectionOp::Remove(id));
    }
}

/// The validated/unvalidated parts of the artifact pool.
pub trait EcdsaPoolSection: Send + Sync {
    /// Checks if the artifact present in the pool.
    fn contains(&self, msg_id: &IDkgMessageId) -> bool;

    /// Looks up an artifact by the Id.
    fn get(&self, msg_id: &IDkgMessageId) -> Option<IDkgMessage>;

    /// Iterator for signed dealing objects.
    fn signed_dealings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_>;

    /// Iterator for signed dealing objects matching the prefix.
    fn signed_dealings_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        unimplemented!()
    }

    /// Iterator for dealing support objects.
    fn dealing_support(&self)
        -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_>;

    /// Iterator for dealing support objects matching the prefix.
    fn dealing_support_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<IDkgDealingSupport>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        unimplemented!()
    }

    /// Iterator for signature share objects.
    fn ecdsa_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_>;

    /// Iterator for signature share objects matching the prefix.
    fn ecdsa_signature_shares_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_> {
        unimplemented!()
    }

    /// Iterator for signature share objects.
    fn schnorr_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_>;

    /// Iterator for signature share objects matching the prefix.
    fn schnorr_signature_shares_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<SchnorrSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        unimplemented!()
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SigShare)> + '_>;

    /// Iterator for complaint objects.
    fn complaints(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaComplaint)> + '_>;

    /// Iterator for complaint objects matching the prefix.
    fn complaints_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaComplaint>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaComplaint)> + '_> {
        unimplemented!()
    }

    /// Iterator for opening objects.
    fn openings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaOpening)> + '_>;

    /// Iterator for opening objects matching the prefix.
    fn openings_by_prefix(
        &self,
        _prefix: EcdsaPrefixOf<EcdsaOpening>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaOpening)> + '_> {
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
