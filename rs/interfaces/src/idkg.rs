//! IDKG related public interfaces.

use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::idkg::{
    EcdsaSigShare, IDkgMessage, IDkgPrefixOf, IDkgStats, SchnorrSigShare, SigShare,
    SignedIDkgComplaint, SignedIDkgOpening,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};

#[derive(Debug)]
pub enum IDkgChangeAction {
    AddToValidated(IDkgMessage),
    MoveToValidated(IDkgMessage),
    RemoveValidated(IDkgMessageId),
    RemoveUnvalidated(IDkgMessageId),
    HandleInvalid(IDkgMessageId, String),
}

pub type IDkgChangeSet = Vec<IDkgChangeAction>;

#[derive(Debug, Clone)]
pub enum IDkgPoolSectionOp {
    Insert(IDkgMessage),
    Remove(IDkgMessageId),
}

#[derive(Clone, Debug, Default)]
pub struct IDkgPoolSectionOps {
    pub ops: Vec<IDkgPoolSectionOp>,
}

impl IDkgPoolSectionOps {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn insert(&mut self, message: IDkgMessage) {
        self.ops.push(IDkgPoolSectionOp::Insert(message));
    }

    pub fn remove(&mut self, id: IDkgMessageId) {
        self.ops.push(IDkgPoolSectionOp::Remove(id));
    }
}

/// The validated/unvalidated parts of the artifact pool.
pub trait IDkgPoolSection: Send + Sync {
    /// Checks if the artifact present in the pool.
    fn contains(&self, msg_id: &IDkgMessageId) -> bool;

    /// Looks up an artifact by the Id.
    fn get(&self, msg_id: &IDkgMessageId) -> Option<IDkgMessage>;

    /// Iterator for signed dealing objects.
    fn signed_dealings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_>;

    /// Iterator for signed dealing objects matching the prefix.
    fn signed_dealings_by_prefix(
        &self,
        _prefix: IDkgPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        unimplemented!()
    }

    /// Iterator for dealing support objects.
    fn dealing_support(&self)
        -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_>;

    /// Iterator for dealing support objects matching the prefix.
    fn dealing_support_by_prefix(
        &self,
        _prefix: IDkgPrefixOf<IDkgDealingSupport>,
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
        _prefix: IDkgPrefixOf<EcdsaSigShare>,
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
        _prefix: IDkgPrefixOf<SchnorrSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        unimplemented!()
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SigShare)> + '_>;

    /// Iterator for complaint objects.
    fn complaints(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_>;

    /// Iterator for complaint objects matching the prefix.
    fn complaints_by_prefix(
        &self,
        _prefix: IDkgPrefixOf<SignedIDkgComplaint>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_> {
        unimplemented!()
    }

    /// Iterator for opening objects.
    fn openings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_>;

    /// Iterator for opening objects matching the prefix.
    fn openings_by_prefix(
        &self,
        _prefix: IDkgPrefixOf<SignedIDkgOpening>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_> {
        unimplemented!()
    }
}

/// The mutable interface for validated/unvalidated parts of the artifact pool.
pub trait MutableIDkgPoolSection: Send + Sync {
    /// Applies the changes to the pool.
    fn mutate(&mut self, ops: IDkgPoolSectionOps);

    /// Get the immutable handle.
    fn as_pool_section(&self) -> &dyn IDkgPoolSection;
}

/// Artifact pool for the IDKG messages (query interface)
pub trait IDkgPool: Send + Sync {
    /// Return a reference to the validated PoolSection.
    fn validated(&self) -> &dyn IDkgPoolSection;

    /// Return a reference to the unvalidated PoolSection.
    fn unvalidated(&self) -> &dyn IDkgPoolSection;

    /// Returns reference to the stats. The stats are not persisted.
    fn stats(&self) -> &dyn IDkgStats;
}
