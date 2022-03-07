//! Canister Http related public interfaces.
use crate::artifact_pool::UnvalidatedArtifact;
use ic_types::{
    artifact::{CanisterHttpResponseId, PriorityFn},
    canister_http::CanisterHttpResponseShare,
    Height,
};

pub enum CanisterHttpChangeAction {
    AddToValidated(CanisterHttpResponseShare),
    MoveToValidated(CanisterHttpResponseId),
    RemoveValidated(CanisterHttpResponseId),
    RemoveUnvalidated(CanisterHttpResponseId),
    HandleInvalid(CanisterHttpResponseId, String),
}

pub type CanisterHttpChangeSet = Vec<CanisterHttpChangeAction>;

/// Artifact pool for the ECDSA messages (query interface)
pub trait CanisterHttpPool: Send + Sync {
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_>;
    fn get_unvalidated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_>;
}

/// Artifact pool for the ECDSA messages (update interface)
pub trait MutableCanisterHttpPool: CanisterHttpPool {
    /// Adds the entry to the unvalidated section of the artifact pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<CanisterHttpResponseShare>);

    /// Mutates the artifact pool by applying the change set.
    fn apply_changes(&mut self, change_set: CanisterHttpChangeSet);
}

pub trait CanisterHttpGossip: Send + Sync {
    fn get_priority_function(
        &self,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> PriorityFn<CanisterHttpResponseId, Height>;
}
