//! Canister Http related public interfaces.
use crate::artifact_pool::UnvalidatedArtifact;
use crate::consensus_pool::ConsensusPoolCache;
use ic_types::crypto::CryptoHashOf;
use ic_types::{
    artifact::{CanisterHttpResponseId, PriorityFn},
    canister_http::{CanisterHttpResponseContent, CanisterHttpResponseShare},
    Height,
};

pub enum CanisterHttpChangeAction {
    AddToValidated(CanisterHttpResponseShare, CanisterHttpResponseContent),
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
    fn get_response_content_items(
        &self,
    ) -> Box<
        dyn Iterator<
                Item = (
                    &CryptoHashOf<CanisterHttpResponseContent>,
                    &CanisterHttpResponseContent,
                ),
            > + '_,
    >;

    fn lookup_validated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare>;

    fn lookup_unvalidated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare>;
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

pub trait CanisterHttpPoolManager: Send {
    /// A function to be invoked every time the canister http pool is changed.
    fn on_state_change(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet;
}

pub enum CanisterHttpResponseAttribute {
    None,
}
