//! The DKG public interface.
use crate::artifact_pool::UnvalidatedArtifact;
use ic_types::{
    artifact::{DkgMessageAttribute, DkgMessageId, PriorityFn},
    consensus::dkg,
    crypto::CryptoHashOf,
    Height,
};
use std::time::Duration;

/// An interface for distributed key generation.
pub trait Dkg: Send {
    fn on_state_change(&self, dkg_pool: &dyn DkgPool) -> ChangeSet;
}

/// Methods related to gossiping DKG.
pub trait DkgGossip: Send + Sync {
    fn get_priority_function(
        &self,
        dkg_pool: &dyn DkgPool,
    ) -> PriorityFn<DkgMessageId, DkgMessageAttribute>;
}

/// The DkgPool is used to store messages that are exchanged between nodes in
/// the process of executing dkg.
pub trait DkgPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// Returns the validated entries older than the age threshold
    fn get_validated_older_than(
        &self,
        age_threshold: Duration,
    ) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// The start height of the currently _computed_ DKG interval; the invariant
    /// we want to maintain for all messages in validated and unvalidated
    /// sections is that they correspond to a DKG Id with the start height
    /// equal to current_start_height.
    fn get_current_start_height(&self) -> Height;
    /// Checks if the message is present in the validated section.
    fn validated_contains(&self, msg: &dkg::Message) -> bool;
}

/// Trait containing only mutable functions wrt. DkgPool
pub trait MutableDkgPool: DkgPool {
    /// Inserts a dkg message into the unvalidated part of the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<dkg::Message>);

    /// Applies a set of change actions to the pool.
    fn apply_changes(&mut self, change_set: ChangeSet);
}

/// Various actions that can be perfomed in DKG.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ChangeAction {
    AddToValidated(dkg::Message),
    MoveToValidated(dkg::Message),
    HandleInvalid(CryptoHashOf<dkg::Message>, String),
    Purge(Height),
}

pub type ChangeSet = Vec<ChangeAction>;

impl From<ChangeAction> for ChangeSet {
    fn from(change_action: ChangeAction) -> Self {
        vec![change_action]
    }
}
