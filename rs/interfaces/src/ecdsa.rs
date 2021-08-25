//! ECDSA related public interfaces.

use crate::artifact_pool::UnvalidatedArtifact;
use ic_types::artifact::{EcdsaMessageAttribute, EcdsaMessageId, PriorityFn};
use ic_types::consensus::ecdsa::EcdsaMessage;

#[derive(Debug)]
pub enum EcdsaChangeAction {}

pub type EcdsaChangeSet = Vec<EcdsaChangeAction>;

/// Artifact pool for the ECDSA messages (query interface)
pub trait EcdsaPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &EcdsaMessage> + '_>;
}

/// Artifact pool for the ECDSA messages (update interface)
pub trait MutableEcdsaPool: EcdsaPool {
    fn insert(&mut self, msg: UnvalidatedArtifact<EcdsaMessage>);
    fn apply_changes(&mut self, change_set: EcdsaChangeSet);
}

/// Checks and processes the changes (if any)
pub trait Ecdsa: Send {
    fn on_state_change(&self, ecds_pool: &dyn EcdsaPool) -> EcdsaChangeSet;
}

pub trait EcdsaGossip: Send + Sync {
    fn get_priority_function(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
    ) -> PriorityFn<EcdsaMessageId, EcdsaMessageAttribute>;
}
