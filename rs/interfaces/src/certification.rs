//! The certification public interface.
use crate::{
    consensus_pool::ConsensusPoolCache,
    validation::{ValidationError, ValidationResult},
};
use ic_types::artifact::{CertificationMessageAttribute, CertificationMessageId};
use ic_types::{
    artifact::{CertificationMessageFilter, PriorityFn},
    consensus::certification::{Certification, CertificationMessage, CertificationShare},
    crypto::CryptoError,
    CryptoHashOfPartialState, Height, RegistryVersion, SubnetId,
};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// The certifier component is responsible for signing execution states.
/// These signatures are required, to securely transmit a set of inter-canister
/// messages from one sub-network to another, or to synchronize the replica
/// state.
///
/// For creating a signature for a state, every replica follows the
/// following algorithm:
///
/// 1. Request a set of (height, hash) tuples from its local StateManager, where
/// `hash` is the hash of the replicated state after processing the batch at the
/// specified height. The StateManager is responsible for selecting which parts
/// of the replicated state are included in the computation of the hash.
///
/// 2. Sign the hash-height tuple, resulting in a CertificationShare, and place
/// the CertificationShare in the certification pool, to be gossiped to other
/// replicas.
///
/// 3. On every invocation of `on_state_change`, if sufficiently many
/// CertificationShares for the same (height, hash) pair were received, combine
/// them into a full Certification and put it into the certification pool. At
/// that point, the CertificationShares are not required anymore and can be
/// purged.
///
/// 4. For every (height, hash) pair with a full Certification, submit
/// the pair (height, Certification) to the StateManager.
///
/// 5. Whenever the catch-up package height increases, remove all certification
/// artifacts below this height.
pub trait Certifier: Send {
    /// Should be called on every change of the certification pool and timeouts.
    fn on_state_change(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        certification_pool: Arc<RwLock<dyn CertificationPool>>,
    ) -> ChangeSet;
}

/// Trait containing methods related to gossiping.
pub trait CertifierGossip: Send + Sync {
    /// Return the priority function for the Gossip protocol to optimize the
    /// artifact exchange.
    fn get_priority_function(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        certification_pool: &dyn CertificationPool,
    ) -> PriorityFn<CertificationMessageId, CertificationMessageAttribute>;

    /// Return a filter that represents what artifacts are needed.
    fn get_filter(&self) -> CertificationMessageFilter;
}

/// Contains all possible change actions applicable to the certification pool.
pub type ChangeSet = Vec<ChangeAction>;

/// Change actions applicable to the certification pool.
#[derive(Debug, Eq, PartialEq)]
pub enum ChangeAction {
    /// Adds the artifact to the validated pool.
    AddToValidated(CertificationMessage),
    /// Moves an artifact from the unvalidated to the validated section.
    MoveToValidated(CertificationMessage),
    /// Removes an artifact from the unvalidated pool section.
    RemoveFromUnvalidated(CertificationMessage),
    /// Removes all artifacts below the given height.
    RemoveAllBelow(Height),
    /// This action marks an invalid artifact, e.g. if the signature check
    /// failed.
    HandleInvalid(CertificationMessage, String),
}

/// Trait containing only immutable functions wrt. Certification Pool
pub trait CertificationPool {
    /// Returns the certification for the given height, if available.
    fn certification_at_height(&self, height: Height) -> Option<Certification>;

    /// Returns an iterator over all shares for the given height.
    fn shares_at_height(&self, height: Height)
        -> Box<dyn Iterator<Item = CertificationShare> + '_>;

    /// Returns all validated certification shares.
    fn validated_shares(&self) -> Box<dyn Iterator<Item = CertificationShare> + '_>;

    /// Returns an iterator of all unvalidated full certification for the given
    /// height.
    fn unvalidated_certifications_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &Certification> + '_>;

    /// Returns an iterator of all unvalidated shares for the given height.
    fn unvalidated_shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &CertificationShare> + '_>;

    /// Returns all heights (sorted, ascending), where at least a single
    /// artifact is present. Intended to be used by the purger.
    fn all_heights_with_artifacts(&self) -> Vec<Height>;

    /// Returns all heights which have a full validated certification.
    fn certified_heights(&self) -> HashSet<Height>;
}

/// Trait containing only mutable functions wrt. Certification Pool
pub trait MutableCertificationPool: CertificationPool {
    /// Inserts a certification message into the unvalidated part of the pool.
    fn insert(&mut self, msg: CertificationMessage);

    /// Applies a set of change actions to the pool.
    fn apply_changes(&mut self, change_set: ChangeSet);
}

/// Enumeration of all permanent errors the verifier component can return.
#[derive(Debug, PartialEq)]
pub enum CertificationPermanentError {
    CryptoError(CryptoError),
    UnexpectedCertificationHash(CryptoHashOfPartialState),
    RejectedByRejectingVerifier, // for testing only
}

/// Enumeration of all transient errors the verifier component can return.
#[derive(Debug, PartialEq)]
pub enum CertificationTransientError {
    CryptoError(CryptoError),
}

impl From<CryptoError> for CertificationTransientError {
    fn from(err: CryptoError) -> CertificationTransientError {
        CertificationTransientError::CryptoError(err)
    }
}

impl From<CryptoError> for CertificationPermanentError {
    fn from(err: CryptoError) -> CertificationPermanentError {
        CertificationPermanentError::CryptoError(err)
    }
}

impl<T> From<CertificationPermanentError> for ValidationError<CertificationPermanentError, T> {
    fn from(err: CertificationPermanentError) -> ValidationError<CertificationPermanentError, T> {
        ValidationError::Permanent(err)
    }
}

impl<P> From<CertificationTransientError> for ValidationError<P, CertificationTransientError> {
    fn from(err: CertificationTransientError) -> ValidationError<P, CertificationTransientError> {
        ValidationError::Transient(err)
    }
}

pub type VerifierError = ValidationError<CertificationPermanentError, CertificationTransientError>;

/// Verifier is used to verify state hash certifications. It will be injected
/// into XNet and StateSync components so that they can ensure the authenticity
/// of parts of the replicated state sent over from other sub-networks.
pub trait Verifier: Send + Sync {
    /// This method verifies whether the given certification contains a valid
    /// signature on the given hash on behalf of the subnet specified in
    /// subnet_id with respect to the `registry_version`.
    fn validate(
        &self,
        subnet_id: SubnetId,
        certification: &Certification,
        registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError>;
}
