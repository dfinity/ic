//! The state manager public interface.
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_types::{
    consensus::certification::Certification, CryptoHashOfPartialState, CryptoHashOfState, Height,
};
use phantom_newtype::BitMask;
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StateManagerError {
    /// The state at the specified height was removed and cannot be recovered
    /// anymore.
    StateRemoved(Height),
    /// The state at the specified height is not committed yet.
    StateNotCommittedYet(Height),
}

impl std::fmt::Display for StateManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateRemoved(height) => {
                write!(f, "state at height {} has already been removed", height)
            }
            Self::StateNotCommittedYet(height) => {
                write!(f, "state at height {} is not committed yet", height)
            }
        }
    }
}

impl std::error::Error for StateManagerError {}

pub type StateManagerResult<T> = Result<T, StateManagerError>;

/// Errors for functions returning state hashes that are permanent (i.e. no
/// point in retrying)
#[derive(Error, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PermanentStateHashError {
    #[error("state at height {0} has already been removed and cannot be recovered anymore")]
    StateRemoved(Height),
    #[error("state at height {0} was committed with CertificationScope::Metadata, not CertificationScope::Full")]
    StateNotFullyCertified(Height),
}

/// Errors for functions returning state hashes that rely on asynchronous
/// computations that have not finished yet.
#[derive(Error, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransientStateHashError {
    #[error("state at height {0} is not committed yet")]
    StateNotCommittedYet(Height),
    #[error("hash of state at height {0} is not fully computed yet")]
    HashNotComputedYet(Height),
}

/// Errors for functions returning state hashes
#[derive(Error, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StateHashError {
    /// The error is permanent and will not change if retried later
    #[error(transparent)]
    Permanent(#[from] PermanentStateHashError),
    /// The error is temporary and possibly due to asynchronous computations not
    /// having finished yet. May succeed if retried.
    #[error(transparent)]
    Transient(#[from] TransientStateHashError),
}

/// Indicates the subset of the state that needs to be certified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationScope {
    /// Only certify the system metadata.
    Metadata,
    /// Certify the full state.
    Full,
}

pub enum CertificationTag {}

/// A bit mask for accepting certified/uncertified states.
pub type CertificationMask = BitMask<CertificationTag, u32>;

/// The mask that only accepts certified states.
pub const CERT_CERTIFIED: CertificationMask = CertificationMask::new(1);
/// The mask that only accepts uncertified states.
pub const CERT_UNCERTIFIED: CertificationMask = CertificationMask::new(2);
/// The mask that accepts all states, not matter what their
/// certification status is.
pub const CERT_ANY: CertificationMask = CertificationMask::new(1 | 2);

/// A node state with a `height` attached to it, indicating that the state was
/// obtained by executing a block with the given `height`.
#[derive(Clone, Debug, PartialEq)]
pub struct Labeled<State> {
    height: Height,
    state: State,
}

impl<State> Labeled<State> {
    pub fn new(height: Height, state: State) -> Self {
        Self { height, state }
    }

    /// The height this state corresponds to.
    pub fn height(&self) -> Height {
        self.height
    }

    /// Returns a read-only reference the state.
    pub fn get_ref(&self) -> &State {
        &self.state
    }

    /// Drops the label and returns the raw state.
    pub fn take(self) -> State {
        self.state
    }
}

/// APIs related to fetching and certifying the state.
// tag::state-manager-interface[]
pub trait StateManager: StateReader {
    /// Returns a snapshot of the list of state hashes that need to be
    /// certified ("the list" below).
    ///
    /// The actual list is maintained by the StateManager.  The
    /// following operations can modify the list:
    ///
    /// * A call to `commit_and_certify` starts a potentially asynchronous
    ///   computation that adds an entry to the list.  This implies that the
    ///   list will contain every height at some point, unless the state is
    ///   removed before its hash is computed.
    ///
    /// * A call to `deliver_state_certification` with a certification of some
    ///   height removes the corresponding entry from the list.
    ///
    /// * A call to one of the `remove_*_below` methods removes the corresponding
    ///   entry from the list.
    ///
    /// Since the hash computation can be asynchronous, the order in
    /// which heights appear in the list can differ from the order in
    /// which states are committed.  E.g., the following outcome is
    /// possible:
    ///
    /// ```text
    /// sm.commit_and_certify(state_1, h_1, scope_1)
    /// sm.commit_and_certify(state_1, h_2, scope_1)
    /// sm.list_state_hashes_to_certify() = [(h_2, H_2)]
    /// sm.list_state_hashes_to_certify() = [(h_1, H_1), (h_2, H_2)]
    /// ```
    ///
    /// # Properties
    ///
    /// * The entries in the list are unique and sorted by height.
    ///
    ///   ```text
    ///   let l = state_manager.list_state_hashes_to_certify()
    ///   ∀ i, j ∈ indices(l): i < j ⇒ l[i].height < l[j].height
    ///   ```
    ///
    /// * The hash associated with a height is guaranteed not to change.
    ///
    ///   ```text
    ///   let l_1 = state_manager.list_state_hashes_to_certify()
    ///   ...
    ///   let l_2 = state_manager.list_state_hashes_to_certify()
    ///   ∀ (h_1, H_1) ∈ l_1, (h_2, H_2) ∈ l_2: h_1 = h_2 ⇒ H_1 = H_2
    ///   ```
    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)>;

    /// Delivers a `certification` corresponding to some state hash / height
    /// pair.
    ///
    /// Does nothing if another certification for the same state has
    /// already been delivered.
    ///
    /// ## Post-conditions
    ///
    /// `(height, ·) ∉ state_manager.list_state_hashes_to_certify()`
    ///
    /// ## Panics
    ///
    /// Panics if certification.content.hash is not equal to the hash computed
    /// from the state at height certification.content.height.
    fn deliver_state_certification(&self, certification: Certification);

    /// Returns the hash of the state at the specified `height`.
    ///
    /// # Errors
    ///
    /// * If the state at `height` was already removed with a call to
    ///   `remove_states_below()` the `Permanent(StateRemoved)` error
    ///   is returned.
    ///
    /// * If the state at `height` was not committed with
    ///   `CertificationScope::Full`, the `Permanent(StateNotFullyCertified)`
    ///   error is returned. See `commit_and_certify()`.
    ///
    /// * If the state at `height` is not committed yet, the
    ///   `Transient(StateNotCommittedYet)` error is returned. See
    ///   `commit_and_certify()`.
    ///
    /// * The state hash can be computed asynchronously.  If the state itself is
    ///   available, but the hash is not computed yet, the
    ///   `Transient(StateNoteComputedYet)` error is returned.
    fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError>;

    /// Initiates asynchronous procedure of state synchronization with the
    /// target state specified by its height and root hash.
    ///
    /// # Parameters
    ///
    /// * `height` - the height of the state to be fetched.
    /// * `root_hash` - the expected root hash of the state. States with
    ///   matching height but mismatching root_hash will be ignored.
    /// * `cup_interval_length` - the interval between state heights eligible
    ///   for state sync (CUP = Catch Up Package). Also known as DKG
    ///   (Distributed Key Generation) interval.
    ///
    /// Does nothing if `self.latest_state_height() >= height`.
    ///
    /// Note that there is no explicit notification (or callback) indicating
    /// that the fetch is complete.  The caller is supposed to poll
    /// `self.latest_state_height()` periodically to learn that the state became
    /// available.
    ///
    /// # Panics
    ///
    /// Panics if the state is already known and its root_hash differs, i.e.
    /// `self.get_state_hash_at(height) = Ok(Some(h)) ∧ h ≠ root_hash`
    fn fetch_state(
        &self,
        height: Height,
        root_hash: CryptoHashOfState,
        cup_interval_length: Height,
    );

    /// Returns the list of heights corresponding to accessible states matching
    /// the mask.  E.g. `list_state_heights(CERT_ANY)` will return all
    /// accessible states.
    ///
    /// Note that the initial state at height 0 is considered uncertified from
    /// the State Manager point of view.  This is because the protocol requires
    /// each replica to individually obtain the initial state using some
    /// out-of-band mechanism (i.e., not state sync).  Also note that the
    /// authenticity of this initial state will be verified by some protocol
    /// external to this component.
    ///
    /// The list of heights is guaranteed to be
    /// * Non-empty if `cert_mask = CERT_ANY` as it will contain at least height
    ///   0 even if no states were committed yet.
    /// * Sorted in ascending order.
    fn list_state_heights(&self, cert_mask: CertificationMask) -> Vec<Height>;

    /// Notify this state manager that states with heights strictly less than
    /// the specified `height` can be removed.
    ///
    /// Note that:
    ///  * The initial state (height = 0) cannot be removed.
    ///  * Some states matching the removal criteria might be kept alive.  For
    ///    example, the last fully persisted state might be preserved to
    ///    optimize future operations.
    ///  * It is the responsibiltiy of the caller to not remove the most recent
    ///    certified state
    fn remove_states_below(&self, height: Height);

    /// Notify the state manager that states committed with partial certification
    /// state and heights strictly less than specified `height` can be removed.
    ///
    /// Note that:
    ///  * The initial state (height = 0) cannot be removed.
    ///  * Some states matching the removal criteria might be kept alive.  For
    ///    example, the last fully persisted state might be preserved to
    ///    optimize future operations.
    ///  * No checkpoints are removed, see also `remove_states_below()`
    ///  * It is the responsibiltiy of the caller to not remove the most recent
    ///    certified state
    fn remove_inmemory_states_below(&self, height: Height);

    /// Commits the `state` at given `height`, limits the certification to
    /// `scope`. The `state` must be the mutable state obtained via a call to
    /// `take_tip`.
    ///
    /// Does nothing if `height ≤ state_manager.latest_state_height()`.
    ///
    /// # Panics
    ///
    /// Panics if the state at `height` has already been committed before but
    /// has a different hash.
    fn commit_and_certify(&self, state: Self::State, height: Height, scope: CertificationScope);

    /// Returns the version of the state that can be modified in-place and the
    /// height of that state.
    ///
    /// This function transfers the ownership of the mutable state from
    /// StateManager to the caller.
    ///
    /// # Panics
    ///
    /// * This function panics if StateManager doesn't own the mutable state.
    ///   That means that `take_tip` cannot be called twice in a row, every
    ///   invocation of `take_tip` must be balanced by a call to
    ///   `commit_and_certify`.
    fn take_tip(&self) -> (Height, Self::State);

    /// Returns the version of the state that can be modified in-place (TIP) if
    /// the requested height matches height(TIP).
    ///
    /// # Errors
    ///
    ///  * If the height < height(TIP), returns `StateRemoved`.
    ///
    ///  * If the height(TIP) < height, returns `StateNotCommittedYet`.
    ///
    /// # Panics
    ///
    /// * This function panics if StateManager doesn't own the TIP. See
    ///   `take_tip` for more details.
    fn take_tip_at(&self, height: Height) -> StateManagerResult<Self::State>;

    /// Reports that the given `height` diverged, i.e., consensus agreed on the
    /// hash of state at `height`, and this was not the state produced by this
    /// state manager.
    ///
    /// This function triggers non-determinism recovery procedure, which
    /// involves pruning all the states that might be diverged as well.
    ///
    /// # Panics
    ///
    /// This function always panics because there is no point in continuing the
    /// normal operation.  We rely on orchestrator restarting the replica, which
    /// in turn will initiate the normal recovery procedure.
    fn report_diverged_state(&self, height: Height);
}
// end::state-manager-interface[]

/// This component is analogous to the `StateManager` except that it is used to
/// access State which cannot be checkpointed or snapshotted.
pub trait StateReader: Send + Sync {
    /// Type of state managed by StateReader.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Returns a shared object of the state at the specified `height`. If the
    /// state is not available locally, the method blocks until the state is
    /// fetched.
    ///
    /// # Errors
    ///
    /// * If the state at `height` was already removed, the `StateRemoved` error
    ///   is returned.
    ///
    /// * If the state at `height` is not committed yet, the
    ///   `StateNotCommittedYet` error is returned.
    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>>;

    /// Returns a shared object of the state at the latest committed block
    /// height.  If nothing was committed so far, returns an empty valid
    /// state.
    fn get_latest_state(&self) -> Labeled<Arc<Self::State>>;

    /// Returns the height of the latest state available.
    fn latest_state_height(&self) -> Height;

    /// Returns the height of the latest certified state available.
    fn latest_certified_height(&self) -> Height;

    /// Reads part of the certified state tree specified by the shape of
    /// `paths`.  Path can reference either a leaf or a subtree.  E.g.,
    ///  if the tree looks like this:
    ///
    /// ```text
    ///  * -+- time - 1000
    ///     |
    ///     `- request_status -+- 1 - status - processing
    ///                        |
    ///                        `- 2 - status - processing
    /// ```
    ///
    /// then the allowed paths are:
    ///
    /// * /time
    /// * /request_status
    /// * /request_status/1
    /// * /request_status/2
    /// * /request_status/1/status
    /// * /request_status/2/status
    ///
    /// Use `Leaf(())` to indicate "subtree rooted at this path", e.g.,
    /// `SubTree { "request_status" => SubTree { "1" => Leaf(()) } }`
    /// is a subtree that requests all the nodes below path `/request_status/1`.
    ///
    /// Returns None if there is no certified state available yet.
    fn read_certified_state(
        &self,
        paths: &LabeledTree<()>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)>;
}
