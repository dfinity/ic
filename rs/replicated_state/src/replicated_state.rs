use super::{
    canister_state::CanisterState,
    metadata_state::{IngressHistoryState, Stream, Streams, SystemMetadata},
};
use crate::{canister_state::QUEUE_INDEX_NONE, CanisterQueues};
use ic_base_types::PrincipalId;
use ic_logger::{fatal, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{RequestOrResponse, Response};
use ic_types::{
    ingress::IngressStatus,
    messages::MessageId,
    user_error::{ErrorCode, UserError},
    CanisterId, Cycles, MemoryAllocation, NumBytes, QueueIndex, SubnetId, Time,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub enum StateError {
    /// Message enqueuing failed due to no matching canister ID.
    CanisterNotFound(CanisterId),

    /// Message enqueuing failed due to full in/out queue.
    QueueFull { capacity: usize },

    /// Canister is stopped, not accepting any messages.
    CanisterStopped(CanisterId),

    /// Canister is stopping, only accepting responses.
    CanisterStopping(CanisterId),

    /// Canister is out of cycles.
    CanisterOutOfCycles {
        canister_id: CanisterId,
        available: Cycles,
        requested: Cycles,
    },

    /// Message enqueuing failed due to calling an unknown subnet method.
    UnknownSubnetMethod(String),

    /// Message enqueuing failed due to calling a subnet method with
    /// an invalid payload.
    InvalidSubnetPayload,
}

pub const LABEL_VALUE_CANISTER_NOT_FOUND: &str = "CanisterNotFound";
pub const LABEL_VALUE_QUEUE_FULL: &str = "QueueFull";
pub const LABEL_VALUE_CANISTER_STOPPED: &str = "CanisterStopped";
pub const LABEL_VALUE_CANISTER_STOPPING: &str = "CanisterStopping";
pub const LABEL_VALUE_CANISTER_OUT_OF_CYCLES: &str = "CanisterOutOfCycles";
pub const LABEL_VALUE_UNKNOWN_SUBNET_METHOD: &str = "UnknownSubnetMethod";
pub const LABEL_VALUE_INVALID_SUBNET_PAYLOAD: &str = "InvalidSubnetPayload";

impl StateError {
    /// Returns a string representation of the `StateError` variant name to be
    /// used as a metric label value (e.g. `"QueueFull"`).
    pub fn to_label_value(&self) -> &'static str {
        match self {
            StateError::CanisterNotFound(_) => LABEL_VALUE_CANISTER_NOT_FOUND,
            StateError::QueueFull { .. } => LABEL_VALUE_QUEUE_FULL,
            StateError::CanisterStopped(_) => LABEL_VALUE_CANISTER_STOPPED,
            StateError::CanisterStopping(_) => LABEL_VALUE_CANISTER_STOPPING,
            StateError::CanisterOutOfCycles { .. } => LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
            StateError::UnknownSubnetMethod(_) => LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
            StateError::InvalidSubnetPayload => LABEL_VALUE_INVALID_SUBNET_PAYLOAD,
        }
    }
}

impl std::error::Error for StateError {}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::CanisterNotFound(canister_id) => {
                write!(f, "Canister {} not found", canister_id)
            }
            StateError::QueueFull { capacity } => {
                write!(f, "Maximum queue capacity {} reached", capacity)
            }
            StateError::CanisterStopped(canister_id) => {
                write!(f, "Canister {} is stopped", canister_id)
            }
            StateError::CanisterStopping(canister_id) => {
                write!(f, "Canister {} is stopping", canister_id)
            }
            StateError::CanisterOutOfCycles {
                canister_id,
                available,
                requested,
            } => write!(
                f,
                "Canister {} has currently {} available cycles, but {} was requested",
                canister_id, available, requested
            ),
            StateError::UnknownSubnetMethod(method) => write!(
                f,
                "Cannot enqueue management message. Method {} is unknown.",
                method
            ),
            StateError::InvalidSubnetPayload => write!(
                f,
                "Cannot enqueue management message. Candid payload is invalid."
            ),
        }
    }
}

/// ReplicatedState is the deterministic replicated state of the system.
/// Broadly speaking it consists of two parts:  CanisterState used for canister
/// execution and SystemMetadata used for message routing and history queries.
//
// * We don't derive `Serialize` and `Deserialize` because these are handled by
// our OP layer.
// * We don't derive `Hash` because `ingress_history` is a Hashmap that doesn't
// derive `Hash`.
#[derive(Clone, Debug)]
pub struct ReplicatedState {
    /// States of all canisters, indexed by canister ids.
    pub canister_states: BTreeMap<CanisterId, CanisterState>,

    /// Deterministic processing metadata.
    pub metadata: SystemMetadata,

    /// Queues for holding messages sent/received by the subnet.
    // EXE-92: this should be private
    pub subnet_queues: CanisterQueues,

    /// Queue for holding responses arriving from Consensus.
    ///
    /// Responses from consensus are to be processed each round.
    /// The queue is, therefore, emptied at the end of every round.
    // TODO(EXE-109): Move this queue into `subnet_queues`
    pub consensus_queue: Vec<Response>,

    pub root: PathBuf,
}

// We use custom impl of PartialEq because state root is not part of identity.
impl PartialEq for ReplicatedState {
    fn eq(&self, rhs: &Self) -> bool {
        (
            &self.canister_states,
            &self.metadata,
            &self.subnet_queues,
            &self.consensus_queue,
        ) == (
            &rhs.canister_states,
            &rhs.metadata,
            &rhs.subnet_queues,
            &rhs.consensus_queue,
        )
    }
}

impl ReplicatedState {
    /// Creates a new empty node state.
    pub fn new_rooted_at(
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        root: PathBuf,
    ) -> ReplicatedState {
        ReplicatedState {
            root,
            canister_states: BTreeMap::new(),
            metadata: SystemMetadata::new(own_subnet_id, own_subnet_type),
            subnet_queues: CanisterQueues::default(),
            consensus_queue: Vec::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn canister_state(&self, canister_id: &CanisterId) -> Option<&CanisterState> {
        self.canister_states.get(canister_id)
    }

    pub fn canister_state_mut(&mut self, canister_id: &CanisterId) -> Option<&mut CanisterState> {
        self.canister_states.get_mut(canister_id)
    }

    pub fn take_canister_state(&mut self, canister_id: &CanisterId) -> Option<CanisterState> {
        self.canister_states.remove(canister_id)
    }

    pub fn take_canister_states(&mut self) -> BTreeMap<CanisterId, CanisterState> {
        std::mem::replace(&mut self.canister_states, BTreeMap::new())
    }

    /// Insert the canister state into the replicated state. If a canister
    /// already exists for the given canister id, it will be replaced. It is the
    /// responsibility of the caller of this function to ensure that any
    /// relevant state associated with the older canister state are properly
    /// cleaned up.
    pub fn put_canister_state(&mut self, canister_state: CanisterState) {
        self.canister_states
            .insert(canister_state.canister_id(), canister_state);
    }

    pub fn put_canister_states(&mut self, canisters: BTreeMap<CanisterId, CanisterState>) {
        self.canister_states.extend(canisters.into_iter());
    }

    /// Returns an iterator over canister states, ordered by canister ID.
    pub fn canisters_iter(
        &self,
    ) -> std::collections::btree_map::Values<'_, CanisterId, CanisterState> {
        self.canister_states.values()
    }

    /// Returns a mutable iterator over canister states, ordered by canister ID.
    pub fn canisters_iter_mut(
        &mut self,
    ) -> std::collections::btree_map::ValuesMut<'_, CanisterId, CanisterState> {
        self.canister_states.values_mut()
    }

    pub fn system_metadata(&self) -> &SystemMetadata {
        &self.metadata
    }

    pub fn set_system_metadata(&mut self, metadata: SystemMetadata) {
        self.metadata = metadata;
    }

    pub fn get_ingress_status(&self, message_id: &MessageId) -> IngressStatus {
        self.metadata
            .ingress_history
            .get(message_id)
            .cloned()
            .unwrap_or(IngressStatus::Unknown)
    }

    pub fn get_ingress_history(&self) -> IngressHistoryState {
        self.metadata.ingress_history.clone()
    }

    pub fn set_ingress_status(&mut self, message_id: MessageId, status: IngressStatus) {
        self.metadata
            .ingress_history
            .insert(message_id, status, self.time());
    }

    pub fn prune_ingress_history(&mut self) {
        self.metadata.ingress_history.prune(self.time());
    }

    /// Removes the Streams from this ReplicatedState.
    pub fn take_streams(&mut self) -> Streams {
        std::mem::replace(Arc::make_mut(&mut self.metadata.streams), BTreeMap::new())
    }

    /// Atomically updates streams to the provided ones.
    pub fn put_streams(&mut self, streams: Streams) {
        *Arc::make_mut(&mut self.metadata.streams) = streams;
    }

    /// Returns a reference to all streams.
    pub fn streams(&self) -> &Streams {
        &self.metadata.streams
    }

    /// Returns all subnets for which a stream is available.
    pub fn subnets_with_available_streams(&self) -> Vec<SubnetId> {
        self.metadata.streams.keys().cloned().collect()
    }

    /// Retrieves a reference to the stream from this subnet to the destination
    /// subnet, if such a stream exists.
    pub fn get_stream(&self, destination_subnet_id: SubnetId) -> Option<&Stream> {
        self.metadata.streams.get(&destination_subnet_id)
    }

    /// Retrieves a mutable reference to the stream from this subnet to the
    /// destination subnet, if such a stream exists.
    pub fn get_mut_stream(&mut self, destination_subnet_id: SubnetId) -> Option<&mut Stream> {
        let streams = Arc::make_mut(&mut self.metadata.streams);
        streams.get_mut(&destination_subnet_id)
    }

    pub fn modify_streams<F: FnOnce(&mut Streams)>(&mut self, f: F) {
        let mut streams = self.take_streams();
        f(&mut streams);
        self.put_streams(streams);
    }

    /// Returns the sum of reserved compute allocations of all currently
    /// available canisters.
    pub fn total_compute_allocation(&self) -> u64 {
        self.canisters_iter()
            .map(|canister| canister.scheduler_state.compute_allocation.as_percent())
            .sum()
    }

    /// Returns the total memory taken by canisters in bytes.
    ///
    /// Either the memory allocation that has been reserved is taken into
    /// account or the logical memory used in case no memory allocation has
    /// been reserved explicitly.
    pub fn total_memory_taken(&self) -> NumBytes {
        self.canisters_iter()
            .map(|canister| match canister.memory_allocation() {
                MemoryAllocation::Reserved(bytes) => bytes,
                MemoryAllocation::BestEffort => canister.memory_usage(),
            })
            .sum()
    }

    pub fn find_subnet_id(&self, principal_id: PrincipalId) -> Result<SubnetId, UserError> {
        let subnet_id = self
            .metadata
            .network_topology
            .routing_table
            .route(principal_id);

        match subnet_id {
            None => Err(UserError::new(
                ErrorCode::SubnetNotFound,
                format!("Could not find subnetId given principalId {}", principal_id),
            )),
            Some(subnet_id) => Ok(subnet_id),
        }
    }

    /// Pushes a `RequestOrResponse` into the induction pool.
    /// The induction pool can either be that of a canister or that of the
    /// subnet.
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        match self.canister_state_mut(&msg.receiver()) {
            Some(receiver_canister) => receiver_canister.push_input(index, msg),
            None => {
                let subnet_id = self.metadata.own_subnet_id.get_ref();
                if msg.receiver().get_ref() == subnet_id {
                    self.subnet_queues.push_input(index, msg)
                } else {
                    Err((StateError::CanisterNotFound(msg.receiver()), msg))
                }
            }
        }
    }

    pub fn time(&self) -> Time {
        self.metadata.time()
    }

    /// Iterates over all canisters on the subnet, checking if a source canister
    /// has output messages for a destination canister on the same subnet and
    /// moving them from the source to the destination canister if the
    /// destination canister has room for them.
    ///
    /// This method only handles messages sent to actual other canisters.
    /// Messages sent to the subnet or self are not handled i.e. they take the
    /// slow path through message routing.
    pub fn induct_messages_on_same_subnet(&mut self, log: &ReplicaLogger) {
        let mut canisters = self.take_canister_states();

        // Get a list of canisters in the map before we iterate over the map.
        // This is because we cannot hold an immutable reference to the map
        // while trying to simultaenously mutate it.
        let canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();

        for source_canister_id in canister_ids {
            // Remove the source canister from the map so that we can
            // `get_mut()` on the map futher below for the destination canister.
            // Borrow rules do not allow us to hold multiple mutable references.
            let mut source_canister = match canisters.remove(&source_canister_id) {
                None => fatal!(
                    log,
                    "Should be guaranteed that the canister exists in the map."
                ),
                Some(canister) => canister,
            };

            for (dest_canister_id, source_output_queue) in source_canister
                .system_state
                .queues_mut()
                .output_queues_mut()
                .iter_mut()
            {
                let dest_canister = match canisters.get_mut(&dest_canister_id) {
                    None => continue,
                    Some(canister) => canister,
                };

                while let Some((_, msg)) = source_output_queue.peek() {
                    match dest_canister.push_input(QUEUE_INDEX_NONE, msg) {
                        Err(_) => break,
                        Ok(()) => match source_output_queue.pop() {
                            Some(_) => (),
                            None => fatal!(
                                log,
                                "Since peek above returned a message, popping it should not fail."
                            ),
                        },
                    }
                }
            }
            canisters.insert(source_canister_id, source_canister);
        }
        self.put_canister_states(canisters);
    }
}
