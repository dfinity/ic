use super::{
    canister_state::CanisterState,
    metadata_state::{IngressHistoryState, Stream, Streams, SystemMetadata},
};
use crate::{metadata_state::StreamMap, CanisterQueues};
use ic_base_types::PrincipalId;
use ic_interfaces::{
    execution_environment::CanisterOutOfCyclesError, messages::CanisterInputMessage,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    ingress::IngressStatus,
    messages::{is_subnet_message, MessageId, RequestOrResponse, Response, SignedIngressContent},
    user_error::{ErrorCode, UserError},
    xnet::QueueId,
    CanisterId, MemoryAllocation, NumBytes, QueueIndex, SubnetId, Time,
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
    CanisterOutOfCycles(CanisterOutOfCyclesError),

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
            StateError::CanisterOutOfCycles(_) => LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
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
            StateError::CanisterOutOfCycles(err) => write!(f, "{}", err.to_string()),
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
    // Must remain private.
    subnet_queues: CanisterQueues,

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

    pub fn new_from_checkpoint(
        canister_states: BTreeMap<CanisterId, CanisterState>,
        metadata: SystemMetadata,
        subnet_queues: CanisterQueues,
        consensus_queue: Vec<Response>,
        root: PathBuf,
    ) -> Self {
        Self {
            canister_states,
            metadata,
            subnet_queues,
            consensus_queue,
            root,
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

    /// Returns all subnets for which a stream is available.
    pub fn subnets_with_available_streams(&self) -> Vec<SubnetId> {
        self.metadata.streams.keys().cloned().collect()
    }

    /// Retrieves a reference to the stream from this subnet to the destination
    /// subnet, if such a stream exists.
    pub fn get_stream(&self, destination_subnet_id: &SubnetId) -> Option<&Stream> {
        self.metadata.streams.get(destination_subnet_id)
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

    /// Pushes a `RequestOrResponse` into the induction pool (canister or subnet
    /// input queue).
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

    /// Pushes an ingress message into the induction pool (canister or subnet
    /// ingress queue).
    pub fn push_ingress(&mut self, msg: SignedIngressContent) -> Result<(), StateError> {
        if is_subnet_message(&msg, self.metadata.own_subnet_id) {
            self.subnet_queues.push_ingress(msg.into());
        } else {
            let canister_id = msg.canister_id();
            let canister = match self.canister_states.get_mut(&canister_id) {
                Some(canister) => canister,
                None => return Err(StateError::CanisterNotFound(canister_id)),
            };
            canister.push_ingress(msg.into());
        }
        Ok(())
    }

    /// Extracts the next inter-canister or ingress message (in that order) from
    /// `self.subnet_queues`.
    pub fn pop_subnet_input(&mut self) -> Option<CanisterInputMessage> {
        self.subnet_queues.pop_input()
    }

    /// Pushes a `Response` type message into the relevant subnet output queue.
    /// The protocol should have already reserved a slot, so this cannot fail.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_subnet_output_response(&mut self, msg: Response) {
        self.subnet_queues.push_output_response(msg)
    }

    /// Returns an iterator that consumes all messages in all output queues
    /// (canisters and subnet).
    pub fn output_into_iter(
        &mut self,
    ) -> impl std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)> + '_ {
        let own_subnet_id = self.metadata.own_subnet_id;
        self.canister_states
            .values_mut()
            .flat_map(|canister| canister.output_into_iter())
            .chain(
                self.subnet_queues
                    .output_into_iter(CanisterId::from(own_subnet_id)),
            )
    }

    pub fn time(&self) -> Time {
        self.metadata.time()
    }

    /// Returns an immutable reference to `self.subnet_queues`.
    pub fn subnet_queues(&self) -> &CanisterQueues {
        &self.subnet_queues
    }
}

/// A trait exposing `ReplicatedState` functionality for the exclusive use of
/// Message Routing.
pub trait ReplicatedStateMessageRouting {
    /// Returns a reference to the streams.
    fn streams(&self) -> &StreamMap;

    /// Returns a mutable reference to the streams.
    fn mut_streams(&mut self) -> &mut Streams;

    /// Removes the streams from this `ReplicatedState`.
    fn take_streams(&mut self) -> Streams;

    /// Atomically replaces the streams.
    fn put_streams(&mut self, streams: Streams);
}

impl ReplicatedStateMessageRouting for ReplicatedState {
    fn streams(&self) -> &StreamMap {
        &self.metadata.streams.streams()
    }

    fn mut_streams(&mut self) -> &mut Streams {
        Arc::make_mut(&mut self.metadata.streams)
    }

    fn take_streams(&mut self) -> Streams {
        std::mem::take(Arc::make_mut(&mut self.metadata.streams))
    }

    fn put_streams(&mut self, streams: Streams) {
        // Should never replace a non-empty Streams via `put_streams()`.
        assert!(self.metadata.streams.streams().is_empty());

        *Arc::make_mut(&mut self.metadata.streams) = streams;
    }
}

pub mod testing {
    use super::*;
    use crate::metadata_state::testing::StreamsTesting;

    /// Exposes `ReplicatedState` internals for use in other crates' unit tests.
    pub trait ReplicatedStateTesting {
        /// Testing only: Returns a mutable reference to `self.subnet_queues`.
        fn subnet_queues_mut(&mut self) -> &mut CanisterQueues;

        /// Testing only: Replaces `SystemMetadata::streams` with the provided
        /// ones.
        fn with_streams(&mut self, streams: StreamMap);

        /// Testing only: Modifies `SystemMetadata::streams` by applying the
        /// provided function.
        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F);
    }

    impl ReplicatedStateTesting for ReplicatedState {
        fn subnet_queues_mut(&mut self) -> &mut CanisterQueues {
            &mut self.subnet_queues
        }

        fn with_streams(&mut self, streams: StreamMap) {
            self.modify_streams(|streamz| *streamz = streams);
        }

        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F) {
            let mut streams = self.take_streams();
            streams.modify_streams(f);
            self.put_streams(streams);
        }
    }
}
