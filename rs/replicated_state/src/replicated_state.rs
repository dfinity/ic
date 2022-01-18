use super::{
    canister_state::CanisterState,
    metadata_state::{IngressHistoryState, Stream, Streams, SystemMetadata},
};
use crate::{
    canister_state::{
        system_state::{push_input, CanisterOutputQueuesIterator},
        ENFORCE_MESSAGE_MEMORY_USAGE,
    },
    metadata_state::StreamMap,
    CanisterQueues,
};
use ic_base_types::PrincipalId;
use ic_interfaces::{
    execution_environment::CanisterOutOfCyclesError, messages::CanisterInputMessage,
};
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    ingress::IngressStatus,
    messages::{is_subnet_message, MessageId, RequestOrResponse, Response, SignedIngressContent},
    user_error::{ErrorCode, UserError},
    xnet::QueueId,
    CanisterId, MemoryAllocation, NumBytes, QueueIndex, SubnetId, Time,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Input queue type: Local or Remote Subnet
pub enum InputQueueType {
    /// Local Subnet input messages
    LocalSubnet,
    /// Remote Subnet input messages
    RemoteSubnet,
}

/// Next input queue: round-robin across Local, Ingress, and Remote Subnet
#[derive(Clone, Copy, Eq, Debug, PartialEq)]
pub enum NextInputQueue {
    /// Local Subnet input messages
    LocalSubnet,
    /// Ingress messages
    Ingress,
    /// Remote Subnet input messages
    RemoteSubnet,
}

impl Default for NextInputQueue {
    fn default() -> Self {
        NextInputQueue::LocalSubnet
    }
}

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

    /// Canister state is invalid because of broken invariant.
    InvariantBroken(String),

    /// Message enqueuing failed due to calling an unknown subnet method.
    UnknownSubnetMethod(String),

    /// Message enqueuing failed due to calling a subnet method with
    /// an invalid payload.
    InvalidSubnetPayload,

    /// Message enqueuing would have caused the canister or subnet to run over
    /// their memory limit.
    OutOfMemory { requested: NumBytes, available: i64 },
}

/// Circular iterator that consumes messages from all canisters' and the
/// subnet's output queues. All messages that have not been explicitly popped
/// will remain in the state.
///
/// The iterator loops over the canisters (plus subnet) consuming one output
/// message from each in a round robin fashion. For each canister and the subnet
/// a circular iterator again ensures that messages are consumed from output
/// queues in a round robin fashion.
///
/// Additional operations compared to a standard iterator:
///  * peeking (returning a reference to the next message without consuming it);
///    and
///  * excluding whole queues from iteration while retaining their messages
///    (e.g. in order to efficiently implement per destination limits).
#[derive(Debug)]
struct OutputIterator<'a> {
    /// Priority queue of non-empty canister iterators. The next message will be
    /// popped / peeked from the first iterator.
    canister_iterators: VecDeque<CanisterOutputQueuesIterator<'a>>,

    /// Number of messages left in the iterator.
    size: usize,
}

impl<'a> OutputIterator<'a> {
    fn new(
        own_subnet_id: SubnetId,
        canisters: &'a mut BTreeMap<CanisterId, CanisterState>,
        subnet_queues: &'a mut CanisterQueues,
    ) -> Self {
        let mut canister_iterators: VecDeque<_> = canisters
            .iter_mut()
            .map(|(owner, canister)| canister.system_state.output_into_iter(*owner))
            .filter(|handle| !handle.is_empty())
            .collect();

        // Push the subnet queues in front in order to make sure that at least one
        // system message is always routed as long as there is space for it.
        let subnet_queues_iter = subnet_queues.output_into_iter(CanisterId::from(own_subnet_id));
        if !subnet_queues_iter.is_empty() {
            canister_iterators.push_front(subnet_queues_iter)
        }
        let size = canister_iterators.iter().map(|q| q.size_hint().0).sum();

        OutputIterator {
            canister_iterators,
            size,
        }
    }

    /// Computes the number of messages left in `queue_handles`.
    ///
    /// Time complexity: O(N).
    fn compute_size(queue_handles: &VecDeque<CanisterOutputQueuesIterator<'a>>) -> usize {
        queue_handles.iter().map(|q| q.size_hint().0).sum()
    }
}

impl std::iter::Iterator for OutputIterator<'_> {
    type Item = (QueueId, QueueIndex, RequestOrResponse);

    /// Pops a message from the next canister. If this was not the last message
    /// for that canister, the canister iterator is moved to the back of the
    /// iteration order.
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut canister_iterator) = self.canister_iterators.pop_front() {
            if let Some((queue_id, queue_index, msg)) = canister_iterator.next() {
                self.size -= 1;
                if !canister_iterator.is_empty() {
                    self.canister_iterators.push_back(canister_iterator);
                }
                debug_assert_eq!(Self::compute_size(&self.canister_iterators), self.size);

                return Some((queue_id, queue_index, msg));
            }
        }
        None
    }

    /// Returns the exact number of messages left in the iterator.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size, Some(self.size))
    }
}

pub trait PeekableOutputIterator:
    std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)>
{
    /// Peeks into the iterator and returns a reference to the item `next`
    /// would return.
    fn peek(&self) -> Option<(QueueId, QueueIndex, Arc<RequestOrResponse>)>;

    /// Permanently filters out from iteration the next queue (i.e. all messages
    /// with the same sender and receiver as the next). The mesages are retained
    /// in the output queue.
    fn exclude_queue(&mut self);
}

impl PeekableOutputIterator for OutputIterator<'_> {
    fn peek(&self) -> Option<(QueueId, QueueIndex, Arc<RequestOrResponse>)> {
        self.canister_iterators.front().and_then(|it| it.peek())
    }

    fn exclude_queue(&mut self) {
        if let Some(mut canister_iterator) = self.canister_iterators.pop_front() {
            self.size -= canister_iterator.exclude_queue();
            if !canister_iterator.is_empty() {
                self.canister_iterators.push_front(canister_iterator);
            }
            debug_assert_eq!(Self::compute_size(&self.canister_iterators), self.size);
        }
    }
}

pub const LABEL_VALUE_CANISTER_NOT_FOUND: &str = "CanisterNotFound";
pub const LABEL_VALUE_QUEUE_FULL: &str = "QueueFull";
pub const LABEL_VALUE_CANISTER_STOPPED: &str = "CanisterStopped";
pub const LABEL_VALUE_CANISTER_STOPPING: &str = "CanisterStopping";
pub const LABEL_VALUE_CANISTER_OUT_OF_CYCLES: &str = "CanisterOutOfCycles";
pub const LABEL_VALUE_INVARIANT_BROKEN: &str = "InvariantBroken";
pub const LABEL_VALUE_UNKNOWN_SUBNET_METHOD: &str = "UnknownSubnetMethod";
pub const LABEL_VALUE_INVALID_SUBNET_PAYLOAD: &str = "InvalidSubnetPayload";
pub const LABEL_VALUE_OUT_OF_MEMORY: &str = "OutOfMemory";

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
            StateError::InvariantBroken(_) => LABEL_VALUE_INVARIANT_BROKEN,
            StateError::UnknownSubnetMethod(_) => LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
            StateError::InvalidSubnetPayload => LABEL_VALUE_INVALID_SUBNET_PAYLOAD,
            StateError::OutOfMemory { .. } => LABEL_VALUE_OUT_OF_MEMORY,
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

            StateError::InvariantBroken(err) => {
                write!(f, "Invariant broken: {}", err)
            }
            StateError::UnknownSubnetMethod(method) => write!(
                f,
                "Cannot enqueue management message. Method {} is unknown.",
                method
            ),
            StateError::InvalidSubnetPayload => write!(
                f,
                "Cannot enqueue management message. Candid payload is invalid."
            ),
            StateError::OutOfMemory {
                requested,
                available,
            } => write!(
                f,
                "Cannot enqueue message. Out of memory: requested {}, available {}",
                requested, available
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
        let mut res = Self {
            canister_states,
            metadata,
            subnet_queues,
            consensus_queue,
            root,
        };
        res.update_stream_responses_size_bytes();
        res
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
        std::mem::take(&mut self.canister_states)
    }

    pub fn routing_table(&self) -> Arc<RoutingTable> {
        Arc::clone(&self.metadata.network_topology.routing_table)
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
    /// This accounts for the canister memory reservation, where specified; and
    /// the actual canister memory usage, where no explicit memory reservation
    /// has been made.
    pub fn total_memory_taken(&self) -> NumBytes {
        let mut memory_taken = self
            .canisters_iter()
            .map(|canister| match canister.memory_allocation() {
                MemoryAllocation::Reserved(bytes) => bytes,
                MemoryAllocation::BestEffort => {
                    canister.memory_usage(self.metadata.own_subnet_type)
                }
            })
            .sum();
        if ENFORCE_MESSAGE_MEMORY_USAGE && self.metadata.own_subnet_type != SubnetType::System {
            memory_taken += (self.subnet_queues.memory_usage() as u64).into();
        }
        memory_taken
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
    ///
    /// The messages from the same subnet get pushed into the local subnet
    /// queue, while the messages form the other subnets get pushed to the inter
    /// subnet queues.
    ///
    /// On failure (queue full, canister not found, out of memory), returns the
    /// corresponding error and the original message.
    ///
    /// Updates `subnet_available_memory` to reflect any change in memory usage.
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
        max_canister_memory_size: NumBytes,
        subnet_available_memory: &mut i64,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let own_subnet_type = self.metadata.own_subnet_type;
        let input_queue_type = match self.find_subnet_id(*msg.sender().get_ref()) {
            Ok(sender_subnet_id) => {
                if self.metadata.own_subnet_id == sender_subnet_id {
                    InputQueueType::LocalSubnet
                } else {
                    InputQueueType::RemoteSubnet
                }
            }
            Err(_) => InputQueueType::LocalSubnet, // unknown sender is local subnet
        };
        match self.canister_state_mut(&msg.receiver()) {
            Some(receiver_canister) => receiver_canister.push_input(
                index,
                msg,
                max_canister_memory_size,
                subnet_available_memory,
                own_subnet_type,
                input_queue_type,
            ),
            None => {
                let subnet_id = self.metadata.own_subnet_id.get_ref();
                if msg.receiver().get_ref() == subnet_id {
                    push_input(
                        &mut self.subnet_queues,
                        index,
                        msg,
                        // No canister limit, so pass the subnet limit twice.
                        *subnet_available_memory,
                        subnet_available_memory,
                        own_subnet_type,
                        input_queue_type,
                    )
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

    /// Extracts the next inter-canister or ingress message (round-robin) from
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

    /// Returns a circular iterator that consumes messages from all canisters'
    /// and the subnet's output queues.
    ///
    /// The iterator loops over the canisters (plus subnet) consuming one output
    /// message from each in a round robin fashion. For each canister and the
    /// subnet a circular iterator again ensures that messages are consumed
    /// from output queues in a round robin fashion.
    ///
    /// The iterator is peekable so that one can obtain a reference to the next
    /// message. Calling `next` will consume the message and remove it from the
    /// state. All messages that have not been explicitly consumed will remain
    /// in the state.
    pub fn output_into_iter(&mut self) -> impl PeekableOutputIterator + '_ {
        let own_subnet_id = self.metadata.own_subnet_id;

        OutputIterator::new(
            own_subnet_id,
            &mut self.canister_states,
            &mut self.subnet_queues,
        )
    }

    pub fn time(&self) -> Time {
        self.metadata.time()
    }

    /// Returns an immutable reference to `self.subnet_queues`.
    pub fn subnet_queues(&self) -> &CanisterQueues {
        &self.subnet_queues
    }

    /// Updates the byte size of responses in streams for each canister.
    fn update_stream_responses_size_bytes(&mut self) {
        let stream_responses_size_bytes = self.metadata.streams.responses_size_bytes();
        for (canister_id, canister_state) in self.canister_states.iter_mut() {
            canister_state.set_stream_responses_size_bytes(
                stream_responses_size_bytes
                    .get(canister_id)
                    .cloned()
                    .unwrap_or_default(),
            )
        }
    }

    /// Returns the number of canisters in this `ReplicatedState`.
    pub fn num_canisters(&self) -> usize {
        self.canister_states.len()
    }
}

/// A trait exposing `ReplicatedState` functionality for the exclusive use of
/// Message Routing.
pub trait ReplicatedStateMessageRouting {
    /// Returns a reference to the streams.
    fn streams(&self) -> &StreamMap;

    /// Removes the streams from this `ReplicatedState`.
    fn take_streams(&mut self) -> Streams;

    /// Atomically replaces the streams.
    fn put_streams(&mut self, streams: Streams);
}

impl ReplicatedStateMessageRouting for ReplicatedState {
    fn streams(&self) -> &StreamMap {
        self.metadata.streams.streams()
    }

    fn take_streams(&mut self) -> Streams {
        std::mem::take(Arc::make_mut(&mut self.metadata.streams))
    }

    fn put_streams(&mut self, streams: Streams) {
        // Should never replace a non-empty Streams via `put_streams()`.
        assert!(self.metadata.streams.streams().is_empty());

        *Arc::make_mut(&mut self.metadata.streams) = streams;
        self.update_stream_responses_size_bytes();
    }
}

pub mod testing {
    use super::*;
    use crate::{metadata_state::testing::StreamsTesting, testing::CanisterQueuesTesting};

    /// Exposes `ReplicatedState` internals for use in other crates' unit tests.
    pub trait ReplicatedStateTesting {
        /// Testing only: Returns a reference to `self.subnet_queues`
        fn subnet_queues(&self) -> &CanisterQueues;

        /// Testing only: Returns a mutable reference to `self.subnet_queues`.
        fn subnet_queues_mut(&mut self) -> &mut CanisterQueues;

        /// Testing only: Replaces `self.subnet_queues` with `subnet_queues`
        fn put_subnet_queues(&mut self, subnet_queues: CanisterQueues);

        /// Testing only: Replaces `SystemMetadata::streams` with the provided
        /// ones.
        fn with_streams(&mut self, streams: StreamMap);

        /// Testing only: Modifies `SystemMetadata::streams` by applying the
        /// provided function.
        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F);

        /// Testing only: Returns the number of messages across all canister and
        /// subnet output queues.
        fn output_message_count(&self) -> usize;
    }

    impl ReplicatedStateTesting for ReplicatedState {
        fn subnet_queues(&self) -> &CanisterQueues {
            &self.subnet_queues
        }

        fn subnet_queues_mut(&mut self) -> &mut CanisterQueues {
            &mut self.subnet_queues
        }

        fn put_subnet_queues(&mut self, subnet_queues: CanisterQueues) {
            self.subnet_queues = subnet_queues;
        }

        fn with_streams(&mut self, streams: StreamMap) {
            self.modify_streams(|streamz| *streamz = streams);
        }

        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F) {
            let mut streams = self.take_streams();
            streams.modify_streams(f);
            self.put_streams(streams);
        }

        fn output_message_count(&self) -> usize {
            self.canister_states
                .values()
                .map(|canister| canister.system_state.queues().output_message_count())
                .sum::<usize>()
                + self.subnet_queues.output_message_count()
        }
    }
}
