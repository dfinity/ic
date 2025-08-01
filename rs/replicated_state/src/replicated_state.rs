use super::{
    canister_state::CanisterState,
    metadata_state::{
        subnet_call_context_manager::{ReshareChainKeyContext, SignWithThresholdContext},
        IngressHistoryState, Stream, StreamMap, SystemMetadata,
    },
};
use crate::{
    canister_snapshots::{CanisterSnapshot, CanisterSnapshots},
    canister_state::{
        queues::{CanisterInput, CanisterQueuesLoopDetector},
        system_state::{push_input, CanisterOutputQueuesIterator},
    },
    CanisterQueues, DroppedMessageMetrics,
};
use ic_base_types::{PrincipalId, SnapshotId};
use ic_btc_replica_types::BitcoinAdapterResponse;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::messaging::{
    IngressInductionError, LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_CANISTER_STOPPED,
    LABEL_VALUE_CANISTER_STOPPING,
};
use ic_management_canister_types_private::CanisterStatusType;
use ic_protobuf::state::queues::v1::canister_queues::NextInputQueue;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    batch::{ConsensusResponse, RawQueryStats},
    ingress::IngressStatus,
    messages::{CallbackId, CanisterMessage, Ingress, MessageId, RequestOrResponse, Response},
    time::CoarseTime,
    AccumulatedPriority, CanisterId, Cycles, MemoryAllocation, NumBytes, SubnetId, Time,
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::{AddAssign, SubAssign};
use std::sync::Arc;
use strum_macros::{EnumCount, EnumIter};

/// Maximum message length of a synthetic reject response produced by message
/// routing.
pub const MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN: usize = 255;

/// Input queue type: local or remote subnet.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum InputQueueType {
    /// Local subnet input messages.
    LocalSubnet,
    /// Remote subnet input messages.
    RemoteSubnet,
}

/// Next input source: round-robin across local subnet canister messages;
/// ingress messages; and remote subnet canister messages.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, EnumCount, EnumIter)]
pub enum InputSource {
    /// Local subnet input messages.
    #[default]
    LocalSubnet = 0,
    /// Ingress messages.
    Ingress = 1,
    /// Remote subnet input messages.
    RemoteSubnet = 2,
}

impl From<&InputSource> for NextInputQueue {
    fn from(next: &InputSource) -> Self {
        match next {
            // Encode `LocalSubnet` as `Unspecified` because it is decoded as such (and it
            // serializes to zero bytes).
            InputSource::LocalSubnet => NextInputQueue::Unspecified,
            InputSource::Ingress => NextInputQueue::Ingress,
            InputSource::RemoteSubnet => NextInputQueue::RemoteSubnet,
        }
    }
}

impl From<NextInputQueue> for InputSource {
    fn from(next: NextInputQueue) -> Self {
        match next {
            NextInputQueue::Unspecified | NextInputQueue::LocalSubnet => InputSource::LocalSubnet,
            NextInputQueue::Ingress => InputSource::Ingress,
            NextInputQueue::RemoteSubnet => InputSource::RemoteSubnet,
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum StateError {
    /// Message enqueuing failed due to no matching canister ID.
    CanisterNotFound(CanisterId),

    /// Canister is stopped, not accepting any messages.
    CanisterStopped(CanisterId),

    /// Canister is stopping, only accepting responses.
    CanisterStopping(CanisterId),

    /// Message enqueuing failed due to full in/out queue.
    QueueFull { capacity: usize },

    /// Message enqueuing would have caused the canister or subnet to run over
    /// their memory limit.
    OutOfMemory { requested: NumBytes, available: i64 },

    /// Response enqueuing failed due to not matching the expected response.
    NonMatchingResponse {
        err_str: String,
        originator: CanisterId,
        callback_id: CallbackId,
        respondent: CanisterId,
        deadline: CoarseTime,
    },

    /// No corresponding request found when trying to push a response from the bitcoin adapter.
    BitcoinNonMatchingResponse { callback_id: u64 },
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

    /// Number of (potentially stale) message references left in the iterator.
    size: usize,
}

impl<'a> OutputIterator<'a> {
    fn new(
        canisters: &'a mut BTreeMap<CanisterId, CanisterState>,
        subnet_queues: &'a mut CanisterQueues,
        seed: u64,
    ) -> Self {
        let mut canister_iterators: VecDeque<_> = canisters
            .values_mut()
            .filter(|canister| canister.has_output())
            .map(|canister| canister.system_state.output_into_iter())
            .collect();

        let mut rng = ChaChaRng::seed_from_u64(seed);
        let rotation = rng.gen_range(0..canister_iterators.len().max(1));
        canister_iterators.rotate_left(rotation);

        // Push the subnet queues in front in order to make sure that at least one
        // system message is always routed as long as there is space for it.
        if subnet_queues.has_output() {
            canister_iterators.push_front(subnet_queues.output_into_iter());
        }

        let size = canister_iterators.iter().map(|q| q.size()).sum();

        OutputIterator {
            canister_iterators,
            size,
        }
    }

    /// Computes the number of (potentially stale) message references left in
    /// `queue_handles`.
    ///
    /// Time complexity: O(N).
    fn compute_size(queue_handles: &VecDeque<CanisterOutputQueuesIterator<'a>>) -> usize {
        queue_handles.iter().map(|q| q.size()).sum()
    }
}

impl std::iter::Iterator for OutputIterator<'_> {
    type Item = RequestOrResponse;

    /// Pops a message from the next canister. If this was not the last message
    /// for that canister, the canister iterator is moved to the back of the
    /// iteration order.
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(mut canister_iterator) = self.canister_iterators.pop_front() {
            // `next()` may consume an arbitrary number of stale references.
            self.size -= canister_iterator.size();
            let next = canister_iterator.next();
            self.size += canister_iterator.size();

            if next.is_some() {
                if !canister_iterator.is_empty() {
                    self.canister_iterators.push_back(canister_iterator);
                }

                debug_assert_eq!(Self::compute_size(&self.canister_iterators), self.size);
                return next;
            }
        }

        debug_assert_eq!(0, self.size);
        None
    }

    /// Returns the bounds on the number of messages remaining in the iterator.
    ///
    /// Since any message reference may or may not be stale (due to expiration /
    /// load shedding), there may be anywhere between 0 and `size` messages left in
    /// the iterator.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.size))
    }
}

pub trait PeekableOutputIterator: std::iter::Iterator<Item = RequestOrResponse> {
    /// Peeks into the iterator and returns a reference to the message that
    /// `next()` would return.
    fn peek(&self) -> Option<&RequestOrResponse>;

    /// Permanently filters out from iteration the next queue (i.e. all messages
    /// with the same sender and receiver as the next). The messages are retained
    /// in the output queue.
    fn exclude_queue(&mut self);

    /// Returns the number of (potentially stale) message references left in the
    /// iterator.
    fn size(&self) -> usize;
}

impl PeekableOutputIterator for OutputIterator<'_> {
    fn peek(&self) -> Option<&RequestOrResponse> {
        self.canister_iterators.front()?.peek()
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

    fn size(&self) -> usize {
        self.size
    }
}

pub const LABEL_VALUE_QUEUE_FULL: &str = "QueueFull";
pub const LABEL_VALUE_OUT_OF_MEMORY: &str = "OutOfMemory";
pub const LABEL_VALUE_INVALID_RESPONSE: &str = "InvalidResponse";
pub const LABEL_VALUE_BITCOIN_NON_MATCHING_RESPONSE: &str = "BitcoinNonMatchingResponse";

impl StateError {
    /// Returns a string representation of the `StateError` variant name to be
    /// used as a metric label value (e.g. `"QueueFull"`).
    pub fn to_label_value(&self) -> &'static str {
        match self {
            StateError::CanisterNotFound(_) => LABEL_VALUE_CANISTER_NOT_FOUND,
            StateError::CanisterStopped(_) => LABEL_VALUE_CANISTER_STOPPED,
            StateError::CanisterStopping(_) => LABEL_VALUE_CANISTER_STOPPING,
            StateError::QueueFull { .. } => LABEL_VALUE_QUEUE_FULL,
            StateError::OutOfMemory { .. } => LABEL_VALUE_OUT_OF_MEMORY,
            StateError::NonMatchingResponse { .. } => LABEL_VALUE_INVALID_RESPONSE,
            StateError::BitcoinNonMatchingResponse { .. } => {
                LABEL_VALUE_BITCOIN_NON_MATCHING_RESPONSE
            }
        }
    }

    /// Creates a `StateError::CanisterNotFound` variant with the given error
    /// message for the given `Response`.
    pub fn non_matching_response(err_str: impl ToString, response: &Response) -> Self {
        Self::NonMatchingResponse {
            err_str: err_str.to_string(),
            originator: response.originator,
            callback_id: response.originator_reply_callback,
            respondent: response.respondent,
            deadline: response.deadline,
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
            StateError::CanisterStopped(canister_id) => {
                write!(f, "Canister {} is stopped", canister_id)
            }
            StateError::CanisterStopping(canister_id) => {
                write!(f, "Canister {} is stopping", canister_id)
            }
            StateError::QueueFull { capacity } => {
                write!(f, "Maximum queue capacity {} reached", capacity)
            }
            StateError::OutOfMemory {
                requested,
                available,
            } => write!(
                f,
                "Cannot enqueue message. Out of memory: requested {}, available {}",
                requested, available
            ),
            StateError::NonMatchingResponse {err_str, originator, callback_id, respondent, deadline} => write!(
                f,
                "Cannot enqueue response with callback ID {} due to {} : originator => {}, respondent => {}, deadline => {}",
                callback_id, err_str, originator, respondent, Time::from(*deadline)
            ),
            StateError::BitcoinNonMatchingResponse { callback_id } => {
                write!(
                    f,
                    "Bitcoin: Attempted to push a response for callback ID {} without an in-flight corresponding request",
                    callback_id
                )
            }
        }
    }
}

/// Represents the memory taken in bytes by various resources.
///
/// Should be used in cases where the deterministic state machine needs to
/// compute how much available memory exists for canisters to use for the
/// various resources while respecting the relevant configured limits.
pub struct MemoryTaken {
    /// Execution memory accounts for canister memory reservation where
    /// specified and the actual canister memory usage (including
    /// Wasm custom sections) where no explicit memory reservation
    /// has been made.
    execution: NumBytes,
    /// Memory taken by guaranteed response canister messages or reservations.
    guaranteed_response_messages: NumBytes,
    /// Memory taken by best-effort canister messages.
    best_effort_messages: NumBytes,
    /// Memory taken by Wasm Custom Sections.
    wasm_custom_sections: NumBytes,
    /// Memory taken by canister history.
    canister_history: NumBytes,
}

impl MemoryTaken {
    /// Returns the amount of memory taken by execution state.
    pub fn execution(&self) -> NumBytes {
        self.execution
    }

    /// Returns the amount of memory taken by guaranteed response canister messages
    /// or reservations.
    pub fn guaranteed_response_messages(&self) -> NumBytes {
        self.guaranteed_response_messages
    }

    /// Returns the amount of memory taken by best-effort canister messages.
    pub fn best_effort_messages(&self) -> NumBytes {
        self.best_effort_messages
    }

    /// Returns the amount of memory taken by all canister messages (guaranteed
    /// response and best-effort).
    pub fn messages_total(&self) -> NumBytes {
        self.guaranteed_response_messages + self.best_effort_messages
    }

    /// Returns the amount of memory taken by Wasm Custom Sections.
    pub fn wasm_custom_sections(&self) -> NumBytes {
        self.wasm_custom_sections
    }

    /// Returns the amount of memory taken by canister history.
    pub fn canister_history(&self) -> NumBytes {
        self.canister_history
    }
}

/// Combination of memory used by and reserved for guaranteed response messages
/// and memory used by best-effort messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MessageMemoryUsage {
    /// Memory used by and reserved for guaranteed response canister messages, in
    /// bytes.
    pub guaranteed_response: NumBytes,

    /// Memory used by best-effort canister messages, in bytes.
    pub best_effort: NumBytes,
}

impl MessageMemoryUsage {
    pub const ZERO: MessageMemoryUsage = MessageMemoryUsage {
        guaranteed_response: NumBytes::new(0),
        best_effort: NumBytes::new(0),
    };

    /// Returns the total memory used by all canister messages (guaranteed response
    /// or best-effort).
    pub fn total(&self) -> NumBytes {
        self.guaranteed_response + self.best_effort
    }

    /// Calculates `self` + `rhs`.
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an
    /// arithmetic overflow would occur on either field. If an overflow would have
    /// occurred then the wrapped value is returned.
    pub fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let (guaranteed_response, overflow1) = self
            .guaranteed_response
            .get()
            .overflowing_add(rhs.guaranteed_response.get());
        let (best_effort, overflow2) = self
            .best_effort
            .get()
            .overflowing_add(rhs.best_effort.get());
        (
            Self {
                guaranteed_response: guaranteed_response.into(),
                best_effort: best_effort.into(),
            },
            overflow1 || overflow2,
        )
    }

    /// Returns `true` iff both fields of `self` are greater than or equal to the
    /// corresponding fields of `rhs`.
    pub fn ge(&self, rhs: Self) -> bool {
        self.guaranteed_response >= rhs.guaranteed_response && self.best_effort >= rhs.best_effort
    }
}

impl AddAssign<MessageMemoryUsage> for MessageMemoryUsage {
    fn add_assign(&mut self, rhs: MessageMemoryUsage) {
        self.guaranteed_response += rhs.guaranteed_response;
        self.best_effort += rhs.best_effort;
    }
}

impl SubAssign<MessageMemoryUsage> for MessageMemoryUsage {
    fn sub_assign(&mut self, rhs: MessageMemoryUsage) {
        self.guaranteed_response -= rhs.guaranteed_response;
        self.best_effort -= rhs.best_effort;
    }
}

/// ReplicatedState is the deterministic replicated state of the system.
/// Broadly speaking it consists of two parts:  CanisterState used for canister
/// execution and SystemMetadata used for message routing and history queries.
//
// * We don't derive `Serialize` and `Deserialize` because these are handled by
// our OP layer.
#[derive(Clone, PartialEq, Debug, ValidateEq)]
pub struct ReplicatedState {
    /// States of all canisters, indexed by canister ids.
    #[validate_eq(CompareWithValidateEq)]
    pub canister_states: BTreeMap<CanisterId, CanisterState>,

    /// Deterministic processing metadata.
    #[validate_eq(CompareWithValidateEq)]
    pub metadata: SystemMetadata,

    /// Queues for holding messages sent/received by the subnet.
    ///
    /// The Management Canister does not make outgoing calls as itself (it does so
    /// on behalf of canisters, but those messages are enqueued in the canister's
    /// output queue). Therefore, there's only a `push_subnet_output_response()`
    /// method (no equivalent for requests) and an explicit check against inducting
    /// responses into the subnet queues. This assumption is used in a number of
    /// places (e.g. when shedding or timing out messages), so adding support for
    /// outgoing calls in the future will likely require significant changes across
    /// `ReplicatedState` and `SystemState`.
    //
    // Must remain private.
    #[validate_eq(CompareWithValidateEq)]
    subnet_queues: CanisterQueues,

    /// Queue for holding responses arriving from Consensus.
    ///
    /// Responses from consensus are to be processed each round.
    /// The queue is, therefore, emptied at the end of every round.
    // TODO(EXE-109): Move this queue into `subnet_queues`
    pub consensus_queue: Vec<ConsensusResponse>,

    /// Temporary query stats received during the current epoch.
    /// Reset during the start of each epoch.
    pub epoch_query_stats: RawQueryStats,

    /// Manages the canister snapshots.
    #[validate_eq(CompareWithValidateEq)]
    pub canister_snapshots: CanisterSnapshots,
}

impl ReplicatedState {
    /// Creates a new empty replicated state.
    pub fn new(own_subnet_id: SubnetId, own_subnet_type: SubnetType) -> ReplicatedState {
        ReplicatedState {
            canister_states: BTreeMap::new(),
            metadata: SystemMetadata::new(own_subnet_id, own_subnet_type),
            subnet_queues: CanisterQueues::default(),
            consensus_queue: Vec::new(),
            epoch_query_stats: RawQueryStats::default(),
            canister_snapshots: CanisterSnapshots::default(),
        }
    }

    /// Creates a replicated state from a checkpoint.
    pub fn new_from_checkpoint(
        canister_states: BTreeMap<CanisterId, CanisterState>,
        metadata: SystemMetadata,
        subnet_queues: CanisterQueues,
        epoch_query_stats: RawQueryStats,
        canister_snapshots: CanisterSnapshots,
    ) -> Self {
        Self {
            canister_states,
            metadata,
            subnet_queues,
            consensus_queue: Vec::new(),
            epoch_query_stats,
            canister_snapshots,
        }
    }

    /// References into _all_ fields.
    pub fn component_refs(
        &self,
    ) -> (
        &BTreeMap<CanisterId, CanisterState>,
        &SystemMetadata,
        &CanisterQueues,
        &Vec<ConsensusResponse>,
        &RawQueryStats,
        &CanisterSnapshots,
    ) {
        let ReplicatedState {
            ref canister_states,
            ref metadata,
            ref subnet_queues,
            ref consensus_queue,
            ref epoch_query_stats,
            ref canister_snapshots,
        } = self;
        (
            canister_states,
            metadata,
            subnet_queues,
            consensus_queue,
            epoch_query_stats,
            canister_snapshots,
        )
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

    /// Time complexity: O(n), where n is the number of canisters.
    pub fn get_scheduler_priorities(&self) -> BTreeMap<CanisterId, AccumulatedPriority> {
        self.canister_states
            .iter()
            .map(|(canister_id, canister_state)| {
                (
                    *canister_id,
                    canister_state.scheduler_state.accumulated_priority,
                )
            })
            .collect()
    }

    /// Insert the canister state into the replicated state. If a canister
    /// already exists for the given canister ID, it will be replaced. It is the
    /// responsibility of the caller of this function to ensure that any
    /// relevant state associated with the older canister state are properly
    /// cleaned up.
    pub fn put_canister_state(&mut self, canister_state: CanisterState) {
        self.canister_states
            .insert(canister_state.canister_id(), canister_state);
    }

    /// Replaces the content of `self.canister_states` with the provided `canisters`.
    ///
    /// Panics if `self.canister_states` was not empty. The intended use is to
    /// call `put_canister_states()` after `take_canister_states()`, with no
    /// other canister-related calls in-between, in order to prevent concurrent
    /// mutations from replacing each other.
    pub fn put_canister_states(&mut self, canisters: BTreeMap<CanisterId, CanisterState>) {
        assert!(self.canister_states.is_empty());
        self.canister_states = canisters;
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

    // Loads a fresh version of the canister from the state and ensures that it
    // has a call context manager i.e. it is not stopped.
    pub fn get_active_canister(
        &self,
        canister_id: &CanisterId,
    ) -> Result<&CanisterState, UserError> {
        let canister = self.canister_state(canister_id).ok_or_else(|| {
            UserError::new(
                ErrorCode::CanisterNotFound,
                format!("Canister {} not found", canister_id),
            )
        })?;

        if canister.system_state.call_context_manager().is_none() {
            Err(UserError::new(
                ErrorCode::CanisterStopped,
                format!(
                    "Canister {} is stopped and therefore does not have a CallContextManager",
                    canister.canister_id()
                ),
            ))
        } else {
            Ok(canister)
        }
    }

    pub fn system_metadata(&self) -> &SystemMetadata {
        &self.metadata
    }

    pub fn get_ingress_status(&self, message_id: &MessageId) -> &IngressStatus {
        self.metadata
            .ingress_history
            .get(message_id)
            .unwrap_or(&IngressStatus::Unknown)
    }

    pub fn get_ingress_history(&self) -> &IngressHistoryState {
        &self.metadata.ingress_history
    }

    /// Sets the `status` for `message_id` in the ingress history. It will
    /// be ensured that the cumulative payload size of statuses in the
    /// ingress history will be below or equal to `ingress_memory_capacity`
    /// by transitioning `Completed` and `Failed` statuses to `Done` from
    /// oldest to newest in case inserting `status` pushes the memory
    /// consumption over the bound.
    ///
    /// Returns the previous status associated with `message_id`.
    pub fn set_ingress_status(
        &mut self,
        message_id: MessageId,
        status: IngressStatus,
        ingress_memory_capacity: NumBytes,
    ) -> Arc<IngressStatus> {
        self.metadata.ingress_history.insert(
            message_id,
            status,
            self.time(),
            ingress_memory_capacity,
        )
    }

    /// Prunes ingress history statuses with a pruning time older than
    /// `self.time()`.
    pub fn prune_ingress_history(&mut self) {
        self.metadata.ingress_history.prune(self.time());
    }

    /// Returns all subnets for which a stream is available.
    pub fn subnets_with_available_streams(&self) -> Vec<SubnetId> {
        self.metadata.streams.keys().cloned().collect()
    }

    /// Returns all signature request contexts.
    pub fn signature_request_contexts(&self) -> &BTreeMap<CallbackId, SignWithThresholdContext> {
        &self
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts
    }

    /// Returns all reshare chain key contexts.
    pub fn reshare_chain_key_contexts(&self) -> &BTreeMap<CallbackId, ReshareChainKeyContext> {
        &self
            .metadata
            .subnet_call_context_manager
            .reshare_chain_key_contexts
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

    /// Canister migrations require that a canister is stopped, has no guaranteed responses
    /// in any outgoing stream, and nothing in the input or output queue (guaranteed or otherwise).
    pub fn ready_for_migration(&self, canister: &CanisterId) -> bool {
        let streams_flushed = || {
            self.metadata
                .streams
                .iter()
                .all(|(_, stream)| stream.guaranteed_response_counts().get(canister).is_none())
        };

        let canister_state = match self.canister_state(canister) {
            Some(canister_state) => canister_state,
            None => return false,
        };

        let stopped = canister_state.system_state.status() == CanisterStatusType::Stopped;

        stopped && !canister_state.has_input() && !canister_state.has_output() && streams_flushed()
    }

    /// Computes the memory taken by different types of memory resources.
    pub fn memory_taken(&self) -> MemoryTaken {
        let (
            raw_memory_taken,
            mut guaranteed_response_message_memory_taken,
            mut best_effort_message_memory_taken,
            wasm_custom_sections_memory_taken,
            canister_history_memory_taken,
            wasm_chunk_store_memory_usage,
        ) = self
            .canisters_iter()
            .map(|canister| {
                (
                    match canister.memory_allocation() {
                        MemoryAllocation::Reserved(bytes) => bytes,
                        MemoryAllocation::BestEffort => canister.execution_memory_usage(),
                    },
                    canister
                        .system_state
                        .guaranteed_response_message_memory_usage(),
                    canister.system_state.best_effort_message_memory_usage(),
                    canister.wasm_custom_sections_memory_usage(),
                    canister.canister_history_memory_usage(),
                    canister.wasm_chunk_store_memory_usage(),
                )
            })
            .reduce(|accum, val| {
                (
                    accum.0 + val.0,
                    accum.1 + val.1,
                    accum.2 + val.2,
                    accum.3 + val.3,
                    accum.4 + val.4,
                    accum.5 + val.5,
                )
            })
            .unwrap_or_default();

        guaranteed_response_message_memory_taken +=
            (self.subnet_queues.guaranteed_response_memory_usage() as u64).into();
        best_effort_message_memory_taken +=
            (self.subnet_queues.best_effort_message_memory_usage() as u64).into();

        let canister_snapshots_memory_taken = self.canister_snapshots.memory_taken();

        MemoryTaken {
            execution: raw_memory_taken
                + canister_history_memory_taken
                + wasm_chunk_store_memory_usage
                + canister_snapshots_memory_taken,
            guaranteed_response_messages: guaranteed_response_message_memory_taken,
            best_effort_messages: best_effort_message_memory_taken,
            wasm_custom_sections: wasm_custom_sections_memory_taken,
            canister_history: canister_history_memory_taken,
        }
    }

    /// Computes the memory taken by guaranteed response messages.
    ///
    /// This is a more efficient alternative to `memory_taken()` for cases when only
    /// the message memory usage is necessary.
    pub fn guaranteed_response_message_memory_taken(&self) -> NumBytes {
        let canisters_memory_usage: NumBytes = self
            .canisters_iter()
            .map(|canister| {
                canister
                    .system_state
                    .guaranteed_response_message_memory_usage()
            })
            .sum();
        let subnet_memory_usage =
            (self.subnet_queues.guaranteed_response_memory_usage() as u64).into();

        canisters_memory_usage + subnet_memory_usage
    }

    /// Computes the memory taken by best-effort response messages.
    pub fn best_effort_message_memory_taken(&self) -> NumBytes {
        let canisters_memory_usage: NumBytes = self
            .canisters_iter()
            .map(|canister| canister.system_state.best_effort_message_memory_usage())
            .sum();
        let subnet_memory_usage =
            (self.subnet_queues.best_effort_message_memory_usage() as u64).into();

        canisters_memory_usage + subnet_memory_usage
    }

    /// Returns the total memory taken by the ingress history in bytes.
    pub fn total_ingress_memory_taken(&self) -> NumBytes {
        self.metadata.ingress_history.memory_usage()
    }

    /// Returns the total number of callbacks across all canisters.
    pub fn callback_count(&self) -> usize {
        self.canisters_iter()
            .map(|canister| {
                canister
                    .system_state
                    .call_context_manager()
                    .map_or(0, |ccm| ccm.callbacks().len())
            })
            .sum()
    }

    /// Returns the `SubnetId` hosting the given `principal_id` (canister or
    /// subnet).
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
    /// queue, while the messages from the other subnets get pushed to the inter
    /// subnet queues.
    ///
    /// On success, returns `Ok(true)` if the message was successfully inducted; or
    /// `Ok(false)` if the message was a best-effort response that was silently
    /// dropped.
    ///
    /// On failure (queue full, canister not found, out of memory), returns the
    /// corresponding error and the original message.
    ///
    /// Updates `subnet_available_guaranteed_response_memory` to reflect any change
    /// in memory usage.
    pub fn push_input(
        &mut self,
        msg: RequestOrResponse,
        subnet_available_guaranteed_response_memory: &mut i64,
    ) -> Result<bool, (StateError, RequestOrResponse)> {
        let own_subnet_type = self.metadata.own_subnet_type;
        let sender = msg.sender();
        let input_queue_type = if sender.get_ref() == self.metadata.own_subnet_id.get_ref()
            || self.canister_states.contains_key(&sender)
        {
            InputQueueType::LocalSubnet
        } else {
            InputQueueType::RemoteSubnet
        };

        let receiver = msg.receiver();
        match self.canister_state_mut(&receiver) {
            Some(receiver_canister) => receiver_canister.push_input(
                msg,
                subnet_available_guaranteed_response_memory,
                own_subnet_type,
                input_queue_type,
            ),
            None => {
                let subnet_id = self.metadata.own_subnet_id.get_ref();
                if receiver.get_ref() == subnet_id {
                    match &msg {
                        RequestOrResponse::Request(_) => push_input(
                            &mut self.subnet_queues,
                            msg,
                            subnet_available_guaranteed_response_memory,
                            own_subnet_type,
                            input_queue_type,
                        ),

                        RequestOrResponse::Response(response) => Err((
                            StateError::non_matching_response(
                                "Management canister does not accept canister responses",
                                response,
                            ),
                            msg,
                        )),
                    }
                } else {
                    match msg {
                        // Best-effort responses are silently dropped if the canister is not found.
                        RequestOrResponse::Response(response) if response.is_best_effort() => {
                            Ok(false)
                        }
                        // For all other messages this is an error.
                        _ => Err((StateError::CanisterNotFound(receiver), msg)),
                    }
                }
            }
        }
    }

    /// Pushes an ingress message into the induction pool (canister or subnet
    /// ingress queue).
    pub fn push_ingress(&mut self, msg: Ingress) -> Result<(), IngressInductionError> {
        if msg.is_addressed_to_subnet(self.metadata.own_subnet_id) {
            self.subnet_queues.push_ingress(msg);
        } else {
            let canister_id = msg.receiver;
            let canister = match self.canister_states.get_mut(&canister_id) {
                Some(canister) => canister,
                None => return Err(IngressInductionError::CanisterNotFound(canister_id)),
            };
            canister.push_ingress(msg);
        }
        Ok(())
    }

    /// Extracts the next inter-canister or ingress message (round-robin) from
    /// `self.subnet_queues`.
    pub fn pop_subnet_input(&mut self) -> Option<CanisterMessage> {
        self.subnet_queues
            .pop_input()
            .map(subnet_input_into_canister_message)
    }

    /// Peeks the next inter-canister or ingress message (round-robin) from
    /// `self.subnet_queues`.
    pub fn peek_subnet_input(&mut self) -> Option<CanisterMessage> {
        self.subnet_queues
            .peek_input()
            .map(subnet_input_into_canister_message)
    }

    /// Skips the next inter-canister or ingress message from `self.subnet_queues`.
    pub fn skip_subnet_input(&mut self, loop_detector: &mut CanisterQueuesLoopDetector) {
        self.subnet_queues.skip_input(loop_detector);
    }

    /// Creates a new loop detector.
    pub fn subnet_queues_loop_detector(&self) -> CanisterQueuesLoopDetector {
        CanisterQueuesLoopDetector::default()
    }

    /// Pushes a `Response` type message into the relevant subnet output queue.
    /// The protocol should have already reserved a slot, so this cannot fail.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_subnet_output_response(&mut self, msg: Arc<Response>) {
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
        let time = self.metadata.time();

        OutputIterator::new(
            &mut self.canister_states,
            &mut self.subnet_queues,
            // We seed the output iterator with the time. We can do this because
            // we don't need unpredictability of the rotation.
            time.as_nanos_since_unix_epoch(),
        )
    }

    pub fn time(&self) -> Time {
        self.metadata.time()
    }

    /// Returns an immutable reference to `self.subnet_queues`.
    pub fn subnet_queues(&self) -> &CanisterQueues {
        &self.subnet_queues
    }

    /// See `IngressQueue::filter_messages()` for documentation.
    pub fn filter_subnet_queues_ingress_messages<F>(&mut self, filter: F) -> Vec<Arc<Ingress>>
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.subnet_queues.filter_ingress_messages(filter)
    }

    /// Returns an immutable reference to `self.epoch_query_stats`.
    pub fn query_stats(&self) -> &RawQueryStats {
        &self.epoch_query_stats
    }

    /// Returns the number of canisters in this `ReplicatedState`.
    pub fn num_canisters(&self) -> usize {
        self.canister_states.len()
    }

    /// Garbage collects empty canister and subnet queues.
    pub fn garbage_collect_canister_queues(&mut self) {
        for (_canister_id, canister) in self.canister_states.iter_mut() {
            canister.system_state.garbage_collect_canister_queues();
        }
        self.subnet_queues.garbage_collect();
    }

    /// Pushes a response from the Bitcoin Adapter into the state.
    pub fn push_response_bitcoin(
        &mut self,
        response: BitcoinAdapterResponse,
    ) -> Result<(), StateError> {
        crate::bitcoin::push_response(self, response)
    }

    /// Times out all messages with expired deadlines (given the state time) in all
    /// canister (but not subnet) queues. Returns the total amount of attached
    /// cycles that was lost.
    ///
    /// See `CanisterQueues::time_out_messages` for further details.
    pub fn time_out_messages(&mut self, metrics: &impl DroppedMessageMetrics) -> Cycles {
        let current_time = self.metadata.time();
        // Because the borrow checker requires us to remove each canister before
        // calling `time_out_messages()` on it and replace it afterwards; and removing
        // and replacing every canister on a large subnet is very costly; we first
        // filter for the (usually much fewer) canisters with timed out requests and only
        // apply the costly remove-call-replace to those.
        let canister_ids_with_expired_deadlines = self
            .canister_states
            .iter()
            .filter(|(_, canister_state)| {
                canister_state
                    .system_state
                    .has_expired_message_deadlines(current_time)
            })
            .map(|(canister_id, _)| *canister_id)
            .collect::<Vec<_>>();

        let mut cycles_lost = Cycles::zero();
        for canister_id in canister_ids_with_expired_deadlines {
            let mut canister = self.canister_states.remove(&canister_id).unwrap();
            let canister_cycles_lost = canister.system_state.time_out_messages(
                current_time,
                &canister_id,
                &self.canister_states,
                metrics,
            );
            cycles_lost += canister_cycles_lost;
            self.canister_states.insert(canister_id, canister);
        }

        if self.subnet_queues.has_expired_deadlines(current_time) {
            let subnet_cycles_lost = self.subnet_queues.time_out_messages(
                current_time,
                &self.metadata.own_subnet_id.into(),
                &self.canister_states,
                metrics,
            );
            cycles_lost += subnet_cycles_lost;
        }

        cycles_lost
    }

    /// Times out all callbacks with expired deadlines (given the state time) that
    /// have not already been timed out. Returns the number of timed out callbacks
    /// and any errors that prevented a `DeadlineExpired` response from being
    /// enqueued (which would signal a bug).
    ///
    /// See `CanisterQueues::time_out_callbacks` for further details.
    pub fn time_out_callbacks(&mut self) -> (usize, Vec<StateError>) {
        let current_time = CoarseTime::floor(self.metadata.time());
        // Because the borrow checker requires us to remove each canister before
        // calling `time_out_callbacks()` on it and replace it afterwards; and removing
        // and replacing every canister on a large subnet is very costly; we first
        // filter for the (usually much fewer) canisters with timed out callbacks and
        // only apply the costly remove-call-replace to those.
        let canister_ids_with_expired_callbacks = self
            .canister_states
            .iter()
            .filter(|(_, canister_state)| {
                canister_state
                    .system_state
                    .has_expired_callbacks(current_time)
            })
            .map(|(canister_id, _)| *canister_id)
            .collect::<Vec<_>>();

        let mut expired_callback_count = 0;
        let mut errors = Vec::new();
        for canister_id in canister_ids_with_expired_callbacks {
            let mut canister = self.canister_states.remove(&canister_id).unwrap();
            let (canister_expired_callback_count, canister_errors) = canister
                .system_state
                .time_out_callbacks(current_time, &canister_id, &self.canister_states);
            expired_callback_count += canister_expired_callback_count;
            errors.extend(canister_errors);
            self.canister_states.insert(canister_id, canister);
        }

        (expired_callback_count, errors)
    }

    /// Enforces the best-effort message limit by repeatedly shedding the largest
    /// best-effort message of the canister with the highest best-effort message
    /// memory usage until the total memory usage drops below the limit.
    ///
    /// Returns the total amount of attached cycles that was lost.
    ///
    /// Time complexity: `O(n * log(n))`.
    pub fn enforce_best_effort_message_limit(
        &mut self,
        limit: NumBytes,
        metrics: &impl DroppedMessageMetrics,
    ) -> Cycles {
        const ZERO_BYTES: NumBytes = NumBytes::new(0);

        // Check if we need to do anything at all before constructing a priority queue.
        let mut memory_usage = self.best_effort_message_memory_taken();
        if memory_usage <= limit {
            // No need to do anything.
            return Cycles::zero();
        }

        // Construct a priority queue of canisters by best-effort message memory usage.
        let mut priority_queue: BTreeSet<_> = self
            .canister_states
            .iter()
            .filter_map(|(canister_id, canister)| {
                let memory_usage = canister.system_state.best_effort_message_memory_usage();
                if memory_usage > ZERO_BYTES {
                    Some((memory_usage, *canister_id))
                } else {
                    None
                }
            })
            .collect();
        let subnet_queues_memory_usage = self.subnet_queues.best_effort_message_memory_usage();
        if subnet_queues_memory_usage > 0 {
            priority_queue.insert((
                (subnet_queues_memory_usage as u64).into(),
                self.metadata.own_subnet_id.into(),
            ));
        }

        let mut cycles_lost = Cycles::zero();

        // Shed messages from the canisters with the largest memory usage until we are
        // below the limit.
        //
        // The `is_empty()` check is a safety net, in case a canister somehow reports
        // non-zero best-effort memory usage but then fails to shed a message.
        while memory_usage > limit && !priority_queue.is_empty() {
            let (memory_usage_before, canister_id) = priority_queue.pop_last().unwrap();

            let (message_shed, memory_usage_after, message_cycles_lost) =
                if canister_id.get() == self.metadata.own_subnet_id.get() {
                    // Shed from the subnet queues.
                    let (message_shed, message_cycles_lost) = self
                        .subnet_queues
                        .shed_largest_message(&canister_id, &self.canister_states, metrics);
                    let memory_usage_after =
                        (self.subnet_queues.best_effort_message_memory_usage() as u64).into();
                    (message_shed, memory_usage_after, message_cycles_lost)
                } else {
                    // Shed from a canister's queues: remove the canister, shed its largest message,
                    // replace it.
                    let mut canister = self.canister_states.remove(&canister_id).unwrap();
                    let (message_shed, message_cycles_lost) = canister
                        .system_state
                        .shed_largest_message(&canister_id, &self.canister_states, metrics);
                    let memory_usage_after =
                        canister.system_state.best_effort_message_memory_usage();
                    self.canister_states.insert(canister_id, canister);
                    (message_shed, memory_usage_after, message_cycles_lost)
                };
            debug_assert!(message_shed);

            // Replace the canister in the priority queue iff its memory usage is still
            // non-zero AND a message was actually shed.
            if memory_usage_after > ZERO_BYTES && message_shed {
                priority_queue.insert((memory_usage_after, canister_id));
            }

            // Update the total memory usage.
            debug_assert!(memory_usage_before > memory_usage_after);
            let memory_usage_delta = memory_usage_before - memory_usage_after;
            memory_usage -= memory_usage_delta;
            debug_assert_eq!(self.best_effort_message_memory_taken(), memory_usage);

            cycles_lost += message_cycles_lost;
        }
        cycles_lost
    }

    /// Adds a new snapshot to the list of snapshots.
    ///
    /// This function is used by the management canister's TakeSnapshot function to change the state.
    /// Note that the rest of the logic, e.g. constructing the `snapshot` is done in the calling code.
    pub fn take_snapshot(
        &mut self,
        snapshot_id: SnapshotId,
        snapshot: Arc<CanisterSnapshot>,
    ) -> SnapshotId {
        self.metadata
            .unflushed_checkpoint_ops
            .take_snapshot(snapshot.canister_id(), snapshot_id);
        self.canister_snapshots.push(snapshot_id, snapshot)
    }

    /// Adds a new snapshot to the list of snapshots.
    pub fn create_snapshot_from_metadata(
        &mut self,
        snapshot_id: SnapshotId,
        snapshot: Arc<CanisterSnapshot>,
    ) {
        self.metadata
            .unflushed_checkpoint_ops
            .create_snapshot_from_metadata(snapshot_id);
        self.canister_snapshots.push(snapshot_id, snapshot);
    }

    /// This records a data upload event such that the data can be flushed to disk before a checkpoint.
    pub fn record_snapshot_data_upload(&mut self, snapshot_id: SnapshotId) {
        self.metadata
            .unflushed_checkpoint_ops
            .upload_data(snapshot_id);
    }

    /// Delete a snapshot from the list of snapshots.
    pub fn delete_snapshot(&mut self, snapshot_id: SnapshotId) -> Option<Arc<CanisterSnapshot>> {
        let result = self.canister_snapshots.remove(snapshot_id);
        if result.is_some() {
            self.metadata
                .unflushed_checkpoint_ops
                .delete_snapshot(snapshot_id)
        }
        result
    }

    /// Delete all snapshots belonging to the given canister id.
    pub fn delete_snapshots(&mut self, canister_id: CanisterId) {
        let deleted = self.canister_snapshots.delete_snapshots(canister_id);
        for snapshot_id in deleted {
            self.metadata
                .unflushed_checkpoint_ops
                .delete_snapshot(snapshot_id);
        }
    }

    /// Splits the replicated state as part of subnet splitting phase 1, retaining
    /// only the canisters of `subnet_id` (as determined by the provided routing
    /// table).
    ///
    /// A subnet split starts with a subnet A and results in two subnets, A' and B.
    /// For the sake of clarity, comments refer to the two resulting subnets as
    /// *subnet A'* and *subnet B*; and to the original subnet as *subnet A*.
    /// Because subnet A' retains the subnet ID of subnet A, it is identified by
    /// having `subnet_id == self.own_subnet_id`. Conversely, subnet B has
    /// `subnet_id != self.own_subnet_id`.
    ///
    /// This first phase only consists of:
    ///  * Splitting the canisters hosted by A among A' and B, as determined by the
    ///    provided routing table.
    ///  * Splitting the canister snapshots stored by A among A' and B,
    ///    as determined by the canister splitting.
    ///  * Producing a new, empty `MetadataState` for subnet B, but preserving
    ///    the ingress history unchanged.
    ///
    /// Preserving the individual canister states and ingress history without
    /// mutations in a first phase, makes it trivial to ensure that the state has
    /// not been tampered with during the split (by checking that the file hashes
    /// have not changed).
    ///
    /// Internal adjustments to the various parts of the state happen in a second
    /// phase, during subnet startup (see [`Self::after_split()`]).
    pub fn split(
        self,
        subnet_id: SubnetId,
        routing_table: &RoutingTable,
        new_subnet_batch_time: Option<Time>,
    ) -> Result<Self, String> {
        // Destructure `self` and put it back together, in order for the compiler to
        // enforce an explicit decision whenever new fields are added.
        let Self {
            mut canister_states,
            metadata,
            mut subnet_queues,
            consensus_queue,
            epoch_query_stats: _,
            mut canister_snapshots,
        } = self;

        // Consensus queue is always empty at the end of the round.
        assert!(consensus_queue.is_empty());

        // Retain only canisters hosted by `own_subnet_id`.
        //
        // TODO: Validate that canisters are split across no more than 2 subnets.
        canister_states
            .retain(|canister_id, _| routing_table.route(canister_id.get()) == Some(subnet_id));

        // All subnet messages (ingress and canister) only remain on subnet A' because:
        //
        //  * Message Routing would drop a response from subnet B to a request it had
        //    routed to subnet A.
        //  * Message Routing will take care of routing the responses to the originator,
        //    regardless of subnet.
        //  * Some requests (ingress or canister) will fail if the target canister has
        //    been migrated away, but the alternative would require unpacking and acting
        //    on the contents of arbitrary methods' payloads.
        if metadata.own_subnet_id != subnet_id {
            // On subnet B, start with empty subnet queues.
            subnet_queues = CanisterQueues::default();
        }

        // Obtain a new metadata state for subnet B. No-op for subnet A' (apart from
        // setting the split marker).
        let mut metadata = metadata.split(subnet_id, new_subnet_batch_time)?;

        // Retain only the canister snapshots belonging to the local canisters.
        let deleted =
            canister_snapshots.split(|canister_id| canister_states.contains_key(&canister_id));
        for snapshot_id in deleted {
            metadata
                .unflushed_checkpoint_ops
                .delete_snapshot(snapshot_id);
        }

        Ok(Self {
            canister_states,
            metadata,
            subnet_queues,
            consensus_queue,
            epoch_query_stats: RawQueryStats::default(), // Don't preserve query stats during subnet splitting.
            canister_snapshots,
        })
    }

    /// Makes adjustments to the replicated state, in the second phase of a subnet
    /// split (see `Self::split()` for the first phase).
    ///
    /// This second phase, during subnet startup:
    ///
    /// * Updates canisters' input schedules, based on `self.canister_states`.
    /// * Prunes the ingress history, retaining only messages addressed to this
    ///   subnet and messages in terminal states (which will time out).
    pub fn after_split(&mut self) {
        // Destructure `self` in order for the compiler to enforce an explicit decision
        // whenever new fields are added.
        //
        // (!) DO NOT USE THE ".." WILDCARD, THIS SERVES THE SAME FUNCTION AS a `match`!
        let Self {
            ref mut canister_states,
            ref mut metadata,
            ref mut subnet_queues,
            consensus_queue: _,
            epoch_query_stats: _,
            canister_snapshots: _,
        } = self;

        // Reset query stats after subnet split
        self.epoch_query_stats = RawQueryStats::default();

        metadata
            .split_from
            .expect("Not a state resulting from a subnet split");

        // Adjust `CanisterQueues::(local|remote)_subnet_input_schedule` based on which
        // canisters are present in `canister_states`.
        let local_canister_ids = canister_states.keys().cloned().collect::<Vec<_>>();
        for canister_id in local_canister_ids.iter() {
            let mut canister_state = canister_states.remove(canister_id).unwrap();
            canister_state
                .system_state
                .split_input_schedules(canister_id, canister_states);
            canister_states.insert(*canister_id, canister_state);
        }

        // Drop in-progress management calls being executed by canisters on subnet B
        // (`own_subnet_id != split_from`). The corresponding calls will be rejected on
        // subnet A', ensuring consistency across subnet and canister states.
        if metadata.split_from != Some(metadata.own_subnet_id) {
            for canister_state in canister_states.values_mut() {
                canister_state.drop_in_progress_management_calls_after_split();
            }
        }

        // Prune the ingress history. And reject in-progress subnet messages being
        // executed by canisters no longer on this subnet.
        metadata.after_split(
            |canister_id| canister_states.contains_key(&canister_id),
            subnet_queues,
        );
    }
}

/// Converts a `CanisterInput` popped from a subnet input queue into a
/// `CanisterMessage`.
///
/// As opposed to actual canister queues, subnet input queues should never hold
/// any kind of response (because the management canister does not make any
/// outbound calls as itself).
fn subnet_input_into_canister_message(input: CanisterInput) -> CanisterMessage {
    match input {
        CanisterInput::Ingress(ingress) => CanisterMessage::Ingress(ingress),
        CanisterInput::Request(request) => CanisterMessage::Request(request),
        CanisterInput::Response(_)
        | CanisterInput::DeadlineExpired(_)
        | CanisterInput::ResponseDropped(_) => {
            unreachable!("Subnet input queues should never hold responses")
        }
    }
}

/// A trait exposing `ReplicatedState` functionality for the exclusive use of
/// Message Routing.
pub trait ReplicatedStateMessageRouting {
    /// Returns a reference to the streams.
    fn streams(&self) -> &StreamMap;

    /// Removes the streams from this `ReplicatedState`.
    fn take_streams(&mut self) -> StreamMap;

    /// Atomically replaces the streams.
    fn put_streams(&mut self, streams: StreamMap);
}

impl ReplicatedStateMessageRouting for ReplicatedState {
    fn streams(&self) -> &StreamMap {
        &self.metadata.streams
    }

    fn take_streams(&mut self) -> StreamMap {
        std::mem::take(Arc::make_mut(&mut self.metadata.streams))
    }

    fn put_streams(&mut self, streams: StreamMap) {
        // Should never replace a non-empty StreamMap via `put_streams()`.
        assert!(self.metadata.streams.is_empty());

        *Arc::make_mut(&mut self.metadata.streams) = streams;
    }
}

pub mod testing {
    use super::*;

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
            f(&mut streams);
            self.put_streams(streams);
        }

        fn output_message_count(&self) -> usize {
            self.canister_states
                .values()
                .map(|canister| canister.system_state.queues().output_queues_message_count())
                .sum::<usize>()
                + self.subnet_queues.output_queues_message_count()
        }
    }

    /// Early warning system / stumbling block forcing the authors of changes adding
    /// or removing replicated state fields to think about and/or ask the Message
    /// Routing team to think about any repercussions to the subnet splitting logic.
    ///
    /// If you do find yourself having to make changes to this function, it is quite
    /// possible that you have not broken anything. But there is a non-zero chance
    /// for changes to the structure of the replicated state to also require changes
    /// to the subnet splitting logic or risk breaking it. Which is why this brute
    /// force check exists.
    ///
    /// See `ReplicatedState::split()` and `ReplicatedState::after_split()` for more
    /// context.
    #[allow(dead_code)]
    fn subnet_splitting_change_guard_do_not_modify_without_reading_doc_comment() {
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let _state = ReplicatedState {
            // No need to cover canister states, they get split based on the routing table.
            canister_states: Default::default(),
            // Covered in `crate::metadata_state::testing`.
            metadata: SystemMetadata::new(
                SubnetId::new(PrincipalId::new_subnet_test_id(13)),
                SubnetType::Application,
            ),
            subnet_queues: Default::default(),
            consensus_queue: Default::default(),
            epoch_query_stats: Default::default(),
            // TODO(EXC-1527): Handle canister snapshots during a subnet split.
            canister_snapshots: CanisterSnapshots::default(),
        };
    }
}
