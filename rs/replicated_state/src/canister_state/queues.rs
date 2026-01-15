mod input_schedule;
mod message_pool;
pub mod proto;
mod queue;
pub mod refunds;
#[cfg(test)]
mod tests;

pub use self::input_schedule::CanisterQueuesLoopDetector;
use self::input_schedule::InputSchedule;
use self::message_pool::{
    Context, InboundReference, Kind, MessagePool, OutboundReference, SomeReference,
};
use self::queue::{CanisterQueue, IngressQueue, InputQueue, OutputQueue};
use self::refunds::RefundPool;
use crate::page_map::int_map::MutableIntMap;
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;
use crate::{
    CanisterState, CheckpointLoadingMetrics, DroppedMessageMetrics, InputQueueType, InputSource,
    StateError,
};
use ic_base_types::PrincipalId;
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::MessageMemoryUsage;
use ic_management_canister_types_private::IC_00;
use ic_protobuf::state::queues::v1 as pb_queues;
use ic_types::messages::{
    CallbackId, Ingress, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE, Payload, RejectContext, Request,
    RequestOrResponse, Response,
};
use ic_types::{CanisterId, CountBytes, Cycles, NumBytes, Time};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use message_pool::ToContext;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::{From, TryFrom};
use std::sync::Arc;
use strum::EnumCount;

pub const DEFAULT_QUEUE_CAPACITY: usize = 500;

/// Wrapper around the induction pool (ingress and input queues); a priority
/// queue for round-robin scheduling across senders when consuming input
/// messages; and output queues.
///
/// Encapsulates the `InductionPool` component described in the spec. The reason
/// for bundling together the induction pool and output queues is to reliably
/// implement backpressure via queue slot reservations for response messages.
///
/// # Structure
///
/// At a high level,`CanisterQueues` can be broken down into several components:
///
///  1. Ingress queue: queue of user messages, see [IngressQueue] for details.
///
///  2. Canister input and output queues: a map of pairs of canister input and
///     output queues; one pair per canister (including ourselves). Canister
///     queues come in pairs in order to reliably implement backpressure, by
///     reserving queue slots for responses: before a request can be enqueued
///     into an input / output queue, a response slot must have been reserved in
///     the reverse output / input queue.
///
///     Canister queues hold references (of type `message_pool::Reference<T>`)
///     into the message pool (see below) or into maps of expired callbacks or
///     shed responses ("compact responses", represented as `CallbackIds`). Some
///     references may be *stale* due to expiration or load shedding.
///
///  3. Message pool (for the purpose of this breakdown, also includes the maps
///     of compact responses): backing storage for canister input and output
///     queues.
///
///     The message pool holds the messages referenced from `canister_queues`,
///     with support for time-based expiration and load shedding. Also maintains
///     message count and size stats, broken down along several dimensions.
///
///     In order to handle shedding of inbound responses; as well as for compact
///     representation of timeout responses; shed and expired `CallbackIds`
///     ("compact responses") are maintained in separate maps. When it peeks or
///     pops such a `CallbackId`, `SystemState` retrieves the `Callback` and
///     synthesizes a reject response based on it.
///
///  4. Queue stats: slot and memory reservation stats, for efficient validation
///     checks and memory usage calculations.
///
///  5. Input schedules: FIFO queues of local and remote subnet senders plus a
///     "next input" pointer for round-robin consumption of input messages.
///
/// # Hard invariants
///
///  * The reference at the front of a non-empty canister input or output queue
///    is non-stale.
///
///    This is to avoid a live lock where a canister's output queue(s) are
///    filled to capacity with stale references, preventing any more messages
///    from being enqueued; but at the same time the canister is never included
///    in an `OutputIterator` (the only way of consuming the stale references)
///    because it has no outbound messages in its pool.
///
///    Dropping this invariant would require `available_output_request_slots()`
///    to iterate over every input and output queue in order to discount stale
///    references in the front from the count of available slots. Or else,
///    (re-)introduce the old "slots in use in output queues" queue stat and use
///    that to determine whether or not to create an output iterator for a
///    canister. The former is potentially horribly inefficient; the latter
///    requires additional code and significant test coverage. Without one of
///    these changes, Execution will synchronously fail any call made by the
///    canister. On top of this, the push implementation would need to actively
///    try to pop a stale reference from the front of the queue whenever the
///    queue is at capacity. See https://github.com/dfinity/ic/pull/1293 for an
///    attempted implementation.
///
///  * `callbacks_with_enqueued_response` contains the precise set of
///    `CallbackIds` of all inbound responses and compact responses.
///
/// # Soft invariants
///
///  * `QueueStats`' input / output queue slot reservation stats are consistent
///    with the actual number of reserved slots across input / output queues.
///
///  * All keys (references) in the pool and in the compact response maps are
///    enqueued in the canister queues exactly once.
///
///  * `InputSchedule` invariants: all non-empty input queues are scheduled;
///    input schedules are internally consistent; local canisters are scheduled
///    in the local input schedule, remote canisters in any schedule.
///
///  # External invariants
///
///  * `QueueStats`' slot and memory reservation stats are consistent with
///    `CallContextManager`'s callbacks and non-responded call contexts (see
///    `SystemState::check_invariants()` for details).
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub struct CanisterQueues {
    /// Queue of ingress (user) messages.
    #[validate_eq(CompareWithValidateEq)]
    ingress_queue: IngressQueue,

    /// Per remote canister input and output queues. Queues hold references into the
    /// message pool, some of which may be stale due to expiration or load shedding.
    ///
    /// The reference at the front of each queue, if any, is guaranteed to be
    /// non-stale. A reference in an output queue is stale if there exists no
    /// corresponding message in the message pool. This can happen if the message
    /// was expired or shed. A reference in an input queue is stale if there exists
    /// no corresponding message in the message pool; or entry in the compact
    /// response maps (which record the `CallbackIds` of expired / shed inbound
    /// best-effort responses).
    canister_queues: BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,

    /// Backing store for `canister_queues` references, combining a `MessagePool`
    /// and maps of compact responses (`CallbackIds` of expired / shed responses),
    /// with specific behavior for inbound vs outbound messages.
    #[validate_eq(CompareWithValidateEq)]
    store: MessageStoreImpl,

    /// Slot and memory reservation stats. Message count and size stats are
    /// maintained separately in the `MessagePool`.
    #[validate_eq(CompareWithValidateEq)]
    queue_stats: QueueStats,

    /// Round-robin schedule for `pop_input()` across ingress, local subnet senders
    /// and remote subnet senders; as well as within the local subnet senders and
    /// remote subnet senders groups.
    input_schedule: InputSchedule,

    /// The `CallbackIds` of all responses enqueued in input queues, whether an
    /// actual `Response` in the message pool or a compact response (`CallbackId`)
    /// in `expired_callbacks` or `shed_responses`.
    ///
    /// Used for response deduplication (whether due to a locally generated reject
    /// response to a best-effort call; or due to a malicious / buggy subnet).
    callbacks_with_enqueued_response: MutableIntMap<CallbackId, ()>,
}

/// Circular iterator that consumes output queue messages: loops over output
/// queues, popping one message at a time from each in a round robin fashion.
/// All messages that have not been explicitly popped will remain in the state.
///
/// Additional operations compared to a standard iterator:
///  * peeking (returning a reference to the next message without consuming it);
///    and
///  * excluding whole queues from iteration while retaining them in the state
///    (e.g. in order to efficiently implement per destination limits).
#[derive(Debug)]
pub struct CanisterOutputQueuesIterator<'a> {
    /// Priority queue of non-empty output queues. The next message to be popped
    /// / peeked is the one at the front of the first queue.
    queues: VecDeque<(&'a CanisterId, &'a mut Arc<OutputQueue>)>,

    /// Mutable store holding the messages referenced by `queues`.
    store: &'a mut MessageStoreImpl,

    /// Number of (potentially stale) messages left in the iterator.
    size: usize,
}

impl<'a> CanisterOutputQueuesIterator<'a> {
    /// Creates a new output queue iterator from the given
    /// `CanisterQueues::canister_queues` (a map of `CanisterId` to an input queue,
    /// output queue pair) and `MessagePool`.
    fn new(
        queues: &'a mut BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,
        store: &'a mut MessageStoreImpl,
    ) -> Self {
        let queues: VecDeque<_> = queues
            .iter_mut()
            .filter(|(_, (_, queue))| queue.len() > 0)
            .map(|(canister, (_, queue))| (canister, queue))
            .collect();
        let size = Self::compute_size(&queues);

        CanisterOutputQueuesIterator {
            queues,
            store,
            size,
        }
    }

    /// Returns the first message from the next queue.
    pub fn peek(&self) -> Option<&RequestOrResponse> {
        let queue = &self.queues.front()?.1;
        let reference = queue.peek().expect("Empty queue in iterator.");

        Some(self.store.get(reference))
    }

    /// Pops the first message from the next queue.
    ///
    /// Advances the queue to the next non-stale message. If such a message exists,
    /// the queue is moved to the back of the iteration order, else it is dropped.
    pub fn pop(&mut self) -> Option<RequestOrResponse> {
        let (receiver, queue) = self.queues.pop_front()?;
        debug_assert!(self.size >= queue.len());
        self.size -= queue.len();

        // Queue must be non-empty and message at the front of queue non-stale.
        let msg = self
            .store
            .queue_pop_and_advance(queue)
            .expect("Empty queue in output iterator.");
        debug_assert_eq!(Ok(()), self.store.queue_front_not_stale(queue, receiver));

        if queue.len() > 0 {
            self.size += queue.len();
            self.queues.push_back((receiver, queue));
        }
        debug_assert_eq!(Self::compute_size(&self.queues), self.size);
        debug_assert_eq!(self.queues.is_empty(), self.size == 0);

        Some(msg)
    }

    /// Permanently excludes from iteration the next queue (i.e. all messages
    /// with the same sender and receiver as the next message). The messages are
    /// retained in the output queue.
    ///
    /// Returns the number of (potentially stale) messages left in the just excluded
    /// queue.
    pub fn exclude_queue(&mut self) -> usize {
        let excluded = self
            .queues
            .pop_front()
            .map(|(_, q)| q.len())
            .unwrap_or_default();

        debug_assert!(self.size >= excluded);
        self.size -= excluded;
        debug_assert_eq!(Self::compute_size(&self.queues), self.size);
        debug_assert_eq!(self.queues.is_empty(), self.size == 0);

        excluded
    }

    /// Checks if the iterator has finished.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.queues.is_empty(), self.size == 0);
        self.queues.is_empty()
    }

    /// Returns the number of (potentially stale) messages left in the iterator.
    pub fn size(&self) -> usize {
        debug_assert_eq!(self.queues.is_empty(), self.size == 0);
        self.size
    }

    /// Computes the number of (potentially stale) messages left in `queues`.
    ///
    /// Time complexity: `O(n)`.
    fn compute_size(queues: &VecDeque<(&'a CanisterId, &'a mut Arc<OutputQueue>)>) -> usize {
        queues.iter().map(|(_, q)| q.len()).sum()
    }
}

impl Iterator for CanisterOutputQueuesIterator<'_> {
    type Item = RequestOrResponse;

    /// Alias for `pop`.
    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
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

/// Kinds of canister inputs returned by `CanisterQueues::pop_input()` /
/// `CanisterQueues::peek_input()`: in addition to the regular ingress messages
/// and canister requests / responses, `pop_input()` / `peek_input()` may also
/// return concise "reject response for callback ID" messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum CanisterInput {
    Ingress(Arc<Ingress>),
    Request(Arc<Request>),
    Response(Arc<Response>),
    /// A concise reject response meaning "call deadine has expired".
    DeadlineExpired(CallbackId),
    /// A concise reject response meaning "call response was dropped".
    ResponseDropped(CallbackId),
}

impl CanisterInput {
    /// Returns the underlying `CallbackId` if this is a `Response` or an
    /// `UnknownResponse`; `None` otherwise.
    fn response_callback_id(&self) -> Option<CallbackId> {
        match self {
            CanisterInput::Response(response) => Some(response.originator_reply_callback),

            CanisterInput::DeadlineExpired(callback_id)
            | CanisterInput::ResponseDropped(callback_id) => Some(*callback_id),

            _ => None,
        }
    }
}

impl From<RequestOrResponse> for CanisterInput {
    fn from(msg: RequestOrResponse) -> Self {
        match msg {
            RequestOrResponse::Request(request) => CanisterInput::Request(request),
            RequestOrResponse::Response(response) => CanisterInput::Response(response),
        }
    }
}

/// A backing store for canister input and output queues, consisting of:
///
///  * a `MessagePool`, holding messages and providing message stats (count,
///    size) and support for time-based expiration and load shedding; and
///  * maps of compact responses (`CallbackIds` that have either expired or
///    whose responses have been shed.
///
/// Implements the `MessageStore` trait for both inbound messages
/// (`T = CanisterInput` items that are either pooled messages or compact
/// responses) and outbound messages (pooled `RequestOrResponse items`).
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
struct MessageStoreImpl {
    /// Pool holding the messages referenced by `canister_queues`, providing message
    /// stats (count, size) and support for time-based expiration and load shedding.
    #[validate_eq(CompareWithValidateEq)]
    pool: MessagePool,

    /// "Deadline expired" compact reject responses (`CallbackIds`), returned as
    /// `CanisterInput::DeadlineExpired` by `peek_input()` / `pop_input()` (and
    /// "inflated" by `SystemState` into `SysUnknown` reject responses based on the
    /// callback).
    expired_callbacks: MutableIntMap<InboundReference, CallbackId>,

    /// Compact reject responses (`CallbackIds`) replacing best-effort responses
    /// that were shed. These are returned as `CanisterInput::ResponseDropped` by
    /// `peek_input()` / `pop_input()` (and "inflated" by `SystemState` into
    /// `SysUnknown` reject responses based on the callback).
    shed_responses: MutableIntMap<InboundReference, CallbackId>,
}

impl MessageStoreImpl {
    /// Inserts an inbound message into the pool.
    fn insert_inbound(&mut self, msg: RequestOrResponse) -> InboundReference {
        self.pool.insert_inbound(msg)
    }

    /// Pops and returns the item at the front of the given queue, advancing to the
    /// next non-stale reference.
    ///
    /// Panics if the reference at the front of the queue is stale.
    fn queue_pop_and_advance<T: Clone>(&mut self, queue: &mut Arc<CanisterQueue<T>>) -> Option<T>
    where
        MessageStoreImpl: MessageStore<T>,
    {
        if queue.len() == 0 {
            return None;
        }

        let queue = Arc::make_mut(queue);
        let reference = queue.pop()?;

        // Advance to the next non-stale reference.
        self.queue_advance(queue);

        Some(self.take(reference))
    }

    /// Advances the queue to the next non-stale reference.
    fn queue_advance<T: Clone>(&mut self, queue: &mut CanisterQueue<T>)
    where
        MessageStoreImpl: MessageStore<T>,
    {
        queue.pop_while(|reference| self.is_stale(reference));
    }

    /// Returns `true` if `ingress_queue` or at least one of the canister input
    /// queues is not empty; `false` otherwise.
    pub fn has_input(&self) -> bool {
        self.pool.message_stats().inbound_message_count > 0
            || !self.expired_callbacks.is_empty()
            || !self.shed_responses.is_empty()
    }

    /// Returns `true` if at least one output queue is not empty; false otherwise.
    pub fn has_output(&self) -> bool {
        self.pool.message_stats().outbound_message_count > 0
    }

    /// Tests whether the message store contains neither pooled messages nor compact
    /// responses.
    fn is_empty(&self) -> bool {
        self.pool.len() == 0 && self.expired_callbacks.is_empty() && self.shed_responses.is_empty()
    }

    /// Helper function for concisely validating the hard invariant that a canister
    /// queue is either empty or has a non-stale reference at the front, by writing
    /// `debug_assert_eq!(Ok(()), store.queue_front_not_stale(...)`.
    ///
    /// Time complexity: `O(log(n))`.
    fn queue_front_not_stale<T>(
        &self,
        queue: &CanisterQueue<T>,
        canister_id: &CanisterId,
    ) -> Result<(), String>
    where
        MessageStoreImpl: MessageStore<T>,
        T: ToContext,
    {
        if let Some(reference) = queue.peek()
            && self.is_stale(reference)
        {
            return Err(format!(
                "Stale reference at the front of {:?} queue to/from {}",
                T::context(),
                canister_id
            ));
        }

        Ok(())
    }
}

/// Defines context-specific (inbound / outbound) message store operations
/// (lookup, removal, staleness check) for `MessageStoreImpl`.
trait MessageStore<T> {
    /// The type returned by `get()`: `&T` if the implementation actually holds
    /// items of type `T`; or the type `T` if it has to be built on demand.
    type TRef<'a>
    where
        Self: 'a;

    /// Looks up the referenced item. Panics if the reference is stale.
    fn get(&self, reference: message_pool::Reference<T>) -> Self::TRef<'_>;

    /// Removes the referenced item. Panics if the reference is stale.
    fn take(&mut self, reference: message_pool::Reference<T>) -> T;

    /// Checks whether the given reference is stale (i.e. neither in the pool, nor
    /// in one of the compact response maps iff inbound).
    fn is_stale(&self, reference: message_pool::Reference<T>) -> bool;
}

impl MessageStore<CanisterInput> for MessageStoreImpl {
    type TRef<'a> = CanisterInput;

    fn get(&self, reference: InboundReference) -> CanisterInput {
        if let Some(msg) = self.pool.get(reference) {
            debug_assert!(!self.expired_callbacks.contains_key(&reference));
            debug_assert!(!self.shed_responses.contains_key(&reference));
            return msg.clone().into();
        } else if reference.is_inbound_best_effort_response() {
            if let Some(callback_id) = self.expired_callbacks.get(&reference) {
                debug_assert!(!self.shed_responses.contains_key(&reference));
                return CanisterInput::DeadlineExpired(*callback_id);
            } else if let Some(callback_id) = self.shed_responses.get(&reference) {
                return CanisterInput::ResponseDropped(*callback_id);
            }
        }

        panic!("stale reference at the front of input queue");
    }

    fn take(&mut self, reference: InboundReference) -> CanisterInput {
        if let Some(msg) = self.pool.take(reference) {
            debug_assert!(!self.expired_callbacks.contains_key(&reference));
            debug_assert!(!self.shed_responses.contains_key(&reference));
            return msg.into();
        } else if reference.is_inbound_best_effort_response() {
            if let Some(callback_id) = self.expired_callbacks.remove(&reference) {
                debug_assert!(!self.shed_responses.contains_key(&reference));
                return CanisterInput::DeadlineExpired(callback_id);
            } else if let Some(callback_id) = self.shed_responses.remove(&reference) {
                return CanisterInput::ResponseDropped(callback_id);
            }
        }

        panic!("stale reference at the front of input queue");
    }

    fn is_stale(&self, reference: InboundReference) -> bool {
        self.pool.get(reference).is_none()
            && !(reference.is_inbound_best_effort_response()
                && (self.expired_callbacks.contains_key(&reference)
                    || self.shed_responses.contains_key(&reference)))
    }
}

impl MessageStore<RequestOrResponse> for MessageStoreImpl {
    type TRef<'a> = &'a RequestOrResponse;

    fn get(&self, reference: OutboundReference) -> &RequestOrResponse {
        self.pool
            .get(reference)
            .expect("stale reference at the front of output queue")
    }

    fn take(&mut self, reference: OutboundReference) -> RequestOrResponse {
        self.pool
            .take(reference)
            .expect("stale reference at the front of output queue")
    }

    fn is_stale(&self, reference: OutboundReference) -> bool {
        self.pool.get(reference).is_none()
    }
}

trait InboundMessageStore: MessageStore<CanisterInput> {
    /// Enqueues a "deadline expired" compact response for the given callback.
    fn push_inbound_timeout_response(&mut self, callback_id: CallbackId) -> InboundReference;

    /// Collects the `CallbackIds` of all responses and compact responses enqueued
    /// in input queues.
    ///
    /// Returns an error if there are duplicate `CallbackIds` among the responses;
    /// or if not all inbound responses or compact responses are enqueued.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn callbacks_with_enqueued_response(
        &self,
        canister_queues: &BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,
    ) -> Result<MutableIntMap<CallbackId, ()>, String>;
}

impl InboundMessageStore for MessageStoreImpl {
    fn push_inbound_timeout_response(&mut self, callback_id: CallbackId) -> InboundReference {
        let reference = self.pool.make_inbound_timeout_response_reference();
        self.expired_callbacks.insert(reference, callback_id);
        reference
    }

    fn callbacks_with_enqueued_response(
        &self,
        canister_queues: &BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,
    ) -> Result<MutableIntMap<CallbackId, ()>, String> {
        let mut callbacks = MutableIntMap::new();
        canister_queues
            .values()
            .flat_map(|(input_queue, _)| input_queue.iter())
            .try_for_each(|reference| {
                let (a, b, c) = (
                    self.pool.get(*reference),
                    self.expired_callbacks.get(reference),
                    self.shed_responses.get(reference),
                );
                let callback_id = match (a, b, c) {
                    // Pooled response.
                    (Some(RequestOrResponse::Response(rep)), None, None) => {
                        rep.originator_reply_callback
                    }

                    // Compact response.
                    (None, Some(callback_id), None) | (None, None, Some(callback_id)) => {
                        *callback_id
                    }

                    // Request or stale reference.
                    (Some(RequestOrResponse::Request(_)), None, None) | (None, None, None) => {
                        return Ok(());
                    }

                    // Two or more of the above. This should never happen.
                    _ => {
                        return Err(format!(
                            "CanisterQueues: Multiple responses for {reference:?}"
                        ));
                    }
                };

                if callbacks.insert(callback_id, ()).is_none() {
                    Ok(())
                } else {
                    Err(format!(
                        "CanisterQueues: Duplicate inbound response callback: {callback_id:?}"
                    ))
                }
            })?;

        let response_count = self.pool.message_stats().inbound_response_count
            + self.expired_callbacks.len()
            + self.shed_responses.len();
        if callbacks.len() != response_count {
            return Err(format!(
                "CanisterQueues: Have {} inbound responses, but only {} are enqueued",
                response_count,
                callbacks.len()
            ));
        }

        Ok(callbacks)
    }
}

impl CanisterQueues {
    /// Pushes an ingress message into the induction pool.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.ingress_queue.push(msg)
    }

    /// Pops the next ingress message from `ingress_queue`.
    fn pop_ingress(&mut self) -> Option<Arc<Ingress>> {
        self.ingress_queue.pop()
    }

    /// Peeks the next ingress message from `ingress_queue`.
    fn peek_ingress(&self) -> Option<Arc<Ingress>> {
        self.ingress_queue.peek()
    }

    /// For each output queue, invokes `f` on every message until `f` returns
    /// `Err`; then moves on to the next output queue.
    ///
    /// All messages that `f` returned `Ok` for, are popped. Messages that `f`
    /// returned `Err` for and all those following them in the respective output
    /// queue are retained.
    ///
    /// Do note that because a queue can only be skipped over if `f` returns `Err`
    /// on a non-stale message, queues are always either fully consumed or left with
    /// a non-stale reference at the front.
    pub(crate) fn output_queues_for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, &RequestOrResponse) -> Result<(), ()>,
    {
        for (canister_id, (_, queue)) in self.canister_queues.iter_mut() {
            loop {
                let Some(reference) = queue.peek() else {
                    break;
                };
                let queue = Arc::make_mut(queue);
                let Some(msg) = self.store.pool.get(reference) else {
                    // Expired / dropped message. Pop it and advance.
                    assert_eq!(Some(reference), queue.pop());
                    continue;
                };

                match f(canister_id, msg) {
                    // `f` rejected the message, move on to the next queue.
                    Err(_) => break,

                    // Message was consumed, pop it.
                    Ok(_) => {
                        self.store.take(reference);
                        assert_eq!(Some(reference), queue.pop());
                    }
                }
            }
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
    }

    /// Returns an iterator that loops over output queues, popping one message
    /// at a time from each in a round robin fashion. The iterator consumes all
    /// popped messages.
    pub(crate) fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator<'_> {
        CanisterOutputQueuesIterator::new(&mut self.canister_queues, &mut self.store)
    }

    /// See `IngressQueue::filter_messages()` for documentation.
    pub fn filter_ingress_messages<F>(&mut self, filter: F) -> Vec<Arc<Ingress>>
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.ingress_queue.filter_messages(filter)
    }

    /// Enqueues a canister-to-canister message into the induction pool.
    ///
    /// If the message is a `Request` and it is enqueued successfully, `Ok(None)` is
    /// returned; and a slot is reserved in the corresponding output queue for the
    /// eventual response.
    ///
    /// If the message is a `Response`, `SystemState` will have already checked for
    /// a matching callback:
    ///
    ///  * If this is a guaranteed `Response`, the protocol should have reserved a
    ///    slot for it, so the push should not fail for lack of one (although an
    ///    error may be produced in case of a bug in the upper layers) and
    ///    `Ok(None)` is returned.
    ///  * If this is a best-effort `Response`, a slot is available and no duplicate
    ///    (time out) response is already enqueued, it is enqueued and `Ok(None)` is
    ///    returned.
    ///  * If this is a best-effort `Response` and a duplicate (time out) response
    ///    is already enqueued (which is implicitly true when no slot is available),
    ///    the response is silently dropped and `Ok(Some(response))` is returned.
    ///
    /// If the message was enqueued, adds the sender to the appropriate input
    /// schedule (local or remote), if not already there.
    ///
    /// # Errors
    ///
    /// If pushing fails, returns the provided message along with a `StateError`:
    ///
    ///  * `QueueFull` if pushing a `Request` and the corresponding input or output
    ///    queues are full.
    ///
    ///  * `NonMatchingResponse` if pushing a guaranteed `Response` and the
    ///    corresponding input queue does not have a reserved slot; or it is a
    ///    duplicate.
    pub(super) fn push_input(
        &mut self,
        msg: RequestOrResponse,
        input_queue_type: InputQueueType,
    ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
        let sender = msg.sender();
        let input_queue = match msg {
            RequestOrResponse::Request(_) => {
                let (input_queue, output_queue) =
                    get_or_insert_queues(&mut self.canister_queues, &sender);
                if let Err(e) = input_queue.check_has_request_slot() {
                    return Err((e, msg));
                }
                // Safe to already (attempt to) reserve an output slot here, as the `push()`
                // below is guaranteed to succeed due to the check above.
                if let Err(e) = Arc::make_mut(output_queue).try_reserve_response_slot() {
                    return Err((e, msg));
                }
                Arc::make_mut(input_queue)
            }
            RequestOrResponse::Response(ref response) => {
                match self.canister_queues.get_mut(&sender) {
                    Some((queue, _)) if queue.check_has_reserved_response_slot().is_ok() => {
                        // Check against duplicate responses.
                        if self
                            .callbacks_with_enqueued_response
                            .insert(response.originator_reply_callback, ())
                            .is_some()
                        {
                            debug_assert_eq!(Ok(()), self.test_invariants());
                            if response.deadline == NO_DEADLINE {
                                // This is a critical error for a guaranteed response.
                                return Err((
                                    StateError::non_matching_response(
                                        "Duplicate response",
                                        response,
                                    ),
                                    msg,
                                ));
                            } else {
                                // But it's OK for a best-effort response. Silently drop it.
                                return Ok(Some(response.clone()));
                            }
                        }
                        Arc::make_mut(queue)
                    }

                    // Queue does not exist or has no reserved slot for this response.
                    _ => {
                        if response.deadline == NO_DEADLINE {
                            // Critical error for a guaranteed response.
                            return Err((
                                StateError::non_matching_response(
                                    "No reserved response slot",
                                    response,
                                ),
                                msg,
                            ));
                        } else {
                            // This must be a duplicate best-effort response (since `SystemState` has
                            // aleady checked for a matching callback). Silently drop it.
                            debug_assert!(
                                self.callbacks_with_enqueued_response
                                    .get(&response.originator_reply_callback)
                                    .is_some()
                            );
                            return Ok(Some(response.clone()));
                        }
                    }
                }
            }
        };

        self.queue_stats.on_push(&msg, Context::Inbound);
        let reference = self.store.insert_inbound(msg);
        match reference.kind() {
            Kind::Request => input_queue.push_request(reference),
            Kind::Response => input_queue.push_response(reference),
        }

        // Add sender canister ID to the appropriate input schedule queue if it is not
        // already scheduled.
        if input_queue.len() == 1 {
            self.input_schedule.schedule(sender, input_queue_type);
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        Ok(None)
    }

    /// Enqueues a "deadline expired" compact response for the given best-effort
    /// callback, iff a response for the callback is not already enqueued.
    ///
    /// Must only be called for existent, not-yet-executing callbacks (i.e. not for
    /// a paused or aborted callback). This is ensured by `SystemState`, by checking
    /// against the `CallContextManager`'s set of callbacks.
    ///
    ///
    /// Returns:
    ///  * `Ok(true)` if a "deadline expired" compact response was enqueued;
    ///  * `Ok(false)` if no compact response was enqueued (because the callback
    ///    already had a response);
    ///  * `Err` iff a compact response should have been enqueued, but wasn't
    ///    because no reserved slot was available.
    pub(super) fn try_push_deadline_expired_input(
        &mut self,
        callback_id: CallbackId,
        respondent: &CanisterId,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> Result<bool, String> {
        // For a not yet executed callback, there must be a queue with either a reserved
        // slot or an enqueued response.
        let Some((input_queue, _)) = self.canister_queues.get_mut(respondent) else {
            return Err(format!(
                "No input queue for expired callback: {callback_id}"
            ));
        };

        // Check against duplicate responses.
        if self
            .callbacks_with_enqueued_response
            .insert(callback_id, ())
            .is_some()
        {
            // There is already a response enqueued for the callback.
            return Ok(false);
        }

        if input_queue.check_has_reserved_response_slot().is_err() {
            // No response enqueued for `callback_id`, but no reserved slot either. This
            // should never happen.
            self.callbacks_with_enqueued_response.remove(&callback_id);
            return Err(format!(
                "No reserved response slot for expired callback: {callback_id}"
            ));
        }

        let reference = self.store.push_inbound_timeout_response(callback_id);
        Arc::make_mut(input_queue).push_response(reference);
        self.queue_stats.on_push_timeout_response();

        // Add sender canister ID to the appropriate input schedule queue if it is not
        // already scheduled.
        if input_queue.len() == 1 {
            let input_queue_type =
                input_queue_type_fn(own_canister_id, local_canisters)(respondent);
            self.input_schedule.schedule(*respondent, input_queue_type);
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));

        Ok(true)
    }

    /// Pops the next canister input queue message.
    ///
    /// Note: We pop senders from the front of `input_schedule` and insert them
    /// to the back, which allows us to handle messages from different
    /// originators in a round-robin fashion.
    ///
    /// It is possible for the input schedule to contain an empty or GC-ed input
    /// queue if all messages in said queue have expired / were shed since it was
    /// scheduled. Meaning that iteration may be required.
    fn pop_canister_input(&mut self, input_queue_type: InputQueueType) -> Option<CanisterInput> {
        while let Some(sender) = self.input_schedule.peek(input_queue_type) {
            let Some((input_queue, _)) = self.canister_queues.get_mut(sender) else {
                // Queue pair was garbage collected.
                self.input_schedule
                    .pop(input_queue_type)
                    .expect("pop() should return the sender peeked above");
                continue;
            };

            let msg = self.store.queue_pop_and_advance(input_queue);

            // Update the input schedule.
            if input_queue.len() != 0 {
                // Input queue contains other messages, re-enqueue the sender.
                self.input_schedule.reschedule(*sender, input_queue_type);
            } else {
                // Input queue was consumed, remove the sender from the input schedule.
                self.input_schedule
                    .pop(input_queue_type)
                    .expect("pop() should return the sender peeked above");
            }

            if let Some(msg_) = &msg {
                if let Some(callback_id) = msg_.response_callback_id() {
                    assert!(
                        self.callbacks_with_enqueued_response
                            .remove(&callback_id)
                            .is_some()
                    );
                }
                debug_assert_eq!(Ok(()), self.test_invariants());
                debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
                return msg;
            }
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        None
    }

    /// Peeks the next canister input queue message.
    ///
    /// It is possible for the input schedule to contain an empty or GC-ed input
    /// queue if all messages in said queue have expired / were shed since it was
    /// scheduled. Requires a `&mut self` reference to achieve amortized `O(1)` time
    /// complexity by immediately consuming empty input queues when encountered.
    fn peek_canister_input(&mut self, input_queue_type: InputQueueType) -> Option<CanisterInput> {
        while let Some(sender) = self.input_schedule.peek(input_queue_type) {
            if let Some(reference) = self
                .canister_queues
                .get(sender)
                .and_then(|(input_queue, _)| input_queue.peek())
            {
                let msg = self.store.get(reference);
                debug_assert_eq!(Ok(()), self.test_invariants());
                debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
                return Some(msg);
            }

            // Queue was garbage collected or is empty.
            self.input_schedule
                .pop(input_queue_type)
                .expect("pop() should return the sender peeked above");
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        None
    }

    /// Skips the next sender canister from the given input schedule (local or
    /// remote).
    fn skip_canister_input(&mut self, input_queue_type: InputQueueType) {
        // Skip over any empty or GC-ed input queues.
        while let Some(sender) = self.input_schedule.peek(input_queue_type) {
            // If the input queue is non-empty, re-enqueue the sender at the back of the
            // input schedule queue and exit. Else, pop the sender and try the next.
            if self
                .canister_queues
                .get(sender)
                .is_some_and(|(input_queue, _)| input_queue.len() != 0)
            {
                self.input_schedule.reschedule(*sender, input_queue_type);
                break;
            } else {
                self.input_schedule
                    .pop(input_queue_type)
                    .expect("pop() should return the sender peeked above");
            }
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
    }

    /// Returns `true` if `ingress_queue` or at least one of the canister input
    /// queues is not empty; `false` otherwise.
    pub fn has_input(&self) -> bool {
        !self.ingress_queue.is_empty() || self.store.has_input()
    }

    /// Returns `true` if at least one output queue is not empty; false otherwise.
    pub fn has_output(&self) -> bool {
        self.store.has_output()
    }

    /// Peeks the ingress or inter-canister input message that would be returned by
    /// `pop_input()`.
    ///
    /// Requires a `&mut self` reference to achieve amortized `O(1)` time complexity
    /// by immediately consuming empty input queues when encountered.
    pub(crate) fn peek_input(&mut self) -> Option<CanisterInput> {
        // Try all 3 input sources: ingress, local and remote subnets.
        for _ in 0..InputSource::COUNT {
            let peeked = match self.input_schedule.input_source() {
                InputSource::Ingress => self.peek_ingress().map(CanisterInput::Ingress),
                InputSource::RemoteSubnet => self.peek_canister_input(InputQueueType::RemoteSubnet),
                InputSource::LocalSubnet => self.peek_canister_input(InputQueueType::LocalSubnet),
            };

            match peeked {
                Some(msg) => return Some(msg),
                None => {
                    // Advance to the next input source.
                    self.input_schedule.next_input_source();
                }
            }
        }

        None
    }

    /// Skips the next ingress or inter-canister input message.
    pub(crate) fn skip_input(&mut self, loop_detector: &mut CanisterQueuesLoopDetector) {
        match self.input_schedule.next_input_source() {
            InputSource::Ingress => {
                self.ingress_queue.skip_ingress_input();
                loop_detector.ingress_queue_skip_count += 1;
            }

            InputSource::RemoteSubnet => {
                self.skip_canister_input(InputQueueType::RemoteSubnet);
                loop_detector.remote_queue_skip_count += 1;
            }

            InputSource::LocalSubnet => {
                self.skip_canister_input(InputQueueType::LocalSubnet);
                loop_detector.local_queue_skip_count += 1;
            }
        }
    }

    /// Pops the next ingress or inter-canister input message (round-robin) and
    /// advances to the next input source.
    pub(crate) fn pop_input(&mut self) -> Option<CanisterInput> {
        // Try all 3 input sources: ingress, local and remote subnets.
        for _ in 0..InputSource::COUNT {
            let popped = match self.input_schedule.next_input_source() {
                InputSource::Ingress => self.pop_ingress().map(CanisterInput::Ingress),
                InputSource::RemoteSubnet => self.pop_canister_input(InputQueueType::RemoteSubnet),
                InputSource::LocalSubnet => self.pop_canister_input(InputQueueType::LocalSubnet),
            };

            if popped.is_some() {
                return popped;
            }
        }

        None
    }

    /// Pushes a `Request` into the relevant output queue. Also reserves a slot for
    /// the eventual response in the matching input queue.
    ///
    /// # Errors
    ///
    /// Returns a `QueueFull` error along with the provided message if either
    /// the output queue or the matching input queue is full.
    //
    // NOTE: DO NOT CHANGE THE VISIBILITY OF THIS METHOD. IT IS ONLY SUPPOSED TO BE
    // CALLED FOR CANISTERS (I.E. NOT FOR THE SUBNET QUEUES).
    pub(super) fn push_output_request(
        &mut self,
        request: Arc<Request>,
        time: Time,
    ) -> Result<(), (StateError, Arc<Request>)> {
        let (input_queue, output_queue) =
            get_or_insert_queues(&mut self.canister_queues, &request.receiver);

        if let Err(e) = output_queue.check_has_request_slot() {
            return Err((e, request));
        }
        if let Err(e) = Arc::make_mut(input_queue).try_reserve_response_slot() {
            return Err((e, request));
        }

        self.queue_stats
            .on_push_request(&request, Context::Outbound);

        let reference = self.store.pool.insert_outbound_request(request, time);
        Arc::make_mut(output_queue).push_request(reference);

        debug_assert_eq!(Ok(()), self.test_invariants());
        Ok(())
    }

    /// Immediately reject an output request by pushing a `Response` onto the
    /// input queue without ever putting the `Request` on an output queue. This
    /// can only be used for `IC00` requests and requests to subnet IDs.
    ///
    /// This is expected to be used in cases of invalid sender canister version
    /// in management canister calls and `IC00` routing where no
    /// destination subnet is found that the `Request` could be routed to
    /// or if the canister directly includes subnet IDs in the request.
    /// Hence, an immediate (reject) `Response` is added to the relevant
    /// input queue.
    pub(crate) fn reject_subnet_output_request(
        &mut self,
        request: Request,
        reject_context: RejectContext,
        subnet_ids: &BTreeSet<PrincipalId>,
    ) -> Result<(), StateError> {
        assert!(
            request.receiver == IC_00 || subnet_ids.contains(&request.receiver.get()),
            "reject_subnet_output_request can only be used to reject management canister requests"
        );

        let (input_queue, _output_queue) =
            get_or_insert_queues(&mut self.canister_queues, &request.receiver);
        Arc::make_mut(input_queue).try_reserve_response_slot()?;
        self.queue_stats
            .on_push_request(&request, Context::Outbound);
        debug_assert_eq!(Ok(()), self.test_invariants());

        let response = RequestOrResponse::Response(Arc::new(Response {
            originator: request.sender,
            respondent: request.receiver,
            originator_reply_callback: request.sender_reply_callback,
            refund: request.payment,
            response_payload: Payload::Reject(reject_context),
            deadline: request.deadline,
        }));
        self.push_input(response, InputQueueType::LocalSubnet)
            .map(|dropped_response| {
                debug_assert!(dropped_response.is_none());
            })
            .map_err(|(e, _msg)| e)
    }

    /// Returns the number of output requests that can be pushed to each
    /// canister before either the respective input or output queue is full.
    ///
    /// Time complexity: `O(n)`.
    pub fn available_output_request_slots(&self) -> BTreeMap<CanisterId, usize> {
        // When pushing a request we need to reserve a slot on the input
        // queue for the eventual reply. So we are limited by the amount of
        // space in both the output and input queues.
        self.canister_queues
            .iter()
            .map(|(canister, (input_queue, output_queue))| {
                (
                    *canister,
                    input_queue
                        .available_response_slots()
                        .min(output_queue.available_request_slots()),
                )
            })
            .collect()
    }

    /// Pushes a `Response` into the relevant output queue. The protocol should have
    /// already reserved a slot, so this cannot fail.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_output_response(&mut self, response: Arc<Response>) {
        self.queue_stats
            .on_push_response(&response, Context::Outbound);

        // Since we reserve an output queue slot whenever we induct a request; and
        // we would never garbage collect a non-empty queue (including one with just a
        // reserved slot); we are guaranteed that the output queue exists.
        let output_queue = &mut self
            .canister_queues
            .get_mut(&response.originator)
            .expect("pushing response into inexistent output queue")
            .1;
        let reference = self.store.pool.insert_outbound_response(response);
        Arc::make_mut(output_queue).push_response(reference);

        debug_assert_eq!(Ok(()), self.test_invariants());
    }

    /// Returns a reference to the (non-stale) message at the front of the respective
    /// output queue, if any.
    pub(super) fn peek_output(&self, canister_id: &CanisterId) -> Option<&RequestOrResponse> {
        let output_queue = &self.canister_queues.get(canister_id)?.1;

        Some(self.store.get(output_queue.peek()?))
    }

    /// Pops the next message from the output queue to `dst_canister`.
    pub(super) fn pop_canister_output(
        &mut self,
        dst_canister: &CanisterId,
    ) -> Option<RequestOrResponse> {
        let queue = &mut self.canister_queues.get_mut(dst_canister)?.1;
        let msg = self.store.queue_pop_and_advance(queue);

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        msg
    }

    /// Tries to induct a message from the output queue to `own_canister_id` into
    /// the input queue from `own_canister_id`.
    ///
    /// Returns `Ok(None)` if the message was successfully inducted;
    /// `Ok(Some(response))` if the message was a duplicate best-effort response
    /// that was silently dropped; and `Err(())` if there was no message to induct
    /// or the input queue was full.
    pub(super) fn induct_message_to_self(
        &mut self,
        own_canister_id: CanisterId,
    ) -> Result<Option<Arc<Response>>, ()> {
        let msg = self.peek_output(&own_canister_id).ok_or(())?.clone();

        let res = self
            .push_input(msg, InputQueueType::LocalSubnet)
            .map_err(|_| ())?;

        let queue = &mut self
            .canister_queues
            .get_mut(&own_canister_id)
            .expect("Output queue existed above so lookup should not fail.")
            .1;
        self.store
            .queue_pop_and_advance(queue)
            .expect("Message peeked above so pop should not fail.");

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        Ok(res)
    }

    /// Returns a reference to the pool's message stats.
    fn message_stats(&self) -> &message_pool::MessageStats {
        self.store.pool.message_stats()
    }

    /// Returns the number of enqueued ingress messages.
    pub fn ingress_queue_message_count(&self) -> usize {
        self.ingress_queue.size()
    }

    /// Returns the total byte size of enqueued ingress messages.
    pub fn ingress_queue_size_bytes(&self) -> usize {
        self.ingress_queue.count_bytes()
    }

    /// Returns the number of non-stale canister messages enqueued in input queues.
    pub fn input_queues_message_count(&self) -> usize {
        self.message_stats().inbound_message_count
            + self.store.expired_callbacks.len()
            + self.store.shed_responses.len()
    }

    /// Returns the number of reserved slots across all input queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn input_queues_reserved_slots(&self) -> usize {
        self.queue_stats.input_queues_reserved_slots
    }

    /// Returns the total byte size of canister input queues (queues + messages).
    ///
    /// Does not account for callback references for expired callbacks or dropped
    /// responses, as these are constant size per callback and thus can be included
    /// in the cost of a callback.
    pub fn input_queues_size_bytes(&self) -> usize {
        self.message_stats().inbound_size_bytes
            + self.canister_queues.len() * size_of::<InputQueue>()
    }

    /// Returns the number of non-stale requests enqueued in input queues.
    pub fn input_queues_request_count(&self) -> usize {
        self.message_stats().inbound_message_count - self.message_stats().inbound_response_count
    }

    /// Returns the number of non-stale responses enqueued in input queues.
    pub fn input_queues_response_count(&self) -> usize {
        self.message_stats().inbound_response_count
            + self.store.expired_callbacks.len()
            + self.store.shed_responses.len()
    }

    /// Returns the number of actual (non-stale) messages in output queues.
    pub fn output_queues_message_count(&self) -> usize {
        self.message_stats().outbound_message_count
    }

    /// Returns the number of reserved slots across all output queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn output_queues_reserved_slots(&self) -> usize {
        self.queue_stats.output_queues_reserved_slots
    }

    /// Returns the memory usage of all best-effort messages (zero iff there are
    /// zero pooled best-effort messages).
    ///
    /// Does not account for callback references for expired callbacks or dropped
    /// responses, as these are constant size per callback and thus can be included
    /// in the cost of a callback.
    pub fn best_effort_message_memory_usage(&self) -> usize {
        self.message_stats().best_effort_message_bytes
    }

    /// Returns the memory usage of all guaranteed response messages.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.queue_stats.guaranteed_response_memory_usage()
            + self.message_stats().guaranteed_response_memory_usage()
    }

    /// Returns the total byte size of guaranteed responses across input and
    /// output queues.
    pub fn guaranteed_responses_size_bytes(&self) -> usize {
        self.message_stats().guaranteed_responses_size_bytes
    }

    /// Returns the total memory reservations for guaranteed responses across input
    /// and output queues.
    ///
    /// Note that this is different from slots reserved for responses (whether
    /// best effort or guaranteed) which are used to implement backpressure.
    pub fn guaranteed_response_memory_reservations(&self) -> usize {
        self.queue_stats.guaranteed_response_memory_reservations
    }

    /// Returns the sum total of bytes above `MAX_RESPONSE_COUNT_BYTES` per
    /// oversized guaranteed response call request.
    pub fn oversized_guaranteed_requests_extra_bytes(&self) -> usize {
        self.message_stats()
            .oversized_guaranteed_requests_extra_bytes
    }

    /// Returns the total cycles attached to all messages across input and output
    /// queues.
    pub fn attached_cycles(&self) -> Cycles {
        self.message_stats().cycles
    }

    /// Garbage collects all input and output queue pairs that are both empty.
    ///
    /// Because there is no useful information in an empty queue, there is no
    /// need to retain them. In order to avoid state divergence (e.g. because
    /// some replicas have an empty queue pair and some have garbage collected
    /// it) we simply need to ensure that queues are garbage collected
    /// deterministically across all replicas (e.g. at checkpointing time or
    /// every round; but not e.g. when deserializing, which may happen at
    /// different times on restarting or state syncing replicas).
    ///
    /// Time complexity: `O(num_queues)`.
    pub fn garbage_collect(&mut self) {
        self.garbage_collect_impl();

        // Reset all fields to default if we have no messages. This is so that an empty
        // `CanisterQueues` serializes as an empty byte array (and there is no need to
        // persist it explicitly).
        if self.canister_queues.is_empty() && self.ingress_queue.is_empty() {
            // The schedules and stats will already have default (zero) values, only `store`
            // and `input_schedule` must be reset explicitly.
            debug_assert!(self.store.is_empty());
            self.store = MessageStoreImpl::default();
            self.input_schedule = InputSchedule::default();

            // Trust but verify. Ensure that the `CanisterQueues` now encodes to zero bytes.
            debug_assert_eq!(
                0,
                pb_queues::CanisterQueues::from(self as &Self).encoded_len()
            );
        }
    }

    /// Implementation of `garbage_collect()`, ensuring the latter always resets
    /// all fields to their default values when all queues are empty, regardless
    /// of whether we bail out early or not.
    fn garbage_collect_impl(&mut self) {
        if self.canister_queues.is_empty() {
            return;
        }

        self.canister_queues
            .retain(|_canister_id, (input_queue, output_queue)| {
                input_queue.has_used_slots() || output_queue.has_used_slots()
            });
        debug_assert_eq!(Ok(()), self.test_invariants());
    }

    /// Queries whether the deadline of any message in the pool has expired.
    ///
    /// Time complexity: `O(1)`.
    pub fn has_expired_deadlines(&self, current_time: Time) -> bool {
        self.store.pool.has_expired_deadlines(current_time)
    }

    /// Drops expired messages given a current time, releasing any slot reservations
    /// and enqueueing inbound reject responses for own outbound requests.
    ///
    /// This covers all best-effort messages except responses in input queues (which
    /// we don't want to expire); plus guaranteed response requests in output queues
    /// (which don't have an explicit deadline, but expire after an implicit
    /// `REQUEST_LIFETIME`).
    ///
    /// Enqueues refund messages for all dropped messages that had attached cycles
    /// and for which no reject response refunding the cycles was enqueued.
    ///
    /// Updating the correct input queues schedule after enqueueing a reject response
    /// into a previously empty input queue also requires the set of local canisters
    /// to decide whether the destination canister was local or remote.
    pub fn time_out_messages(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
        refunds: &mut RefundPool,
        metrics: &impl DroppedMessageMetrics,
    ) {
        let expired_messages = self.store.pool.expire_messages(current_time);

        let input_queue_type_fn = input_queue_type_fn(own_canister_id, local_canisters);
        for (reference, msg) in expired_messages.into_iter() {
            metrics.observe_timed_out_message(
                reference.kind().to_label_value(),
                reference.context().to_label_value(),
                reference.class().to_label_value(),
            );
            self.on_message_dropped(reference, msg, refunds, &input_queue_type_fn);
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn));
    }

    /// Removes the largest best-effort message in the underlying pool. Returns
    /// `true` if a message was removed; `false` otherwise.
    ///
    /// Enqueues a refund message if the shed message had attached cycles and no
    /// reject response refunding the cycles was enqueued.
    ///
    /// Updates the stats for the dropped message and (where applicable) the
    /// generated response. `own_canister_id` and `local_canisters` are required
    /// to determine the correct input queue schedule to update (if applicable).
    ///
    /// Time complexity: `O(log(n))`.
    pub fn shed_largest_message(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
        refunds: &mut RefundPool,
        metrics: &impl DroppedMessageMetrics,
    ) -> bool {
        if let Some((reference, msg)) = self.store.pool.shed_largest_message() {
            let input_queue_type_fn = input_queue_type_fn(own_canister_id, local_canisters);
            metrics.observe_shed_message(
                reference.kind().to_label_value(),
                reference.context().to_label_value(),
                msg.count_bytes(),
            );
            self.on_message_dropped(reference, msg, refunds, &input_queue_type_fn);

            debug_assert_eq!(Ok(()), self.test_invariants());
            debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn));
            return true;
        }

        false
    }

    /// Handles the timing out or shedding of a message from the pool.
    ///
    /// Updates the stats, replaces shed inbound responses with compact reject
    /// responses, generates reject responses for expired outbound requests, etc.
    ///
    /// Enqueues a refund message if the message had attached cycles and no reject
    /// response refunding the cycles was enqueued.
    ///
    /// `input_queue_type_fn` is required to determine the appropriate sender
    /// schedule to update when generating a reject response.
    fn on_message_dropped(
        &mut self,
        reference: SomeReference,
        msg: RequestOrResponse,
        refunds: &mut RefundPool,
        input_queue_type_fn: impl Fn(&CanisterId) -> InputQueueType,
    ) {
        match reference {
            SomeReference::Inbound(reference) => {
                self.on_inbound_message_dropped(reference, msg, refunds)
            }
            SomeReference::Outbound(reference) => {
                self.on_outbound_message_dropped(reference, msg, refunds, input_queue_type_fn)
            }
        }
    }

    /// Handles the timing out or shedding of an inbound message from the pool.
    ///
    /// Replaces a shed inbound best-effort response with a compact reject response.
    /// Releases the outbound slot reservation of a shed or expired inbound request.
    /// Updates the stats for the dropped message.
    ///
    /// Enqueues a refund message if the dropped message had attached cycles.
    fn on_inbound_message_dropped(
        &mut self,
        reference: InboundReference,
        msg: RequestOrResponse,
        refunds: &mut RefundPool,
    ) {
        match msg {
            RequestOrResponse::Response(response) => {
                // This is an inbound response, remember its `originator_reply_callback`, so
                // we can later produce a `ResponseDropped` for it, when popped.
                assert_eq!(
                    None,
                    self.store
                        .shed_responses
                        .insert(reference, response.originator_reply_callback)
                );
                refunds.add(response.originator, response.refund);
            }

            RequestOrResponse::Request(request) => {
                let remote = request.sender;
                let (input_queue, output_queue) = self
                    .canister_queues
                    .get_mut(&remote)
                    .expect("No matching queue for dropped message.");

                if input_queue.peek() == Some(reference) {
                    let input_queue = Arc::make_mut(input_queue);
                    input_queue.pop();
                    self.store.queue_advance(input_queue);
                }

                // Release the outbound response slot.
                Arc::make_mut(output_queue).release_reserved_response_slot();
                self.queue_stats.on_drop_input_request(&request);
                refunds.add(request.sender, request.payment);
            }
        }
    }

    /// Handles the timing out or shedding of an outbound message from the pool.
    ///
    /// Generates and enqueues a reject response if the message was an outbound
    /// request. Updates the stats for the dropped message and the generated
    /// response.
    ///
    /// Enqueues a refund message if the message had attached cycles and no reject
    /// response refunding the cycles was enqueued.
    ///
    /// `input_queue_type_fn` is required to determine the appropriate sender
    /// schedule to update when generating a reject response.
    fn on_outbound_message_dropped(
        &mut self,
        reference: OutboundReference,
        msg: RequestOrResponse,
        refunds: &mut RefundPool,
        input_queue_type_fn: impl Fn(&CanisterId) -> InputQueueType,
    ) {
        let remote = msg.receiver();
        let (input_queue, output_queue) = self
            .canister_queues
            .get_mut(&remote)
            .expect("No matching queue for dropped message.");

        // Ensure that the first reference in a queue is never stale: if we drop the
        // message at the front of a queue, advance to the first non-stale reference.
        //
        // Defensive check, reference may have already been popped by an earlier
        // `on_message_dropped()` call if multiple messages expired at once (e.g. given
        // a queue containing references `[1, 2]`; `1` and `2` expire as part of the
        // same `time_out_messages()` call; `on_message_dropped(1)` will also pop `2`).
        if output_queue.peek() == Some(reference) {
            let output_queue = Arc::make_mut(output_queue);
            output_queue.pop();
            self.store.queue_advance(output_queue);
        }

        match msg {
            RequestOrResponse::Request(request) => {
                let response = generate_timeout_response(&request);

                // Update stats for the generated response.
                self.queue_stats
                    .on_push_response(&response, Context::Inbound);

                // We protect against duplicate responses here, but we cannot check that this is
                // an active (i.e. existent and not paused/aborted) callback. This is OK, as we
                // could not have started executing a response (whether reject or reply) for a
                // request that was still in an output queue.
                assert!(
                    self.callbacks_with_enqueued_response
                        .insert(response.originator_reply_callback, ())
                        .is_none()
                );
                let reference = self.store.insert_inbound(response.into());
                Arc::make_mut(input_queue).push_response(reference);

                // If the input queue is not already in a sender schedule, add it.
                if input_queue.len() == 1 {
                    let input_queue_type = input_queue_type_fn(&remote);
                    self.input_schedule.schedule(remote, input_queue_type);
                }
            }

            RequestOrResponse::Response(response) => {
                // Outbound (best-effort) responses can be dropped with impunity.
                refunds.add(response.originator, response.refund);
            }
        }
    }

    /// Re-partitions the local sender schedule and remote sender schedule based on
    /// the set of all local canisters plus `own_canister_id` (since Rust's
    /// ownership rules would prevent us from mutating `self` if it was still under
    /// `local_canisters`).
    ///
    /// For use after a subnet split or other kind of canister migration. While an
    /// input queue that finds itself in the wrong schedule would get removed from
    /// said schedule as soon as it became empty (and would then get enqueued into
    /// the correct schedule), there is no guarantee that a given queue will ever
    /// become empty. Because of that, we explicitly re-partition schedules during
    /// canister migrations.
    pub(crate) fn split_input_schedules(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) {
        let input_queue_type_fn = input_queue_type_fn(own_canister_id, local_canisters);
        self.input_schedule.split(&input_queue_type_fn);

        debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn));
    }

    /// Helper function to concisely validate `CanisterQueues`' input schedule
    /// during deserialization; or in debug builds, by writing
    /// `debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn))`.
    ///
    /// Checks that the canister IDs of all input queues that contain at least one
    /// message are enqueued exactly once in the input schedule.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn schedules_ok(
        &self,
        input_queue_type_fn: &dyn Fn(&CanisterId) -> InputQueueType,
    ) -> Result<(), String> {
        self.input_schedule.test_invariants(
            self.canister_queues
                .iter()
                .map(|(canister_id, (input_queue, _))| (canister_id, &**input_queue)),
            &input_queue_type_fn,
        )
    }

    /// Helper function for concisely validating invariants other than those of
    /// input queue schedules (no stale references at queue front, valid stats,
    /// accurate tracking of callbacks with enqueued responses) during
    /// deserialization; or in debug builds, by writing
    /// `debug_assert_eq!(Ok(()), self.test_invariants())`.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn test_invariants(&self) -> Result<(), String> {
        // Invariant: all canister queues (input or output) are either empty or start
        // with a non-stale reference.
        for (canister_id, (input_queue, output_queue)) in self.canister_queues.iter() {
            self.store.queue_front_not_stale(input_queue, canister_id)?;
            self.store
                .queue_front_not_stale(output_queue, canister_id)?;
        }

        // Reserved slot stats match the actual number of reserved slots.
        let calculated_stats = Self::calculate_queue_stats(
            &self.canister_queues,
            self.queue_stats.guaranteed_response_memory_reservations,
        );
        if self.queue_stats != calculated_stats {
            return Err(format!(
                "Inconsistent stats:\n  expected: {:?}\n  actual: {:?}",
                calculated_stats, self.queue_stats
            ));
        }

        // `callbacks_with_enqueued_response` contains the precise set of `CallbackIds`
        // of all inbound responses.
        let enqueued_response_callbacks = self
            .store
            .callbacks_with_enqueued_response(&self.canister_queues)?;
        if self.callbacks_with_enqueued_response != enqueued_response_callbacks {
            return Err(format!(
                "Inconsistent `callbacks_with_enqueued_response`:\n  expected: {:?}\n  actual: {:?}",
                enqueued_response_callbacks, self.callbacks_with_enqueued_response
            ));
        }

        Ok(())
    }

    /// Computes stats for the given canister queues. Used when deserializing and in
    /// `debug_assert!()` checks. Takes the number of memory reservations from the
    /// caller, as the queues have no need to track memory reservations, so it
    /// cannot be computed. Size of guaranteed responses in streams is ignored as it is
    /// limited.
    ///
    /// Time complexity: `O(canister_queues.len())`.
    fn calculate_queue_stats(
        canister_queues: &BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,
        guaranteed_response_memory_reservations: usize,
    ) -> QueueStats {
        let (input_queues_reserved_slots, output_queues_reserved_slots) = canister_queues
            .values()
            .map(|(iq, oq)| (iq.reserved_slots(), oq.reserved_slots()))
            .fold((0, 0), |(acc0, acc1), (item0, item1)| {
                (acc0 + item0, acc1 + item1)
            });
        QueueStats {
            guaranteed_response_memory_reservations,
            input_queues_reserved_slots,
            output_queues_reserved_slots,
        }
    }
}

/// Returns the existing matching pair of input and output queues from/to
/// the given canister; or creates a pair of empty queues, if non-existent.
///
/// Written as a free function in order to avoid borrowing the full
/// `CanisterQueues`, which then requires looking up the queues again.
fn get_or_insert_queues<'a>(
    canister_queues: &'a mut BTreeMap<CanisterId, (Arc<InputQueue>, Arc<OutputQueue>)>,
    canister_id: &CanisterId,
) -> (&'a mut Arc<InputQueue>, &'a mut Arc<OutputQueue>) {
    let (input_queue, output_queue) = canister_queues.entry(*canister_id).or_insert_with(|| {
        let input_queue = Arc::new(CanisterQueue::new(DEFAULT_QUEUE_CAPACITY));
        let output_queue = Arc::new(CanisterQueue::new(DEFAULT_QUEUE_CAPACITY));
        (input_queue, output_queue)
    });
    (input_queue, output_queue)
}

/// Generates a timeout reject response from a request, refunding its payment.
fn generate_timeout_response(request: &Request) -> Response {
    Response {
        originator: request.sender,
        respondent: request.receiver,
        originator_reply_callback: request.sender_reply_callback,
        refund: request.payment,
        response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
            RejectCode::SysTransient,
            "Request timed out.",
            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
        )),
        deadline: request.deadline,
    }
}

/// Returns a function that determines the input queue type (local or remote)
/// of a given sender, based on the set of all local canisters, plus
/// `own_canister_id` (since Rust's ownership rules would prevent us from
/// mutating a canister's queues if they were still under `local_canisters`).
fn input_queue_type_fn<'a>(
    own_canister_id: &'a CanisterId,
    local_canisters: &'a BTreeMap<CanisterId, CanisterState>,
) -> impl Fn(&CanisterId) -> InputQueueType + 'a {
    move |sender| {
        if sender == own_canister_id || local_canisters.contains_key(sender) {
            InputQueueType::LocalSubnet
        } else {
            InputQueueType::RemoteSubnet
        }
    }
}

/// Tracks slot and guaranteed response memory reservations across input and
/// output queues. Transient byte size of responses already routed into streams
/// is ignored as the streams size is limited.
///
/// Stats for the enqueued messages themselves (counts and sizes by kind,
/// context and class) are tracked separately in `message_pool::MessageStats`.
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
struct QueueStats {
    /// Count of guaranteed response memory reservations across input and output
    /// queues. This is equivalent to the number of outstanding (inbound or outbound)
    /// guaranteed response calls and is used for computing message memory
    /// usage (as `MAX_RESPONSE_COUNT_BYTES` per request).
    ///
    /// Note that this is different from slots reserved for responses (whether
    /// best effort or guaranteed), which are used to implement backpressure.
    ///
    /// This is a counter maintained by `CanisterQueues` / `QueueStats`, but not
    /// computed from the queues themselves. Rather, it is validated against the
    /// number of unresponded guaranteed response callbacks and call contexts in the
    /// `CallContextManager`.
    guaranteed_response_memory_reservations: usize,

    /// Count of slots reserved in input queues. Note that this is different from
    /// memory reservations for guaranteed responses.
    input_queues_reserved_slots: usize,

    /// Count of slots reserved in output queues. Note that this is different from
    /// memory reservations for guaranteed responses.
    output_queues_reserved_slots: usize,
}

impl QueueStats {
    /// Returns the memory usage of reservations for guaranteed responses.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.guaranteed_response_memory_reservations * MAX_RESPONSE_COUNT_BYTES
    }

    /// Updates the stats to reflect the enqueueing of the given message in the given
    /// context.
    fn on_push(&mut self, msg: &RequestOrResponse, context: Context) {
        match msg {
            RequestOrResponse::Request(request) => self.on_push_request(request, context),
            RequestOrResponse::Response(response) => self.on_push_response(response, context),
        }
    }

    /// Updates the stats to reflect the enqueueing of the given request in the
    /// given context.
    fn on_push_request(&mut self, request: &Request, context: Context) {
        // If pushing a guaranteed response request, make a memory reservation.
        if request.deadline == NO_DEADLINE {
            self.guaranteed_response_memory_reservations += 1;
        }

        if context == Context::Outbound {
            // If pushing a request into an output queue, reserve an input queue slot.
            self.input_queues_reserved_slots += 1;
        } else {
            // And the other way around.
            self.output_queues_reserved_slots += 1;
        }
    }

    /// Updates the stats to reflect the enqueueing of the given response in the
    /// given context.
    fn on_push_response(&mut self, response: &Response, context: Context) {
        // If pushing a guaranteed response, consume a memory reservation.
        if response.deadline == NO_DEADLINE {
            debug_assert!(self.guaranteed_response_memory_reservations > 0);
            self.guaranteed_response_memory_reservations = self
                .guaranteed_response_memory_reservations
                .saturating_sub(1);
        }

        if context == Context::Inbound {
            // If pushing a response into an input queue, consume an input queue slot.
            debug_assert!(self.input_queues_reserved_slots > 0);
            self.input_queues_reserved_slots = self.input_queues_reserved_slots.saturating_sub(1);
        } else {
            // And the other way around.
            debug_assert!(self.output_queues_reserved_slots > 0);
            self.output_queues_reserved_slots = self.output_queues_reserved_slots.saturating_sub(1);
        }
    }

    /// Updates the stats to reflect the enqueueing of a "deadline expired"
    /// reference into an input queue.
    fn on_push_timeout_response(&mut self) {
        // Pushing a response into an input queue, consume an input queue slot.
        debug_assert!(self.input_queues_reserved_slots > 0);
        self.input_queues_reserved_slots = self.input_queues_reserved_slots.saturating_sub(1);
    }

    /// Updates the stats to reflect the dropping of the given request from an input
    /// queue.
    fn on_drop_input_request(&mut self, request: &Request) {
        // We should never be expiring or shedding a guaranteed response input request.
        debug_assert_ne!(NO_DEADLINE, request.deadline);

        debug_assert!(self.output_queues_reserved_slots > 0);
        self.output_queues_reserved_slots = self.output_queues_reserved_slots.saturating_sub(1);
    }
}

/// Checks whether `available_guaranteed_response_memory` is sufficient to allow
/// enqueueing `msg` into an input or output queue.
///
/// Returns:
///  * `Ok(())` if `msg` is a best-effort message, as best-effort messages don't
///    consume guaranteed response memory.
///  * `Ok(())` if `msg` is a guaranteed `Response`, as guaranteed responses
///    always return memory.
///  * `Ok(())` if `msg` is a guaranteed response `Request` and
///    `available_guaranteed_response_memory` is sufficient.
///  * `Err(msg.count_bytes())` if `msg` is a guaranteed response `Request` and
///    `msg.count_bytes() > available_guaranteed_response_memory`.
pub fn can_push(
    msg: &RequestOrResponse,
    available_guaranteed_response_memory: i64,
) -> Result<(), usize> {
    match msg {
        RequestOrResponse::Request(req) if req.is_best_effort() => Ok(()),
        RequestOrResponse::Request(req) => {
            let required = req.count_bytes().max(MAX_RESPONSE_COUNT_BYTES);
            if required as i64 <= available_guaranteed_response_memory {
                Ok(())
            } else {
                Err(required)
            }
        }
        RequestOrResponse::Response(_) => Ok(()),
    }
}

/// Returns the guaranteed response and best-effort memory used by `req` if
/// enqueued into an input or output queue.
///
/// Best-effort requests use `req.count_bytes()` worth of best-effort memory.
/// Guaranteed response requests use the maximum of `MAX_RESPONSE_COUNT_BYTES`
/// (reservation for the largest possible response) and `req.count_bytes()` (if
/// larger).
pub fn memory_usage_of_request(req: &Request) -> MessageMemoryUsage {
    if req.is_best_effort() {
        MessageMemoryUsage {
            guaranteed_response: NumBytes::new(0),
            best_effort: (req.count_bytes() as u64).into(),
        }
    } else {
        MessageMemoryUsage {
            guaranteed_response: (req.count_bytes().max(MAX_RESPONSE_COUNT_BYTES) as u64).into(),
            best_effort: NumBytes::new(0),
        }
    }
}

pub mod testing {
    use super::input_schedule::testing::InputScheduleTesting;
    use super::{CanisterQueues, MessageStore};
    use crate::{InputQueueType, StateError};
    use ic_types::messages::{Request, RequestOrResponse, Response};
    use ic_types::{CanisterId, Time};
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Exposes public testing-only `CanisterQueues` methods to be used in other
    /// crates' unit tests.
    pub trait CanisterQueuesTesting {
        /// Returns the number of messages in `ingress_queue`.
        fn ingress_queue_size(&self) -> usize;

        /// Pops the next message from the output queue to `dst_canister`.
        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse>;

        /// Returns the number of output queues, empty or not.
        fn output_queues_len(&self) -> usize;

        /// Publicly exposes `CanisterQueues::push_input()`.
        fn push_input(
            &mut self,
            msg: RequestOrResponse,
            input_queue_type: InputQueueType,
        ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)>;

        /// Publicly exposes the local sender input_schedule.
        fn local_sender_schedule(&self) -> &VecDeque<CanisterId>;

        /// Publicly exposes the remote sender input_schedule.
        fn remote_sender_schedule(&self) -> &VecDeque<CanisterId>;

        /// Returns an iterator over the raw contents of the output queue to
        /// `canister_id`; or `None` if no such output queue exists.
        fn output_queue_iter_for_testing(
            &self,
            canister_id: &CanisterId,
        ) -> Option<impl Iterator<Item = &RequestOrResponse>>;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse> {
            self.pop_canister_output(dst_canister)
        }

        fn output_queues_len(&self) -> usize {
            self.canister_queues.len()
        }

        fn push_input(
            &mut self,
            msg: RequestOrResponse,
            input_queue_type: InputQueueType,
        ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
            self.push_input(msg, input_queue_type)
        }

        fn local_sender_schedule(&self) -> &VecDeque<CanisterId> {
            self.input_schedule.local_sender_schedule()
        }

        fn remote_sender_schedule(&self) -> &VecDeque<CanisterId> {
            self.input_schedule.remote_sender_schedule()
        }

        fn output_queue_iter_for_testing(
            &self,
            canister_id: &CanisterId,
        ) -> Option<impl Iterator<Item = &RequestOrResponse>> {
            self.canister_queues
                .get(canister_id)
                .map(|(_, output_queue)| {
                    output_queue
                        .iter()
                        .filter(|&reference| !self.store.is_stale(*reference))
                        .map(|&reference| self.store.get(reference))
                })
        }
    }

    #[allow(dead_code)]
    /// Produces a `CanisterQueues` with requests enqueued in output queues,
    /// together with a `VecDeque` of raw requests, in the order in which they would
    /// be returned by `CanisterOutputQueuesIterator`.
    pub fn new_canister_output_queues_for_test(
        requests: Vec<Request>,
        sender: CanisterId,
        num_receivers: usize,
    ) -> (CanisterQueues, VecDeque<RequestOrResponse>) {
        let mut canister_queues = CanisterQueues::default();
        let mut updated_requests = VecDeque::new();
        requests.into_iter().enumerate().for_each(|(i, mut req)| {
            req.sender = sender;
            req.receiver = CanisterId::from_u64((i % num_receivers) as u64);
            let req = Arc::new(req);
            updated_requests.push_back(RequestOrResponse::Request(Arc::clone(&req)));
            canister_queues
                .push_output_request(req, Time::from_nanos_since_unix_epoch(i as u64))
                .unwrap();
        });
        (canister_queues, updated_requests)
    }
}
