mod input_schedule;
mod message_pool;
mod queue;
#[cfg(test)]
mod tests;

pub use self::input_schedule::CanisterQueuesLoopDetector;
use self::input_schedule::InputSchedule;
use self::message_pool::{Context, Kind, MessagePool};
use self::queue::{CanisterQueue, IngressQueue};
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;
use crate::{CanisterState, CheckpointLoadingMetrics, InputQueueType, InputSource, StateError};
use ic_base_types::PrincipalId;
use ic_error_types::RejectCode;
use ic_management_canister_types::IC_00;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::queues::v1 as pb_queues;
use ic_protobuf::state::queues::v1::canister_queues::CanisterQueuePair;
use ic_protobuf::types::v1 as pb_types;
use ic_types::messages::{
    CanisterMessage, Ingress, Payload, RejectContext, Request, RequestOrResponse, Response,
    MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE,
};
use ic_types::{CanisterId, CountBytes, Time};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
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
///     reserving queue slots for responses: before a message can be enqueued
///     into an input / output queue, a response slot must have been reserved in
///     the reverse output / input queue.
///
///     Canister queues hold references (of type `message_pool::Id`) into the
///     message pool (see below) or into maps of expired callbacks or shed
///     responses. Some references may be *stale* due to expiration or load
///     shedding.
///
///  3. Message pool (for the purpose of this breakdown, also includes the maps
///     of expired callbacks and shed responses): backing storage for canister
///     input and output queues.
///
///     The message pool holds the messages referenced from `canister_queues`,
///     with support for time-based expiration and load shedding. Also maintains
///     message count and size stats, broken down along several dimensions.
///
///     In order to handle shedding of inbound responses; as well as for compact
///     representation of timeout responses; shed and expired `CallbackIds`` are
///     maintained in separate maps. When it peeks or pops such a `CallbackId`,
///     `SystemState` retrieves the `Callback` and synthesizes a reject response
///     based on it.
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
/// # Soft invariants
///
///  * `QueueStats`' input / output queue slot reservation stats are consistent
///    with the actual number of reserved slots across input / output queues.
///
///  * All keys (references) in the pool and in the shed / expired callback maps
///    are enqueued in the canister queues exactly once.
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
    /// non-stale.
    canister_queues: BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,

    /// Pool holding the messages referenced by `canister_queues`, providing message
    /// stats (count, size) and support for time-based expiration and load shedding.
    #[validate_eq(CompareWithValidateEq)]
    pool: MessagePool,

    /// Slot and memory reservation stats. Message count and size stats are
    /// maintained separately in the `MessagePool`.
    queue_stats: QueueStats,

    /// Round-robin schedule for `pop_input()` across ingress, local subnet senders
    /// and remote subnet senders; as well as within the local subnet senders and
    /// remote subnet senders groups.
    input_schedule: InputSchedule,
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
    queues: VecDeque<(&'a CanisterId, &'a mut CanisterQueue)>,

    /// Mutable pool holding the messages referenced by `queues`.
    pool: &'a mut MessagePool,

    /// Number of (potentially stale) messages left in the iterator.
    size: usize,
}

impl<'a> CanisterOutputQueuesIterator<'a> {
    /// Creates a new output queue iterator from the given
    /// `CanisterQueues::canister_queues` (a map of `CanisterId` to an input queue,
    /// output queue pair) and `MessagePool`.
    fn new(
        queues: &'a mut BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
        pool: &'a mut MessagePool,
    ) -> Self {
        let queues: VecDeque<_> = queues
            .iter_mut()
            .filter(|(_, (_, queue))| queue.len() > 0)
            .map(|(canister, (_, queue))| (canister, queue))
            .collect();
        let size = Self::compute_size(&queues);

        CanisterOutputQueuesIterator { queues, pool, size }
    }

    /// Returns the first message from the next queue.
    pub fn peek(&self) -> Option<&RequestOrResponse> {
        let queue = &self.queues.front()?.1;
        let reference = queue.peek().expect("Empty queue in iterator.");

        let msg = self.pool.get(reference);
        assert!(msg.is_some(), "stale reference at front of output queue");
        msg
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
        let msg = pop_and_advance(queue, self.pool).expect("Empty queue in output iterator.");
        debug_assert_eq!(Ok(()), queue_front_not_stale(queue, self.pool, receiver));

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
    fn compute_size(queues: &VecDeque<(&'a CanisterId, &'a mut CanisterQueue)>) -> usize {
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
            while let Some(reference) = queue.peek() {
                let Some(msg) = self.pool.get(reference) else {
                    // Expired / dropped message. Pop it and advance.
                    assert_eq!(Some(reference), queue.pop());
                    continue;
                };

                match f(canister_id, msg) {
                    // `f` rejected the message, move on to the next queue.
                    Err(_) => break,

                    // Message was consumed, pop it.
                    Ok(_) => {
                        self.pool
                            .take(reference)
                            .expect("get() returned a message, take() should not fail");
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
    pub(crate) fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator {
        CanisterOutputQueuesIterator::new(&mut self.canister_queues, &mut self.pool)
    }

    /// See `IngressQueue::filter_messages()` for documentation.
    pub fn filter_ingress_messages<F>(&mut self, filter: F) -> Vec<Arc<Ingress>>
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.ingress_queue.filter_messages(filter)
    }

    /// Pushes a canister-to-canister message into the induction pool.
    ///
    /// If the message is a `Request` this will also reserve a slot in the
    /// corresponding output queue for the eventual response.
    ///
    /// If the message is a `Response` the protocol will have already reserved a
    /// slot for it, so the push should not fail due to the input queue being full
    /// (although an error may be returned in case of a bug in the upper layers).
    ///
    /// Adds the sender to the appropriate input schedule (local or remote), if not
    /// already there.
    ///
    /// # Errors
    ///
    /// If pushing fails, returns the provided message along with a
    /// `StateError`:
    ///
    ///  * `QueueFull` if pushing a `Request` and the corresponding input or
    ///    output queues are full.
    ///
    ///  * `NonMatchingResponse` if pushing a `Response` and the corresponding input
    ///    queue does not have a reserved slot.
    pub(super) fn push_input(
        &mut self,
        msg: RequestOrResponse,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
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
                if let Err(e) = output_queue.try_reserve_response_slot() {
                    return Err((e, msg));
                }
                input_queue
            }
            RequestOrResponse::Response(ref response) => {
                match self.canister_queues.get_mut(&sender) {
                    Some((queue, _)) if queue.check_has_reserved_response_slot().is_ok() => queue,

                    // Queue does not exist or has no reserved slot for this response.
                    _ => {
                        return Err((
                            StateError::NonMatchingResponse {
                                err_str: "No reserved response slot".to_string(),
                                originator: response.originator,
                                callback_id: response.originator_reply_callback,
                                respondent: response.respondent,
                                deadline: response.deadline,
                            },
                            msg,
                        ));
                    }
                }
            }
        };

        self.queue_stats.on_push(&msg, Context::Inbound);
        let reference = self.pool.insert_inbound(msg);
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
        Ok(())
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
    fn pop_canister_input(&mut self, input_queue_type: InputQueueType) -> Option<CanisterMessage> {
        while let Some(sender) = self.input_schedule.peek(input_queue_type) {
            let Some((input_queue, _)) = self.canister_queues.get_mut(sender) else {
                // Queue pair was garbage collected.
                self.input_schedule
                    .pop(input_queue_type)
                    .expect("pop() should return the sender peeked above");
                continue;
            };
            let msg = pop_and_advance(input_queue, &mut self.pool);

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

            if let Some(msg) = msg {
                debug_assert_eq!(Ok(()), self.test_invariants());
                debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
                return Some(msg.into());
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
    fn peek_canister_input(&mut self, input_queue_type: InputQueueType) -> Option<CanisterMessage> {
        while let Some(sender) = self.input_schedule.peek(input_queue_type) {
            if let Some(reference) = self
                .canister_queues
                .get(sender)
                .and_then(|(input_queue, _)| input_queue.peek())
            {
                let msg = self
                    .pool
                    .get(reference)
                    .expect("stale reference at the front of input queue");
                debug_assert_eq!(Ok(()), self.test_invariants());
                debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
                return Some(msg.clone().into());
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
                .map(|(input_queue, _)| input_queue.len() != 0)
                .unwrap_or(false)
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
        !self.ingress_queue.is_empty() || self.pool.message_stats().inbound_message_count > 0
    }

    /// Returns `true` if at least one output queue is not empty; false otherwise.
    pub fn has_output(&self) -> bool {
        self.pool.message_stats().outbound_message_count > 0
    }

    /// Peeks the ingress or inter-canister input message that would be returned by
    /// `pop_input()`.
    ///
    /// Requires a `&mut self` reference to achieve amortized `O(1)` time complexity
    /// by immediately consuming empty input queues when encountered.
    pub(crate) fn peek_input(&mut self) -> Option<CanisterMessage> {
        // Try all 3 input sources: ingress, local and remote subnets.
        for _ in 0..InputSource::COUNT {
            let peeked = match self.input_schedule.input_source() {
                InputSource::Ingress => self.peek_ingress().map(CanisterMessage::Ingress),
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
    pub(crate) fn pop_input(&mut self) -> Option<CanisterMessage> {
        // Try all 3 input sources: ingress, local and remote subnets.
        for _ in 0..InputSource::COUNT {
            let input_source = self.input_schedule.next_input_source();

            let popped = match input_source {
                InputSource::Ingress => self.pop_ingress().map(CanisterMessage::Ingress),
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
    pub fn push_output_request(
        &mut self,
        request: Arc<Request>,
        time: Time,
    ) -> Result<(), (StateError, Arc<Request>)> {
        let (input_queue, output_queue) =
            get_or_insert_queues(&mut self.canister_queues, &request.receiver);

        if let Err(e) = output_queue.check_has_request_slot() {
            return Err((e, request));
        }
        if let Err(e) = input_queue.try_reserve_response_slot() {
            return Err((e, request));
        }

        self.queue_stats
            .on_push_request(&request, Context::Outbound);

        let reference = self.pool.insert_outbound_request(request, time);
        output_queue.push_request(reference);

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
        subnet_ids: &[PrincipalId],
    ) -> Result<(), StateError> {
        assert!(
            request.receiver == IC_00 || subnet_ids.contains(&request.receiver.get()),
            "reject_subnet_output_request can only be used to reject management canister requests"
        );

        let (input_queue, _output_queue) =
            get_or_insert_queues(&mut self.canister_queues, &request.receiver);
        input_queue.try_reserve_response_slot()?;
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
        let reference = self.pool.insert_outbound_response(response);
        output_queue.push_response(reference);

        debug_assert_eq!(Ok(()), self.test_invariants());
    }

    /// Returns a reference to the (non-stale) message at the front of the respective
    /// output queue, if any.
    pub(super) fn peek_output(&self, canister_id: &CanisterId) -> Option<&RequestOrResponse> {
        let output_queue = &self.canister_queues.get(canister_id)?.1;

        let msg = self.pool.get(output_queue.peek()?);
        assert!(msg.is_some(), "stale reference at front of output queue");
        msg
    }

    /// Tries to induct a message from the output queue to `own_canister_id`
    /// into the input queue from `own_canister_id`. Returns `Err(())` if there
    /// was no message to induct or the input queue was full.
    pub(super) fn induct_message_to_self(&mut self, own_canister_id: CanisterId) -> Result<(), ()> {
        let msg = self.peek_output(&own_canister_id).ok_or(())?.clone();

        self.push_input(msg, InputQueueType::LocalSubnet)
            .map_err(|_| ())?;

        let queue = &mut self
            .canister_queues
            .get_mut(&own_canister_id)
            .expect("Output queue existed above so lookup should not fail.")
            .1;
        pop_and_advance(queue, &mut self.pool)
            .expect("Message peeked above so pop should not fail.");

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&|_| InputQueueType::RemoteSubnet));
        Ok(())
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
        self.pool.message_stats().inbound_message_count
    }

    /// Returns the number of reserved slots across all input queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn input_queues_reserved_slots(&self) -> usize {
        self.queue_stats.input_queues_reserved_slots
    }

    /// Returns the total byte size of canister input queues (queues +
    /// messages).
    pub fn input_queues_size_bytes(&self) -> usize {
        self.pool.message_stats().inbound_size_bytes
            + self.canister_queues.len() * size_of::<CanisterQueue>()
    }

    /// Returns the number of non-stale requests enqueued in input queues.
    pub fn input_queues_request_count(&self) -> usize {
        self.pool.message_stats().inbound_message_count
            - self.pool.message_stats().inbound_response_count
    }

    /// Returns the number of non-stale responses enqueued in input queues.
    pub fn input_queues_response_count(&self) -> usize {
        self.pool.message_stats().inbound_response_count
    }

    /// Returns the number of actual (non-stale) messages in output queues.
    pub fn output_queues_message_count(&self) -> usize {
        self.pool.message_stats().outbound_message_count
    }

    /// Returns the number of reserved slots across all output queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn output_queues_reserved_slots(&self) -> usize {
        self.queue_stats.output_queues_reserved_slots
    }

    /// Returns the memory usage of all best-effort messages.
    pub fn best_effort_memory_usage(&self) -> usize {
        self.pool.message_stats().best_effort_message_bytes
    }

    /// Returns the memory usage of all guaranteed response messages.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.queue_stats.guaranteed_response_memory_usage()
            + self.pool.message_stats().guaranteed_response_memory_usage()
    }

    /// Returns the total byte size of guaranteed responses across input and
    /// output queues.
    pub fn guaranteed_responses_size_bytes(&self) -> usize {
        self.pool.message_stats().guaranteed_responses_size_bytes
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
        self.pool
            .message_stats()
            .oversized_guaranteed_requests_extra_bytes
    }

    /// Sets the (transient) size in bytes of guaranteed responses routed from
    /// output queues into streams and not yet garbage collected.
    pub(super) fn set_stream_guaranteed_responses_size_bytes(&mut self, size_bytes: usize) {
        self.queue_stats
            .transient_stream_guaranteed_responses_size_bytes = size_bytes;
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
            // The schedules and stats will already have default (zero) values, only `pool`
            // and `input_schedule` must be reset explicitly.
            debug_assert!(self.pool.len() == 0);
            self.pool = MessagePool::default();
            self.input_schedule = InputSchedule::default();

            // Trust but verify. Ensure that everything is actually set to default.
            debug_assert_eq!(CanisterQueues::default(), *self);
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
        self.pool.has_expired_deadlines(current_time)
    }

    /// Drops expired messages given a current time, enqueuing a reject response for
    /// own requests into the matching reverse queue (input or output).
    ///
    /// Updating the correct input queues schedule after enqueuing a reject response
    /// into a previously empty input queue also requires the set of local canisters
    /// to decide whether the destination canister was local or remote.
    ///
    /// Returns the number of messages that were timed out.
    pub fn time_out_messages(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> usize {
        let expired_messages = self.pool.expire_messages(current_time);

        let input_queue_type_fn = input_queue_type_fn(own_canister_id, local_canisters);
        for (reference, msg) in expired_messages.iter() {
            self.on_message_dropped(*reference, msg, &input_queue_type_fn);
        }

        debug_assert_eq!(Ok(()), self.test_invariants());
        debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn));
        expired_messages.len()
    }

    /// Removes the largest best-effort message in the underlying pool. Returns
    /// `true` if a message was removed; `false` otherwise.
    ///
    /// Updates the stats for the dropped message and (where applicable) the
    /// generated response. `own_canister_id` and `local_canisters` are required
    /// to determine the correct input queue schedule to update (if applicable).
    pub fn shed_largest_message(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> bool {
        if let Some((reference, msg)) = self.pool.shed_largest_message() {
            let input_queue_type_fn = input_queue_type_fn(own_canister_id, local_canisters);
            self.on_message_dropped(reference, &msg, &input_queue_type_fn);

            debug_assert_eq!(Ok(()), self.test_invariants());
            debug_assert_eq!(Ok(()), self.schedules_ok(&input_queue_type_fn));
            return true;
        }

        false
    }

    /// Handles the timing out or shedding of a message from the pool.
    ///
    /// Records the callback of a shed inbound best-effort response. Releases the
    /// outbound slot reservation of a shed inbound request. Generates and enqueues
    /// a reject response if the message was an outbound request. Updates the stats
    /// for the dropped message and (where applicable) the generated response.
    ///
    /// `input_queue_type_fn` is required to determine the appropriate sender
    /// schedule to update when generating a reject response.
    fn on_message_dropped(
        &mut self,
        reference: message_pool::Id,
        msg: &RequestOrResponse,
        input_queue_type_fn: impl Fn(&CanisterId) -> InputQueueType,
    ) {
        use Context::*;

        let context = reference.context();
        let remote = match context {
            Inbound => msg.sender(),
            Outbound => msg.receiver(),
        };
        let (input_queue, output_queue) = self
            .canister_queues
            .get_mut(&remote)
            .expect("No matching queue for dropped message.");
        let (queue, reverse_queue) = match context {
            Inbound => (input_queue, output_queue),
            Outbound => (output_queue, input_queue),
        };

        // Ensure that the first reference in a queue is never stale: if we dropped the
        // message at the front of a queue, advance to the first non-stale reference.
        //
        // Defensive check, reference may have already been popped by an earlier
        // `on_message_dropped()` call if multiple messages expired at once (e.g. given
        // a queue containing references `[1, 2]`; `1` and `2` expire as part of the
        // same `time_out_messages()` call; `on_message_dropped(1)` will also pop `2`).
        if queue.peek() == Some(reference) {
            queue.pop();
            queue.pop_while(|reference| self.pool.get(reference).is_none());
        }

        // Release the response slot, generate reject responses or remember shed inbound
        // responses, as necessary.
        match (context, msg) {
            // Inbound request: release the outbound response slot.
            (Inbound, RequestOrResponse::Request(request)) => {
                reverse_queue.release_reserved_response_slot();
                self.queue_stats.on_drop_input_request(request);
            }

            // Outbound request: produce a `SYS_TRANSIENT` timeout reject response.
            (Outbound, RequestOrResponse::Request(request)) => {
                let response = generate_timeout_response(request);

                // Update stats for the generated response.
                self.queue_stats.on_push_response(&response, Inbound);

                let reference = self.pool.insert_inbound(response.into());
                reverse_queue.push_response(reference);

                // If the input queue is not already in a sender schedule, add it.
                if reverse_queue.len() == 1 {
                    let input_queue_type = input_queue_type_fn(&remote);
                    self.input_schedule.schedule(remote, input_queue_type);
                }
            }

            // Inbound or outbound response, nothing left to do.
            //
            // TODO(MR-603): Recall the `Id` -> `CallbackId` of shed inbound responses and
            // generate a reject response on the fly when the respective `Id` is popped.
            (_, RequestOrResponse::Response(_)) => {}
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
                .map(|(canister_id, (input_queue, _))| (canister_id, input_queue)),
            &input_queue_type_fn,
        )
    }

    /// Helper function for concisely validating invariants other than those of
    /// input queue schedules (no stale references at queue front, valid stats)
    /// during deserialization; or in debug builds, by writing
    /// `debug_assert_eq!(Ok(()), self.test_invariants())`.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn test_invariants(&self) -> Result<(), String> {
        // Invariant: all canister queues (input or output) are either empty or start
        // with a non-stale reference.
        for (canister_id, (input_queue, output_queue)) in self.canister_queues.iter() {
            queue_front_not_stale(input_queue, &self.pool, canister_id)?;
            queue_front_not_stale(output_queue, &self.pool, canister_id)?;
        }

        // Reserved slot stats match the actual number of reserved slots.
        let calculated_stats = Self::calculate_queue_stats(
            &self.canister_queues,
            self.queue_stats.guaranteed_response_memory_reservations,
            self.queue_stats
                .transient_stream_guaranteed_responses_size_bytes,
        );
        if self.queue_stats != calculated_stats {
            return Err(format!(
                "Inconsistent stats:\n  expected: {:?}\n  actual: {:?}",
                calculated_stats, self.queue_stats
            ));
        }

        Ok(())
    }

    /// Computes stats for the given canister queues. Used when deserializing and in
    /// `debug_assert!()` checks. Takes the number of memory reservations from the
    /// caller, as the queues have no need to track memory reservations, so it
    /// cannot be computed. Same with the size of guaranteed responses in streams.
    ///
    /// Time complexity: `O(canister_queues.len())`.
    fn calculate_queue_stats(
        canister_queues: &BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
        guaranteed_response_memory_reservations: usize,
        transient_stream_guaranteed_responses_size_bytes: usize,
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
            transient_stream_guaranteed_responses_size_bytes,
        }
    }
}

/// Returns the existing matching pair of input and output queues from/to
/// the given canister; or creates a pair of empty queues, if non-existent.
///
/// Written as a free function in order to avoid borrowing the full
/// `CanisterQueues`, which then requires looking up the queues again.
fn get_or_insert_queues<'a>(
    canister_queues: &'a mut BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
    canister_id: &CanisterId,
) -> (&'a mut CanisterQueue, &'a mut CanisterQueue) {
    let (input_queue, output_queue) = canister_queues.entry(*canister_id).or_insert_with(|| {
        let input_queue = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
        let output_queue = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
        (input_queue, output_queue)
    });
    (input_queue, output_queue)
}

/// Pops and returns the message at the front of the queue and advances the
/// queue to the next message / non-stale reference.
fn pop_and_advance(queue: &mut CanisterQueue, pool: &mut MessagePool) -> Option<RequestOrResponse> {
    let reference = queue.pop()?;
    queue.pop_while(|reference| pool.get(reference).is_none());

    let msg = pool.take(reference);
    assert!(msg.is_some(), "stale reference at the front of queue");
    msg
}

/// Helper function for concisely validating the hard invariant that a canister
/// queue is either empty of has a non-stale reference at the front, by writing
/// `debug_assert_eq!(Ok(()), queue_front_not_stale(...)`.
///
/// Time complexity: `O(log(n))`.
fn queue_front_not_stale(
    queue: &CanisterQueue,
    pool: &MessagePool,
    canister_id: &CanisterId,
) -> Result<(), String> {
    if let Some(reference) = queue.peek() {
        if pool.get(reference).is_none() {
            return Err(format!(
                "Stale reference at the front of {:?} queue to/from {}",
                reference.context(),
                canister_id
            ));
        }
    }

    Ok(())
}

/// Generates a timeout reject response from a request, refunding its payment.
fn generate_timeout_response(request: &Arc<Request>) -> Response {
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

/// Returns a function that determines the input queue type (local or remote) of
/// a given sender, based on a the set of all local canisters, plus
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

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        let (next_input_source, local_sender_schedule, remote_sender_schedule) =
            (&item.input_schedule).into();

        Self {
            ingress_queue: (&item.ingress_queue).into(),
            input_queues: Default::default(),
            output_queues: Default::default(),
            canister_queues: item
                .canister_queues
                .iter()
                .map(|(canid, (iq, oq))| CanisterQueuePair {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    input_queue: Some(iq.into()),
                    output_queue: Some(oq.into()),
                })
                .collect(),
            pool: if item.pool != MessagePool::default() {
                Some((&item.pool).into())
            } else {
                None
            },
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
            guaranteed_response_memory_reservations: item
                .queue_stats
                .guaranteed_response_memory_reservations
                as u64,
        }
    }
}

impl TryFrom<(pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics)> for CanisterQueues {
    type Error = ProxyDecodeError;
    fn try_from(
        (item, metrics): (pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
        let mut canister_queues = BTreeMap::new();
        let mut pool = MessagePool::default();

        if !item.input_queues.is_empty() || !item.output_queues.is_empty() {
            // Backward compatibility: deserialize from `input_queues` and `output_queues`.

            if item.pool.is_some() || !item.canister_queues.is_empty() {
                return Err(ProxyDecodeError::Other(
                    "Both `input_queues`/`output_queues` and `pool`/`canister_queues` are populated"
                        .to_string(),
                ));
            }

            if item.input_queues.len() != item.output_queues.len() {
                return Err(ProxyDecodeError::Other(format!(
                    "CanisterQueues: Mismatched input ({}) and output ({}) queue lengths",
                    item.input_queues.len(),
                    item.output_queues.len()
                )));
            }
            for (ie, oe) in item
                .input_queues
                .into_iter()
                .zip(item.output_queues.into_iter())
            {
                if ie.canister_id != oe.canister_id {
                    return Err(ProxyDecodeError::Other(format!(
                        "CanisterQueues: Mismatched input {:?} and output {:?} queue entries",
                        ie.canister_id, oe.canister_id
                    )));
                }

                let canister_id = try_from_option_field(ie.canister_id, "QueueEntry::canister_id")?;
                let original_iq: queue::InputQueue =
                    try_from_option_field(ie.queue, "QueueEntry::queue")?;
                let original_oq: queue::OutputQueue =
                    try_from_option_field(oe.queue, "QueueEntry::queue")?;
                let iq = (original_iq, &mut pool).try_into()?;
                let oq = (original_oq, &mut pool).try_into()?;

                if canister_queues.insert(canister_id, (iq, oq)).is_some() {
                    metrics.observe_broken_soft_invariant(format!(
                        "CanisterQueues: Duplicate queues for canister {}",
                        canister_id
                    ));
                }
            }
        } else {
            pool = item.pool.unwrap_or_default().try_into()?;

            let mut enqueued_pool_messages = BTreeSet::new();
            canister_queues = item
                .canister_queues
                .into_iter()
                .map(|qp| {
                    let canister_id: CanisterId =
                        try_from_option_field(qp.canister_id, "CanisterQueuePair::canister_id")?;
                    let iq: CanisterQueue = try_from_option_field(
                        qp.input_queue.map(|q| (q, Context::Inbound)),
                        "CanisterQueuePair::input_queue",
                    )?;
                    let oq: CanisterQueue = try_from_option_field(
                        qp.output_queue.map(|q| (q, Context::Outbound)),
                        "CanisterQueuePair::output_queue",
                    )?;

                    iq.iter().chain(oq.iter()).for_each(|&reference| {
                        if pool.get(reference).is_some()
                            && !enqueued_pool_messages.insert(reference)
                        {
                            metrics.observe_broken_soft_invariant(format!(
                                "CanisterQueues: Message {:?} enqueued more than once",
                                reference
                            ));
                        }
                    });

                    Ok((canister_id, (iq, oq)))
                })
                .collect::<Result<_, Self::Error>>()?;

            if enqueued_pool_messages.len() != pool.len() {
                metrics.observe_broken_soft_invariant(format!(
                    "CanisterQueues: Pool holds {} messages, but only {} of them are enqueued",
                    pool.len(),
                    enqueued_pool_messages.len()
                ));
            }
        }

        let queue_stats = Self::calculate_queue_stats(
            &canister_queues,
            item.guaranteed_response_memory_reservations as usize,
            0,
        );

        let input_schedule = InputSchedule::try_from((
            item.next_input_source,
            item.local_sender_schedule,
            item.remote_sender_schedule,
        ))?;

        let queues = Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            canister_queues,
            pool,
            queue_stats,
            input_schedule,
        };

        // Safe to pretend that all senders are remote, as the validation logic allows
        // for deleted local canisters (which would be categorized as remote).
        if let Err(msg) = queues.schedules_ok(&|_| InputQueueType::RemoteSubnet) {
            metrics.observe_broken_soft_invariant(msg);
        }
        queues.test_invariants().map_err(ProxyDecodeError::Other)?;

        Ok(queues)
    }
}

/// Tracks slot and guaranteed response memory reservations across input and
/// output queues; and holds a (transient) byte size of responses already routed
/// into streams (tracked separately, at the replicated state level, as messages
/// are routed to and GC-ed from streams).
///
/// Stats for the enqueued messages themselves (counts and sizes by kind,
/// context and class) are tracked separately in `message_pool::MessageStats`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
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

    /// Transient: size in bytes of guaranteed responses routed from `output_queues`
    /// into streams and not yet garbage collected.
    ///
    /// This is updated by `ReplicatedState::put_streams()`, called by MR after
    /// every streams mutation (induction, routing, GC). And is (re)populated during
    /// checkpoint loading by `ReplicatedState::new_from_checkpoint()`.
    transient_stream_guaranteed_responses_size_bytes: usize,
}

impl QueueStats {
    /// Returns the memory usage of reservations for guaranteed responses plus
    /// guaranteed responses in streans.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.guaranteed_response_memory_reservations * MAX_RESPONSE_COUNT_BYTES
            + self.transient_stream_guaranteed_responses_size_bytes
    }

    /// Updates the stats to reflect the enqueuing of the given message in the given
    /// context.
    fn on_push(&mut self, msg: &RequestOrResponse, context: Context) {
        match msg {
            RequestOrResponse::Request(request) => self.on_push_request(request, context),
            RequestOrResponse::Response(response) => self.on_push_response(response, context),
        }
    }

    /// Updates the stats to reflect the enqueuing of the given request in the given
    /// context.
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

    /// Updates the stats to reflect the enqueuing of the given response in the
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

    /// Updates the stats to reflect the dropping of the given request from an input
    /// queue.
    fn on_drop_input_request(&mut self, request: &Request) {
        // We should never be expiring or shedding a guaranteed response input request.
        debug_assert_ne!(NO_DEADLINE, request.deadline);

        debug_assert!(self.output_queues_reserved_slots > 0);
        self.output_queues_reserved_slots = self.output_queues_reserved_slots.saturating_sub(1);
    }
}

/// Checks whether `available_memory` for guaranteed response messages is
/// sufficient to allow enqueuing `msg` into an input or output queue.
///
/// Returns:
///  * `Ok(())` if `msg` is a best-effort message, as best-effort messages don't
///    consume guaranteed response memory.
///  * `Ok(())` if `msg` is a guaranteed `Response`, as guaranteed responses
///    always return memory.
///  * `Ok(())` if `msg` is a guaranteed response `Request` and
///    `available_memory` is sufficient.
///  * `Err(msg.count_bytes())` if `msg` is a guaranteed response `Request` and
///    `msg.count_bytes() > available_memory`.
pub fn can_push(msg: &RequestOrResponse, available_memory: i64) -> Result<(), usize> {
    match msg {
        RequestOrResponse::Request(req) => {
            let required = memory_required_to_push_request(req);
            if required as i64 <= available_memory || required == 0 {
                Ok(())
            } else {
                Err(required)
            }
        }
        RequestOrResponse::Response(_) => Ok(()),
    }
}

/// Returns the guaranteed response memory required to push `req` onto an input
/// or output queue.
///
/// For best-effort requests, this is always zero. For guaranteed response
/// requests, this is the maximum of `MAX_RESPONSE_COUNT_BYTES` (to be reserved
/// for a guaranteed response) and `req.count_bytes()` (if larger).
pub fn memory_required_to_push_request(req: &Request) -> usize {
    if req.deadline != NO_DEADLINE {
        return 0;
    }

    req.count_bytes().max(MAX_RESPONSE_COUNT_BYTES)
}

pub mod testing {
    use super::input_schedule::testing::InputScheduleTesting;
    use super::CanisterQueues;
    use crate::{InputQueueType, StateError};
    use ic_types::messages::{CanisterMessage, Request, RequestOrResponse};
    use ic_types::{CanisterId, Time};
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Exposes public testing-only `CanisterQueues` methods to be used in other
    /// crates' unit tests.
    pub trait CanisterQueuesTesting {
        /// Returns the number of messages in `ingress_queue`.
        fn ingress_queue_size(&self) -> usize;

        /// Pops the next message from the output queue associated with
        /// `dst_canister`.
        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse>;

        /// Returns the number of output queues, empty or not.
        fn output_queues_len(&self) -> usize;

        /// Returns the number of messages in `output_queues`.
        fn output_message_count(&self) -> usize;

        /// Publicly exposes `CanisterQueues::push_input()`.
        fn push_input(
            &mut self,
            msg: RequestOrResponse,
            input_queue_type: InputQueueType,
        ) -> Result<(), (StateError, RequestOrResponse)>;

        /// Publicly exposes `CanisterQueues::pop_input()`.
        fn pop_input(&mut self) -> Option<CanisterMessage>;

        /// Publicly exposes the local sender input_schedule.
        fn local_sender_schedule(&self) -> &VecDeque<CanisterId>;

        /// Publicly exposes the remote sender input_schedule.
        fn remote_sender_schedule(&self) -> &VecDeque<CanisterId>;

        /// Returns an iterator over the raw contents of the output queue to
        /// `canister_id`; or `None` if no such output queue exists.
        fn output_queue_iter_for_testing(
            &self,
            canister_id: &CanisterId,
        ) -> Option<impl Iterator<Item = RequestOrResponse>>;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse> {
            let queue = &mut self.canister_queues.get_mut(dst_canister).unwrap().1;
            super::pop_and_advance(queue, &mut self.pool)
        }

        fn output_queues_len(&self) -> usize {
            self.canister_queues.len()
        }

        fn output_message_count(&self) -> usize {
            self.pool.message_stats().outbound_message_count
        }

        fn push_input(
            &mut self,
            msg: RequestOrResponse,
            input_queue_type: InputQueueType,
        ) -> Result<(), (StateError, RequestOrResponse)> {
            self.push_input(msg, input_queue_type)
        }

        fn pop_input(&mut self) -> Option<CanisterMessage> {
            self.pop_input()
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
        ) -> Option<impl Iterator<Item = RequestOrResponse>> {
            self.canister_queues
                .get(canister_id)
                .map(|(_, output_queue)| {
                    output_queue
                        .iter()
                        .filter_map(|&reference| self.pool.get(reference).cloned())
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
