mod message_pool;
mod queue;
#[cfg(test)]
mod tests;

use self::message_pool::{MessageId, MessagePool};
use self::queue::{CanisterQueue, IngressQueue, MessageReference};
use crate::canister_state::queues::message_pool::Class;
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;
use crate::{CanisterState, InputQueueType, NextInputQueue, StateError};
use ic_base_types::PrincipalId;
use ic_error_types::RejectCode;
use ic_management_canister_types::IC_00;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::{v1 as pb_queues, v1::canister_queues::NextInputQueue as ProtoNextInputQueue},
    types::v1 as pb_types,
};
use ic_types::messages::{CallbackId, NO_DEADLINE};
use ic_types::methods::Callback;
use ic_types::{
    messages::{
        CanisterMessage, Ingress, Payload, RejectContext, Request, RequestOrResponse, Response,
        MAX_RESPONSE_COUNT_BYTES,
    },
    xnet::{QueueId, SessionId},
    CanisterId, CountBytes, Cycles, Time,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    convert::{From, TryFrom},
    ops::{AddAssign, SubAssign},
    sync::Arc,
};

pub const DEFAULT_QUEUE_CAPACITY: usize = 500;

/// Encapsulates information about `CanisterQueues`,
/// used in detecting a loop when consuming the input messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanisterQueuesLoopDetector {
    pub local_queue_skip_count: usize,
    pub remote_queue_skip_count: usize,
    pub ingress_queue_skip_count: usize,
}

impl CanisterQueuesLoopDetector {
    /// Detects a loop in `CanisterQueues`.
    pub fn detected_loop(&self, canister_queues: &CanisterQueues) -> bool {
        let skipped_all_remote =
            self.remote_queue_skip_count >= canister_queues.remote_subnet_input_schedule.len();

        let skipped_all_local =
            self.local_queue_skip_count >= canister_queues.local_subnet_input_schedule.len();

        let skipped_all_ingress =
            self.ingress_queue_skip_count >= canister_queues.ingress_queue.ingress_schedule_size();

        // An empty queue is skipped implicitly by `peek_input()` and `pop_input()`.
        // This means that no new messages can be consumed from an input source if
        // - either it is empty,
        // - or all its queues were explicitly skipped.
        // Note that `skipped_all_remote`, `skipped_all_local`, and `skipped_all_ingress`
        // are trivially true if the corresponding input source is empty because empty
        // queues are removed from the source.
        skipped_all_remote && skipped_all_local && skipped_all_ingress
    }
}

/// Wrapper around the induction pool (ingress and input queues); a priority
/// queue used for round-robin scheduling of senders when consuming input
/// messages; and output queues.
///
/// Responsible for queue lifetime management, fair scheduling of inputs across
/// sender canisters and queue backpressure.
///
/// Encapsulates the `InductionPool` component described in the spec. The reason
/// for bundling together the induction pool and output queues is to reliably
/// implement backpressure via queue slot reservations for response messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanisterQueues {
    /// Queue of ingress (user) messages.
    ingress_queue: IngressQueue,

    /// Per remote canister input and output queues.
    canister_queues: BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,

    pool: MessagePool,

    /// FIFO queue of local subnet sender canister IDs ensuring round-robin
    /// consumption of input messages. Only senders with non-empty queues
    /// are scheduled.
    ///
    /// We rely on `ReplicatedState::canister_states` to decide whether a canister
    /// is local or not. This test is subject to race conditions (e.g. if the sender
    /// has just been deleted), meaning that the separation into local and remote
    /// senders is best effort.
    local_subnet_input_schedule: VecDeque<CanisterId>,

    /// FIFO queue of remote subnet sender canister IDs ensuring round-robin
    /// consumption of input messages. Only senders with non-empty queues
    /// are scheduled.
    ///
    /// We rely on `ReplicatedState::canister_states` to decide whether a canister
    /// is local or not. This test is subject to race conditions (e.g. if the sender
    /// has just been deleted), meaning that the separation into local and remote
    /// senders is best effort.
    remote_subnet_input_schedule: VecDeque<CanisterId>,

    /// Running `input_queues` stats.
    input_queues_stats: InputQueuesStats,

    /// Running `output_queues` stats.
    output_queues_stats: OutputQueuesStats,

    /// Running memory usage stats, across input and output queues.
    memory_usage_stats: MemoryUsageStats,

    /// Round-robin across ingress and cross-net input queues for pop_input().
    next_input_queue: NextInputQueue,
}

/// Circular iterator that consumes output queue messages: loops over output
/// queues, popping one message at a time from each in a round robin fashion.
/// All messages that have not been explicitly popped will remain in the state.
///
/// Additional operations compared to a standard iterator:
///  * peeking (returning a reference to the next message without consuming it);
///    and
///  * excluding whole queues from iteration while retaining their messages
///    (e.g. in order to efficiently implement per destination limits).
#[derive(Debug)]
pub struct CanisterOutputQueuesIterator<'a> {
    /// ID of the canister that owns the output queues being iterated.
    owner: CanisterId,

    /// Priority queue of non-empty output queues. The next message to be popped
    /// / peeked is the one at the head of the first queue.
    queues: VecDeque<(&'a CanisterId, &'a mut CanisterQueue)>,

    pool: &'a mut MessagePool,

    /// Number of messages that can be popped before the iterator finishes.
    size: usize,

    /// The canister's memory usage stats, to be updated as messages are popped.
    memory_stats: &'a mut MemoryUsageStats,

    /// Canister output queue stats, to be updated as messages are popped.
    queue_stats: &'a mut OutputQueuesStats,
}

impl<'a> CanisterOutputQueuesIterator<'a> {
    fn new(
        owner: CanisterId,
        queues: &'a mut BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
        pool: &'a mut MessagePool,
        memory_stats: &'a mut MemoryUsageStats,
        queue_stats: &'a mut OutputQueuesStats,
    ) -> Self {
        let queues: VecDeque<_> = queues
            .iter_mut()
            .filter(|(_, (_, queue))| queue.len() > 0)
            .map(|(canister, (_, queue))| (canister, queue))
            .collect();
        let size = Self::compute_size(&queues);

        CanisterOutputQueuesIterator {
            owner,
            queues,
            pool,
            size,
            memory_stats,
            queue_stats,
        }
    }

    /// Returns the first (non-stale) message from the first queue holding one.
    ///
    /// Consumes all encountered stale references. Removes all consumed queues from
    /// the iteration order.
    ///
    /// Note: While it is slightly unusual to pass a mutable reference to an
    /// apparently read-only operation such as `peek()`, we need to be able to prune
    /// stale queue entries whenever we see them or else risk turning this into an
    /// `O(N)` time operation. We could instead fall back on internal mutability,
    /// but the additional complexity is unnecessary given the current uses.
    pub fn peek(&mut self) -> Option<(QueueId, &RequestOrResponse)> {
        while let Some((receiver, queue)) = self.queues.front_mut() {
            while let Some(reference) = queue.peek() {
                let queue_id = QueueId {
                    src_canister: self.owner,
                    dst_canister: **receiver,
                    session_id: SessionId::new(0),
                };

                // FIXME: Generate a reject response.
                let msg = match self.pool.get(reference.id().unwrap()) {
                    Some(msg) => msg,

                    // Stale reference, pop it and try again.
                    None => {
                        queue.pop();
                        continue;
                    }
                };

                return Some((queue_id, msg));
            }

            // Queue only contained stale references and was exhausted.
            self.queues.pop_front();
        }
        None
    }

    /// Pops the first (non-stale) message from the first queue holding one. If this
    /// was not the last message in that queue, the queue is moved to the back of
    /// the iteration order.
    ///
    /// Consumes all encountered stale references. Removes all consumed queues from
    /// the iteration order.
    pub fn pop(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        while let Some((receiver, queue)) = self.queues.pop_front() {
            while let Some(reference) = queue.pop() {
                let queue_id = QueueId {
                    src_canister: self.owner,
                    dst_canister: *receiver,
                    session_id: SessionId::new(0),
                };

                // FIXME: Generate a reject response.
                let msg = match self.pool.take(reference.id().unwrap()) {
                    Some(msg) => msg,

                    // Stale reference, try again.
                    None => {
                        continue;
                    }
                };

                if queue.len() > 0 {
                    self.queues.push_back((receiver, queue));
                }

                *self.memory_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                *self.queue_stats -= OutputQueuesStats::stats_delta(&msg);
                self.size -= 1;
                debug_assert_eq!(Self::compute_size(&self.queues), self.size);

                return Some((queue_id, msg));
            }
        }
        None
    }

    /// Permanently excludes from iteration the next queue (i.e. all messages
    /// with the same sender and receiver as the next message). The messages are
    /// retained in the output queue.
    ///
    /// Returns the number of messages left in the excluded queue.
    pub fn exclude_queue(&mut self) -> usize {
        let ignored = self
            .queues
            .pop_front()
            .map(|(_, q)| q.len())
            .unwrap_or_default();

        self.size -= ignored;
        debug_assert_eq!(Self::compute_size(&self.queues), self.size);

        ignored
    }

    /// Checks if the iterator has finished.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Computes the number of messages left in `queues`.
    ///
    /// Time complexity: O(N).
    fn compute_size(queues: &VecDeque<(&'a CanisterId, &'a mut CanisterQueue)>) -> usize {
        queues.iter().map(|(_, q)| q.len()).sum()
    }
}

impl Iterator for CanisterOutputQueuesIterator<'_> {
    type Item = (QueueId, RequestOrResponse);

    /// Alias for `pop`.
    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }

    /// Returns the exact number of messages left in the iterator.
    fn size_hint(&self) -> (usize, Option<usize>) {
        // FIXME
        (self.size, Some(self.size))
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
    pub(crate) fn output_queues_for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, &RequestOrResponse) -> Result<(), ()>,
    {
        for (canister_id, (_, queue)) in self.canister_queues.iter_mut() {
            while let Some(reference) = queue.peek() {
                // FIXME: Generate a reject response.
                let msg = match self.pool.get(reference.id().unwrap()) {
                    // Actual message.
                    Some(msg) => msg,

                    // Expired / dropped message. Pop it and advance.
                    None => {
                        queue
                            .pop()
                            .expect("peek() returned a message, pop() should not fail");
                        continue;
                    }
                };

                match f(canister_id, msg) {
                    // `f` rejected the message, move on to next queue.
                    Err(_) => break,

                    // Message consumed, pop it and update the stats.
                    Ok(_) => {
                        queue.pop();

                        self.output_queues_stats -= OutputQueuesStats::stats_delta(msg);
                        self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, msg);
                    }
                }
            }
        }
        debug_assert!(self.stats_ok());
    }

    /// Returns an iterator that loops over output queues, popping one message
    /// at a time from each in a round robin fashion. The iterator consumes all
    /// popped messages.
    pub(crate) fn output_into_iter(&mut self, owner: CanisterId) -> CanisterOutputQueuesIterator {
        CanisterOutputQueuesIterator::new(
            owner,
            &mut self.canister_queues,
            &mut self.pool,
            &mut self.memory_usage_stats,
            &mut self.output_queues_stats,
        )
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
    /// (although an error will be returned in case of a bug in the upper layers).
    ///
    /// # Errors
    ///
    /// If pushing fails, returns the provided message along with a
    /// `StateError`:
    ///
    ///  * `QueueFull` if pushing a `Request` and the corresponding input or
    ///    output queues are full.
    ///
    ///  * `InvariantBroken` if pushing a `Response` and the receiving canister is
    ///    not expecting one.
    pub(super) fn push_input(
        &mut self,
        msg: RequestOrResponse,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let sender = msg.sender();
        let input_queue = match &msg {
            RequestOrResponse::Request(req) => {
                let (input_queue, output_queue) = self.get_or_insert_queues(&sender);
                // FIXME: Also check for a memory reservation for guaranteed responses.
                if let Err(e) = input_queue.check_has_request_slot() {
                    return Err((e, msg));
                }
                // Safe to already (attempt to) reserve an output slot here, as the `push()`
                // below is guaranteed to succeed due to the check above.
                if let Err(e) = output_queue.try_reserve_response_slot(req) {
                    return Err((e, msg));
                }
                // Make the borrow checker happy.
                &mut self.canister_queues.get_mut(&sender).unwrap().0
            }
            RequestOrResponse::Response(rep) => match self.canister_queues.get_mut(&sender) {
                Some((queue, _)) => {
                    let class = if rep.deadline == NO_DEADLINE {
                        Class::GuaranteedResponse
                    } else {
                        Class::BestEffort
                    };
                    if let Err(e) = queue.check_has_reserved_response_slot(class) {
                        return Err((e, msg));
                    }
                    queue
                }
                None => return Err((StateError::QueueFull { capacity: 0 }, msg)),
            },
        };
        let iq_stats_delta = InputQueuesStats::stats_delta(QueueOp::Push, &msg);
        let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Push, &msg);

        // FIXME: Try looking up the message ID first.
        match msg {
            RequestOrResponse::Request(_) => {
                let id = self.pool.insert_inbound(msg);
                input_queue.push_request(id)
            }
            RequestOrResponse::Response(_) => {
                let id = self.pool.insert_inbound(msg);
                input_queue.push_response(id)
            }
        }

        // Add sender canister ID to the input schedule queue if it isn't already there.
        // Sender was not scheduled iff its input queue was empty before the push (i.e.
        // queue size is 1 after the push).
        if input_queue.len() == 1 {
            match input_queue_type {
                InputQueueType::LocalSubnet => self.local_subnet_input_schedule.push_back(sender),
                InputQueueType::RemoteSubnet => self.remote_subnet_input_schedule.push_back(sender),
            }
        }

        self.input_queues_stats += iq_stats_delta;
        self.memory_usage_stats += mu_stats_delta;
        debug_assert!(self.stats_ok());

        Ok(())
    }

    /// Pops the next canister-to-canister message from `input_queues`.
    ///
    /// Note: We pop senders from the head of `input_schedule` and insert them
    /// to the back, which allows us to handle messages from different
    /// originators in a round-robin fashion.
    fn pop_canister_input(&mut self, input_queue: InputQueueType) -> Option<CanisterMessage> {
        let input_schedule = match input_queue {
            InputQueueType::LocalSubnet => &mut self.local_subnet_input_schedule,
            InputQueueType::RemoteSubnet => &mut self.remote_subnet_input_schedule,
        };

        while let Some(sender) = input_schedule.pop_front() {
            // Get the message queue of this canister.
            let input_queue = &mut self.canister_queues.get_mut(&sender).unwrap().0;
            while let Some(reference) = input_queue.pop() {
                // FIXME: Generate a reject response.
                let msg = match self.pool.take(reference.id().unwrap()) {
                    Some(message) => message,

                    // Stale reference, try again.
                    None => {
                        continue;
                    }
                };

                // If the queue still isn't empty, re-add sender canister ID to the end of the
                // input schedule queue.
                if input_queue.len() != 0 {
                    input_schedule.push_back(sender);
                }

                self.input_queues_stats -= InputQueuesStats::stats_delta(QueueOp::Pop, &msg);
                self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                debug_assert!(self.stats_ok());

                let msg = match msg {
                    RequestOrResponse::Request(msg) => CanisterMessage::Request(msg),
                    RequestOrResponse::Response(msg) => CanisterMessage::Response(msg),
                };

                return Some(msg);
            }
        }

        None
    }

    /// Peeks the next canister-to-canister message from `input_queues`.
    fn peek_canister_input(&mut self, input_queue: InputQueueType) -> Option<CanisterMessage> {
        let input_schedule = match input_queue {
            InputQueueType::LocalSubnet => &mut self.local_subnet_input_schedule,
            InputQueueType::RemoteSubnet => &mut self.remote_subnet_input_schedule,
        };

        while let Some(sender) = input_schedule.front() {
            // Get the message queue of this canister.
            let input_queue = &mut self.canister_queues.get_mut(sender).unwrap().0;

            while let Some(reference) = input_queue.peek() {
                // Look up the message.
                // FIXME: Generate a reject response.
                let msg = match self.pool.get(reference.id().unwrap()) {
                    Some(msg) => msg,

                    // Stale reference, pop it and try again.
                    None => {
                        input_queue.pop();
                        continue;
                    }
                };

                let ret = match msg {
                    RequestOrResponse::Request(msg) => CanisterMessage::Request(Arc::clone(msg)),
                    RequestOrResponse::Response(msg) => CanisterMessage::Response(Arc::clone(msg)),
                };
                return Some(ret);
            }

            // Queue only contained stale references and was exhausted.
            input_schedule.pop_front();
        }

        None
    }

    /// Skips the next canister-to-canister message from `input_queues`.
    fn skip_canister_input(&mut self, input_queue: InputQueueType) {
        let input_schedule = match input_queue {
            InputQueueType::LocalSubnet => &mut self.local_subnet_input_schedule,
            InputQueueType::RemoteSubnet => &mut self.remote_subnet_input_schedule,
        };
        if let Some(sender) = input_schedule.pop_front() {
            let input_queue = &mut self.canister_queues.get_mut(&sender).unwrap().0;
            if input_queue.len() != 0 {
                input_schedule.push_back(sender);
            }
        }
    }

    /// Returns `true` if `ingress_queue` or at least one of the `input_queues`
    /// is not empty; `false` otherwise.
    pub fn has_input(&self) -> bool {
        !self.ingress_queue.is_empty() || self.input_queues_stats.message_count > 0
    }

    /// Returns `true` if at least one output queue is not empty; false
    /// otherwise.
    pub fn has_output(&self) -> bool {
        self.output_queues_stats.message_count > 0
    }

    /// Peeks the next inter-canister or ingress message (round-robin) from
    /// `self.subnet_queues`.
    ///
    /// Note: While it is slightly unusual to pass a mutable reference to an
    /// apparently read-only operation such as `peek()`, we need to be able to prune
    /// stale queue entries whenever we see them or else risk turning this into an
    /// `O(N)` time operation. We could instead fall back on internal mutability,
    /// but the additional complexity is unnecessary given the current uses.
    pub(crate) fn peek_input(&mut self) -> Option<CanisterMessage> {
        // Try all 3 inputs: Ingress, Local, and Remote subnets
        for _ in 0..3 {
            let next_input = match self.next_input_queue {
                NextInputQueue::Ingress => self.peek_ingress().map(CanisterMessage::Ingress),
                NextInputQueue::RemoteSubnet => {
                    self.peek_canister_input(InputQueueType::RemoteSubnet)
                }
                NextInputQueue::LocalSubnet => {
                    self.peek_canister_input(InputQueueType::LocalSubnet)
                }
            };

            match next_input {
                Some(msg) => return Some(msg),
                // Try another input queue.
                None => {
                    self.next_input_queue = match self.next_input_queue {
                        NextInputQueue::LocalSubnet => NextInputQueue::Ingress,
                        NextInputQueue::Ingress => NextInputQueue::RemoteSubnet,
                        NextInputQueue::RemoteSubnet => NextInputQueue::LocalSubnet,
                    }
                }
            }
        }

        None
    }

    /// Skips the next inter-canister or ingress message from `self.subnet_queues`.
    pub(crate) fn skip_input(&mut self, loop_detector: &mut CanisterQueuesLoopDetector) {
        let current_input_queue = self.next_input_queue;
        match current_input_queue {
            NextInputQueue::Ingress => {
                self.ingress_queue.skip_ingress_input();
                loop_detector.ingress_queue_skip_count += 1;
                self.next_input_queue = NextInputQueue::RemoteSubnet
            }

            NextInputQueue::RemoteSubnet => {
                self.skip_canister_input(InputQueueType::RemoteSubnet);
                loop_detector.remote_queue_skip_count += 1;
                self.next_input_queue = NextInputQueue::LocalSubnet;
            }

            NextInputQueue::LocalSubnet => {
                self.skip_canister_input(InputQueueType::LocalSubnet);
                loop_detector.local_queue_skip_count += 1;
                self.next_input_queue = NextInputQueue::Ingress;
            }
        }
    }

    /// Extracts the next ingress, priority, or normal message (round-robin).
    ///
    /// We define three buckets of queues: messages from canisters on the same
    /// subnet (local subnet), ingress, and messages from canisters on other
    /// subnets (remote subnet).
    ///
    /// Each time this function is called, we round robin between these three
    /// buckets. We also round robin between the queues in the local subnet and
    /// remote subnet buckets when we pop messages from those buckets.
    pub(crate) fn pop_input(&mut self) -> Option<CanisterMessage> {
        // Try all 3 inputs: Ingress, Local, and Remote subnets
        for _ in 0..3 {
            let cur_input_queue = self.next_input_queue;
            // Switch to the next input queue
            self.next_input_queue = match self.next_input_queue {
                NextInputQueue::LocalSubnet => NextInputQueue::Ingress,
                NextInputQueue::Ingress => NextInputQueue::RemoteSubnet,
                NextInputQueue::RemoteSubnet => NextInputQueue::LocalSubnet,
            };

            let next_input = match cur_input_queue {
                NextInputQueue::Ingress => self.pop_ingress().map(CanisterMessage::Ingress),

                NextInputQueue::RemoteSubnet => {
                    self.pop_canister_input(InputQueueType::RemoteSubnet)
                }

                NextInputQueue::LocalSubnet => self.pop_canister_input(InputQueueType::LocalSubnet),
            };

            if next_input.is_some() {
                return next_input;
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
        let (input_queue, output_queue) = self.get_or_insert_queues(&request.receiver);

        if let Err(e) = output_queue.check_has_request_slot() {
            return Err((e, request));
        }
        if let Err(e) = input_queue.try_reserve_response_slot(&request) {
            return Err((e, request));
        }
        // Make the borrow checker happy.
        let (_, output_queue) = &mut self.canister_queues.get_mut(&request.receiver).unwrap();

        let mu_stats_delta = MemoryUsageStats::request_stats_delta(QueueOp::Push, &request);
        let oq_stats_delta =
            OutputQueuesStats::stats_delta(&RequestOrResponse::Request(request.clone()));

        let id = self.pool.insert_outbound_request(request, time);
        output_queue.push_request(id);

        self.input_queues_stats.reserved_slots += 1;
        self.output_queues_stats += oq_stats_delta;
        self.memory_usage_stats += mu_stats_delta;
        debug_assert!(self.stats_ok());

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

        let (input_queue, _output_queue) = self.get_or_insert_queues(&request.receiver);
        input_queue.try_reserve_response_slot(&request)?;
        self.input_queues_stats.reserved_slots += 1;
        self.memory_usage_stats += MemoryUsageStats::request_stats_delta(QueueOp::Push, &request);
        debug_assert!(self.stats_ok());

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
    // FIXME: There is no check for reserved slots or guaranteed response memory reservations.
    pub fn push_output_response(&mut self, response: Arc<Response>) {
        let mu_stats_delta = MemoryUsageStats::response_stats_delta(QueueOp::Push, &response);
        let oq_stats_delta =
            OutputQueuesStats::stats_delta(&RequestOrResponse::Response(response.clone()));

        // Since we reserve an output queue slot whenever we induct a request; and
        // we would never garbage collect a non-empty queue (including one with just a
        // reserved slot); we are guaranteed that the output queue exists.
        let output_queue = &mut self
            .canister_queues
            .get_mut(&response.originator)
            .expect("pushing response into inexistent output queue")
            .1;
        let id = self.pool.insert_outbound_response(response);
        output_queue.push_response(id);

        self.memory_usage_stats += mu_stats_delta;
        self.output_queues_stats += oq_stats_delta;
        debug_assert!(self.stats_ok());
    }

    /// Returns a reference to the first non-stale message in the respective output
    /// queue, if any.
    ///
    /// Note: While it is slightly unusual to pass a mutable reference to an
    /// apparently read-only operation such as `peek()`, we need to be able to prune
    /// stale queue entries whenever we see them or else risk turning this into an
    /// `O(N)` time operation. We could instead fall back on internal mutability,
    /// but the additional complexity is unnecessary given the current uses.
    pub(super) fn peek_output(&mut self, canister_id: &CanisterId) -> Option<&RequestOrResponse> {
        // Get the message queue of this canister.
        let output_queue = &mut self.canister_queues.get_mut(canister_id)?.1;

        while let Some(reference) = output_queue.peek() {
            // Look up the message.
            // FIXME: Generate a reject response.
            match self.pool.get(reference.id().unwrap()) {
                msg @ Some(_) => return msg,

                // Stale reference, pop it and try again.
                None => {
                    output_queue.pop();
                    continue;
                }
            };
        }

        None
    }

    /// Tries to induct a message from the output queue to `own_canister_id`
    /// into the input queue from `own_canister_id`. Returns `Err(())` if there
    /// was no message to induct or the input queue was full.
    pub(super) fn induct_message_to_self(&mut self, own_canister_id: CanisterId) -> Result<(), ()> {
        let msg = self.peek_output(&own_canister_id).ok_or(())?.clone();

        let oq_stats_delta = OutputQueuesStats::stats_delta(&msg);
        let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);

        self.push_input(msg, InputQueueType::LocalSubnet)
            .map_err(|_| ())?;

        let reference = self
            .canister_queues
            .get_mut(&own_canister_id)
            .expect("Output queue existed above so should not fail.")
            .1
            .pop()
            .expect("Message peeked above so pop should not fail.");
        // FIXME: Generate a reject response.
        self.pool
            .take(reference.id().unwrap())
            .expect("Message peeked above so take should not fail.");

        self.output_queues_stats -= oq_stats_delta;
        self.memory_usage_stats -= mu_stats_delta;
        debug_assert!(self.stats_ok());

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

    /// Returns the number of canister messages enqueued in input queues.
    pub fn input_queues_message_count(&self) -> usize {
        self.input_queues_stats.message_count
    }

    /// Returns the number of reserved slots across all input queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn input_queues_reserved_slots(&self) -> usize {
        self.input_queues_stats.reserved_slots as usize
    }

    /// Returns the number of actual messages in output queues.
    pub fn output_queues_message_count(&self) -> usize {
        self.output_queues_stats.message_count
    }
    /// Returns the total byte size of canister input queues (queues +
    /// messages).
    pub fn input_queues_size_bytes(&self) -> usize {
        self.input_queues_stats.size_bytes
    }

    pub fn input_queues_response_count(&self) -> usize {
        self.input_queues_stats.response_count
    }

    /// Returns the memory usage of all best-effort messages.
    pub fn best_effort_memory_usage(&self) -> usize {
        self.pool.memory_usage_stats().best_effort_message_bytes
    }

    /// Returns the memory usage of all guaranteed response messages.
    pub fn memory_usage(&self) -> usize {
        self.memory_usage_stats.memory_usage() + self.pool.memory_usage_stats().memory_usage()
    }

    /// Returns the total byte size of guaranteed responses across input and
    /// output queues.
    pub fn guaranteed_responses_size_bytes(&self) -> usize {
        self.pool
            .memory_usage_stats()
            .guaranteed_responses_size_bytes
    }

    /// Returns the total memory reservations for guaranteed responses across input
    /// and output queues.
    ///
    /// Note that this is different from slots reserved for responses (whether
    /// best effort or guaranteed) which are used to implement backpressure.
    pub fn guaranteed_response_memory_reservations(&self) -> usize {
        self.memory_usage_stats
            .guaranteed_response_memory_reservations as usize
    }

    /// Returns the sum total of bytes above `MAX_RESPONSE_COUNT_BYTES` per
    /// oversized guaranteed response call request.
    pub fn oversized_guaranteed_requests_extra_bytes(&self) -> usize {
        self.pool
            .memory_usage_stats()
            .oversized_guaranteed_requests_extra_bytes
    }

    /// Sets the (transient) size in bytes of responses routed from
    /// `output_queues` into streams and not yet garbage collected.
    pub(super) fn set_stream_responses_size_bytes(&mut self, size_bytes: usize) {
        self.memory_usage_stats
            .transient_stream_responses_size_bytes = size_bytes;
    }

    /// Returns the byte size of responses already routed to streams as set by
    /// the last call to `set_stream_responses_size_bytes()`.
    pub fn stream_responses_size_bytes(&self) -> usize {
        self.memory_usage_stats
            .transient_stream_responses_size_bytes
    }

    /// Returns an existing matching pair of input and output queues from/to
    /// the given canister; or creates a pair of empty queues, if non-existent.
    fn get_or_insert_queues(
        &mut self,
        canister_id: &CanisterId,
    ) -> (&mut CanisterQueue, &mut CanisterQueue) {
        let (input_queue, output_queue) =
            self.canister_queues.entry(*canister_id).or_insert_with(|| {
                let input_queue = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
                let output_queue = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
                self.input_queues_stats.size_bytes += CanisterQueue::empty_size_bytes();
                (input_queue, output_queue)
            });
        (input_queue, output_queue)
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
            // The schedules and stats will already have default (zero) values, only
            // `next_input_queue` and `pool` must be reset explicitly.
            self.next_input_queue = Default::default();
            assert!(self.pool.len() == 0);
            self.pool = MessagePool::default();

            // Trust but verify. Ensure everything is actually set to default.
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

        // Adjust stats for any queue pairs we are going to GC.
        let mut have_empty_pair = false;
        for (_canister_id, (input_queue, output_queue)) in self.canister_queues.iter() {
            if !input_queue.has_used_slots() && !output_queue.has_used_slots() {
                self.input_queues_stats.size_bytes -= CanisterQueue::empty_size_bytes();
                have_empty_pair = true;
            }
        }
        // Bail out early if there is nothing to GC.
        if !have_empty_pair {
            return;
        }

        // Actually drop empty queue pairs.
        self.canister_queues
            .retain(|_canister_id, (input_queue, output_queue)| {
                // FIXME: Try doing both dropping and stats adjusting here.
                input_queue.has_used_slots() || output_queue.has_used_slots()
            });
        debug_assert!(self.stats_ok());
    }

    /// Helper function to concisely validate stats adjustments in debug builds,
    /// by writing `debug_assert!(self.stats_ok())`.
    fn stats_ok(&self) -> bool {
        debug_assert_eq!(
            Self::calculate_input_queues_stats(&self.canister_queues, &self.pool),
            self.input_queues_stats
        );
        debug_assert_eq!(
            Self::calculate_output_queues_stats(&self.canister_queues, &self.pool),
            self.output_queues_stats
        );
        debug_assert_eq!(
            Self::calculate_memory_usage_stats(&self.canister_queues),
            self.memory_usage_stats
        );
        true
    }

    /// Helper function to concisely validate `CanisterQueues` schedules in debug builds,
    /// by writing 'debug_assert!(self.schedules_ok(own_canister_id, local_canisters)'.
    ///
    /// Checks that all canister IDs of input queues that contain at least one message
    /// are found exactly once in either the input schedule for the local subnet or the
    /// input schedule for remote subnets.
    fn schedules_ok(
        &self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> bool {
        let mut local_canister_ids = HashSet::new();
        let mut remote_canister_ids = HashSet::new();
        for (canister_id, (input_queue, _)) in self.canister_queues.iter() {
            if input_queue.len() == 0 {
                continue;
            }
            if canister_id == own_canister_id || local_canisters.contains_key(canister_id) {
                local_canister_ids.insert(canister_id);
            } else {
                remote_canister_ids.insert(canister_id);
            }
        }

        for (canister_ids, schedule) in [
            (local_canister_ids, &self.local_subnet_input_schedule),
            (remote_canister_ids, &self.remote_subnet_input_schedule),
        ] {
            // Ensure that there are no duplicate entries in `schedule`.
            assert_eq!(canister_ids.len(), schedule.len());
            assert_eq!(canister_ids, schedule.iter().collect::<HashSet<_>>());
        }

        true
    }

    /// Computes input queues stats from scratch. Used when deserializing and
    /// in `debug_assert!()` checks.
    ///
    /// Time complexity: `O(num_messages)`.
    fn calculate_input_queues_stats(
        canister_queues: &BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
        pool: &MessagePool,
    ) -> InputQueuesStats {
        let mut stats = InputQueuesStats::default();
        for (q, _) in canister_queues.values() {
            // stats.message_count += q.len();
            // stats.response_count += q.calculate_stat_sum2(response_count);
            stats.message_count += q.calculate_message_count(pool);
            stats.response_count += q.calculate_response_count(pool);
            stats.reserved_slots += q.reserved_slots() as isize;
            // FIXME
            stats.size_bytes += q.calculate_size_bytes(pool);
        }
        stats
    }

    /// Computes output queues stats from scratch. Used when deserializing and
    /// in `debug_assert!()` checks.
    ///
    /// Time complexity: `O(num_messages)`.
    fn calculate_output_queues_stats(
        canister_queues: &BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
        pool: &MessagePool,
    ) -> OutputQueuesStats {
        let mut stats = OutputQueuesStats::default();
        for (_, q) in canister_queues.values() {
            // stats.message_count += q.len();
            stats.message_count += q.calculate_message_count(pool);
        }
        stats
    }

    /// Computes memory usage stats from scratch. Used when deserializing and in
    /// `debug_assert!()` checks.
    ///
    /// Time complexity: `O(num_messages)`.
    fn calculate_memory_usage_stats(
        canister_queues: &BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
    ) -> MemoryUsageStats {
        let mut stats = MemoryUsageStats::default();
        for (iq, oq) in canister_queues.values() {
            // FIXME
            stats.guaranteed_response_memory_reservations +=
                iq.response_memory_reservations() as i64;
            stats.guaranteed_response_memory_reservations +=
                oq.response_memory_reservations() as i64;
        }
        stats
    }

    /// Queries whether the deadline of any message in the pool has expired.
    ///
    /// Time complexity: `O(1)`.
    pub fn has_expired_deadlines(&self, current_time: Time) -> bool {
        self.pool.has_expired_deadlines(current_time)
    }

    // /// Times out requests in `OutputQueues` given a current time, enqueuing a reject response
    // /// for each into the matching `InputQueue`.
    // ///
    // /// Updating the correct input queues schedule after enqueuing a reject response into a
    // /// previously empty queue also requires the full set of local canisters to decide whether
    // /// the destination canister was local or remote.
    // ///
    // /// Returns the number of requests that were timed out.
    // pub fn time_out_requests(
    //     &mut self,
    //     current_time: Time,
    //     own_canister_id: &CanisterId,
    //     local_canisters: &BTreeMap<CanisterId, CanisterState>,
    // ) -> u64 {
    //     let mut timed_out_requests_count = 0;
    //     for (canister_id, (input_queue, output_queue)) in self.canister_queues.iter_mut() {
    //         for request in output_queue.time_out_requests(current_time) {
    //             let response = generate_timeout_response(&request);

    //             // Request was dropped, update stats.
    //             let request = RequestOrResponse::Request(request);
    //             self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &request);
    //             self.output_queues_stats -= OutputQueuesStats::stats_delta(&request);

    //             // Push response, update stats.
    //             let iq_stats_delta = InputQueuesStats::stats_delta(QueueOp::Push, &response);
    //             let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Push, &response);
    //             input_queue.push(response).unwrap();
    //             self.input_queues_stats += iq_stats_delta;
    //             self.memory_usage_stats += mu_stats_delta;

    //             // If this was a previously empty input queue, add it to input queue schedule.
    //             if input_queue.len() == 1 {
    //                 if canister_id == own_canister_id || local_canisters.contains_key(canister_id) {
    //                     self.local_subnet_input_schedule.push_back(*canister_id);
    //                 } else {
    //                     self.remote_subnet_input_schedule.push_back(*canister_id);
    //                 }
    //             }

    //             timed_out_requests_count += 1;
    //         }
    //     }

    //     debug_assert!(self.stats_ok());
    //     debug_assert!(self.schedules_ok(own_canister_id, local_canisters));

    //     timed_out_requests_count
    // }

    /// Drops expired messages given a current time, enqueuing a reject response for
    /// own requests into the matching reverse queue (input or output).
    ///
    /// Updating the correct input queues schedule after enqueuing a reject response into a
    /// previously empty queue also requires the full set of local canisters to decide whether
    /// the destination canister was local or remote.
    ///
    /// Returns the number of requests that were timed out.
    pub fn time_out_messages(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> usize {
        let expired_messages = self.pool.expire_messages(current_time);
        for (id, msg) in expired_messages.iter() {
            self.drop_message_impl(id, msg, own_canister_id, local_canisters);
        }

        debug_assert!(self.stats_ok());
        debug_assert!(self.schedules_ok(own_canister_id, local_canisters));

        expired_messages.len()
    }

    /// Removes the largest best-effort message in the underlying pool. Returns
    /// `true` if a message was removed; `false` otherwise.
    pub fn shed_largest_message(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> bool {
        if let Some((id, msg)) = self.pool.shed_largest_message() {
            self.drop_message_impl(&id, &msg, own_canister_id, local_canisters);

            debug_assert!(self.stats_ok());
            debug_assert!(self.schedules_ok(own_canister_id, local_canisters));

            return true;
        }

        false
    }

    fn drop_message_impl(
        &mut self,
        id: &MessageId,
        msg: &RequestOrResponse,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) {
        self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, msg);
        if id.is_outbound() {
            // Sanity check: ensure that we were the sender.
            debug_assert_eq!(own_canister_id, &msg.sender());

            self.output_queues_stats -= OutputQueuesStats::stats_delta(msg);
        } else {
            // Sanity check: ensure that we were the receiver.
            debug_assert_eq!(own_canister_id, &msg.receiver());

            self.input_queues_stats -= InputQueuesStats::stats_delta(QueueOp::Pop, msg);
        }
        let request = match msg {
            // Own request: produce a `SYS_TRANSIENT` timeout response.
            RequestOrResponse::Request(request) if &request.sender == own_canister_id => request,

            // Expired incoming best-effort request: all done.
            RequestOrResponse::Request(_) => return,

            // Expired outgoing best-effort response: all done.
            RequestOrResponse::Response(_) => return,
        };
        let response = generate_timeout_response(request);
        let destination = &request.receiver;
        let (input_queue, output_queue) = self.canister_queues.get_mut(destination).unwrap();

        // Update memory usage stats.
        // And, depending on where the message was, the input or output queue stats.
        if id.is_outbound() {
            let msg = RequestOrResponse::Response(response);

            // Push response, update stats.
            self.memory_usage_stats += MemoryUsageStats::stats_delta(QueueOp::Push, &msg);
            self.input_queues_stats += InputQueuesStats::stats_delta(QueueOp::Push, &msg);

            let id = self.pool.insert_inbound(msg);
            input_queue.push_response(id);

            // If this was a previously empty input queue, add it to input queue schedule.
            if input_queue.len() == 1 {
                if destination == own_canister_id || local_canisters.contains_key(destination) {
                    self.local_subnet_input_schedule.push_back(*destination)
                } else {
                    self.remote_subnet_input_schedule.push_back(*destination)
                }
            }
        } else {
            self.memory_usage_stats +=
                MemoryUsageStats::response_stats_delta(QueueOp::Push, &response);
            self.output_queues_stats +=
                OutputQueuesStats::stats_delta(&RequestOrResponse::Response(response.clone()));

            let id = self.pool.insert_outbound_response(response);
            output_queue.push_response(id);
        }
    }

    /// Re-partitions `self.local_subnet_input_schedule` and
    /// `self.remote_subnet_input_schedule` based on the set of all local canisters
    /// plus `own_canister_id` (since Rust's ownership rules would prevent us from
    /// mutating `self` if it was still under `local_canisters`).
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
        let local_schedule = std::mem::take(&mut self.local_subnet_input_schedule);
        let remote_schedule = std::mem::take(&mut self.remote_subnet_input_schedule);

        for canister_id in local_schedule.into_iter().chain(remote_schedule) {
            if &canister_id == own_canister_id || local_canisters.contains_key(&canister_id) {
                self.local_subnet_input_schedule.push_back(canister_id);
            } else {
                self.remote_subnet_input_schedule.push_back(canister_id);
            }
        }

        debug_assert!(self.schedules_ok(own_canister_id, local_canisters))
    }
}

/// Generates a timeout reject response from a request, refunding its payment.
fn generate_timeout_response(request: &Arc<Request>) -> Arc<Response> {
    Arc::new(Response {
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
    })
}

#[allow(dead_code)]
fn get_message(
    reference: MessageReference,
    pool: &MessagePool,
    callbacks: &BTreeMap<CallbackId, Callback>,
) -> Option<RequestOrResponse> {
    use MessageReference::*;

    match reference {
        Request(id) => pool.get_request(id).cloned(),
        Response(id) => pool.get_response(id).cloned(),
        LocalRejectResponse(callback) => Some(generate_reject_response(
            callback,
            callbacks,
            RejectCode::SysTransient,
            "Timed out".into(),
        )),
    }
}

/// Generates a reject `Response` for a `Request` message with the provided
/// `RejectCode` and error message.
fn generate_reject_response(
    callback_id: CallbackId,
    callbacks: &BTreeMap<CallbackId, Callback>,
    reject_code: RejectCode,
    message: String,
) -> RequestOrResponse {
    let callback = callbacks.get(&callback_id).unwrap();

    Response {
        originator: callback.originator,
        respondent: callback.respondent,
        originator_reply_callback: callback_id,
        refund: Cycles::zero(),
        response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
            reject_code,
            message,
            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
        )),
        deadline: callback.deadline,
    }
    .into()
}

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        Self {
            ingress_queue: (&item.ingress_queue).into(),
            input_queues: Default::default(),
            output_queues: Default::default(),
            // input_queues: item
            //     .canister_queues
            //     .iter()
            //     .map(|(canid, (input_queue, _))| pb_queues::QueueEntry {
            //         canister_id: Some(pb_types::CanisterId::from(*canid)),
            //         queue: Some(input_queue.into()),
            //     })
            //     .collect(),
            // output_queues: item
            //     .canister_queues
            //     .iter()
            //     .map(|(canid, (_, output_queue))| pb_queues::QueueEntry {
            //         canister_id: Some(pb_types::CanisterId::from(*canid)),
            //         queue: Some(output_queue.into()),
            //     })
            //     .collect(),
            // TODO: input_schedule is deprecated and should be removed next release
            input_schedule: [].into(),
            next_input_queue: match item.next_input_queue {
                // Encode `LocalSubnet` as `Unspecified` because it is decoded as such (and it
                // serializes to zero bytes).
                NextInputQueue::LocalSubnet => ProtoNextInputQueue::Unspecified,
                NextInputQueue::Ingress => ProtoNextInputQueue::Ingress,
                NextInputQueue::RemoteSubnet => ProtoNextInputQueue::RemoteSubnet,
            } as i32,
            local_subnet_input_schedule: item
                .local_subnet_input_schedule
                .iter()
                .map(|canid| pb_types::CanisterId::from(*canid))
                .collect(),
            remote_subnet_input_schedule: item
                .remote_subnet_input_schedule
                .iter()
                .map(|canid| pb_types::CanisterId::from(*canid))
                .collect(),
        }
    }
}

impl TryFrom<pb_queues::CanisterQueues> for CanisterQueues {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_queues::CanisterQueues) -> Result<Self, Self::Error> {
        if item.input_queues.len() != item.output_queues.len() {
            return Err(ProxyDecodeError::Other(format!(
                "CanisterQueues: Mismatched input ({}) and output ({}) queue lengths",
                item.input_queues.len(),
                item.output_queues.len()
            )));
        }
        let mut canister_queues = BTreeMap::new();
        for (ie, oe) in item
            .input_queues
            .into_iter()
            .zip(item.output_queues.into_iter())
        {
            if ie.canister_id != oe.canister_id {
                return Err(ProxyDecodeError::Other(format!(
                    "Mismatched input {:?} and output {:?} queue entries",
                    ie.canister_id, oe.canister_id
                )));
            }

            let can_id = try_from_option_field(ie.canister_id, "CanisterQueues::input_queues::K")?;
            // let iq = try_from_option_field(ie.queue, "CanisterQueues::input_queues::V")?;
            // let oq = try_from_option_field(oe.queue, "CanisterQueues::output_queues::V")?;
            let iq = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
            let oq = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
            canister_queues.insert(can_id, (iq, oq));
        }
        let pool = Default::default();
        let input_queues_stats = Self::calculate_input_queues_stats(&canister_queues, &pool);
        let memory_usage_stats = Self::calculate_memory_usage_stats(&canister_queues);
        let output_queues_stats = Self::calculate_output_queues_stats(&canister_queues, &pool);

        let next_input_queue =
            match ProtoNextInputQueue::try_from(item.next_input_queue).unwrap_or_default() {
                ProtoNextInputQueue::Unspecified | ProtoNextInputQueue::LocalSubnet => {
                    NextInputQueue::LocalSubnet
                }
                ProtoNextInputQueue::Ingress => NextInputQueue::Ingress,
                ProtoNextInputQueue::RemoteSubnet => NextInputQueue::RemoteSubnet,
            };

        let mut local_subnet_input_schedule = VecDeque::new();
        // Upgrade: input_schedule is mapped to local_subnet_input_schedule
        for can_id in item.input_schedule.into_iter() {
            let c = CanisterId::try_from(can_id)?;
            local_subnet_input_schedule.push_back(c);
        }
        for can_id in item.local_subnet_input_schedule.into_iter() {
            let c = CanisterId::try_from(can_id)?;
            local_subnet_input_schedule.push_back(c);
        }
        let mut remote_subnet_input_schedule = VecDeque::new();
        for can_id in item.remote_subnet_input_schedule.into_iter() {
            let c = CanisterId::try_from(can_id)?;
            remote_subnet_input_schedule.push_back(c);
        }

        Ok(Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            canister_queues,
            pool,
            input_queues_stats,
            output_queues_stats,
            memory_usage_stats,
            next_input_queue,
            local_subnet_input_schedule,
            remote_subnet_input_schedule,
        })
    }
}

/// Running message count and byte size stats across input queues.
///
/// Separate from [`MemoryUsageStats`] because the resulting `stats_delta()`
/// method would become quite cumbersome with an extra `QueueType` argument and
/// a `QueueOp` that only applied to memory usage stats; and would result in
/// adding lots of zeros in lots of places.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InputQueuesStats {
    /// Count of messages in input queues.
    message_count: usize,

    /// Count of responses in input queues.
    response_count: usize,

    /// Count of slots reserved in input queue. Note that this is different from
    /// memory reservations for guaranteed responses.
    ///
    /// Signed type so that `stats_delta()` may return `-1`.
    reserved_slots: isize,

    /// Byte size of input queues (queues + messages).
    size_bytes: usize,
}

impl InputQueuesStats {
    /// Calculates the change in input queue stats caused by pushing (+) or
    /// popping (-) the given message.
    fn stats_delta(op: QueueOp, msg: &RequestOrResponse) -> InputQueuesStats {
        let response_count = match msg {
            RequestOrResponse::Response(_) => 1,
            RequestOrResponse::Request(_) => 0,
        };
        // Consume one reserved slot iff pushing a response.
        let reserved_slots = match (op, msg) {
            (QueueOp::Push, RequestOrResponse::Response(_)) => -1,
            _ => 0,
        };

        InputQueuesStats {
            message_count: 1,
            response_count,
            reserved_slots,
            size_bytes: msg.count_bytes(),
        }
    }
}

impl AddAssign<InputQueuesStats> for InputQueuesStats {
    fn add_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count += rhs.message_count;
        self.response_count += rhs.response_count;
        self.reserved_slots += rhs.reserved_slots;
        self.size_bytes += rhs.size_bytes;
    }
}

impl SubAssign<InputQueuesStats> for InputQueuesStats {
    fn sub_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count -= rhs.message_count;
        self.response_count -= rhs.response_count;
        self.reserved_slots -= rhs.reserved_slots;
        self.size_bytes -= rhs.size_bytes;
    }
}

/// Running stats across output queues.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputQueuesStats {
    /// Number of actual messages in output queues.
    message_count: usize,
}

impl OutputQueuesStats {
    /// Calculates the change in output queue stats caused by pushing (+) or
    /// popping (-) the given message.
    fn stats_delta(_msg: &RequestOrResponse) -> OutputQueuesStats {
        OutputQueuesStats { message_count: 1 }
    }
}

impl AddAssign<OutputQueuesStats> for OutputQueuesStats {
    fn add_assign(&mut self, rhs: OutputQueuesStats) {
        self.message_count += rhs.message_count;
    }
}

impl SubAssign<OutputQueuesStats> for OutputQueuesStats {
    fn sub_assign(&mut self, rhs: OutputQueuesStats) {
        self.message_count -= rhs.message_count;
    }
}

/// Tracks memory reservations for guaranteed responses across input and output
/// queues; and holds a (transient) byte size of responses already routed into
/// streams (tracked separately, at the replicated state level, as the canister
/// may be migrated to a different subnet with outstanding responses still left
/// in this subnet's streams).
///
/// The byte sizes of the enqueued messages themselves are tracked separately in
/// `message_pool::MemoryUsageStats`.
#[derive(Clone, Debug, Default, Eq)]
struct MemoryUsageStats {
    /// Sum total of guaranteed response memory reservations across input and output
    /// queues. This is equivalent to the number of outstanding (inbound or outbound)
    /// guaranteed response calls and is used for computing message memory
    /// allocation (as `MAX_RESPONSE_COUNT_BYTES` per request).
    ///
    /// Note that this is different from slots reserved for responses (whether
    /// best effort or guaranteed), which are used to implement backpressure.
    ///
    /// `i64` because we need to be able to add negative amounts (e.g. pushing a
    /// guaranteed response consumes a memory reservation) and it's less verbose
    /// this way.
    guaranteed_response_memory_reservations: i64,

    /// Transient: size in bytes of responses routed from `output_queues` into
    /// streams and not yet garbage collected.
    ///
    /// This is populated by `ReplicatedState::put_streams()`, called by MR
    /// after every streams mutation (induction, routing, GC).
    transient_stream_responses_size_bytes: usize,
}

impl MemoryUsageStats {
    /// Returns the memory usage of reservations for guaranteed responses plus
    /// guaranteed responses in streans.
    pub fn memory_usage(&self) -> usize {
        self.guaranteed_response_memory_reservations as usize * MAX_RESPONSE_COUNT_BYTES
            + self.transient_stream_responses_size_bytes
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given message.
    fn stats_delta(op: QueueOp, msg: &RequestOrResponse) -> MemoryUsageStats {
        match msg {
            RequestOrResponse::Request(request) => Self::request_stats_delta(op, &request),
            RequestOrResponse::Response(response) => Self::response_stats_delta(op, &response),
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) a
    /// request.
    fn request_stats_delta(op: QueueOp, request: &Request) -> MemoryUsageStats {
        MemoryUsageStats {
            // If pushing a guaranteed request, reserve memory for a response.
            guaranteed_response_memory_reservations: match op {
                QueueOp::Push => (request.deadline == NO_DEADLINE) as i64,
                QueueOp::Pop => 0,
            },
            transient_stream_responses_size_bytes: 0,
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) a
    /// response.
    fn response_stats_delta(op: QueueOp, response: &Response) -> MemoryUsageStats {
        MemoryUsageStats {
            // If pushing a guaranteed response, consume a memory reservation.
            guaranteed_response_memory_reservations: match op {
                QueueOp::Push => -((response.deadline == NO_DEADLINE) as i64),
                QueueOp::Pop => 0,
            },
            transient_stream_responses_size_bytes: 0,
        }
    }
}

impl AddAssign<MemoryUsageStats> for MemoryUsageStats {
    fn add_assign(&mut self, rhs: MemoryUsageStats) {
        self.guaranteed_response_memory_reservations += rhs.guaranteed_response_memory_reservations;
        debug_assert!(self.guaranteed_response_memory_reservations >= 0);
    }
}

impl SubAssign<MemoryUsageStats> for MemoryUsageStats {
    fn sub_assign(&mut self, rhs: MemoryUsageStats) {
        self.guaranteed_response_memory_reservations -= rhs.guaranteed_response_memory_reservations;
        debug_assert!(self.guaranteed_response_memory_reservations >= 0);
    }
}

// Custom `PartialEq`, ignoring `transient_stream_responses_size_bytes`.
impl PartialEq for MemoryUsageStats {
    fn eq(&self, rhs: &Self) -> bool {
        self.guaranteed_response_memory_reservations == rhs.guaranteed_response_memory_reservations
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
///   `msg.count_bytes() > available_memory`.
pub fn can_push(msg: &RequestOrResponse, available_memory: i64) -> Result<(), usize> {
    match msg {
        RequestOrResponse::Request(req) => {
            let required = memory_required_to_push_request(req);
            if required as i64 <= available_memory {
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

enum QueueOp {
    Push,
    Pop,
}

pub mod testing {
    use super::{CanisterQueues, MemoryUsageStats, QueueOp};
    use crate::canister_state::queues::OutputQueuesStats;
    use crate::{InputQueueType, StateError};
    use ic_types::{
        messages::{CanisterMessage, Request, RequestOrResponse},
        CanisterId, Time,
    };
    use std::{collections::VecDeque, sync::Arc};

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

        /// Publicly exposes the local subnet input_schedule.
        fn get_local_subnet_input_schedule(&self) -> &VecDeque<CanisterId>;

        /// Publicly exposes the remote subnet input_schedule.
        fn get_remote_subnet_input_schedule(&self) -> &VecDeque<CanisterId>;

        /// Returns an iterator over the raw contents of the output queue to
        /// `canister_id`; or `None` if no such output queue exists.
        fn output_queue_iter_for_testing(
            &self,
            canister_id: CanisterId,
        ) -> Option<impl Iterator<Item = Option<RequestOrResponse>>>;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse> {
            // Advance to the first non-stale message if any.
            self.peek_output(dst_canister)?;

            let reference = self
                .canister_queues
                .get_mut(dst_canister)
                .unwrap()
                .1
                .pop()
                .unwrap();
            // FIXME: Generate a reject response.
            let msg = self.pool.take(reference.id().unwrap()).unwrap();

            self.output_queues_stats -= OutputQueuesStats::stats_delta(&msg);
            self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);

            Some(msg)
        }

        fn output_queues_len(&self) -> usize {
            self.canister_queues.len()
        }

        fn output_message_count(&self) -> usize {
            self.canister_queues
                .values()
                .map(|(_, output_queue)| output_queue.len())
                .sum()
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

        fn get_local_subnet_input_schedule(&self) -> &VecDeque<CanisterId> {
            &self.local_subnet_input_schedule
        }

        fn get_remote_subnet_input_schedule(&self) -> &VecDeque<CanisterId> {
            &self.remote_subnet_input_schedule
        }

        fn output_queue_iter_for_testing(
            &self,
            canister_id: CanisterId,
        ) -> Option<impl Iterator<Item = Option<RequestOrResponse>>> {
            self.canister_queues
                .get(&canister_id)
                .map(|(_, output_queue)| output_queue.iter_for_testing(&self.pool))
        }
    }

    #[allow(dead_code)]
    /// Produces `CanisterQueues` together with a `VecDeque` of raw requests
    /// where the raw requests appear in the same order in the `VecDeque` as
    /// one would expect them being returned by the iterator.
    pub fn new_canister_queues_for_test(
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
