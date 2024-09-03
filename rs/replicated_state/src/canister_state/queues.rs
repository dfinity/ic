mod message_pool;
mod queue;
#[cfg(test)]
mod tests;

use self::message_pool::{Context, MessagePool, REQUEST_LIFETIME};
use self::queue::{CanisterQueue, IngressQueue, InputQueue, OutputQueue};
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;
use crate::{CanisterState, CheckpointLoadingMetrics, InputQueueType, NextInputQueue, StateError};
use ic_base_types::PrincipalId;
use ic_error_types::RejectCode;
use ic_management_canister_types::IC_00;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::queues::v1 as pb_queues;
use ic_protobuf::state::queues::v1::canister_queues::{
    CanisterQueuePair, NextInputQueue as ProtoNextInputQueue,
};
use ic_protobuf::types::v1 as pb_types;
use ic_types::messages::{
    CanisterMessage, Ingress, Payload, RejectContext, Request, RequestOrResponse, Response,
    MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE,
};
use ic_types::{CanisterId, CountBytes, Cycles, Time};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::convert::{From, TryFrom};
use std::ops::{AddAssign, SubAssign};
use std::sync::Arc;

pub const DEFAULT_QUEUE_CAPACITY: usize = 500;

/// Encapsulates information about `CanisterQueues`,
/// used in detecting a loop when consuming the input messages.
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
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
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub struct CanisterQueues {
    /// Queue of ingress (user) messages.
    #[validate_eq(CompareWithValidateEq)]
    ingress_queue: IngressQueue,

    /// Per remote canister input and output queues.
    #[validate_eq(CompareWithValidateEq)]
    canister_queues: BTreeMap<CanisterId, (InputQueue, OutputQueue)>,

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
    #[validate_eq(Ignore)]
    next_input_queue: NextInputQueue,
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
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub struct NewCanisterQueues {
    /// Queue of ingress (user) messages.
    #[validate_eq(CompareWithValidateEq)]
    ingress_queue: IngressQueue,

    /// Per remote canister input and output queues.
    #[validate_eq(CompareWithValidateEq)]
    canister_queues: BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,

    /// Pool holding all messages in `canister_queues`, with support for time-based
    /// expiration and load shedding.
    #[validate_eq(Ignore)]
    pool: MessagePool,

    /// Slot and memory reservation stats. Message count and size stats are
    /// maintained separately in the `MessagePool`.
    queue_stats: QueueStats,

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

    /// Round-robin across ingress and cross-net input queues for `pop_input()`.
    #[validate_eq(Ignore)]
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
    /// Priority queue of non-empty output queues. The next message to be popped
    /// / peeked is the one at the head of the first queue.
    queues: VecDeque<(&'a CanisterId, &'a mut OutputQueue)>,

    /// Number of messages that can be popped before the iterator finishes.
    size: usize,

    /// The canister's memory usage stats, to be updated as messages are popped.
    memory_stats: &'a mut MemoryUsageStats,

    /// Canister output queue stats, to be updated as messages are popped.
    queue_stats: &'a mut OutputQueuesStats,
}

impl<'a> CanisterOutputQueuesIterator<'a> {
    fn new(
        queues: &'a mut BTreeMap<CanisterId, (InputQueue, OutputQueue)>,
        memory_stats: &'a mut MemoryUsageStats,
        queue_stats: &'a mut OutputQueuesStats,
    ) -> Self {
        let queues: VecDeque<_> = queues
            .iter_mut()
            .filter(|(_, (_, queue))| queue.num_messages() > 0)
            .map(|(canister, (_, queue))| (canister, queue))
            .collect();
        let size = Self::compute_size(&queues);

        CanisterOutputQueuesIterator {
            queues,
            size,
            memory_stats,
            queue_stats,
        }
    }

    /// Returns a reference to the message that `pop` / `next` would return.
    pub fn peek(&self) -> Option<&RequestOrResponse> {
        if let Some((_, queue)) = self.queues.front() {
            let msg = queue.peek().expect("Empty queue in iterator");
            return Some(msg);
        }
        None
    }

    /// Pops a message from the next queue. If this was not the last message in
    /// that queue, the queue is moved to the back of the iteration order.
    pub fn pop(&mut self) -> Option<RequestOrResponse> {
        if let Some((receiver, queue)) = self.queues.pop_front() {
            let msg = queue.pop().expect("Empty queue in iterator");

            if queue.num_messages() > 0 {
                self.queues.push_back((receiver, queue));
            }

            *self.memory_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
            *self.queue_stats -= OutputQueuesStats::stats_delta(&msg);
            self.size -= 1;
            debug_assert_eq!(Self::compute_size(&self.queues), self.size);

            return Some(msg);
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
            .map(|(_, q)| q.num_messages())
            .unwrap_or_default();

        self.size -= ignored;
        debug_assert_eq!(Self::compute_size(&self.queues), self.size);

        ignored
    }

    /// Checks if the iterator has finished.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Returns the number of messages left in the iterator.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Computes the number of messages left in `queues`.
    ///
    /// Time complexity: O(N).
    fn compute_size(queues: &VecDeque<(&'a CanisterId, &'a mut OutputQueue)>) -> usize {
        queues.iter().map(|(_, q)| q.num_messages()).sum()
    }
}

impl Iterator for CanisterOutputQueuesIterator<'_> {
    type Item = RequestOrResponse;

    /// Alias for `pop`.
    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }

    /// Returns the bounds on the number of messages remaining in the iterator.
    fn size_hint(&self) -> (usize, Option<usize>) {
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
            while let Some(msg) = queue.peek() {
                match f(canister_id, msg) {
                    // `f` rejected the message, move on to next queue.
                    Err(_) => break,

                    // Message consumed, pop it and update the stats.
                    Ok(_) => {
                        let msg = queue
                            .pop()
                            .expect("peek() returned a message, pop() should not fail");
                        let oq_stats_delta = OutputQueuesStats::stats_delta(&msg);
                        self.output_queues_stats -= oq_stats_delta;
                        self.memory_usage_stats -=
                            MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                    }
                }
            }
        }
        debug_assert!(self.stats_ok());
    }

    /// Returns an iterator that loops over output queues, popping one message
    /// at a time from each in a round robin fashion. The iterator consumes all
    /// popped messages.
    pub(crate) fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator {
        CanisterOutputQueuesIterator::new(
            &mut self.canister_queues,
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
                let (input_queue, output_queue) = self.get_or_insert_queues(&sender);
                if let Err(e) = input_queue.check_has_request_slot() {
                    return Err((e, msg));
                }
                // Safe to already (attempt to) reserve an output slot here, as the `push()`
                // below is guaranteed to succeed due to the check above.
                if let Err(e) = output_queue.reserve_slot() {
                    return Err((e, msg));
                }
                input_queue
            }
            RequestOrResponse::Response(ref response) => {
                match self.canister_queues.get_mut(&sender) {
                    Some((queue, _)) => queue,
                    None => {
                        return Err((
                            StateError::NonMatchingResponse {
                                err_str: "No reserved response slot".to_string(),
                                originator: response.originator,
                                callback_id: response.originator_reply_callback,
                                respondent: response.respondent,
                                deadline: response.deadline,
                            },
                            msg,
                        ))
                    }
                }
            }
        };
        let iq_stats_delta = InputQueuesStats::stats_delta(QueueOp::Push, &msg);
        let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Push, &msg);

        input_queue.push(msg)?;

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

    /// Pops the next canister input queue message.
    ///
    /// Note: We pop senders from the head of `input_schedule` and insert them
    /// to the back, which allows us to handle messages from different
    /// originators in a round-robin fashion.
    fn pop_canister_input(&mut self, input_queue: InputQueueType) -> Option<CanisterMessage> {
        let input_schedule = match input_queue {
            InputQueueType::LocalSubnet => &mut self.local_subnet_input_schedule,
            InputQueueType::RemoteSubnet => &mut self.remote_subnet_input_schedule,
        };
        if let Some(sender) = input_schedule.pop_front() {
            // The sender's input queue.
            let input_queue = &mut self.canister_queues.get_mut(&sender).unwrap().0;
            let msg = input_queue.pop().unwrap();
            // If the input queue is non-empty, re-enqueue the sender at the back of the
            // input schedule queue.
            if input_queue.len() != 0 {
                input_schedule.push_back(sender);
            }

            self.input_queues_stats -= InputQueuesStats::stats_delta(QueueOp::Pop, &msg);
            self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
            debug_assert!(self.stats_ok());

            return Some(msg.into());
        }

        None
    }

    /// Peeks the next canister input queue message.
    fn peek_canister_input(&self, input_queue: InputQueueType) -> Option<CanisterMessage> {
        let input_schedule = match input_queue {
            InputQueueType::LocalSubnet => &self.local_subnet_input_schedule,
            InputQueueType::RemoteSubnet => &self.remote_subnet_input_schedule,
        };
        if let Some(sender) = input_schedule.front() {
            // The sender's input queue.
            let input_queue = &self.canister_queues.get(sender).unwrap().0;
            let msg = input_queue.peek().unwrap();
            return Some(msg.clone().into());
        }

        None
    }

    /// Skips the next canister input queue message.
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

    /// Returns `true` if `ingress_queue` or at least one of the canister input
    /// queues is not empty; `false` otherwise.
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
        if let Err(e) = input_queue.reserve_slot() {
            return Err((e, request));
        }

        let mu_stats_delta = MemoryUsageStats::request_stats_delta(QueueOp::Push, &request);
        let oq_stats_delta =
            OutputQueuesStats::stats_delta(&RequestOrResponse::Request(request.clone()));

        output_queue
            .push_request(request, time + REQUEST_LIFETIME)
            .expect("cannot fail due to the checks above");

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
        input_queue.reserve_slot()?;
        self.input_queues_stats.reserved_slots += 1;
        self.memory_usage_stats += MemoryUsageStats::response_slot_delta();
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
    pub fn push_output_response(&mut self, response: Arc<Response>) {
        let mu_stats_delta = MemoryUsageStats::response_stats_delta(QueueOp::Push, &response);
        let oq_stats_delta =
            OutputQueuesStats::stats_delta(&RequestOrResponse::Response(response.clone()));

        // Since we reserve an output queue slot whenever we induct a request; and
        // we would never garbage collect a non-empty queue (including one with just a
        // reserved slot); we are guaranteed that the output queue exists.
        self.canister_queues
            .get_mut(&response.originator)
            .expect("pushing response into inexistent output queue")
            .1
            .push_response(response);

        self.memory_usage_stats += mu_stats_delta;
        self.output_queues_stats += oq_stats_delta;
        debug_assert!(self.stats_ok());
    }

    /// Returns a reference to the message at the head of the respective output
    /// queue, if any.
    pub(super) fn peek_output(&self, canister_id: &CanisterId) -> Option<&RequestOrResponse> {
        self.canister_queues.get(canister_id)?.1.peek()
    }

    /// Tries to induct a message from the output queue to `own_canister_id`
    /// into the input queue from `own_canister_id`. Returns `Err(())` if there
    /// was no message to induct or the input queue was full.
    pub(super) fn induct_message_to_self(&mut self, own_canister_id: CanisterId) -> Result<(), ()> {
        let msg = self.peek_output(&own_canister_id).ok_or(())?.clone();

        self.push_input(msg, InputQueueType::LocalSubnet)
            .map_err(|_| ())?;

        let msg = self
            .canister_queues
            .get_mut(&own_canister_id)
            .expect("Output queue existed above so lookup should not fail.")
            .1
            .pop()
            .expect("Message peeked above so pop should not fail.");
        let oq_stats_delta = OutputQueuesStats::stats_delta(&msg);
        self.output_queues_stats -= oq_stats_delta;
        self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
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

    /// Returns total amount of cycles included in input queues.
    pub fn input_queue_cycles(&self) -> Cycles {
        self.input_queues_stats.cycles
    }

    /// Returns the number of actual messages in output queues.
    pub fn output_queues_message_count(&self) -> usize {
        self.output_queues_stats.message_count
    }

    /// Returns total amount of cycles included in the output queues.
    pub fn output_queue_cycles(&self) -> Cycles {
        self.output_queues_stats.cycles
    }

    /// Returns the total byte size of canister input queues (queues +
    /// messages).
    pub fn input_queues_size_bytes(&self) -> usize {
        self.input_queues_stats.size_bytes
    }

    pub fn input_queues_request_count(&self) -> usize {
        self.input_queues_stats.message_count - self.input_queues_stats.response_count
    }

    pub fn input_queues_response_count(&self) -> usize {
        self.input_queues_stats.response_count
    }

    /// Returns input queues stats.
    pub fn input_queues_stats(&self) -> &InputQueuesStats {
        &self.input_queues_stats
    }

    /// Returns the number of reserved slots across all output queues.
    ///
    /// Note that this is different from memory reservations for guaranteed
    /// responses.
    pub fn output_queues_reserved_slots(&self) -> usize {
        self.memory_usage_stats.reserved_slots as usize
            - self.input_queues_stats.reserved_slots as usize
    }

    /// Returns the memory usage of all guaranteed response messages.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.memory_usage_stats.memory_usage()
    }

    /// Returns the total byte size of guaranteed responses across input and
    /// output queues.
    pub fn guaranteed_responses_size_bytes(&self) -> usize {
        self.memory_usage_stats.responses_size_bytes
    }

    /// Returns the total memory reservations for guaranteed responses across input
    /// and output queues.
    ///
    /// Note that this is different from slots reserved for responses (whether
    /// best effort or guaranteed) which are used to implement backpressure.
    pub fn guaranteed_response_memory_reservations(&self) -> usize {
        self.memory_usage_stats.reserved_slots as usize
    }

    /// Returns the sum total of bytes above `MAX_RESPONSE_COUNT_BYTES` per
    /// oversized guaranteed response call request.
    pub fn oversized_guaranteed_requests_extra_bytes(&self) -> usize {
        self.memory_usage_stats.oversized_requests_extra_bytes
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
    ) -> (&mut InputQueue, &mut OutputQueue) {
        let (input_queue, output_queue) =
            self.canister_queues.entry(*canister_id).or_insert_with(|| {
                let input_queue = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
                let output_queue = OutputQueue::new(DEFAULT_QUEUE_CAPACITY);
                self.input_queues_stats.size_bytes += input_queue.calculate_size_bytes();
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
            // `next_input_queue` must be reset explicitly.
            self.next_input_queue = Default::default();

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
                self.input_queues_stats.size_bytes -= input_queue.calculate_size_bytes();
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
                input_queue.has_used_slots() || output_queue.has_used_slots()
            });
        debug_assert!(self.stats_ok());
    }

    /// Helper function to concisely validate stats adjustments in debug builds,
    /// by writing `debug_assert!(self.stats_ok())`.
    fn stats_ok(&self) -> bool {
        debug_assert_eq!(
            Self::calculate_input_queues_stats(&self.canister_queues),
            self.input_queues_stats
        );
        debug_assert_eq!(
            Self::calculate_output_queues_stats(&self.canister_queues),
            self.output_queues_stats
        );
        debug_assert_eq!(
            Self::calculate_memory_usage_stats(&self.canister_queues),
            self.memory_usage_stats
        );
        true
    }

    /// Helper function to concisely validate `CanisterQueues`' input schedules
    /// during deserialization; or in debug builds, by writing
    /// `debug_assert_eq!(Ok(()), self.schedules_ok(own_canister_id, local_canisters)``.
    ///
    /// Checks that all canister IDs of input queues that contain at least one message
    /// are found exactly once in either the input schedule for the local subnet or the
    /// input schedule for remote subnets.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn schedules_ok(
        &self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> Result<(), String> {
        let mut local_schedule: HashSet<_> = self.local_subnet_input_schedule.iter().collect();
        let mut remote_schedule: HashSet<_> = self.remote_subnet_input_schedule.iter().collect();

        if local_schedule.len() != self.local_subnet_input_schedule.len()
            || remote_schedule.len() != self.remote_subnet_input_schedule.len()
            || local_schedule.intersection(&remote_schedule).count() != 0
        {
            return Err(format!(
                "Duplicate entries in local and/or remote input schedules:\n  `local_subnet_input_schedule`: {:?}\n  `remote_subnet_input_schedule`: {:?}",
                self.local_subnet_input_schedule, self.remote_subnet_input_schedule,
            ));
        }

        for (canister_id, (input_queue, _)) in self.canister_queues.iter() {
            if input_queue.len() == 0 {
                continue;
            }

            if canister_id == own_canister_id || local_canisters.contains_key(canister_id) {
                // Definitely a local canister.
                if !local_schedule.remove(canister_id) {
                    return Err(format!(
                        "Local canister with non-empty input queue ({:?}) absent from `local_subnet_input_schedule`",
                        canister_id
                    ));
                }
            } else {
                // Remote canister or deleted local canister. Check in both schedules.
                if !remote_schedule.remove(canister_id) && !local_schedule.remove(canister_id) {
                    return Err(format!(
                        "Canister with non-empty input queue ({:?}) absent from input schedules",
                        canister_id
                    ));
                }
            }
        }

        if !local_schedule.is_empty() || !remote_schedule.is_empty() {
            return Err(format!(
                "Canister(s) with no inputs enqueued in input schedule:\n  local: {:?}\n  remote: {:?}",
                local_schedule, remote_schedule,
            ));
        }

        Ok(())
    }

    /// Computes input queues stats from scratch. Used when deserializing and
    /// in `debug_assert!()` checks.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_input_queues_stats(
        canister_queues: &BTreeMap<CanisterId, (InputQueue, OutputQueue)>,
    ) -> InputQueuesStats {
        let mut stats = InputQueuesStats::default();
        let response_count = |msg: &RequestOrResponse| match *msg {
            RequestOrResponse::Request(_) => 0,
            RequestOrResponse::Response(_) => 1,
        };
        for (q, _) in canister_queues.values() {
            stats.message_count += q.len();
            stats.response_count += q.calculate_stat_sum(response_count);
            stats.reserved_slots += q.reserved_slots() as isize;
            stats.size_bytes += q.calculate_size_bytes();
            stats.cycles += q.cycles_in_queue();
        }
        stats
    }

    /// Computes output queues stats from scratch. Used when deserializing and
    /// in `debug_assert!()` checks.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_output_queues_stats(
        canister_queues: &BTreeMap<CanisterId, (InputQueue, OutputQueue)>,
    ) -> OutputQueuesStats {
        let mut stats = OutputQueuesStats::default();
        for (_, q) in canister_queues.values() {
            stats.message_count += q.num_messages();
            stats.cycles += q.cycles_in_queue();
        }
        stats
    }

    /// Computes memory usage stats from scratch. Used when deserializing and in
    /// `debug_assert!()` checks.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_memory_usage_stats(
        canister_queues: &BTreeMap<CanisterId, (InputQueue, OutputQueue)>,
    ) -> MemoryUsageStats {
        // Actual byte size for responses, 0 for requests.
        let response_size_bytes = |msg: &RequestOrResponse| match *msg {
            RequestOrResponse::Request(_) => 0,
            RequestOrResponse::Response(_) => msg.count_bytes(),
        };
        // `max(0, msg.count_bytes() - MAX_RESPONSE_COUNT_BYTES)` for requests, 0 for
        // responses.
        let request_overhead_bytes = |msg: &RequestOrResponse| match *msg {
            RequestOrResponse::Request(_) => {
                msg.count_bytes().saturating_sub(MAX_RESPONSE_COUNT_BYTES)
            }
            RequestOrResponse::Response(_) => 0,
        };

        let mut stats = MemoryUsageStats::default();
        for (iq, oq) in canister_queues.values() {
            stats.responses_size_bytes += iq.calculate_stat_sum(response_size_bytes);
            stats.reserved_slots += iq.reserved_slots() as i64;
            stats.oversized_requests_extra_bytes += iq.calculate_stat_sum(request_overhead_bytes);

            stats.responses_size_bytes += oq.calculate_stat_sum(response_size_bytes);
            stats.reserved_slots += oq.reserved_slots() as i64;
            stats.oversized_requests_extra_bytes += oq.calculate_stat_sum(request_overhead_bytes)
        }
        stats
    }

    /// Queries whether any of the `OutputQueues` in `self.canister_queues` have any expired
    /// deadlines in them.
    pub fn has_expired_deadlines(&self, current_time: Time) -> bool {
        self.canister_queues
            .iter()
            .any(|(_, (_, output_queue))| output_queue.has_expired_deadlines(current_time))
    }

    /// Times out requests in `OutputQueues` given a current time, enqueuing a reject response
    /// for each into the matching `InputQueue`.
    ///
    /// Updating the correct input queues schedule after enqueuing a reject response into a
    /// previously empty queue also requires the full set of local canisters to decide whether
    /// the destination canister was local or remote.
    ///
    /// Returns the number of requests that were timed out.
    pub fn time_out_requests(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> u64 {
        let mut timed_out_requests_count = 0;
        for (canister_id, (input_queue, output_queue)) in self.canister_queues.iter_mut() {
            for request in output_queue.time_out_requests(current_time) {
                let response = generate_timeout_response(&request);

                // Request was dropped, update stats.
                let request = RequestOrResponse::Request(request);
                self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &request);
                self.output_queues_stats -= OutputQueuesStats::stats_delta(&request);

                // Push response, update stats.
                let iq_stats_delta = InputQueuesStats::stats_delta(QueueOp::Push, &response);
                let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Push, &response);
                input_queue.push(response).unwrap();
                self.input_queues_stats += iq_stats_delta;
                self.memory_usage_stats += mu_stats_delta;

                // If this was a previously empty input queue, add it to input queue schedule.
                if input_queue.len() == 1 {
                    if canister_id == own_canister_id || local_canisters.contains_key(canister_id) {
                        self.local_subnet_input_schedule.push_back(*canister_id);
                    } else {
                        self.remote_subnet_input_schedule.push_back(*canister_id);
                    }
                }

                timed_out_requests_count += 1;
            }
        }

        debug_assert!(self.stats_ok());
        debug_assert_eq!(Ok(()), self.schedules_ok(own_canister_id, local_canisters));

        timed_out_requests_count
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

        debug_assert_eq!(Ok(()), self.schedules_ok(own_canister_id, local_canisters));
    }
}

/// Generates a timeout reject response from a request, refunding its payment.
fn generate_timeout_response(request: &Arc<Request>) -> RequestOrResponse {
    RequestOrResponse::Response(Arc::new(Response {
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
    }))
}

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        Self {
            ingress_queue: (&item.ingress_queue).into(),
            input_queues: item
                .canister_queues
                .iter()
                .map(|(canid, (input_queue, _))| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(input_queue.into()),
                })
                .collect(),
            output_queues: item
                .canister_queues
                .iter()
                .map(|(canid, (_, output_queue))| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(output_queue.into()),
                })
                .collect(),
            canister_queues: Default::default(),
            pool: None,
            next_input_queue: ProtoNextInputQueue::from(&item.next_input_queue).into(),
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
            guaranteed_response_memory_reservations: item.memory_usage_stats.reserved_slots as u64,
        }
    }
}

impl TryFrom<(pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics)> for CanisterQueues {
    type Error = ProxyDecodeError;
    fn try_from(
        (item, metrics): (pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
        let mut canister_queues = BTreeMap::new();
        if !item.input_queues.is_empty() || !item.output_queues.is_empty() {
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

                let canister_id =
                    try_from_option_field(ie.canister_id, "CanisterQueues::input_queues::K")?;
                let iq = try_from_option_field(ie.queue, "CanisterQueues::input_queues::V")?;
                let oq = try_from_option_field(oe.queue, "CanisterQueues::output_queues::V")?;

                if canister_queues.insert(canister_id, (iq, oq)).is_some() {
                    metrics.observe_broken_soft_invariant(format!(
                        "CanisterQueues: Duplicate queues for canister {}",
                        canister_id
                    ));
                }
            }
        } else {
            // Forward compatibility: deserialize from `canister_queues` and `pool`.
            let pool = item.pool.unwrap_or_default().try_into()?;
            for qp in item.canister_queues.into_iter() {
                let canister_id =
                    try_from_option_field(qp.canister_id, "CanisterQueuePair::canister_id")?;
                let iq = try_from_option_field(
                    qp.input_queue.map(|q| (q, Context::Inbound)),
                    "CanisterQueuePair::input_queue",
                )?;
                let oq = try_from_option_field(
                    qp.output_queue.map(|q| (q, Context::Outbound)),
                    "CanisterQueuePair::output_queue",
                )?;

                if canister_queues
                    .insert(
                        canister_id,
                        ((&iq, &pool).try_into()?, (&oq, &pool).try_into()?),
                    )
                    .is_some()
                {
                    metrics.observe_broken_soft_invariant(format!(
                        "CanisterQueues: Duplicate queues for canister {}",
                        canister_id
                    ));
                }
            }
        }

        let input_queues_stats = Self::calculate_input_queues_stats(&canister_queues);
        let memory_usage_stats = Self::calculate_memory_usage_stats(&canister_queues);
        let output_queues_stats = Self::calculate_output_queues_stats(&canister_queues);

        if memory_usage_stats.reserved_slots as u64 != item.guaranteed_response_memory_reservations
        {
            metrics.observe_broken_soft_invariant(format!(
                "CanisterQueues: Mismatched guaranteed response memory reservations: persisted ({}) != calculated ({})",
                item.guaranteed_response_memory_reservations,
                memory_usage_stats.reserved_slots
            ));
        }

        let next_input_queue = NextInputQueue::from(
            ProtoNextInputQueue::try_from(item.next_input_queue).unwrap_or_default(),
        );

        let mut local_subnet_input_schedule = VecDeque::new();
        for canister_id in item.local_subnet_input_schedule.into_iter() {
            local_subnet_input_schedule.push_back(canister_id.try_into()?);
        }
        let mut remote_subnet_input_schedule = VecDeque::new();
        for canister_id in item.remote_subnet_input_schedule.into_iter() {
            remote_subnet_input_schedule.push_back(canister_id.try_into()?);
        }

        let queues = Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            canister_queues,
            input_queues_stats,
            output_queues_stats,
            memory_usage_stats,
            next_input_queue,
            local_subnet_input_schedule,
            remote_subnet_input_schedule,
        };

        // Safe to call with invalid `own_canister_id` and empty `local_canisters`, as
        // the validation logic allows for deleted local canisters.
        queues
            .schedules_ok(
                &CanisterId::unchecked_from_principal(PrincipalId::new_anonymous()),
                &BTreeMap::new(),
            )
            .unwrap_or_else(|e| metrics.observe_broken_soft_invariant(e));

        Ok(queues)
    }
}

impl NewCanisterQueues {
    /// Helper function to concisely validate `CanisterQueues`' input schedules
    /// during deserialization; or in debug builds, by writing
    /// `debug_assert_eq!(Ok(()), self.schedules_ok(own_canister_id, local_canisters)`.
    ///
    /// Checks that all canister IDs of input queues that contain at least one message
    /// are found exactly once in either the input schedule for the local subnet or the
    /// input schedule for remote subnets.
    ///
    /// Time complexity: `O(n * log(n))`.
    fn schedules_ok(
        &self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> Result<(), String> {
        let mut local_schedule: HashSet<_> = self.local_subnet_input_schedule.iter().collect();
        let mut remote_schedule: HashSet<_> = self.remote_subnet_input_schedule.iter().collect();

        if local_schedule.len() != self.local_subnet_input_schedule.len()
            || remote_schedule.len() != self.remote_subnet_input_schedule.len()
            || local_schedule.intersection(&remote_schedule).count() != 0
        {
            return Err(format!(
                "Duplicate entries in local and/or remote input schedules:\n  `local_subnet_input_schedule`: {:?}\n  `remote_subnet_input_schedule`: {:?}",
                self.local_subnet_input_schedule, self.remote_subnet_input_schedule,
            ));
        }

        for (canister_id, (input_queue, _)) in self.canister_queues.iter() {
            if input_queue.len() == 0 {
                continue;
            }

            if canister_id == own_canister_id || local_canisters.contains_key(canister_id) {
                // Definitely a local canister.
                if !local_schedule.remove(canister_id) {
                    return Err(format!(
                        "Local canister with non-empty input queue ({:?}) absent from `local_subnet_input_schedule`",
                        canister_id
                    ));
                }
            } else {
                // Remote canister or deleted local canister. Check in both schedules.
                if !remote_schedule.remove(canister_id) && !local_schedule.remove(canister_id) {
                    return Err(format!(
                        "Canister with non-empty input queue ({:?}) absent from input schedules",
                        canister_id
                    ));
                }
            }
        }

        if !local_schedule.is_empty() || !remote_schedule.is_empty() {
            return Err(format!(
                "Canister(s) with no inputs enqueued in input schedule:\n  local: {:?}\n  remote: {:?}",
                local_schedule, remote_schedule,
            ));
        }

        Ok(())
    }

    /// Computes stats for the given canister queues. Used when deserializing and in
    /// `debug_assert!()` checks. Takes the number of memory reservations from the
    /// caller, as the queues have no need to track memory reservations, so it
    /// cannot be computed.
    ///
    /// Time complexity: `O(canister_queues.len())`.
    fn calculate_queue_stats(
        canister_queues: &BTreeMap<CanisterId, (CanisterQueue, CanisterQueue)>,
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
            transient_stream_responses_size_bytes: 0,
        }
    }
}

impl From<&NewCanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &NewCanisterQueues) -> Self {
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
            next_input_queue: ProtoNextInputQueue::from(&item.next_input_queue).into(),
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
            guaranteed_response_memory_reservations: item
                .queue_stats
                .guaranteed_response_memory_reservations
                as u64,
        }
    }
}

impl TryFrom<(pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics)> for NewCanisterQueues {
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

                    iq.iter().chain(oq.iter()).for_each(|queue_item| {
                        if pool.get(queue_item.id()).is_some()
                            && !enqueued_pool_messages.insert(queue_item.id())
                        {
                            metrics.observe_broken_soft_invariant(format!(
                                "CanisterQueues: Message {:?} enqueued more than once",
                                queue_item.id()
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
        );

        let next_input_queue = NextInputQueue::from(
            ProtoNextInputQueue::try_from(item.next_input_queue).unwrap_or_default(),
        );

        let mut local_subnet_input_schedule = VecDeque::new();
        for canister_id in item.local_subnet_input_schedule.into_iter() {
            local_subnet_input_schedule.push_back(canister_id.try_into()?);
        }
        let mut remote_subnet_input_schedule = VecDeque::new();
        for canister_id in item.remote_subnet_input_schedule.into_iter() {
            remote_subnet_input_schedule.push_back(canister_id.try_into()?);
        }

        let queues = Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            canister_queues,
            pool,
            queue_stats,
            next_input_queue,
            local_subnet_input_schedule,
            remote_subnet_input_schedule,
        };

        // Safe to call with invalid `own_canister_id` and empty `local_canisters`, as
        // the validation logic allows for deleted local canisters.
        if let Err(e) = queues.schedules_ok(
            &CanisterId::unchecked_from_principal(PrincipalId::new_anonymous()),
            &BTreeMap::new(),
        ) {
            metrics.observe_broken_soft_invariant(e.to_string());
        }

        Ok(queues)
    }
}

/// Running message count and byte size stats across input queues.
///
/// Separate from [`MemoryUsageStats`] because the resulting `stats_delta()`
/// method would become quite cumbersome with an extra `QueueType` argument and
/// a `QueueOp` that only applied to memory usage stats; and would result in
/// adding lots of zeros in lots of places.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct InputQueuesStats {
    /// Count of messages in input queues.
    message_count: usize,

    /// Count of responses in input queues.
    response_count: usize,

    /// Count of reservations in input queue. Signed type because `stats_delta()`
    /// sometimes returns `-1`.
    reserved_slots: isize,

    /// Byte size of input queues (queues + messages).
    size_bytes: usize,

    /// Total amount of cycles contained in the input messages.
    cycles: Cycles,
}

impl InputQueuesStats {
    /// Calculates the change in input queue stats caused by pushing (+) or
    /// popping (-) the given message.
    fn stats_delta(op: QueueOp, msg: &RequestOrResponse) -> InputQueuesStats {
        let response_count = match msg {
            RequestOrResponse::Response(_) => 1,
            RequestOrResponse::Request(_) => 0,
        };
        // Consume one reservation iff pushing a response.
        let reserved_slots = match (op, msg) {
            (QueueOp::Push, RequestOrResponse::Response(_)) => -1,
            _ => 0,
        };

        InputQueuesStats {
            message_count: 1,
            response_count,
            reserved_slots,
            size_bytes: msg.count_bytes(),
            cycles: msg.cycles(),
        }
    }
}

impl AddAssign<InputQueuesStats> for InputQueuesStats {
    fn add_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count += rhs.message_count;
        self.response_count += rhs.response_count;
        self.reserved_slots += rhs.reserved_slots;
        self.size_bytes += rhs.size_bytes;
        self.cycles += rhs.cycles;
    }
}

impl SubAssign<InputQueuesStats> for InputQueuesStats {
    fn sub_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count -= rhs.message_count;
        self.response_count -= rhs.response_count;
        self.reserved_slots -= rhs.reserved_slots;
        self.size_bytes -= rhs.size_bytes;
        self.cycles -= rhs.cycles;
    }
}

/// Running stats across output queues.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct OutputQueuesStats {
    /// Number of actual messages in output queues.
    message_count: usize,

    /// Total amount of cycles contained in the output queues.
    cycles: Cycles,
}

impl OutputQueuesStats {
    /// Calculates the change in output queue stats caused by pushing (+) or
    /// popping (-) the given message.
    fn stats_delta(msg: &RequestOrResponse) -> OutputQueuesStats {
        let cycles_message = match msg {
            RequestOrResponse::Response(response) => response.refund,
            RequestOrResponse::Request(request) => request.payment,
        };
        OutputQueuesStats {
            message_count: 1,
            cycles: cycles_message,
        }
    }
}

impl AddAssign<OutputQueuesStats> for OutputQueuesStats {
    fn add_assign(&mut self, rhs: OutputQueuesStats) {
        self.message_count += rhs.message_count;
        self.cycles += rhs.cycles;
    }
}

impl SubAssign<OutputQueuesStats> for OutputQueuesStats {
    fn sub_assign(&mut self, rhs: OutputQueuesStats) {
        self.message_count -= rhs.message_count;
        self.cycles -= rhs.cycles;
    }
}

/// Running memory utilization stats for input and output queues: total byte
/// size of all responses in input and output queues; and total reservations in
/// input and output queues.
///
/// Memory allocation of output responses in streams is tracked separately, at
/// the replicated state level (as the canister may be migrated to a different
/// subnet with outstanding responses still left in this subnet's streams).
///
/// Separate from [`InputQueuesStats`] because the resulting `stats_delta()`
/// method would become quite cumbersome with an extra `QueueType` argument and
/// a `QueueOp` that only applied to memory usage stats; and would result in
/// adding lots of zeros in lots of places.
#[derive(Clone, Eq, Debug, Default)]
struct MemoryUsageStats {
    /// Sum total of the byte size of every response across input and output
    /// queues.
    responses_size_bytes: usize,

    /// Sum total of reserved slots across input and output queues. This is
    /// equivalent to the number of outstanding (input and output) requests
    /// (across queues and streams) and is used for computing message memory
    /// allocation (as `MAX_RESPONSE_COUNT_BYTES` per request).
    ///
    /// `i64` because we need to be able to add negative amounts (e.g. pushing a
    /// response consumes a reservation) and it's less verbose this way.
    reserved_slots: i64,

    /// Sum total of bytes above `MAX_RESPONSE_COUNT_BYTES` per oversized
    /// request. Execution allows local-subnet requests larger than
    /// `MAX_RESPONSE_COUNT_BYTES`.
    oversized_requests_extra_bytes: usize,

    /// Transient: size in bytes of responses routed from `output_queues` into
    /// streams and not yet garbage collected.
    ///
    /// This is populated by `ReplicatedState::put_streams()`, called by MR
    /// after every streams mutation (induction, routing, GC).
    transient_stream_responses_size_bytes: usize,
}

impl MemoryUsageStats {
    /// Returns the memory usage in bytes computed from the stats.
    pub fn memory_usage(&self) -> usize {
        self.responses_size_bytes
            + self.reserved_slots as usize * MAX_RESPONSE_COUNT_BYTES
            + self.oversized_requests_extra_bytes
            + self.transient_stream_responses_size_bytes
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given message.
    fn stats_delta(op: QueueOp, msg: &RequestOrResponse) -> MemoryUsageStats {
        match msg {
            RequestOrResponse::Request(req) => Self::request_stats_delta(op, req),
            RequestOrResponse::Response(rep) => Self::response_stats_delta(op, rep),
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) a
    /// request.
    fn request_stats_delta(op: QueueOp, req: &Request) -> MemoryUsageStats {
        MemoryUsageStats {
            // No change in responses byte size (as this is a request).
            responses_size_bytes: 0,
            // If we're pushing a request, we are reserving a slot.
            reserved_slots: match op {
                QueueOp::Push => 1,
                QueueOp::Pop => 0,
            },
            oversized_requests_extra_bytes: req
                .count_bytes()
                .saturating_sub(MAX_RESPONSE_COUNT_BYTES),
            transient_stream_responses_size_bytes: 0,
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given response.
    fn response_stats_delta(op: QueueOp, rep: &Response) -> MemoryUsageStats {
        MemoryUsageStats {
            // Adjust responses byte size by this response's byte size.
            responses_size_bytes: rep.count_bytes(),
            // If we're pushing a response, we're consuming a reservation.
            reserved_slots: match op {
                QueueOp::Push => -1,
                QueueOp::Pop => 0,
            },
            // No change in requests overhead (as this is a response).
            oversized_requests_extra_bytes: 0,
            transient_stream_responses_size_bytes: 0,
        }
    }

    /// Stats change from reserving a response slot without enqueueing any
    /// messages.
    fn response_slot_delta() -> MemoryUsageStats {
        MemoryUsageStats {
            responses_size_bytes: 0,
            reserved_slots: 1,
            oversized_requests_extra_bytes: 0,
            transient_stream_responses_size_bytes: 0,
        }
    }
}

impl AddAssign<MemoryUsageStats> for MemoryUsageStats {
    fn add_assign(&mut self, rhs: MemoryUsageStats) {
        self.responses_size_bytes += rhs.responses_size_bytes;
        self.reserved_slots += rhs.reserved_slots;
        self.oversized_requests_extra_bytes += rhs.oversized_requests_extra_bytes;
        debug_assert!(self.reserved_slots >= 0);
    }
}

impl SubAssign<MemoryUsageStats> for MemoryUsageStats {
    fn sub_assign(&mut self, rhs: MemoryUsageStats) {
        self.responses_size_bytes -= rhs.responses_size_bytes;
        self.reserved_slots -= rhs.reserved_slots;
        self.oversized_requests_extra_bytes -= rhs.oversized_requests_extra_bytes;
        debug_assert!(self.reserved_slots >= 0);
    }
}

// Custom `PartialEq`, ignoring `transient_stream_responses_size_bytes`.
impl PartialEq for MemoryUsageStats {
    fn eq(&self, rhs: &Self) -> bool {
        self.responses_size_bytes == rhs.responses_size_bytes
            && self.reserved_slots == rhs.reserved_slots
            && self.oversized_requests_extra_bytes == rhs.oversized_requests_extra_bytes
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
// TODO(MR-569) Remove when `CanisterQueues` has been updated to use this.
#[allow(dead_code)]
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

    /// Transient: size in bytes of responses routed from `output_queues` into
    /// streams and not yet garbage collected.
    ///
    /// This is updated by `ReplicatedState::put_streams()`, called by MR after
    /// every streams mutation (induction, routing, GC). And is (re)populated during
    /// checkpoint loading by `ReplicatedState::new_from_checkpoint()`.
    transient_stream_responses_size_bytes: usize,
}

// TODO(MR-569) Remove when `CanisterQueues` has been updated to use this.
#[allow(dead_code)]
impl QueueStats {
    /// Returns the memory usage of reservations for guaranteed responses plus
    /// guaranteed responses in streans.
    pub fn guaranteed_response_memory_usage(&self) -> usize {
        self.guaranteed_response_memory_reservations * MAX_RESPONSE_COUNT_BYTES
            + self.transient_stream_responses_size_bytes
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
            self.input_queues_reserved_slots -= 1;
        } else {
            // And the other way around.
            debug_assert!(self.output_queues_reserved_slots > 0);
            self.output_queues_reserved_slots -= 1;
        }
    }
}

/// Checks whether `available_memory` is sufficient to allow pushing `msg` onto
/// an input or output queue.
///
/// Returns:
///  * `Ok(())` if `msg` is a `Response`, as responses always return memory.
///  * `Ok(())` if `msg` is a `Request` and `available_memory` is sufficient.
///  * `Err(required_memory)` if `msg` is a `Request` and `required_memory >
///    available_memory`.
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

/// Returns the memory required to push `req` onto an input or output queue.
/// This is the maximum of `MAX_RESPONSE_COUNT_BYTES` (to be reserved for a
/// response) and `req.count_bytes()` (if larger).
pub fn memory_required_to_push_request(req: &Request) -> usize {
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
            canister_id: &CanisterId,
        ) -> Option<impl Iterator<Item = RequestOrResponse>>;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(&mut self, dst_canister: &CanisterId) -> Option<RequestOrResponse> {
            match self.canister_queues.get_mut(dst_canister) {
                None => None,
                Some((_, canister_out_queue)) => {
                    let ret = canister_out_queue.pop();
                    if let Some(msg) = &ret {
                        self.output_queues_stats -= OutputQueuesStats::stats_delta(msg);
                        self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, msg);
                    }
                    ret
                }
            }
        }

        fn output_queues_len(&self) -> usize {
            self.canister_queues.len()
        }

        fn output_message_count(&self) -> usize {
            self.canister_queues
                .values()
                .map(|(_, output_queue)| output_queue.num_messages())
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
            canister_id: &CanisterId,
        ) -> Option<impl Iterator<Item = RequestOrResponse>> {
            self.canister_queues
                .get(canister_id)
                .map(|(_, output_queue)| output_queue.iter_for_testing())
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
