mod queue;
#[cfg(test)]
mod tests;

use crate::StateError;
use ic_interfaces::messages::CanisterInputMessage;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    xnet::{QueueId, SessionId},
    CanisterId, CountBytes, QueueIndex,
};
use queue::{IngressQueue, InputQueue, OutputQueue};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::{From, TryFrom},
    ops::{AddAssign, SubAssign},
    sync::Arc,
};

pub const DEFAULT_QUEUE_CAPACITY: usize = 500;

/// "None" queue index used internally by Message Routing for reject responses
/// generated e.g. when a request cannot be inducted due to a full input queue
/// (and enqueuing the response into the output queue might also fail).
pub const QUEUE_INDEX_NONE: QueueIndex = QueueIndex::new(std::u64::MAX);

/// Wrapper around the induction pool (ingress and input queues); a priority
/// queue used for round-robin scheduling of senders when consuming input
/// messages; and output queues.
///
/// Responsible for queue lifetime management, fair scheduling of inputs across
/// sender canisters and queue backpressure.
///
/// Encapsulates the `InductionPool` component described in the spec. The reason
/// for bundling together the induction pool and output queues is to reliably
/// implement backpressure via queue reservations for response messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CanisterQueues {
    /// Queue of ingress (user) messages.
    ingress_queue: IngressQueue,

    /// Per-sender input (canister-to-canister message) queues.
    input_queues: BTreeMap<CanisterId, InputQueue>,

    /// FIFO queue of sender canister IDs ensuring round-robin consumption of
    /// input messages. Only senders with non-empty queues are scheduled.
    input_schedule: VecDeque<CanisterId>,

    /// Per-receiver output (canister-to-canister message) queues.
    output_queues: BTreeMap<CanisterId, OutputQueue>,

    /// Running `input_queues` stats.
    input_queues_stats: InputQueuesStats,

    /// Running memory usage stats, across input and output queues.
    memory_usage_stats: MemoryUsageStats,
}

impl CanisterQueues {
    /// Inducts messages from the output queue to `self` into the input queue
    /// from `self` until the output queue is consumed or pushing the message
    /// into the input queue fails (presumably because the queue is full).
    pub(crate) fn induct_messages_to_self(&mut self, own_canister_id: CanisterId) {
        loop {
            let msg = {
                let output_queue = match self.output_queues.get(&own_canister_id) {
                    None => return,
                    Some(queue) => queue,
                };
                match output_queue.peek() {
                    Some((_, msg)) => msg,
                    None => return,
                }
            };

            match self.push_input(QUEUE_INDEX_NONE, (*msg).clone()) {
                Err(_) => return,
                Ok(()) => {
                    let msg = self
                        .output_queues
                        .get_mut(&own_canister_id)
                        .expect("Output queue existed above so should not fail.")
                        .pop()
                        .expect("Message peeked above so pop should not fail.")
                        .1;
                    self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                }
            }
        }
    }

    /// Pushes an ingress message into the induction pool.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.ingress_queue.push(msg)
    }

    /// Pops the next ingress message from `ingress_queue`.
    fn pop_ingress(&mut self) -> Option<Ingress> {
        self.ingress_queue.pop()
    }

    /// For each output queue, invokes `f` on every message until `f` returns
    /// `Err`; then moves on to the next output queue.
    ///
    /// All messages that `f` returned `Ok` for, are popped. Messages that `f`
    /// returned `Err` for and all those following them in the respective output
    /// queue are retained.
    pub(crate) fn output_queues_for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, Arc<RequestOrResponse>) -> Result<(), ()>,
    {
        for (canister_id, queue) in self.output_queues.iter_mut() {
            while let Some((_, msg)) = queue.peek() {
                match f(canister_id, msg) {
                    Err(_) => break,
                    Ok(_) => {
                        let msg = queue
                            .pop()
                            .expect("peek() returned a message, pop() should not fail")
                            .1;
                        self.memory_usage_stats -=
                            MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                    }
                }
            }
        }
        debug_assert!(self.stats_ok());
    }

    /// See `IngressQueue::filter_messages()` for documentation.
    pub fn filter_ingress_messages<F>(&mut self, filter: F)
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.ingress_queue.filter_messages(filter);
    }

    /// Pushes a canister-to-canister message into the induction pool.
    ///
    /// If the message is a `Request` this will also reserve a slot in the
    /// corresponding output queue for the eventual response.
    ///
    /// If the message is a `Response` the protocol will have already reserved
    /// space for it, so the push cannot fail due to the input queue being
    /// full.
    ///
    /// # Errors
    ///
    /// If pushing fails, returns the provided message along with a
    /// `StateError`:
    ///
    ///  * `QueueFull` if pushing a `Request` and the corresponding input or
    ///    output queues are full.
    ///
    ///  * `QueueFull` if pushing a `Response` and the receiving canister is not
    ///  expecting one.
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let sender = msg.sender();
        let input_queue = match msg {
            RequestOrResponse::Request(_) => {
                let (input_queue, output_queue) = self.get_or_insert_queues(&sender);
                if let Err(e) = input_queue.check_has_slot() {
                    return Err((e, msg));
                }
                // Safe to already (attempt to) reserve an output slot here, as the `push()`
                // below is guaranteed to succeed due to the check above.
                if let Err(e) = output_queue.reserve_slot() {
                    return Err((e, msg));
                }
                input_queue
            }
            RequestOrResponse::Response(_) => match self.input_queues.get_mut(&sender) {
                Some(queue) => queue,
                None => return Err((StateError::QueueFull { capacity: 0 }, msg)),
            },
        };
        let iq_stats_delta = InputQueuesStats::stats_delta(&msg);
        let mu_stats_delta = MemoryUsageStats::stats_delta(QueueOp::Push, &msg);

        input_queue.push(index, msg)?;

        // Add sender canister ID to the input schedule queue if it isn't already there.
        // Sender was not scheduled iff its input queue was empty before the push (i.e.
        // queue size is 1 after the push).
        if input_queue.num_messages() == 1 {
            self.input_schedule.push_back(sender);
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
    fn pop_canister_input(&mut self) -> Option<RequestOrResponse> {
        if let Some(sender) = self.input_schedule.pop_front() {
            // Get the message queue of this canister.
            let input_queue = self.input_queues.get_mut(&sender).unwrap();
            let msg = input_queue.pop().unwrap();
            // If the queue still isn't empty, re-add sender canister ID to the end of the
            // input schedule queue.
            if input_queue.num_messages() != 0 {
                self.input_schedule.push_back(sender);
            }

            self.input_queues_stats -= InputQueuesStats::stats_delta(&msg);
            self.memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
            debug_assert!(self.stats_ok());

            return Some(msg);
        }

        None
    }

    /// Returns `true` if `ingress_queue` or at least one of the `input_queues`
    /// is not empty; `false` otherwise.
    pub fn has_input(&self) -> bool {
        !self.ingress_queue.is_empty()
            || self
                .input_queues
                .iter()
                .any(|(_, queue)| queue.num_messages() > 0)
    }

    /// Returns `true` if at least one output queue is not empty; false
    /// otherwise.
    pub fn has_output(&self) -> bool {
        self.output_queues
            .iter()
            .any(|(_, queue)| queue.num_messages() > 0)
    }

    /// Extracts the next inter-canister or ingress message (in that order).
    /// If no inter-canister messages are available in the induction pool, we
    /// pop the next ingress message.
    pub fn pop_input(&mut self) -> Option<CanisterInputMessage> {
        // Return the next inter-canister message if one exists.
        if let Some(msg) = self.pop_canister_input() {
            return Some(match msg {
                RequestOrResponse::Request(msg) => CanisterInputMessage::Request(msg),
                RequestOrResponse::Response(msg) => CanisterInputMessage::Response(msg),
            });
        }
        self.pop_ingress().map(CanisterInputMessage::Ingress)
    }

    /// Pushes a `Request` type message into the relevant output queue. Also
    /// reserves a slot for the eventual response on the matching input queue.
    ///
    /// # Errors
    ///
    /// Returns a `QueueFull` error along with the provided message if either
    /// the output queue or the matching input queue is full.
    pub fn push_output_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        let (input_queue, output_queue) = self.get_or_insert_queues(&msg.receiver);

        if let Err(e) = output_queue.check_has_slot() {
            return Err((e, msg));
        }
        if let Err(e) = input_queue.reserve_slot() {
            return Err((e, msg));
        }

        output_queue
            .push_request(msg)
            .expect("cannot fail due to checks above");

        self.memory_usage_stats.reserved_slots += 1;
        debug_assert!(self.stats_ok());

        Ok(())
    }

    /// Pushes a `Response` type message into the relevant output queue. The
    /// protocol should have already reserved a slot, so this cannot fail.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_output_response(&mut self, msg: Response) {
        let mu_stats_delta = MemoryUsageStats::response_stats_delta(QueueOp::Push, &msg);

        // As long as we are not garbage collecting output queues, we are guaranteed
        // that an output queue should exist for pushing responses because one would
        // have been created when the request (that triggered this response) was
        // inducted into the induction pool.
        self.output_queues
            .get_mut(&msg.originator)
            .expect("pushing response into inexistent output queue")
            .push_response(msg);

        self.memory_usage_stats += mu_stats_delta;
        debug_assert!(self.stats_ok());
    }

    /// Returns an iterator that consumes all output messages.
    pub fn output_into_iter(
        &mut self,
        owner: CanisterId,
    ) -> impl std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)> + '_ {
        let memory_usage_stats = &mut self.memory_usage_stats;
        self.output_queues
            .iter_mut()
            // Flat map output queues to their contents (prepended with a `QueueId`).
            .flat_map(move |(receiver, queue)| {
                let queue_id = QueueId {
                    dst_canister: *receiver,
                    src_canister: owner,
                    session_id: SessionId::from(0),
                };
                // Zip repeated `queue_id` with message iterator (the output queue).
                std::iter::repeat(queue_id).zip(queue)
            })
            // Remap to a flat tuple.
            .map(move |(queue_id, (queue_index, msg))| {
                assert_eq!(queue_id.src_canister, msg.sender());
                *memory_usage_stats -= MemoryUsageStats::stats_delta(QueueOp::Pop, &msg);
                // Unfortunately the borrow checker will not allow us to use a `debug_assert!()`
                // here to validate that the stats are still accurate.
                (queue_id, queue_index, msg)
            })
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

    /// Returns the total byte size of canister input queues (queues +
    /// messages).
    pub fn input_queues_size_bytes(&self) -> usize {
        self.input_queues_stats.size_bytes
    }

    /// Returns the total byte size of canister responses across input and
    /// output queues.
    pub fn responses_size_bytes(&self) -> usize {
        self.memory_usage_stats.responses_size_bytes
    }

    /// Returns the total reserved slots across input and output queues.
    pub fn reserved_slots(&self) -> usize {
        self.memory_usage_stats.reserved_slots as usize
    }

    /// Returns an existing a matching pair of input and output queues from/to
    /// the given canister; or creates a pair of empty queues, if non-existent.
    fn get_or_insert_queues(
        &mut self,
        canister_id: &CanisterId,
    ) -> (&mut InputQueue, &mut OutputQueue) {
        let mut queue_bytes = 0;
        let input_queue = self.input_queues.entry(*canister_id).or_insert_with(|| {
            let iq = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
            queue_bytes = iq.calculate_size_bytes();
            iq
        });
        self.input_queues_stats.size_bytes += queue_bytes;
        let output_queue = self
            .output_queues
            .entry(*canister_id)
            .or_insert_with(|| OutputQueue::new(DEFAULT_QUEUE_CAPACITY));
        (input_queue, output_queue)
    }

    /// Helper function to concisely validate stats adjustments in debug builds,
    /// by writing `debug_assert!(self.stats_ok())`.
    fn stats_ok(&self) -> bool {
        debug_assert_eq!(
            Self::calculate_input_queues_stats(&self.input_queues),
            self.input_queues_stats
        );
        debug_assert_eq!(
            Self::calculate_memory_usage_stats(&self.input_queues, &self.output_queues),
            self.memory_usage_stats
        );
        true
    }

    /// Computes `input_queues` stats from scratch. Used when deserializing and
    /// in `debug_assert!()` checks.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_input_queues_stats(
        input_queues: &BTreeMap<CanisterId, InputQueue>,
    ) -> InputQueuesStats {
        let mut stats = InputQueuesStats::default();
        for q in input_queues.values() {
            stats.message_count += q.num_messages();
            stats.size_bytes += q.calculate_size_bytes();
        }
        stats
    }

    /// Computes memory usage stats from scratch. Used when deserializing and in
    /// `debug_assert!()` checks.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_memory_usage_stats(
        input_queues: &BTreeMap<CanisterId, InputQueue>,
        output_queues: &BTreeMap<CanisterId, OutputQueue>,
    ) -> MemoryUsageStats {
        let mut stats = MemoryUsageStats::default();
        for q in input_queues.values() {
            // Actual byte size for responses, 0 for requests.
            stats.responses_size_bytes += q.calculate_stat_sum(|msg| match *msg {
                RequestOrResponse::Request(_) => 0,
                RequestOrResponse::Response(_) => msg.count_bytes(),
            });
            stats.reserved_slots += q.reserved_slots() as i64;
        }
        for q in output_queues.values() {
            // Actual byte size for responses, 0 for requests.
            stats.responses_size_bytes += q.calculate_stat_sum(|msg| match *msg {
                RequestOrResponse::Request(_) => 0,
                RequestOrResponse::Response(_) => msg.count_bytes(),
            });
            stats.reserved_slots += q.reserved_slots() as i64;
        }
        stats
    }
}

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        Self {
            ingress_queue: (&item.ingress_queue).into(),
            input_queues: item
                .input_queues
                .iter()
                .map(|(canid, input_queue)| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(input_queue.into()),
                })
                .collect(),
            input_schedule: item
                .input_schedule
                .iter()
                .map(|canid| pb_types::CanisterId::from(*canid))
                .collect(),
            output_queues: item
                .output_queues
                .iter()
                .map(|(canid, output_queue)| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(output_queue.into()),
                })
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
        if let Some((ie, oe)) = item
            .input_queues
            .iter()
            .zip(item.output_queues.iter())
            .find(|(ie, oe)| ie.canister_id != oe.canister_id)
        {
            return Err(ProxyDecodeError::Other(format!(
                "Mismatched input {:?} and output {:?} queue entries",
                ie.canister_id, oe.canister_id
            )));
        }

        let mut input_queues = BTreeMap::<CanisterId, InputQueue>::new();
        for entry in item.input_queues {
            let can_id =
                try_from_option_field(entry.canister_id, "CanisterQueues::input_queues::K")?;
            let iq: InputQueue =
                try_from_option_field(entry.queue, "CanisterQueues::input_queues::V")?;
            input_queues.insert(can_id, iq);
        }
        let input_queues_stats = Self::calculate_input_queues_stats(&input_queues);

        let mut output_queues = BTreeMap::<CanisterId, OutputQueue>::new();
        for entry in item.output_queues {
            let can_id =
                try_from_option_field(entry.canister_id, "CanisterQueues::output_queues::K")?;

            let oq = try_from_option_field(entry.queue, "CanisterQueues::output_queues::V")?;
            output_queues.insert(can_id, oq);
        }
        let memory_usage_stats = Self::calculate_memory_usage_stats(&input_queues, &output_queues);

        let mut input_schedule = VecDeque::new();
        for can_id in item.input_schedule.into_iter() {
            let c = CanisterId::try_from(can_id)?;
            input_schedule.push_back(c);
        }

        Ok(Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            input_schedule,
            input_queues,
            output_queues,
            input_queues_stats,
            memory_usage_stats,
        })
    }
}

/// Running message count and byte size stats across input queues.
///
/// Separate from [`MemoryUsageStats`] because the resulting `stats_delta()`
/// method would become quite cumbersome with an extra `QueueType` argument and
/// a `QueueOp` that only applied to memory usage stats; and would result in
/// adding lots of zeros in lots of places.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct InputQueuesStats {
    /// Count of messages in input queues.
    message_count: usize,

    /// Byte size of input queues (queues + messages).
    size_bytes: usize,
}

impl InputQueuesStats {
    /// Calculates the change in input queue stats caused by pushing (+) or
    /// popping (-) the given message.
    fn stats_delta(msg: &RequestOrResponse) -> InputQueuesStats {
        InputQueuesStats {
            message_count: 1,
            size_bytes: msg.count_bytes(),
        }
    }
}

impl AddAssign<InputQueuesStats> for InputQueuesStats {
    fn add_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count += rhs.message_count;
        self.size_bytes += rhs.size_bytes;
    }
}

impl SubAssign<InputQueuesStats> for InputQueuesStats {
    fn sub_assign(&mut self, rhs: InputQueuesStats) {
        self.message_count -= rhs.message_count;
        self.size_bytes -= rhs.size_bytes;
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct MemoryUsageStats {
    /// Sum total of the byte size of every response across input and output
    /// queues.
    responses_size_bytes: usize,

    /// Sum total of reserved slots across input and output queues. This is
    /// equivalent to the number of outstanding (input and output) requests
    /// (across queues and streams) and is used for computing message memory
    /// allocation (as `MAX_RESPONSE_COUNT_BYTES` per request).
    ///
    /// `i64` because we need to be able to add negative amounts and it's less
    /// verbose this way.
    reserved_slots: i64,
}

impl MemoryUsageStats {
    /// Calculates the change in stats caused by pushing (+) or popping (-) the
    /// given message.
    fn stats_delta(op: QueueOp, msg: &RequestOrResponse) -> MemoryUsageStats {
        match msg {
            RequestOrResponse::Request(_) => Self::request_stats_delta(op),
            RequestOrResponse::Response(rep) => Self::response_stats_delta(op, rep),
        }
    }

    /// Calculates the change in stats caused by pushing (+) or popping (-) a
    /// request.
    fn request_stats_delta(op: QueueOp) -> MemoryUsageStats {
        MemoryUsageStats {
            // No change in responses byte size (as this is a request).
            responses_size_bytes: 0,
            // If we're pushing a request, we are reserving a slot.
            reserved_slots: match op {
                QueueOp::Push => 1,
                QueueOp::Pop => 0,
            },
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
        }
    }
}

impl AddAssign<MemoryUsageStats> for MemoryUsageStats {
    fn add_assign(&mut self, rhs: MemoryUsageStats) {
        self.responses_size_bytes += rhs.responses_size_bytes;
        self.reserved_slots += rhs.reserved_slots;
        debug_assert!(self.reserved_slots >= 0);
    }
}

impl SubAssign<MemoryUsageStats> for MemoryUsageStats {
    fn sub_assign(&mut self, rhs: MemoryUsageStats) {
        self.responses_size_bytes -= rhs.responses_size_bytes;
        self.reserved_slots -= rhs.reserved_slots;
        debug_assert!(self.reserved_slots >= 0);
    }
}

enum QueueOp {
    Push,
    Pop,
}

pub mod testing {
    use super::CanisterQueues;
    use ic_types::{messages::RequestOrResponse, CanisterId, QueueIndex};

    /// Exposes public testing-only `CanisterQueues` methods to be used in other
    /// crates' unit tests.
    pub trait CanisterQueuesTesting {
        /// Returns the number of messages in `ingress_queue`.
        fn ingress_queue_size(&self) -> usize;

        /// Pops the next message from the output queue associated with
        /// `dst_canister`. Returned `QueueIndex` values are sequential across
        /// successful calls.
        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)>;

        /// Returns the number of output queues, empty or not.
        fn output_queues_len(&self) -> usize;

        /// Returns the total number of messages in the output queues.
        fn output_message_count(&self) -> usize;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)> {
            match self.output_queues.get_mut(dst_canister) {
                None => None,
                Some(canister_out_queue) => canister_out_queue.pop(),
            }
        }

        fn output_queues_len(&self) -> usize {
            self.output_queues.len()
        }

        fn output_message_count(&self) -> usize {
            self.output_queues
                .iter()
                .map(|(_, q)| q.num_messages())
                .sum()
        }
    }
}
