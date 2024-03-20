#![allow(unused)]

use ic_types::messages::{Request, RequestOrResponse, Response, NO_DEADLINE};
use ic_types::time::CoarseTime;
use ic_types::{CountBytes, Time};
use phantom_newtype::Id;
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use crate::canister_state::queues::REQUEST_LIFETIME;

pub struct MessageIdTag;
/// A generated identifier for messages held in a `MessagePool`.
pub type MessageId = Id<MessageIdTag, u64>;

/// A pool of best-effort messages, with built-in support for time-based expiration
/// and load shedding.
#[derive(Clone, Debug)]
pub struct MessagePool {
    /// Pool contents.
    messages: HashMap<MessageId, RequestOrResponse>,

    /// Total size of all messages in the pool, in bytes.
    size_bytes: usize,

    /// Deadline priority queue, earliest deadlines first.
    ///
    /// Message IDs break ties, although this is not necessary to ensure
    /// determinism: applying the same operations (insert, remove, trim) in the same
    /// order already does that.
    deadline_queue: BinaryHeap<(Reverse<CoarseTime>, MessageId)>,

    /// Load shedding priority queue: largest message first.
    ///
    /// Message IDs break ties, although this is not necessary to ensure
    /// determinism: applying the same operations (insert, remove, trim) in the same
    /// order already does that.
    size_queue: BinaryHeap<(usize, MessageId)>,

    /// The ID to be assigned to the next message. Bumped every time a new message
    /// ID is assigned.
    next_message_id: MessageId,
}

/// A reference into a `MessagePool` that differentiates between request and
/// response.
pub(super) enum MessagePoolReference {
    /// Reference to a `Request` held in the message pool.
    Request(MessageId),

    /// Reference to a `Response` held in the message pool.
    Response(MessageId),
}

impl MessagePool {
    pub(crate) fn insert_inbound(&mut self, id: MessageId, msg: RequestOrResponse) {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);

        let deadline = match &msg {
            RequestOrResponse::Request(request) => request.deadline,

            // Never expire responses already enqueued in an input queue.
            RequestOrResponse::Response(_) => NO_DEADLINE,
        };

        self.insert_impl(id, msg, deadline)
            .expect("Conflicting message with newly generated ID");
    }

    pub(crate) fn insert_outbound_request(
        &mut self,
        id: MessageId,
        request: Arc<Request>,
        now: Time,
    ) {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);

        let deadline = if request.deadline == NO_DEADLINE {
            // Guaranteed response call requests expire after `REQUEST_LIFETIME`.
            CoarseTime::ceil(now + REQUEST_LIFETIME)
        } else {
            // Best-effort requests expire as per their specidied deadline.
            request.deadline
        };

        self.insert_impl(id, RequestOrResponse::Request(request), deadline)
            .expect("Conflicting message with newly generated ID");
    }

    pub(crate) fn insert_outbound_response(&mut self, id: MessageId, response: Arc<Response>) {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);

        let deadline = response.deadline;
        self.insert_impl(id, RequestOrResponse::Response(response), deadline)
            .expect("Conflicting message with newly generated ID");
    }

    /// Inserts the given message into the pool with the provided `deadline` (rather
    /// than the message's actual deadline; this is so we can expire the outgoing
    /// requests of guaranteed response calls; and not expire incoming best-effort
    /// responses).
    ///
    /// Returns an error wrapping the provided message if a message with the same ID
    /// already exists in the pool.
    ///
    /// The message is recorded into the deadline queue with the provided `deadline`
    /// iff that is non-zero; it is recorded in the load shedding priority queue iff
    /// the message is a best-effort message.
    fn insert_impl(
        &mut self,
        id: MessageId,
        msg: RequestOrResponse,
        deadline: CoarseTime,
    ) -> Result<(), RequestOrResponse> {
        let size_bytes = msg.count_bytes();
        let is_best_effort = msg.is_best_effort();

        // Insert.
        if let Some(previous) = self.messages.insert(id, msg) {
            // Already had a message with this ID. Replace it and fail.
            return Err(self.messages.insert(id, previous).unwrap());
        }

        // Update pool byte size.
        self.size_bytes += size_bytes;
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);

        // Record in deadline queue iff a deadline was provided.
        if deadline != NO_DEADLINE {
            self.deadline_queue.push((Reverse(deadline), id));
        }

        // Record in load shedding queue iff it's a best-effort message.
        if is_best_effort {
            self.size_queue.push((size_bytes, id));
        }

        Ok(())
    }

    /// Reserves and returns a new message ID.
    pub(crate) fn next_message_id(&mut self) -> MessageId {
        let id = self.next_message_id;
        self.next_message_id = (self.next_message_id.get() + 1).into();
        id
    }

    pub(crate) fn get<'a, R>(&self, reference: &'a R) -> Option<&RequestOrResponse>
    where
        &'a R: TryInto<MessagePoolReference>,
    {
        use MessagePoolReference::*;

        match reference.try_into().ok()? {
            Request(id) => self.get_request(id),
            Response(id) => self.get_response(id),
        }
    }

    pub(crate) fn get_request(&self, id: MessageId) -> Option<&RequestOrResponse> {
        match self.messages.get(&id) {
            request @ Some(RequestOrResponse::Request(_)) => request,
            Some(RequestOrResponse::Response(_)) | None => None,
        }
    }

    pub(crate) fn get_response(&self, id: MessageId) -> Option<&RequestOrResponse> {
        match self.messages.get(&id) {
            response @ Some(RequestOrResponse::Response(_)) => response,
            Some(RequestOrResponse::Request(_)) | None => None,
        }
    }

    fn take_request(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let entry = match self.messages.entry(id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };

        let request = match entry.get() {
            RequestOrResponse::Request(_) => entry.remove(),
            RequestOrResponse::Response(_) => return None,
        };

        self.size_bytes -= request.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);
        self.maybe_trim_queues();

        Some(request)
    }

    fn take_response(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let entry = match self.messages.entry(id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };

        let response = match entry.get() {
            RequestOrResponse::Request(_) => return None,
            RequestOrResponse::Response(_) => entry.remove(),
        };

        self.size_bytes -= response.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);
        self.maybe_trim_queues();

        Some(response)
    }

    /// Removes the message with given reference from the pool.
    ///
    /// Updates the stats; and prunes the priority queues if necessary.
    pub(crate) fn take<'a, R>(&mut self, reference: &'a R) -> Option<RequestOrResponse>
    where
        &'a R: TryInto<MessagePoolReference>,
    {
        use MessagePoolReference::*;

        match reference.try_into().ok()? {
            Request(id) => self.take_request(id),
            Response(id) => self.take_response(id),
        }
    }

    /// Removes the message with given ID from the pool.
    ///
    /// Updates the stats but does not prune the priority queues.
    fn take_impl(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let msg = self.messages.remove(&id)?;

        self.size_bytes -= msg.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);

        Some(msg)
    }

    /// Queries whether the deadline of any message in the pool has expired.
    ///
    /// Time complexity: `O(1)``.
    pub(crate) fn has_expired_deadlines(&self, now: Time) -> bool {
        if let Some((deadline, _)) = self.deadline_queue.peek() {
            let now = CoarseTime::floor(now);
            if deadline.0 < now {
                return true;
            }
        }
        false
    }

    /// Drop all messages with expired deadlines (i.e. `deadline < now`).
    pub(crate) fn expire_messages(&mut self, now: Time) -> Vec<(MessageId, RequestOrResponse)> {
        if self.deadline_queue.is_empty() {
            return Vec::new();
        }

        let now = CoarseTime::floor(now);
        let mut expired = Vec::new();
        while let Some((deadline, id)) = self.deadline_queue.peek() {
            if deadline.0 >= now {
                break;
            }
            let id = id.clone();

            // Pop the deadline queue entry.
            self.deadline_queue.pop();

            // Drop the message, if present.
            self.take_impl(id).map(|msg| expired.push((id, msg)));
        }

        self.maybe_trim_queues();

        expired
    }

    /// Drops the largest message in the pool and returns it.
    pub(crate) fn shed_message(&mut self) -> Option<(MessageId, RequestOrResponse)> {
        // Keep trying until we actually drop a message.
        while let Some((_, id)) = self.size_queue.pop() {
            if let Some(msg) = self.take_impl(id) {
                // A message was shed, prune the queues and return it.
                self.maybe_trim_queues();
                return Some((id, msg));
            }
        }

        // Nothing to shed.
        None
    }

    /// Returns the number of messages in the pool.
    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// Prunes stale entries from the priority queues if they make up more than half
    /// of the entries. This ensures amortized constant time.
    fn maybe_trim_queues(&mut self) {
        let len = self.messages.len();

        if self.deadline_queue.len() > 2 * len + 2 {
            self.deadline_queue
                .retain(|&(_, id)| self.messages.contains_key(&id));
        }
        if self.size_queue.len() > 2 * len + 2 {
            self.size_queue
                .retain(|&(_, id)| self.messages.contains_key(&id));
        }
    }

    /// Computes `size_bytes` from scratch. Used when deserializing and in
    /// `debug_assert!()` checks.
    ///
    /// Time complexity: `O(num_messages)`.
    fn calculate_size_bytes(&self) -> usize {
        self.messages
            .values()
            .map(|message| message.count_bytes())
            .sum()
    }
}

impl PartialEq for MessagePool {
    fn eq(&self, other: &Self) -> bool {
        self.messages == other.messages
    }
}
impl Eq for MessagePool {}

impl Default for MessagePool {
    fn default() -> Self {
        Self {
            messages: Default::default(),
            size_bytes: Default::default(),
            deadline_queue: Default::default(),
            size_queue: Default::default(),
            next_message_id: 0.into(),
        }
    }
}
