#![allow(unused)]

use ic_types::messages::{CallbackId, RequestOrResponse, NO_DEADLINE};
use ic_types::methods::Callback;
use ic_types::time::CoarseTime;
use ic_types::{CanisterId, CountBytes, NumBytes, Time};
use phantom_newtype::Id;
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};

pub struct MessageIdTag;
/// A value used as an opaque nonce to couple outgoing calls with their
/// callbacks.
pub type MessageId = Id<MessageIdTag, u64>;

/// A pool of best-effort messages, with built-in support for time-based
/// expiration and load shedding.
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

impl MessagePool {
    /// Inserts the given message into the pool and enters it into both priority
    /// queues.
    ///
    /// Returns the unique ID assigned to the message.
    pub fn insert(&mut self, message: RequestOrResponse) -> MessageId {
        let id = self.new_message_id();
        self.insert_impl(id, message, true)
            .expect("Existing message with newly generated ID");
        id
    }

    /// Inserts the given inbound response into the pool, entering it in the load
    /// shedding queue only (because we don't want to time out responses already
    /// enqueued in input queues).
    ///
    /// Returns an error wrapping the provided message in case of a conflict.
    pub fn insert_inbound_response(
        &mut self,
        id: MessageId,
        message: RequestOrResponse,
    ) -> Result<(), RequestOrResponse> {
        assert!(id < self.next_message_id);

        self.insert_impl(id, message, false)
    }

    /// Inserts the given message into the pool.
    ///
    /// Returns an error wrapping the provided message if a message with the same ID
    /// already exists in the pool.
    ///
    /// The message is recorded in the load shedding priority queue; it is recorded
    /// into the deadline queue iff `should_expire` is `true`.
    fn insert_impl(
        &mut self,
        id: MessageId,
        message: RequestOrResponse,
        should_expire: bool,
    ) -> Result<(), RequestOrResponse> {
        let deadline = message.deadline();
        assert!(deadline != NO_DEADLINE);
        let size_bytes = message.count_bytes();

        // Insert.
        if let Some(previous) = self.messages.insert(id, message) {
            // Already had a message with this ID. Replace it and fail.
            return Err(self.messages.insert(id, previous).unwrap());
        }

        // Update pool byte size.
        self.size_bytes += size_bytes;
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);

        // Record in priority queues.
        if (should_expire) {
            self.deadline_queue.push((Reverse(deadline), id));
        }
        self.size_queue.push((size_bytes, id));

        Ok(())
    }

    /// Reserves and returns a new message ID.
    pub fn new_message_id(&mut self) -> MessageId {
        let id = self.next_message_id;
        self.next_message_id = (self.next_message_id.get() + 1).into();
        id
    }

    pub fn get_request(&self, id: MessageId) -> Option<&RequestOrResponse> {
        match self.messages.get(&id) {
            request @ Some(RequestOrResponse::Request(_)) => request,
            Some(RequestOrResponse::Response(_)) | None => None,
        }
    }

    pub fn get_response(&self, id: MessageId) -> Option<&RequestOrResponse> {
        match self.messages.get(&id) {
            response @ Some(RequestOrResponse::Response(_)) => response,
            Some(RequestOrResponse::Request(_)) | None => None,
        }
    }

    pub fn take_request(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let entry = match self.messages.entry(id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };

        let request = match entry.get() {
            request @ RequestOrResponse::Request(_) => entry.remove(),
            RequestOrResponse::Response(_) => return None,
        };

        self.size_bytes -= request.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);
        self.maybe_trim_queues();

        Some(request)
    }

    pub fn take_response(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let entry = match self.messages.entry(id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };

        let response = match entry.get() {
            request @ RequestOrResponse::Request(_) => return None,
            response @ RequestOrResponse::Response(_) => entry.remove(),
        };

        self.size_bytes -= response.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);
        self.maybe_trim_queues();

        Some(response)
    }

    /// Removes the message with given ID from the pool.
    ///
    /// Updates the stats; and prunes the priority queues if necessary.
    pub fn take(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let message = self.take_impl(id)?;
        self.maybe_trim_queues();

        Some(message)
    }

    /// Removes the message with given ID from the pool.
    ///
    /// Updates the stats but does not prune the priority queues.
    fn take_impl(&mut self, id: MessageId) -> Option<RequestOrResponse> {
        let message = self.messages.remove(&id)?;

        self.size_bytes -= message.count_bytes();
        debug_assert_eq!(self.calculate_size_bytes(), self.size_bytes);

        Some(message)
    }

    /// Drop all messages with expired deadlines (i.e. `deadline < now`).
    pub fn expire_messages(&mut self, now: Time) -> Vec<RequestOrResponse> {
        if self.deadline_queue.is_empty() {
            return Vec::new();
        }

        let now = CoarseTime::ceil(now);
        let mut expired = Vec::new();
        while let Some((deadline, id)) = self.deadline_queue.peek() {
            if (deadline.0 >= now) {
                break;
            }

            // Drop the message, if still present.
            self.take_impl(*id).map(|message| expired.push(message));

            // Pop the deadline queue entry.
            self.deadline_queue.pop();
        }

        self.maybe_trim_queues();

        expired
    }

    /// Drops the largest message in the pool and returns it.
    pub fn shed_message(&mut self) -> Option<RequestOrResponse> {
        // Keep trying until we actually drop a message.
        while let Some((byte_size, id)) = self.size_queue.pop() {
            if let Some(message) = self.take_impl(id) {
                // A message was shed, prune the queues and return it.
                self.maybe_trim_queues();
                return Some(message);
            }
        }

        // Nothing was shed.
        None
    }

    /// Returns the number of messages in the pool.
    pub fn len(&self) -> usize {
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

/// Helper for generating different hashes for requests and responses.
#[derive(Hash)]
enum MessageType {
    Request,
    Response,
}
