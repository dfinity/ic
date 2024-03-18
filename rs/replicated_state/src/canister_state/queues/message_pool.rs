#![allow(unused)]

use ic_error_types::RejectCode;
use ic_types::messages::{
    CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response, NO_DEADLINE,
};
use ic_types::methods::Callback;
use ic_types::time::CoarseTime;
use ic_types::{CanisterId, CountBytes, Cycles, NumBytes, Time};
use phantom_newtype::Id;
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::Arc;

use crate::canister_state::queues::REQUEST_LIFETIME;
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;

pub struct MessageIdTag;
/// A value used as an opaque nonce to couple outgoing calls with their
/// callbacks.
pub type MessageId = Id<MessageIdTag, u64>;

/// A reference to a message, used as `CanisterQueue` item.
///
/// May be a weak reference into the message pool; or identify a reject response to
/// a specific callback.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MessageReference {
    /// Weak reference to a `Request` held in the message pool.
    ///
    /// Guaranteed response call requests in output queues and best-effort requests
    /// in input or output queues may time out and be dropped from the pool. Such
    /// stale references can be safely ignored.
    ///
    /// Guaranteed response call requests in input queues never time out.
    Request(MessageId),

    /// Weak reference to a `Response` held in the message pool.
    ///
    /// Best-effort responses in output queues may time out and be dropped from the
    /// pool. Stale response references in output queues can be safely ignored.
    ///
    /// A stale response reference is enqueued into an input queue as a
    /// `SYS_UNKNOWN` reject response marker. A matching response may or may not be
    /// inserted into the pool while the reference is backlogged in the input queue.
    /// Meaning that stale response references in input queues are `SYS_UNKNOWN`
    /// reject responses.
    ///
    /// Guaranteed responses never time out.
    Response(MessageId),

    /// Local known (i.e. `SYS_TRANSIENT`) timeout reject response.
    TimeoutRejectResponse(CallbackId),

    /// Local known (i.e. `SYS_TRANSIENT`) drop reject response.
    DropRejectResponse(CallbackId),
}

impl MessageReference {
    /// Returns `true` if this is a reference to a response; or a reject response.
    pub fn is_response(&self) -> bool {
        match self {
            Self::Request(_) => false,

            Self::Response(_) | Self::TimeoutRejectResponse(_) | Self::DropRejectResponse(_) => {
                true
            }
        }
    }
}

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

impl MessagePool {
    pub fn insert_outbound_guaranteed_request(
        &mut self,
        request: Arc<Request>,
        deadline: CoarseTime,
    ) -> MessageId {
        assert_eq!(NO_DEADLINE, request.deadline);

        let id = self.next_message_id();
        self.insert_impl(id, RequestOrResponse::Request(request), deadline)
            .expect("Conflicting message with newly generated ID");

        id
    }

    pub fn insert_inbound_best_effort_response(
        &mut self,
        id: MessageId,
        response: Arc<Response>,
    ) -> MessageId {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);
        // Must be a best-effort response.
        assert_ne!(NO_DEADLINE, response.deadline);

        self.insert_impl(id, RequestOrResponse::Response(response), NO_DEADLINE)
            .expect("Conflicting message with newly generated ID");

        id
    }

    pub fn insert_inbound(&mut self, id: MessageId, msg: RequestOrResponse) {
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

    pub fn insert_outbound(&mut self, id: MessageId, msg: RequestOrResponse, now: Time) {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);

        let deadline = match &msg {
            // Requests of guaranteed response calls expire after `REQUEST_LIFETIME`.
            RequestOrResponse::Request(request) if request.deadline == NO_DEADLINE => {
                CoarseTime::ceil(now + REQUEST_LIFETIME)
            }

            // All other messages expire as per their specidied deadline.
            RequestOrResponse::Request(request) => request.deadline,
            RequestOrResponse::Response(response) => response.deadline,
        };

        self.insert_impl(id, msg, deadline)
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
    pub fn insert_impl(
        &mut self,
        id: MessageId,
        msg: RequestOrResponse,
        deadline: CoarseTime,
    ) -> Result<(), RequestOrResponse> {
        let size_bytes = msg.count_bytes();

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
            assert!(deadline != NO_DEADLINE);
            self.deadline_queue.push((Reverse(deadline), id));
        }

        // Record in load shedding queue iff it's a best-effort message.
        if msg.is_best_effort() {
            self.size_queue.push((size_bytes, id));
        }

        Ok(())
    }

    /// Inserts the given message into the pool and enters it into both priority
    /// queues.
    ///
    /// Returns the unique ID assigned to the message.
    pub fn insert(&mut self, msg: RequestOrResponse) -> MessageId {
        let id = self.next_message_id();
        self.insert_impl2(id, msg, true)
            .expect("Conflicting message with newly generated ID");
        id
    }

    /// Inserts the given inbound response into the pool, entering it in the load
    /// shedding queue only (because we don't want to time out responses already
    /// enqueued in input queues).
    ///
    /// Returns an error wrapping the provided message in case of a conflict.
    pub fn insert_inbound_response2(
        &mut self,
        id: MessageId,
        msg: RequestOrResponse,
    ) -> Result<(), RequestOrResponse> {
        // Must be an already assigned ID.
        assert!(id < self.next_message_id);
        // Must be a response.
        if let RequestOrResponse::Request(_) = msg {
            panic!("Not a response: {:?}", msg)
        }

        self.insert_impl2(id, msg, false)
    }

    /// Inserts the given message into the pool.
    ///
    /// Returns an error wrapping the provided message if a message with the same ID
    /// already exists in the pool.
    ///
    /// The message is recorded in the load shedding priority queue; it is recorded
    /// into the deadline queue iff `should_expire` is `true`.
    fn insert_impl2(
        &mut self,
        id: MessageId,
        msg: RequestOrResponse,
        should_expire: bool,
    ) -> Result<(), RequestOrResponse> {
        let deadline = msg.deadline();
        assert!(deadline != NO_DEADLINE);
        let size_bytes = msg.count_bytes();

        // Insert.
        if let Some(previous) = self.messages.insert(id, msg) {
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
    pub fn next_message_id(&mut self) -> MessageId {
        let id = self.next_message_id;
        self.next_message_id = (self.next_message_id.get() + 1).into();
        id
    }

    pub fn get(&self, reference: MessageReference) -> Option<&RequestOrResponse> {
        use MessageReference::*;

        match reference {
            Request(id) => self.get_request(id),
            Response(id) => self.get_response(id),
            TimeoutRejectResponse(callback) | DropRejectResponse(callback) => None,
        }
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
            RequestOrResponse::Request(_) => entry.remove(),
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
            RequestOrResponse::Request(_) => return None,
            RequestOrResponse::Response(_) => entry.remove(),
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
        let msg = self.take_impl(id)?;
        self.maybe_trim_queues();

        Some(msg)
    }

    /// Removes the message with given reference from the pool.
    ///
    /// Updates the stats; and prunes the priority queues if necessary.
    pub fn take2(&mut self, reference: MessageReference) -> Option<RequestOrResponse> {
        use MessageReference::*;

        match reference {
            Request(id) => self.take_request(id),
            Response(id) => self.take_response(id),
            TimeoutRejectResponse(callback) | DropRejectResponse(callback) => None,
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
            self.take_impl(*id).map(|msg| expired.push(msg));

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
            if let Some(msg) = self.take_impl(id) {
                // A message was shed, prune the queues and return it.
                self.maybe_trim_queues();
                return Some(msg);
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
