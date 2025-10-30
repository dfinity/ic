use super::CanisterInput;
use super::message_pool::{Kind, Reference};
use crate::StateError;
use ic_base_types::CanisterId;
use ic_types::CountBytes;
use ic_types::messages::{Ingress, RequestOrResponse};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::{BTreeMap, VecDeque};
use std::convert::{From, TryFrom, TryInto};
use std::fmt::Debug;
use std::mem::size_of;
use std::sync::Arc;

pub mod proto;
#[cfg(test)]
mod tests;

/// A typed FIFO queue with equal but separate capacities for requests and
/// responses, ensuring full-duplex communication up to its capacity.
///
/// The queue holds typed weak references into a `MessageStore`. The messages
/// that these references point to may expire or be shed, resulting in stale
/// references that are not immediately removed from the queue. Which is why the
/// queue stats track "request slots" and "response slots" instead of "requests"
/// and "responses"; and `len()` returns the length of the queue, not the number
/// of messages that can be popped.
///
/// Backpressure (limiting number of open callbacks to a given destination) is
/// enforced by making enqueuing a request contingent on reserving a slot for
/// the eventual response in the reverse queue; and bounding the number of
/// responses (actually enqueued plus reserved slots) by the queue capacity.
/// Note that this ensures that a response is only ever enqueued into a slot
/// already reserved for it.
///
/// Backpressure should implicitly limit the number of requests (since there
/// cannot be more live requests than callbacks). It is however possible for
/// requests to time out; produce a reject response in the reverse queue; and
/// for that response to be consumed while the request still consumes a slot in
/// the queue; so we must additionally explicitly limit the number of slots used
/// by requests to the queue capacity.
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct CanisterQueue<T> {
    /// A FIFO queue of request and response weak references into the pool.
    ///
    /// Since responses may be enqueued at arbitrary points in time, reserved slots
    /// for responses cannot be explicitly represented in `queue`. They only exist
    /// as the difference between `response_slots` and the number of actually
    /// enqueued response references (calculated as `request_slots + response_slots
    /// - queue.len()`).
    ///
    /// Some messages (all best-effort messages; plus guaranteed response requests
    /// in output queues) may time out or be load shed and be dropped from the pool.
    /// The kind (`Request` or `Response`) of such a stale reference can be learned
    /// from the reference itself.
    ///
    ///  * Stale requests are to be ignored, whether they are found in an input or
    ///    an output queue. They timed out or were shed while enqueued and, if in an
    ///    output queue, a corresponding reject response was generated.
    ///  * Stale responses in output queues (always best-effort) are also to be
    ///    ignored. They timed out or were shed while enqueued and the originating
    ///    canister is responsible for generating a timeout response instead.
    ///  * Stale responses in input queues (always best-effort) are responses that
    ///    were shed while enqueued or are `SYS_UNKNOWN` reject responses enqueued
    ///    as dangling references to begin with. They are to be handled as
    ///    `SYS_UNKNOWN` reject responses ("timeout" if their deadline expired,
    ///    "drop" otherwise).
    queue: VecDeque<Reference<T>>,

    /// Maximum number of requests; or responses + reserved slots; that can be held
    /// in the queue at any one time.
    capacity: usize,

    /// Number of enqueued request references.
    ///
    /// Invariants:
    ///  * `request_slots == queue.iter().filter(|r| r.kind() == Kind::Request).count()`
    ///  * `request_slots <= capacity`
    request_slots: usize,

    /// Number of slots used by response references or reserved for expected
    /// responses.
    ///
    /// Invariants:
    ///  * `response_slots >= queue.iter().filter(|r| r.kind() == Kind::Response).count()`
    ///  * `response_slots <= capacity`
    response_slots: usize,

    /// The type of item referenced by the queue.
    marker: std::marker::PhantomData<T>,
}

/// An `InputQueue` is a `CanisterQueue` holding references to `CanisterInput`
/// items, i.e. either pooled messages or compact responses.
pub(super) type InputQueue = CanisterQueue<CanisterInput>;

/// An `OutputQueue` is a `CanisterQueue` holding references to outbound
/// `RequestOrResponse` items.
pub(super) type OutputQueue = CanisterQueue<RequestOrResponse>;

impl<T> CanisterQueue<T> {
    /// Creates a new `CanisterQueue` with the given capacity.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity,
            request_slots: 0,
            response_slots: 0,
            marker: std::marker::PhantomData,
        }
    }

    /// Returns the number of slots available for requests.
    pub(super) fn available_request_slots(&self) -> usize {
        debug_assert!(self.request_slots <= self.capacity);
        self.capacity - self.request_slots
    }

    /// Returns `Ok(())` if there exists at least one available request slot,
    /// `Err(StateError::QueueFull)` otherwise.
    pub(super) fn check_has_request_slot(&self) -> Result<(), StateError> {
        if self.request_slots >= self.capacity {
            return Err(StateError::QueueFull {
                capacity: self.capacity,
            });
        }
        Ok(())
    }

    /// Enqueues a request.
    ///
    /// Panics if there is no available request slot.
    pub(super) fn push_request(&mut self, reference: Reference<T>) {
        debug_assert!(reference.kind() == Kind::Request);
        assert!(self.request_slots < self.capacity);

        self.queue.push_back(reference);
        self.request_slots += 1;

        debug_assert_eq!(Ok(()), self.check_invariants());
    }

    /// Returns the number of response slots available for reservation.
    pub(super) fn available_response_slots(&self) -> usize {
        debug_assert!(self.response_slots <= self.capacity);
        self.capacity - self.response_slots
    }

    /// Reserves a slot for a response, if available; else returns
    /// `Err(StateError::QueueFull)`.
    pub(super) fn try_reserve_response_slot(&mut self) -> Result<(), StateError> {
        debug_assert!(self.response_slots <= self.capacity);
        if self.response_slots >= self.capacity {
            return Err(StateError::QueueFull {
                capacity: self.capacity,
            });
        }

        self.response_slots += 1;
        debug_assert_eq!(Ok(()), self.check_invariants());
        Ok(())
    }

    /// Releases a reserved response slot.
    ///
    /// This is used when a request in the reverse queue is dropped before having
    /// had a chance to be popped.
    pub(super) fn release_reserved_response_slot(&mut self) {
        debug_assert!(self.response_slots > 0);

        self.response_slots = self.response_slots.saturating_sub(1);
    }

    /// Returns the number of reserved response slots.
    pub(super) fn reserved_slots(&self) -> usize {
        debug_assert!(self.request_slots + self.response_slots >= self.queue.len());
        self.request_slots + self.response_slots - self.queue.len()
    }

    /// Returns `Ok(())` if there exists at least one reserved response slot,
    /// `Err(())` otherwise.
    pub(super) fn check_has_reserved_response_slot(&self) -> Result<(), ()> {
        if self.request_slots + self.response_slots <= self.queue.len() {
            return Err(());
        }

        Ok(())
    }

    /// Enqueues a response into a reserved slot, consuming the slot.
    ///
    /// Panics if there is no reserved response slot.
    pub(super) fn push_response(&mut self, reference: Reference<T>) {
        debug_assert!(reference.kind() == Kind::Response);
        self.check_has_reserved_response_slot()
            .expect("No reserved response slot");

        self.queue.push_back(reference);
        debug_assert_eq!(Ok(()), self.check_invariants());
    }

    /// Pops a reference from the queue. Returns `None` if the queue is empty.
    pub(super) fn pop(&mut self) -> Option<Reference<T>> {
        let reference = self.queue.pop_front()?;

        if reference.kind() == Kind::Response {
            debug_assert!(self.response_slots > 0);
            self.response_slots = self.response_slots.saturating_sub(1);
        } else {
            debug_assert!(self.request_slots > 0);
            self.request_slots -= 1;
        }
        debug_assert_eq!(Ok(()), self.check_invariants());

        Some(reference)
    }

    /// Returns the next reference in the queue; or `None` if the queue is empty.
    pub(super) fn peek(&self) -> Option<Reference<T>> {
        self.queue.front().cloned()
    }

    /// Returns `true` if the queue has one or more used slots.
    ///
    /// This is basically an `is_empty()` test, except it also looks at reserved
    /// slots, so it is named differently to make it clear it doesn't only check for
    /// enqueued references.
    pub(super) fn has_used_slots(&self) -> bool {
        !self.queue.is_empty() || self.response_slots > 0
    }

    /// Returns the length of the queue (including stale references, but not
    /// including reserved slots).
    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }

    /// Discards all references at the front of the queue for which the predicate
    /// holds. Stops when it encounters the first reference for which the predicate
    /// is false.
    pub(super) fn pop_while(&mut self, predicate: impl Fn(Reference<T>) -> bool) {
        while let Some(reference) = self.peek() {
            if !predicate(reference) {
                break;
            }
            self.pop();
        }
    }

    /// Queue invariant check that panics if any invariant does not hold. Intended
    /// to be called during checkpoint loading or from within a `debug_assert!()`.
    ///
    /// Time complexity: `O(n)`.
    fn check_invariants(&self) -> Result<(), String> {
        // Requests and response slots at or below capacity.
        if self.request_slots > self.capacity || self.response_slots > self.capacity {
            return Err(format!(
                "Request ({}) or response ({}) slots exceed capacity ({})",
                self.request_slots, self.response_slots, self.capacity
            ));
        }

        let responses = self
            .queue
            .iter()
            .filter(|msg| msg.kind() == Kind::Response)
            .count();
        if responses > self.response_slots {
            return Err(format!(
                "More responses ({}) than response slots ({})",
                responses, self.response_slots
            ));
        }
        // Queue contains only requests and responses.
        if self.queue.len() != self.request_slots + responses {
            return Err(format!(
                "Invalid `request_slots` ({}): queue length ({}), response count ({})",
                self.request_slots,
                self.queue.len(),
                responses
            ));
        }

        Ok(())
    }

    /// Returns an iterator over the underlying references.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Reference<T>> {
        self.queue.iter()
    }
}

/// Representation of the Ingress queue. There is no upper bound on
/// the number of messages it can store.
///
/// `IngressQueue` has a separate queue of Ingress messages for each
/// target canister based on `effective_canister_id`, and `schedule`
/// of executing target canisters with incoming Ingress messages.
///
/// When the Ingress message is pushed to the `IngressQueue`, it is added
/// to the queue of Ingress messages of the target canister. If the target
/// canister does not have other incoming Ingress messages it is added to
/// the back of `schedule`.
///
/// When `pop()` is called `IngressQueue` returns the first Ingress message
/// from the canister at the front of the `schedule`. If that canister
/// has other incoming Ingress messages it is moved to the
/// back of `schedule`, otherwise it is removed from `schedule`.
///
/// When `skip_ingress_input()` is called canister from the front of the
/// `schedule` is moved to its back.
#[derive(Clone, Eq, PartialEq, Hash, Debug, ValidateEq)]
pub(super) struct IngressQueue {
    // Schedule of canisters that have Ingress messages to be processed.
    // Because `effective_canister_id` of `Ingress` message has type Option<CanisterId>,
    // the same type is used for entries `schedule` and keys in `queues`.
    schedule: VecDeque<Option<CanisterId>>,
    // Per canister queue of Ingress messages.
    #[validate_eq(CompareWithValidateEq)]
    queues: BTreeMap<Option<CanisterId>, VecDeque<Arc<Ingress>>>,
    // Total number of Ingress messages that are waiting to be executed.
    total_ingress_count: usize,
    /// Estimated size in bytes.
    size_bytes: usize,
}

impl IngressQueue {
    /// The memory overhead of a per-canister ingress queue, in bytes.
    const PER_CANISTER_QUEUE_OVERHEAD_BYTES: usize =
        size_of::<Option<CanisterId>>() + size_of::<VecDeque<Arc<Ingress>>>();

    /// Pushes a new ingress message to the back of the queue.
    pub(super) fn push(&mut self, msg: Ingress) {
        let msg_size = Self::ingress_size_bytes(&msg);
        let receiver_ingress_queue = self.queues.entry(msg.effective_canister_id).or_default();

        if receiver_ingress_queue.is_empty() {
            self.schedule.push_back(msg.effective_canister_id);
            self.size_bytes += Self::PER_CANISTER_QUEUE_OVERHEAD_BYTES;
        }

        receiver_ingress_queue.push_back(Arc::new(msg));

        self.size_bytes += msg_size;
        debug_assert_eq!(Self::size_bytes(&self.queues), self.size_bytes);

        self.total_ingress_count += 1;
    }

    /// Returns `None` if the queue is empty, otherwise removes the first Ingress
    /// message of the first scheduled canister, returns it, and moves
    /// that canister at the end of the schedule if it has more messages.
    pub(super) fn pop(&mut self) -> Option<Arc<Ingress>> {
        let canister_id = self.schedule.pop_front()?;

        let canister_ingress_queue = self.queues.get_mut(&canister_id).unwrap();

        let res = canister_ingress_queue.pop_front();

        if !canister_ingress_queue.is_empty() {
            self.schedule.push_back(canister_id);
        } else {
            self.queues.remove(&canister_id);
            self.size_bytes -= Self::PER_CANISTER_QUEUE_OVERHEAD_BYTES;
        }

        let msg = res.unwrap();
        self.size_bytes -= Self::ingress_size_bytes(msg.as_ref());
        debug_assert_eq!(Self::size_bytes(&self.queues), self.size_bytes);

        self.total_ingress_count -= 1;

        Some(msg)
    }

    /// Skips the ingress messages for the currently scheduled canister,
    /// and moves the canister to the end of scheduling queue.
    pub(super) fn skip_ingress_input(&mut self) {
        if let Some(canister_id) = self.schedule.pop_front() {
            self.schedule.push_back(canister_id);
        }
    }

    /// Returns a reference to the ingress message at the front of the queue,
    /// or `None` if the queue is empty.
    pub(super) fn peek(&self) -> Option<Arc<Ingress>> {
        let canister_id = self.schedule.front()?;
        // It is safe to unwrap here since for every value in `self.schedule`
        // we must have corresponding non-empty queue in `self.queues`.
        let ingress = self.queues.get(canister_id).unwrap().front().unwrap();
        Some(Arc::clone(ingress))
    }

    /// Returns the number of Ingress messages in the queue.
    pub(super) fn size(&self) -> usize {
        self.total_ingress_count
    }

    /// Returns the number of canisters with incoming ingress messages.
    pub(super) fn ingress_schedule_size(&self) -> usize {
        self.schedule.len()
    }

    /// Return true if there are no Ingress messages in the queue,
    /// or false otherwise.
    pub(super) fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Calls `filter` on each ingress message in the queue, retaining only the
    /// messages for which the filter returns `true` and dropping the rest.
    ///
    /// Returns all dropped ingress messages.
    pub(super) fn filter_messages<F>(&mut self, mut filter: F) -> Vec<Arc<Ingress>>
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        let mut filtered_messages = vec![];
        for canister_ingress_queue in self.queues.values_mut() {
            canister_ingress_queue.retain_mut(|item| {
                if filter(item) {
                    true
                } else {
                    // Empty `canister_ingress_queues` and their corresponding schedule entry
                    // are pruned below.
                    filtered_messages.push(Arc::clone(item));
                    self.size_bytes -= Self::ingress_size_bytes(&(*item));
                    self.total_ingress_count -= 1;
                    false
                }
            });
        }

        self.schedule.retain_mut(|canister_id| {
            let canister_ingress_queue = self.queues.get(canister_id).unwrap();
            if canister_ingress_queue.is_empty() {
                self.queues.remove(canister_id);
                self.size_bytes -= Self::PER_CANISTER_QUEUE_OVERHEAD_BYTES;
                false
            } else {
                true
            }
        });

        filtered_messages
    }

    /// Returns an estimate of the size of an ingress message in bytes.
    fn ingress_size_bytes(msg: &Ingress) -> usize {
        size_of::<Arc<Ingress>>() + msg.count_bytes()
    }

    /// Calculates the size in bytes of an `IngressQueue` holding the given
    /// ingress messages.
    ///
    /// Time complexity: O(num_messages).
    fn size_bytes(
        per_canister_queues: &BTreeMap<Option<CanisterId>, VecDeque<Arc<Ingress>>>,
    ) -> usize {
        let mut size = size_of::<Self>();
        for queue in per_canister_queues.values() {
            size += queue
                .iter()
                .map(|i| Self::ingress_size_bytes(i))
                .sum::<usize>()
                + Self::PER_CANISTER_QUEUE_OVERHEAD_BYTES;
        }
        size
    }
}

impl Default for IngressQueue {
    fn default() -> Self {
        let queues = BTreeMap::new();
        let size_bytes = Self::size_bytes(&queues);
        Self {
            schedule: VecDeque::new(),
            queues,
            total_ingress_count: 0,
            size_bytes,
        }
    }
}

impl CountBytes for IngressQueue {
    /// Estimate of the queue size in bytes, including metadata.
    fn count_bytes(&self) -> usize {
        self.size_bytes
    }
}
