// TODO(MR-569) Remove when `CanisterQueues` has been updated to use this.
#![allow(dead_code)]

use super::message_pool::{self, Context, Kind, MessagePool, REQUEST_LIFETIME};
use crate::StateError;
use ic_base_types::CanisterId;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::{ingress::v1 as pb_ingress, queues::v1 as pb_queues};
use ic_types::messages::{Ingress, Request, RequestOrResponse, Response, NO_DEADLINE};
use ic_types::time::UNIX_EPOCH;
use ic_types::{CountBytes, Cycles, Time};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::{BTreeMap, VecDeque};
use std::convert::{From, TryFrom, TryInto};
use std::mem::size_of;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// A FIFO queue with equal but separate capacities for requests and responses,
/// ensuring full-duplex communication up to its capacity.
///
/// The queue holds weak references into a `MessagePool`. The messages that
/// these references point to may expire or be shed, resulting in stale
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
pub(crate) struct CanisterQueue {
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
    queue: VecDeque<message_pool::Id>,

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
}

impl CanisterQueue {
    /// Creates a new `CanisterQueue` with the given capacity.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity,
            request_slots: 0,
            response_slots: 0,
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
    pub(super) fn push_request(&mut self, reference: message_pool::Id) {
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
    pub(super) fn push_response(&mut self, reference: message_pool::Id) {
        debug_assert!(reference.kind() == Kind::Response);
        self.check_has_reserved_response_slot()
            .expect("No reserved response slot");

        self.queue.push_back(reference);
        debug_assert_eq!(Ok(()), self.check_invariants());
    }

    /// Pops a reference from the queue. Returns `None` if the queue is empty.
    pub(super) fn pop(&mut self) -> Option<message_pool::Id> {
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
    pub(super) fn peek(&self) -> Option<message_pool::Id> {
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
    pub(super) fn pop_while(&mut self, predicate: impl Fn(message_pool::Id) -> bool) {
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
    pub(super) fn iter(&self) -> impl Iterator<Item = &message_pool::Id> {
        self.queue.iter()
    }
}

impl From<&CanisterQueue> for pb_queues::CanisterQueue {
    fn from(item: &CanisterQueue) -> Self {
        Self {
            queue: item.queue.iter().map(Into::into).collect(),
            capacity: item.capacity as u64,
            response_slots: item.response_slots as u64,
        }
    }
}

impl TryFrom<(pb_queues::CanisterQueue, Context)> for CanisterQueue {
    type Error = ProxyDecodeError;

    fn try_from((item, context): (pb_queues::CanisterQueue, Context)) -> Result<Self, Self::Error> {
        let queue: VecDeque<message_pool::Id> = item
            .queue
            .into_iter()
            .map(|queue_item| match queue_item.r {
                Some(pb_queues::canister_queue::queue_item::R::Reference(_)) => {
                    let reference = message_pool::Id::try_from(queue_item)?;
                    if reference.context() != context {
                        return Err(ProxyDecodeError::Other(format!(
                            "CanisterQueue: {:?} message in {:?} queue",
                            reference.context(),
                            context
                        )));
                    }
                    Ok(reference)
                }
                None => Err(ProxyDecodeError::MissingField("CanisterQueue::queue::r")),
            })
            .collect::<Result<_, ProxyDecodeError>>()?;
        let request_slots = queue
            .iter()
            .filter(|reference| reference.kind() == Kind::Request)
            .count();

        let res = Self {
            queue,
            capacity: super::DEFAULT_QUEUE_CAPACITY,
            request_slots,
            response_slots: item.response_slots as usize,
        };

        res.check_invariants()
            .map(|_| res)
            .map_err(ProxyDecodeError::Other)
    }
}

impl TryFrom<(InputQueue, &mut MessagePool)> for CanisterQueue {
    type Error = ProxyDecodeError;

    fn try_from((iq, pool): (InputQueue, &mut MessagePool)) -> Result<Self, Self::Error> {
        let mut queue = VecDeque::with_capacity(iq.len());
        for msg in iq.queue.queue.into_iter() {
            let reference = pool.insert_inbound(msg);
            queue.push_back(reference);
        }

        let queue = CanisterQueue {
            queue,
            capacity: iq.queue.capacity,
            request_slots: iq.queue.num_request_slots,
            response_slots: iq.queue.num_response_slots,
        };
        queue
            .check_invariants()
            .map(|_| queue)
            .map_err(ProxyDecodeError::Other)
    }
}

impl TryFrom<(OutputQueue, &mut MessagePool)> for CanisterQueue {
    type Error = ProxyDecodeError;

    fn try_from((oq, pool): (OutputQueue, &mut MessagePool)) -> Result<Self, Self::Error> {
        let mut deadline_range_ends = oq.deadline_range_ends.iter();
        let mut deadline_range_end = deadline_range_ends.next();

        let mut queue = VecDeque::with_capacity(oq.num_messages);
        let mut none_entries = 0;
        for (i, msg) in oq.queue.queue.into_iter().enumerate() {
            let msg = match msg {
                Some(msg) => msg,
                None => {
                    none_entries += 1;
                    continue;
                }
            };
            let reference = match msg {
                RequestOrResponse::Request(req) => {
                    let enqueuing_time = if req.deadline == NO_DEADLINE {
                        // Safe to unwrap because `OutputQueue` ensures that every request is covered by
                        // a deadline range.
                        while deadline_range_end.unwrap().1 <= i + oq.begin {
                            deadline_range_end = deadline_range_ends.next();
                        }
                        // Reconstruct the time when the request was enqueued.
                        deadline_range_end
                            .unwrap()
                            .0
                            .checked_sub(REQUEST_LIFETIME)
                            .unwrap()
                    } else {
                        // Irrelevant for best-effort messages, they have explicit deadlines.
                        UNIX_EPOCH
                    };
                    pool.insert_outbound_request(req, enqueuing_time)
                }

                RequestOrResponse::Response(rep) => pool.insert_outbound_response(rep),
            };
            queue.push_back(reference);
        }

        let queue = CanisterQueue {
            queue,
            capacity: oq.queue.capacity,
            request_slots: oq.queue.num_request_slots - none_entries,
            response_slots: oq.queue.num_response_slots,
        };
        queue
            .check_invariants()
            .map(|_| queue)
            .map_err(ProxyDecodeError::Other)
    }
}

impl TryFrom<(&CanisterQueue, &MessagePool)> for InputQueue {
    type Error = ProxyDecodeError;

    fn try_from((q, pool): (&CanisterQueue, &MessagePool)) -> Result<Self, Self::Error> {
        let mut input_queue = InputQueue::new(q.capacity);
        for reference in q.iter() {
            let msg = pool.get(*reference).ok_or_else(|| {
                ProxyDecodeError::Other(format!(
                    "InputQueue: unexpected stale reference ({:?})",
                    reference
                ))
            })?;
            // Safe to unwrap because we cannot exceed the queue capacity.
            if let RequestOrResponse::Response(_) = msg {
                input_queue.reserve_slot().unwrap();
            }
            input_queue.push(msg.clone()).unwrap();
        }
        input_queue.queue.num_response_slots = q.response_slots;

        if !input_queue.queue.check_invariants() {
            return Err(ProxyDecodeError::Other(format!(
                "Invalid InputQueue: {:?}",
                input_queue
            )));
        }

        Ok(input_queue)
    }
}

impl TryFrom<(&CanisterQueue, &MessagePool)> for OutputQueue {
    type Error = ProxyDecodeError;

    fn try_from((q, pool): (&CanisterQueue, &MessagePool)) -> Result<Self, Self::Error> {
        let mut output_queue = OutputQueue::new(q.capacity);
        let mut request_slots = 0;
        let mut response_slots = 0;
        for reference in q.iter() {
            let msg = match pool.get(*reference) {
                Some(msg) => msg.clone(),

                // Stale request, skip it.
                None if reference.kind() == Kind::Request => {
                    continue;
                }

                None => {
                    return Err(ProxyDecodeError::Other(format!(
                        "InputQueue: unexpected stale response reference ({:?})",
                        reference
                    )))
                }
            };
            match msg {
                RequestOrResponse::Request(req) => {
                    let deadline = pool
                        .outbound_guaranteed_request_deadlines()
                        .get(&reference)
                        .cloned()
                        .unwrap_or(req.deadline);
                    // Safe to unwrap because we cannot exceed the queue capacity.
                    output_queue.push_request(req, deadline.into()).unwrap();
                    request_slots += 1;
                }
                RequestOrResponse::Response(rep) => {
                    // Safe to unwrap because we cannot exceed the queue capacity.
                    output_queue.reserve_slot().unwrap();
                    output_queue.push_response(rep);
                    response_slots += 1;
                }
            }
        }
        output_queue.queue.num_request_slots = request_slots;
        output_queue.queue.num_response_slots = response_slots + q.reserved_slots();
        output_queue.num_messages = request_slots + response_slots;

        if !output_queue.queue.check_invariants() {
            return Err(ProxyDecodeError::Other(format!(
                "Invalid OutputQueue: {:?}",
                output_queue.queue
            )));
        }

        Ok(output_queue)
    }
}

/// Trait for queue items in `InputQueue` and `OutputQueue`. Such items must
/// either be a response or a request (including timed out requests).
/// Since an item is either a request or a response, implementing
/// `is_response()` is sufficient.
trait QueueItem<T> {
    /// Returns true if the queue item is a response.
    fn is_response(&self) -> bool;

    /// Converts a request into a queue item.
    fn from_request(request: Arc<Request>) -> T;

    /// Converts a response into a queue item.
    fn from_response(response: Arc<Response>) -> T;
}

impl QueueItem<RequestOrResponse> for RequestOrResponse {
    fn is_response(&self) -> bool {
        matches!(*self, RequestOrResponse::Response(_))
    }

    fn from_request(request: Arc<Request>) -> RequestOrResponse {
        RequestOrResponse::Request(request)
    }
    fn from_response(response: Arc<Response>) -> RequestOrResponse {
        RequestOrResponse::Response(response)
    }
}

impl QueueItem<Option<RequestOrResponse>> for Option<RequestOrResponse> {
    fn is_response(&self) -> bool {
        matches!(*self, Some(RequestOrResponse::Response(_)))
    }

    fn from_request(request: Arc<Request>) -> Option<RequestOrResponse> {
        Some(RequestOrResponse::Request(request))
    }
    fn from_response(response: Arc<Response>) -> Option<RequestOrResponse> {
        Some(RequestOrResponse::Response(response))
    }
}

/// A FIFO queue with equal but separate capacities for requests and responses,
/// ensuring full-duplex communication up to the capacity; and providing a
/// backpressure mechanism in either direction, once the limit is reached. This
/// is the basis for both `InputQueue` and `OutputQueue`.
///
/// Requests are handled in a straightforward manner: pushing a request onto the
/// queue succeeds if there are available request slots, fails if there aren't.
///
/// Response slots are either used by responses or reserved for expected
/// responses. Since an (incoming or outgoing) response always results from an
/// (outgoing or, respectively, incoming) request, it is required to first
/// reserve a slot for a response; and later push the response into the reserved
/// slot, consuming the slot reservation. Attempting to push a response with no
/// reserved slot available will produce an error.
#[derive(Clone, Eq, PartialEq, Hash, Debug, ValidateEq)]
struct QueueWithReservation<T: QueueItem<T> + std::clone::Clone + ValidateEq> {
    /// A FIFO queue of all requests and responses. Since responses may be enqueued
    /// at arbitrary points in time, response reservations cannot be explicitly
    /// represented in `queue`. They only exist as the difference between
    /// `num_responses + num_requests` and `queue.len()`.
    #[validate_eq(CompareWithValidateEq)]
    queue: VecDeque<T>,
    /// Maximum number of requests; or responses + reservations; allowed by the
    /// queue at any one time.
    capacity: usize,
    /// Number of slots used by requests.
    num_request_slots: usize,
    /// Number of slots used by responses and response reservations.
    num_response_slots: usize,
}

impl<T: QueueItem<T> + std::clone::Clone + ValidateEq> QueueWithReservation<T> {
    fn new(capacity: usize) -> Self {
        let queue = VecDeque::new();

        Self {
            queue,
            capacity,
            num_request_slots: 0,
            num_response_slots: 0,
        }
    }

    /// Returns the number of slots available in the queue for reservations.
    fn available_response_slots(&self) -> usize {
        self.capacity.checked_sub(self.num_response_slots).unwrap()
    }

    /// Returns the number slots available for requests.
    fn available_request_slots(&self) -> usize {
        self.capacity.checked_sub(self.num_request_slots).unwrap()
    }

    /// Returns `Ok(())` if there exists at least one available request slot,
    /// `Err(StateError::QueueFull)` otherwise.
    fn check_has_request_slot(&self) -> Result<(), StateError> {
        if self.num_request_slots >= self.capacity {
            return Err(StateError::QueueFull {
                capacity: self.capacity,
            });
        }
        Ok(())
    }

    /// Reserves a slot for a response, if available; else returns `Err(StateError::QueueFull)`.
    fn reserve_slot(&mut self) -> Result<(), StateError> {
        if self.available_response_slots() == 0 {
            return Err(StateError::QueueFull {
                capacity: self.capacity,
            });
        }
        self.num_response_slots += 1;
        debug_assert!(self.check_invariants());
        Ok(())
    }

    /// Pushes a request into the queue or returns an error if the capacity
    /// for requests is exhausted.
    fn push_request(&mut self, request: Arc<Request>) -> Result<(), (StateError, Arc<Request>)> {
        if self.num_request_slots < self.capacity {
            self.num_request_slots += 1;
            self.queue
                .push_back(<T as QueueItem<T>>::from_request(request));
            debug_assert!(self.check_invariants());
            Ok(())
        } else {
            Err((
                StateError::QueueFull {
                    capacity: self.capacity,
                },
                request,
            ))
        }
    }

    /// Pushes a response into a reserved slot, consuming the reservation or
    /// returns an error if there is no reservation available.
    fn push_response(
        &mut self,
        response: Arc<Response>,
    ) -> Result<(), (StateError, Arc<Response>)> {
        if self.reserved_slots() > 0 {
            self.queue
                .push_back(<T as QueueItem<T>>::from_response(response));
            debug_assert!(self.check_invariants());
            Ok(())
        } else {
            Err((
                StateError::NonMatchingResponse {
                    err_str: "No reserved response slot".to_string(),
                    originator: response.originator,
                    callback_id: response.originator_reply_callback,
                    respondent: response.respondent,
                    deadline: response.deadline,
                },
                response,
            ))
        }
    }

    /// Pops an item from the queue. Returns `None` if the queue is empty.
    fn pop(&mut self) -> Option<T> {
        let msg = self.queue.pop_front();
        if let Some(msg) = &msg {
            if msg.is_response() {
                self.num_response_slots = self.num_response_slots.checked_sub(1).unwrap();
            } else {
                self.num_request_slots = self.num_request_slots.checked_sub(1).unwrap();
            }
        }
        debug_assert!(self.check_invariants());
        msg
    }

    /// Returns a reference to the next item in the queue; or `None` if
    /// the queue is empty.
    fn peek(&self) -> Option<&T> {
        self.queue.front()
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        (self.num_request_slots + self.num_response_slots)
            .checked_sub(self.queue.len())
            .unwrap()
    }

    /// Returns `true` if the queue has one or more used slots.
    pub(super) fn has_used_slots(&self) -> bool {
        !self.queue.is_empty() || self.num_response_slots > 0
    }

    /// Calculates the sum of the given stat across all enqueued messages.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_stat_sum(&self, stat: impl Fn(&T) -> usize) -> usize {
        self.queue.iter().map(stat).sum::<usize>()
    }

    /// Queue invariant check that panics if any invariant does not hold. Intended
    /// to be called from within a `debug_assert!()` in production code.
    fn check_invariants(&self) -> bool {
        assert!(self.num_request_slots <= self.capacity);
        assert!(self.num_response_slots <= self.capacity);

        let num_responses = self.queue.iter().filter(|msg| msg.is_response()).count();
        assert!(num_responses <= self.num_response_slots);
        assert_eq!(self.num_request_slots, self.queue.len() - num_responses);

        true
    }
}

impl From<&QueueWithReservation<RequestOrResponse>> for Vec<pb_queues::RequestOrResponse> {
    fn from(q: &QueueWithReservation<RequestOrResponse>) -> Self {
        q.queue.iter().map(|rr| rr.into()).collect()
    }
}

impl From<&QueueWithReservation<Option<RequestOrResponse>>> for Vec<pb_queues::RequestOrResponse> {
    fn from(q: &QueueWithReservation<Option<RequestOrResponse>>) -> Self {
        q.queue
            .iter()
            .map(|opt| match opt {
                Some(rr) => rr.into(),
                None => pb_queues::RequestOrResponse { r: None },
            })
            .collect()
    }
}

/// Computes `num_request_slots` and `num_response_slots`.
/// Also performs sanity checks for `capacity` and the above.
fn get_num_slots(q: &pb_queues::InputOutputQueue) -> Result<(usize, usize), ProxyDecodeError> {
    let mut num_request_slots: u64 = 0;
    let mut num_response_slots: u64 = 0;
    for msg in q.queue.iter() {
        if let pb_queues::RequestOrResponse {
            r: Some(pb_queues::request_or_response::R::Response(_)),
        } = msg
        {
            num_response_slots += 1;
        } else {
            num_request_slots += 1;
        }
    }
    num_response_slots = num_response_slots.saturating_add(q.num_slots_reserved);

    if q.capacity != super::DEFAULT_QUEUE_CAPACITY as u64 {
        return Err(ProxyDecodeError::Other(format!(
            "QueueWithReservation: capacity {}, expecting {}",
            q.capacity,
            super::DEFAULT_QUEUE_CAPACITY
        )));
    }
    if num_request_slots > q.capacity {
        return Err(ProxyDecodeError::Other(format!(
            "QueueWithReservation: request slot count ({}) > capacity ({})",
            num_request_slots, q.capacity,
        )));
    }
    if num_response_slots > q.capacity {
        return Err(ProxyDecodeError::Other(format!(
            "QueueWithReservation: response slot count ({}) > capacity ({})",
            num_response_slots, q.capacity,
        )));
    }

    Ok((num_request_slots as usize, num_response_slots as usize))
}

impl TryFrom<pb_queues::InputOutputQueue> for QueueWithReservation<RequestOrResponse> {
    type Error = ProxyDecodeError;

    fn try_from(q: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        let (num_request_slots, num_response_slots) = get_num_slots(&q)?;

        let queue = q
            .queue
            .into_iter()
            .map(|rr| rr.try_into())
            .collect::<Result<VecDeque<_>, _>>()?;
        Ok(QueueWithReservation {
            queue,
            capacity: super::DEFAULT_QUEUE_CAPACITY,
            num_request_slots,
            num_response_slots,
        })
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for QueueWithReservation<Option<RequestOrResponse>> {
    type Error = ProxyDecodeError;

    fn try_from(q: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        let (num_request_slots, num_response_slots) = get_num_slots(&q)?;

        let queue = q
            .queue
            .into_iter()
            .map(|rr| match rr.r {
                None => Ok(None),
                Some(_) => rr.try_into().map(Some),
            })
            .collect::<Result<VecDeque<_>, _>>()?;
        Ok(QueueWithReservation {
            queue,
            capacity: super::DEFAULT_QUEUE_CAPACITY,
            num_request_slots,
            num_response_slots,
        })
    }
}

/// Representation of a single canister input queue. There is an upper bound on
/// the number of messages it can store.
#[derive(Clone, Eq, PartialEq, Hash, Debug, ValidateEq)]
pub(super) struct InputQueue {
    #[validate_eq(CompareWithValidateEq)]
    queue: QueueWithReservation<RequestOrResponse>,
}

impl InputQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: QueueWithReservation::new(capacity),
        }
    }

    pub(super) fn available_response_slots(&self) -> usize {
        self.queue.available_response_slots()
    }

    pub(super) fn check_has_request_slot(&self) -> Result<(), StateError> {
        self.queue.check_has_request_slot()
    }

    pub(super) fn push(
        &mut self,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        match msg {
            RequestOrResponse::Request(request) => self
                .queue
                .push_request(request)
                .map_err(|(err, request)| (err, RequestOrResponse::Request(request))),
            RequestOrResponse::Response(response) => self
                .queue
                .push_response(response)
                .map_err(|(err, response)| (err, RequestOrResponse::Response(response))),
        }
    }

    pub(super) fn peek(&self) -> Option<&RequestOrResponse> {
        self.queue.peek()
    }

    pub(super) fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.queue.reserve_slot()
    }

    pub(super) fn pop(&mut self) -> Option<RequestOrResponse> {
        self.queue.pop()
    }

    /// Returns the number of messages in the queue.
    pub(super) fn len(&self) -> usize {
        self.queue.queue.len()
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        self.queue.reserved_slots()
    }

    /// Returns `true` if the queue has one or more used slots.
    pub(super) fn has_used_slots(&self) -> bool {
        self.queue.has_used_slots()
    }

    /// Returns the amount of cycles contained in the queue.
    pub(super) fn cycles_in_queue(&self) -> Cycles {
        let mut total_cycles = Cycles::zero();
        for msg in self.queue.queue.iter() {
            total_cycles += msg.cycles();
        }
        total_cycles
    }

    /// Calculates the size in bytes, including struct and messages.
    ///
    /// Time complexity: O(num_messages).
    pub(super) fn calculate_size_bytes(&self) -> usize {
        size_of::<Self>() + self.queue.calculate_stat_sum(|msg| msg.count_bytes())
    }

    /// Calculates the sum of the given stat across all enqueued messages.
    ///
    /// Time complexity: O(num_messages).
    pub(super) fn calculate_stat_sum(&self, stat: fn(&RequestOrResponse) -> usize) -> usize {
        self.queue.calculate_stat_sum(stat)
    }
}

impl From<&InputQueue> for pb_queues::InputOutputQueue {
    fn from(q: &InputQueue) -> Self {
        Self {
            queue: (&q.queue).into(),
            begin: 0,
            capacity: q.queue.capacity as u64,
            num_slots_reserved: q.queue.reserved_slots() as u64,
            deadline_range_ends: Vec::new(),
            timeout_index: 0,
        }
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for InputQueue {
    type Error = ProxyDecodeError;

    fn try_from(q: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        if !q.deadline_range_ends.is_empty() || q.timeout_index != 0 {
            return Err(Self::Error::Other(
                "Found deadlines on decoding InputQueue".to_string(),
            ));
        }
        Ok(Self {
            queue: q.try_into()?,
        })
    }
}

/// Representation of a single Canister output queue.  There is an upper bound
/// on the number of messages it can store. There is also a begin index which
/// can be used effectively as a sequence number for the next message popped out
/// of the queue.
///
/// Uses `Option<_>` items so that requests can be dropped from anywhere in
/// the queue, i.e. replaced with `None`. They will keep their place in the queue
/// until they reach the beginning, where they will be discarded.
///
/// Additionally, an invariant is imposed such that there is always `Some` at the
/// front. This is ensured when a message is popped off the queue by also popping
/// any subsequent `None` items.
#[derive(Clone, Eq, PartialEq, Hash, Debug, ValidateEq)]
pub(crate) struct OutputQueue {
    #[validate_eq(CompareWithValidateEq)]
    queue: QueueWithReservation<Option<RequestOrResponse>>,
    /// Queue begin index.
    ///
    /// This provides consistent indices that identify each queue item, even as
    /// items are being pushed and popped, for use e.g. in `deadline_range_ends`.
    begin: usize,
    /// Ordered ranges of messages having the same request deadline. Each range
    /// is represented as a deadline and its end index (the index just past
    /// the last request where the deadline applies). Both the deadlines and queue
    /// indices are strictly increasing.
    deadline_range_ends: VecDeque<(Time, usize)>,
    /// Index from which request timing out will resume.
    ///
    /// Used to ensure amortized constant time for timing out requests.
    /// May point before the beginning of the queue if messages have been popped
    /// since the last `time_out_requests()` call.
    timeout_index: usize,
    /// The number of actual messages in the queue.
    num_messages: usize,
}

impl OutputQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: QueueWithReservation::new(capacity),
            begin: 0,
            deadline_range_ends: VecDeque::new(),
            timeout_index: 0,
            num_messages: 0,
        }
    }

    pub(super) fn available_request_slots(&self) -> usize {
        self.queue.available_request_slots()
    }

    pub(super) fn check_has_request_slot(&self) -> Result<(), StateError> {
        self.queue.check_has_request_slot()
    }

    pub(super) fn push_request(
        &mut self,
        request: Arc<Request>,
        deadline: Time,
    ) -> Result<(), (StateError, Arc<Request>)> {
        self.queue.push_request(request)?;

        // Update the deadline queue.
        //
        // If the deadline is less than or equal the one at the end of the deadline queue,
        // update the `end` of the last deadline range.
        //
        // If the new deadline is greater than the one of the previous request or there is
        // no previous request in the queue. push a new tuple.
        let end = self.begin + self.queue.queue.len();
        match self.deadline_range_ends.back_mut() {
            Some((back_deadline, deadline_range_end)) if *back_deadline >= deadline => {
                *deadline_range_end = end;
            }
            _ => {
                self.deadline_range_ends.push_back((deadline, end));
            }
        }

        self.num_messages += 1;
        debug_assert!(self.check_invariants());

        Ok(())
    }

    pub(super) fn push_response(&mut self, response: Arc<Response>) {
        self.queue.push_response(response).unwrap();
        self.num_messages += 1;
        debug_assert!(self.check_invariants());
    }

    pub(super) fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.queue.reserve_slot()
    }

    /// Pops a message off the queue and returns it.
    ///
    /// Ensures there is always a 'Some' at the beginning.
    pub(crate) fn pop(&mut self) -> Option<RequestOrResponse> {
        match self.queue.pop() {
            None => None,
            Some(None) => {
                unreachable!("OutputQueue invariant violated: Found `None` at the front.");
            }
            Some(Some(msg)) => {
                self.begin += 1;
                self.advance_to_next_message();

                self.num_messages -= 1;
                debug_assert!(self.check_invariants());

                Some(msg)
            }
        }
    }

    /// Consumes any empty slots at the beginning of the queue and discards consumed deadline ranges.
    fn advance_to_next_message(&mut self) {
        // Remove `None` in the beginning.
        while let Some(None) = self.queue.peek() {
            self.queue.pop();
            self.begin += 1;
        }

        // Remove deadlines that are no longer relevant.
        while let Some((_, deadline_range_end)) = self.deadline_range_ends.front() {
            if *deadline_range_end <= self.begin || *deadline_range_end <= self.timeout_index {
                self.deadline_range_ends.pop_front();
            } else {
                break;
            }
        }
    }

    /// Queue invariant check that panics if any invariant does not hold. Intended
    /// to be called from within a `debug_assert!()` in production code.
    ///
    /// This is (and must remain) strictly a wrapper around `test_invariants()`, as
    /// we should be enforcing the exact same invariants after deserialization as
    /// after mutations.
    ///
    /// # Panics
    ///
    /// If an invariant is violated.
    fn check_invariants(&self) -> bool {
        if let Err(err) = self.test_invariants() {
            panic!("{}", err);
        }
        true
    }

    /// Queue invariant check that produces an error if any invariant does not hold.
    fn test_invariants(&self) -> Result<(), &str> {
        if let Some(None) = self.queue.queue.front() {
            return Err("`None` at the beginning of the queue.");
        }

        if !self
            .deadline_range_ends
            .iter()
            .zip(self.deadline_range_ends.iter().skip(1))
            .all(|(a, b)| a.0 < b.0 && a.1 < b.1)
        {
            return Err("Deadline ranges not sorted.");
        }

        // Deadline indices must be in the
        // `(self.begin, self.begin + self.queue.queue.len()]` interval.
        if let Some((_, first_deadline_range_end)) = self.deadline_range_ends.front() {
            if *first_deadline_range_end <= self.begin {
                return Err("Deadline range end before queue begin.");
            }
            if *first_deadline_range_end <= self.timeout_index {
                return Err("Deadline range end before `timeout_index`.");
            }
        }
        if let Some((_, last_deadline_range_end)) = self.deadline_range_ends.back() {
            if *last_deadline_range_end > self.begin + self.queue.queue.len() {
                return Err("Deadline range end after queue end.");
            }
        }

        if self
            .queue
            .queue
            .iter()
            .take(self.timeout_index.saturating_sub(self.begin))
            .any(|rr| matches!(rr, Some(RequestOrResponse::Request(_))))
        {
            return Err("Request(s) before `timeout_index`.");
        }

        if self.num_messages != self.queue.queue.iter().filter(|rr| rr.is_some()).count() {
            return Err("`num_messages` does is not equal to the number of messages.");
        }

        Ok(())
    }

    /// Returns the message that `pop` would have returned, without removing it
    /// from the queue.
    pub(crate) fn peek(&self) -> Option<&RequestOrResponse> {
        self.queue.peek().map(|msg| msg.as_ref().unwrap())
    }

    /// Number of actual messages in the queue (`None` are ignored).
    pub(super) fn num_messages(&self) -> usize {
        self.num_messages
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        self.queue.reserved_slots()
    }

    /// Returns `true` if the queue has one or more used slots.
    pub(super) fn has_used_slots(&self) -> bool {
        self.queue.has_used_slots()
    }

    /// Returns the amount of cycles contained in the queue.
    pub(super) fn cycles_in_queue(&self) -> Cycles {
        let mut total_cycles = Cycles::zero();
        for msg in self.queue.queue.iter().flatten() {
            total_cycles += msg.cycles();
        }
        total_cycles
    }

    /// Calculates the sum of the given stat across all enqueued messages.
    ///
    /// Time complexity: O(num_messages).
    pub(super) fn calculate_stat_sum(&self, stat: fn(&RequestOrResponse) -> usize) -> usize {
        let stat =
            |item: &Option<RequestOrResponse>| if let Some(item) = item { stat(item) } else { 0 };
        self.queue.calculate_stat_sum(stat)
    }

    /// Returns true if there are any expired deadlines at `current_time`, false otherwise.
    pub(super) fn has_expired_deadlines(&self, current_time: Time) -> bool {
        match self.deadline_range_ends.front() {
            Some((deadline, _)) => *deadline <= current_time,
            None => false,
        }
    }

    /// Purges timed out requests. Returns an iterator over the timed out requests.
    /// Only consumed items are purged.
    pub(super) fn time_out_requests(&mut self, current_time: Time) -> TimedOutRequestsIter {
        TimedOutRequestsIter {
            q: self,
            current_time,
        }
    }

    /// Returns an iterator over the underlying messages.
    ///
    /// For testing purposes only.
    pub(super) fn iter_for_testing(&self) -> impl Iterator<Item = RequestOrResponse> + '_ {
        self.queue.queue.iter().filter_map(|item| item.clone())
    }
}

/// Iterator over timed out requests in an OutputQueue.
///
/// This extracts timed out requests by removing them from the queue,
/// leaving `None` in their place and returning them one by one.
pub(super) struct TimedOutRequestsIter<'a> {
    /// A mutable reference to the queue whose requests are to be timed out and returned.
    q: &'a mut OutputQueue,
    /// The time used to determine which requests should be considered timed out.
    /// This is compared to deadlines in q.deadline_range_ends.
    current_time: Time,
}

impl<'a> Iterator for TimedOutRequestsIter<'a> {
    type Item = Arc<Request>;

    fn next(&mut self) -> Option<Self::Item> {
        use RequestOrResponse::Request;

        while let Some(&(deadline, deadline_range_end)) = self.q.deadline_range_ends.front() {
            if deadline > self.current_time {
                return None;
            }

            self.q.timeout_index = self.q.timeout_index.max(self.q.begin);

            debug_assert!(deadline_range_end <= self.q.begin + self.q.queue.queue.len());
            while self.q.timeout_index < deadline_range_end {
                let i = self.q.timeout_index - self.q.begin;
                self.q.timeout_index += 1;

                if let Some(Request(request)) = match self.q.queue.queue.get_mut(i) {
                    Some(item @ Some(Request(_))) => item.take(),
                    _ => continue,
                } {
                    self.q.num_messages -= 1;
                    self.q.advance_to_next_message();
                    debug_assert!(self.q.check_invariants());

                    return Some(request);
                }
            }
            self.q.deadline_range_ends.pop_front();
        }
        None
    }
}

impl std::iter::Iterator for OutputQueue {
    type Item = RequestOrResponse;

    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }
}

impl From<&OutputQueue> for pb_queues::InputOutputQueue {
    fn from(q: &OutputQueue) -> Self {
        Self {
            queue: (&q.queue).into(),
            begin: q.begin as u64,
            capacity: q.queue.capacity as u64,
            num_slots_reserved: q.queue.reserved_slots() as u64,
            deadline_range_ends: q
                .deadline_range_ends
                .iter()
                .map(
                    |(deadline, deadline_range_end)| pb_queues::MessageDeadline {
                        deadline: deadline.as_nanos_since_unix_epoch(),
                        index: *deadline_range_end as u64,
                    },
                )
                .collect(),
            timeout_index: q.timeout_index as u64,
        }
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for OutputQueue {
    type Error = ProxyDecodeError;

    fn try_from(q: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        let begin = q.begin as usize;
        let timeout_index = q.timeout_index as usize;
        let deadline_range_ends: VecDeque<(Time, usize)> = q
            .deadline_range_ends
            .iter()
            .map(|di| {
                (
                    Time::from_nanos_since_unix_epoch(di.deadline),
                    di.index as usize,
                )
            })
            .collect();
        let queue: QueueWithReservation<Option<RequestOrResponse>> = q.try_into()?;
        let num_messages = queue.queue.iter().filter(|rr| rr.is_some()).count();

        let res = Self {
            begin,
            queue,
            deadline_range_ends,
            timeout_index,
            num_messages,
        };

        if let Err(err) = res.test_invariants() {
            return Err(Self::Error::Other(format!("Invalid OutputQueue: {}", err)));
        }
        Ok(res)
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

impl From<&IngressQueue> for Vec<pb_ingress::Ingress> {
    fn from(item: &IngressQueue) -> Self {
        // When serializing the IngressQueue, we iterate over
        // `schedule` and persist the queues in that order.
        item.schedule
            .iter()
            .flat_map(|canister_id| {
                item.queues
                    .get(canister_id)
                    .unwrap()
                    .iter()
                    .map(|v| pb_ingress::Ingress::from(&(**v)))
            })
            .collect()
    }
}

impl TryFrom<Vec<pb_ingress::Ingress>> for IngressQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: Vec<pb_ingress::Ingress>) -> Result<Self, Self::Error> {
        let mut res = Self::default();

        for ingress_pb in item {
            // Because the contents of `Self::queues` were serialized in `Self::schedule`
            // order, pushing the messages in that same order will implicitly reconstruct
            // `Self::schedule`.
            res.push(ingress_pb.try_into()?);
        }

        Ok(res)
    }
}
