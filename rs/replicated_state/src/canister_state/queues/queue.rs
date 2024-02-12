use crate::StateError;
#[cfg(test)]
mod tests;

use ic_base_types::CanisterId;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::{ingress::v1 as pb_ingress, queues::v1 as pb_queues};
use ic_types::messages::{Ingress, Request, RequestOrResponse, Response};
use ic_types::{CountBytes, Cycles, Time};
use std::collections::BTreeMap;
use std::{
    collections::VecDeque,
    convert::{From, TryFrom, TryInto},
    mem::size_of,
    sync::Arc,
};

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
/// Response slots are used by either actual responses or by reservations for
/// expected responses. Since an (incoming or outgoing) response always results
/// from an (outgoing or, respectively, incoming) request, it is required to
/// first make a reservation for a response; and later push the response into
/// the reserved slot, consuming the reservation. Attempting to push a response
/// with no reservations available will produce an error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct QueueWithReservation<T: QueueItem<T> + std::clone::Clone> {
    /// A FIFO queue of all requests and responses. Since responses may be enqueued
    /// at arbitrary points in time, response reservations cannot be explicitly
    /// represented in `queue`. They only exist as the difference between
    /// `num_responses + num_requests` and `queue.len()`.
    queue: VecDeque<T>,
    /// Maximum number of requests; or responses + reservations; allowed by the
    /// queue at any one time.
    capacity: usize,
    /// Number of slots used by requests.
    num_request_slots: usize,
    /// Number of slots used by responses and response reservations.
    num_response_slots: usize,
}

impl<T: QueueItem<T> + std::clone::Clone> QueueWithReservation<T> {
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
                StateError::QueueFull {
                    capacity: self.capacity,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct InputQueue {
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

    pub fn peek(&self) -> Option<&RequestOrResponse> {
        self.queue.peek()
    }

    pub(super) fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.queue.reserve_slot()
    }

    pub(super) fn pop(&mut self) -> Option<RequestOrResponse> {
        self.queue.pop()
    }

    /// Returns the number of messages in the queue.
    pub(super) fn num_messages(&self) -> usize {
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OutputQueue {
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
    pub fn num_messages(&self) -> usize {
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
    pub fn iter_for_testing(&self) -> impl Iterator<Item = &Option<RequestOrResponse>> {
        self.queue.queue.iter()
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct IngressQueue {
    // Schedule of canisters that have Ingress messages to be processed.
    // Because `effective_canister_id` of `Ingress` message has type Option<CanisterId>,
    // the same type is used for entries `schedule` and keys in `queues`.
    schedule: VecDeque<Option<CanisterId>>,
    // Per canister queue of Ingress messages.
    queues: BTreeMap<Option<CanisterId>, VecDeque<Arc<Ingress>>>,
    // Total number of Ingress messages that are waiting to be executed.
    total_ingress_count: usize,
    /// Estimated size in bytes.
    size_bytes: usize,
}

const PER_CANISTER_QUEUE_OVERHEAD_BYTES: usize =
    size_of::<Option<CanisterId>>() + size_of::<VecDeque<Arc<Ingress>>>();

impl IngressQueue {
    /// Pushes a new ingress message to the back of the queue.
    pub(super) fn push(&mut self, msg: Ingress) {
        let msg_size = Self::ingress_size_bytes(&msg);
        let receiver_ingress_queue = self.queues.entry(msg.effective_canister_id).or_default();

        if receiver_ingress_queue.is_empty() {
            self.schedule.push_back(msg.effective_canister_id);
            self.size_bytes += PER_CANISTER_QUEUE_OVERHEAD_BYTES;
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
            self.size_bytes -= PER_CANISTER_QUEUE_OVERHEAD_BYTES;
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
                self.size_bytes -= PER_CANISTER_QUEUE_OVERHEAD_BYTES;
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
                + PER_CANISTER_QUEUE_OVERHEAD_BYTES;
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
