use crate::StateError;
#[cfg(test)]
mod tests;

use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::{ingress::v1 as pb_ingress, queues::v1 as pb_queues};
use ic_types::CountBytes;
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    QueueIndex,
};
use std::{
    collections::VecDeque,
    convert::{From, TryFrom, TryInto},
    mem::size_of,
    sync::Arc,
};

fn pop_queue<T: std::clone::Clone>(queue: &mut VecDeque<Arc<T>>) -> Option<T> {
    // If there's only one reference to the ref-counted value, we extract it
    // from the Arc and pass it to the caller. If the value is shared, we
    // make another copy for the caller.
    //
    // This is safe as long as we never attempt to clone the state that is
    // currently being modified.
    queue.pop_front().map(|arc| match Arc::try_unwrap(arc) {
        Ok(owned_value) => owned_value,
        Err(shared_ref) => (*shared_ref).clone(),
    })
}

/// A FIFO queue that enforces an upper bound on the number of slots used and
/// reserved. Pushing an item into the queue or reserving a slot may fail if the
/// queue is full. Pushing an item into a reserved slot will always succeed
/// (unless a reservation has not been made, in which case it will panic).
///
/// Stores items inside an `Arc` making it cheaper to copy the queue for
/// creating snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct QueueWithReservation<T: std::clone::Clone> {
    queue: VecDeque<Arc<T>>,
    /// Maximum number of messages allowed in the `queue` above.
    capacity: usize,
    /// Number of slots in the above `queue` currently reserved.  A slot must
    /// first be reserved before it can be pushed to which consumes it.
    num_slots_reserved: usize,
}

impl<T: std::clone::Clone + CountBytes> QueueWithReservation<T> {
    fn new(capacity: usize) -> Self {
        let queue = VecDeque::new();

        Self {
            queue,
            capacity,
            num_slots_reserved: 0,
        }
    }

    /// Returns `Ok(())` if there exists at least one available slot,
    /// `Err(StateError::QueueFull)` otherwise.
    fn check_has_slot(&self) -> Result<(), StateError> {
        if self.queue.len() + self.num_slots_reserved >= self.capacity {
            return Err(StateError::QueueFull {
                capacity: self.capacity,
            });
        }
        Ok(())
    }

    /// Reserves a slot if available, else returns `Err(StateError::QueueFull)`.
    fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.check_has_slot()?;
        self.num_slots_reserved += 1;
        Ok(())
    }

    /// Pushes an item into the queue if not full, returns
    /// `Err(StateError::QueueFull)` along with the provided item otherwise.
    fn push(&mut self, msg: T) -> Result<(), (StateError, T)> {
        if let Err(e) = self.check_has_slot() {
            return Err((e, msg));
        }
        self.queue.push_back(Arc::new(msg));
        Ok(())
    }

    /// Pushes an item into a reserved slot, consuming the reservation or
    /// returns an error if there is no reservation available.
    fn push_into_reserved_slot(&mut self, msg: T) -> Result<(), (StateError, T)> {
        if self.num_slots_reserved > 0 {
            self.num_slots_reserved -= 1;
            self.queue.push_back(Arc::new(msg));
            Ok(())
        } else {
            Err((StateError::QueueFull { capacity: 0 }, msg))
        }
    }

    /// Pops an item off the tail of the queue or `None` if the queue is empty.
    fn pop(&mut self) -> Option<T> {
        pop_queue(&mut self.queue)
    }

    /// Returns an Arc<item> at the head of the queue or `None` if the queue is
    /// empty.
    fn peek(&self) -> Option<Arc<T>> {
        self.queue.front().map(|msg| Arc::clone(msg))
    }

    /// Number of actual messages in the queue.
    fn num_messages(&self) -> usize {
        self.queue.len()
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        self.num_slots_reserved
    }

    /// Calculates the sum of the given stat across all enqueued messages.
    ///
    /// Time complexity: O(num_messages).
    fn calculate_stat_sum(&self, stat: fn(&T) -> usize) -> usize {
        self.queue.iter().map(|msg| stat(msg)).sum::<usize>()
    }
}

impl From<&QueueWithReservation<RequestOrResponse>> for Vec<pb_queues::RequestOrResponse> {
    fn from(item: &QueueWithReservation<RequestOrResponse>) -> Self {
        item.queue.iter().map(|rr| rr.as_ref().into()).collect()
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for QueueWithReservation<RequestOrResponse> {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        if item.capacity != super::DEFAULT_QUEUE_CAPACITY as u64 {
            return Err(ProxyDecodeError::Other(format!(
                "QueueWithReservation: capacity {}, expecting {}",
                item.capacity,
                super::DEFAULT_QUEUE_CAPACITY
            )));
        }
        if item.capacity < item.queue.len() as u64 + item.num_slots_reserved {
            return Err(ProxyDecodeError::Other(format!(
                "QueueWithReservation: message count ({}) + reserved slots ({}) > capacity ({})",
                item.queue.len(),
                item.num_slots_reserved,
                item.capacity,
            )));
        }

        let queue = item
            .queue
            .into_iter()
            .map(|rr| rr.try_into().map(Arc::new))
            .collect::<Result<VecDeque<_>, _>>()?;

        Ok(QueueWithReservation {
            queue,
            capacity: super::DEFAULT_QUEUE_CAPACITY,
            num_slots_reserved: item.num_slots_reserved as usize,
        })
    }
}

/// Representation of a single Canister input queue.  There is an upper bound on
/// number of messages it can store.  There is also a `QueueIndex` which can be
/// used effectively as a sequence number for the next message that the queue
/// expects.  The queue will refuse to insert a message that was not presented
/// with the expected sequence number.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct InputQueue {
    queue: QueueWithReservation<RequestOrResponse>,
    ind: QueueIndex,
}

impl InputQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: QueueWithReservation::new(capacity),
            ind: QueueIndex::from(0),
        }
    }

    pub(super) fn check_has_slot(&self) -> Result<(), StateError> {
        self.queue.check_has_slot()
    }

    pub(super) fn push(
        &mut self,
        msg_ind: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        if msg_ind == self.ind {
            self.ind.inc_assign();
        } else if msg_ind != super::QUEUE_INDEX_NONE {
            // We don't pass `QueueIndex` values through streams, this should never happen.
            panic!(
                "Expected queue index {}, got {}. Message: {:?}",
                self.ind, msg_ind, msg
            );
        }
        match msg {
            RequestOrResponse::Request(_) => self.queue.push(msg),
            RequestOrResponse::Response(_) => self.queue.push_into_reserved_slot(msg),
        }
    }

    pub(super) fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.queue.reserve_slot()
    }

    pub(super) fn pop(&mut self) -> Option<RequestOrResponse> {
        self.queue.pop()
    }

    /// Returns the number of actual messages in the queue.
    pub(super) fn num_messages(&self) -> usize {
        self.queue.num_messages()
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        self.queue.reserved_slots()
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
    fn from(item: &InputQueue) -> Self {
        Self {
            queue: (&item.queue).into(),
            ind: item.ind.get(),
            capacity: item.queue.capacity as u64,
            num_slots_reserved: item.queue.num_slots_reserved as u64,
        }
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for InputQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        Ok(Self {
            ind: item.ind.into(),
            queue: item.try_into()?,
        })
    }
}

/// Representation of a single Canister output queue.  There is an upper bound
/// on the number of messages it can store.  There is also a `QueueIndex` which
/// can be used effectively as a sequence number for the next message popped out
/// of the queue.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OutputQueue {
    queue: QueueWithReservation<RequestOrResponse>,
    ind: QueueIndex,
}

impl OutputQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: QueueWithReservation::new(capacity),
            ind: QueueIndex::from(0),
        }
    }

    pub(super) fn check_has_slot(&self) -> Result<(), StateError> {
        self.queue.check_has_slot()
    }

    pub(super) fn push_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        if let Err((err, RequestOrResponse::Request(msg))) =
            self.queue.push(RequestOrResponse::Request(msg))
        {
            return Err((err, msg));
        }
        Ok(())
    }

    pub(super) fn push_response(&mut self, msg: Response) {
        self.queue
            .push_into_reserved_slot(RequestOrResponse::Response(msg))
            .unwrap();
    }

    pub(super) fn reserve_slot(&mut self) -> Result<(), StateError> {
        self.queue.reserve_slot()
    }

    pub(crate) fn pop(&mut self) -> Option<(QueueIndex, RequestOrResponse)> {
        match self.queue.pop() {
            None => None,
            Some(msg) => {
                let ret = Some((self.ind, msg));
                self.ind.inc_assign();
                ret
            }
        }
    }

    /// Returns the message that `pop` would have returned, without removing it
    /// from the queue.
    pub(crate) fn peek(&self) -> Option<(QueueIndex, Arc<RequestOrResponse>)> {
        self.queue.peek().map(|msg| (self.ind, msg))
    }

    /// Number of actual messages in the queue
    pub fn num_messages(&self) -> usize {
        self.queue.num_messages()
    }

    /// Returns the number of reserved slots in the queue.
    pub(super) fn reserved_slots(&self) -> usize {
        self.queue.reserved_slots()
    }

    /// Calculates the sum of the given stat across all enqueued messages.
    ///
    /// Time complexity: O(num_messages).
    pub(super) fn calculate_stat_sum(&self, stat: fn(&RequestOrResponse) -> usize) -> usize {
        self.queue.calculate_stat_sum(stat)
    }
}

impl std::iter::Iterator for OutputQueue {
    type Item = (QueueIndex, RequestOrResponse);

    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }
}

impl From<&OutputQueue> for pb_queues::InputOutputQueue {
    fn from(item: &OutputQueue) -> Self {
        Self {
            queue: (&item.queue).into(),
            ind: item.ind.get(),
            capacity: item.queue.capacity as u64,
            num_slots_reserved: item.queue.num_slots_reserved as u64,
        }
    }
}

impl TryFrom<pb_queues::InputOutputQueue> for OutputQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::InputOutputQueue) -> Result<Self, Self::Error> {
        Ok(Self {
            ind: item.ind.into(),
            queue: item.try_into()?,
        })
    }
}

/// Representation of the Ingress queue.  There is no upper bound on
/// the number of messages it can store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct IngressQueue {
    queue: VecDeque<Arc<Ingress>>,

    /// Estimated size in bytes.
    size_bytes: usize,
}

impl IngressQueue {
    pub(super) fn push(&mut self, msg: Ingress) {
        self.size_bytes += Self::ingress_size_bytes(&msg);
        self.queue.push_back(Arc::new(msg));
        debug_assert_eq!(Self::size_bytes(&self.queue), self.size_bytes);
    }

    pub(super) fn pop(&mut self) -> Option<Ingress> {
        let res = pop_queue(&mut self.queue);
        if let Some(msg) = res.as_ref() {
            self.size_bytes -= Self::ingress_size_bytes(&msg);
            debug_assert_eq!(Self::size_bytes(&self.queue), self.size_bytes);
        }
        res
    }

    pub(super) fn size(&self) -> usize {
        self.queue.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Calls `filter` on each ingress message in the queue, retaining the
    /// messages for whom the filter returns `true` and dropping the rest.
    pub(super) fn filter_messages<F>(&mut self, filter: F)
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.queue.retain(filter);
        self.size_bytes = Self::size_bytes(&self.queue)
    }

    /// Calculates the size in bytes of an `IngressQueue` holding the given
    /// ingress messages.
    ///
    /// Time complexity: O(num_messages).
    fn size_bytes(queue: &VecDeque<Arc<Ingress>>) -> usize {
        size_of::<Self>()
            + queue
                .iter()
                .map(|i| Self::ingress_size_bytes(i))
                .sum::<usize>()
    }

    /// Returns an estimate of the size of an ingress message in bytes.
    fn ingress_size_bytes(msg: &Ingress) -> usize {
        size_of::<Arc<Ingress>>() + msg.count_bytes()
    }
}

impl Default for IngressQueue {
    fn default() -> Self {
        let queue = Default::default();
        let size_bytes = Self::size_bytes(&queue);
        Self { queue, size_bytes }
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
        item.queue.iter().map(|i| i.as_ref().into()).collect()
    }
}

impl TryFrom<Vec<pb_ingress::Ingress>> for IngressQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: Vec<pb_ingress::Ingress>) -> Result<Self, Self::Error> {
        let queue = item
            .into_iter()
            .map(|i| i.try_into().map(Arc::new))
            .collect::<Result<VecDeque<_>, _>>()?;
        let size_bytes = Self::size_bytes(&queue);

        Ok(IngressQueue { queue, size_bytes })
    }
}
