use crate::StateError;

use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::{ingress::v1 as pb_ingress, queues::v1 as pb_queues};
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    QueueIndex,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::{From, TryFrom, TryInto};
use std::sync::Arc;

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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct QueueWithReservation<T: std::clone::Clone> {
    queue: VecDeque<Arc<T>>,
    // Maximum number of messages allowed in the `queue` above.
    capacity: usize,
    // Number of slots in the above `queue` currently reserved.  A slot must
    // first be reserved before it can be pushed to which consumes it.
    num_slots_reserved: usize,
}

impl<T: std::clone::Clone> QueueWithReservation<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
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
        match self.queue.front() {
            None => None,
            Some(msg) => Some(Arc::clone(msg)),
        }
    }

    /// Number of actual messages in the queue.
    fn num_messages(&self) -> usize {
        self.queue.len()
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

        Ok(QueueWithReservation {
            queue: item
                .queue
                .into_iter()
                .map(|rr| rr.try_into().map(Arc::new))
                .collect::<Result<VecDeque<_>, _>>()?,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    /// Number of actual messages in the queue
    pub(super) fn num_messages(&self) -> usize {
        self.queue.num_messages()
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    /// Returns a copy of the message that `pop` would have returned without
    /// removing it from the queue.
    pub(crate) fn peek(&self) -> Option<(QueueIndex, RequestOrResponse)> {
        match self.queue.peek() {
            None => None,
            Some(msg) => {
                let msg = (*msg).clone();
                Some((self.ind, msg))
            }
        }
    }

    /// Number of actual messages in the queue
    pub fn num_messages(&self) -> usize {
        self.queue.num_messages()
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(super) struct IngressQueue {
    queue: VecDeque<Arc<Ingress>>,
}

impl IngressQueue {
    pub(super) fn push(&mut self, msg: Ingress) {
        self.queue.push_back(Arc::new(msg));
    }

    pub(super) fn pop(&mut self) -> Option<Ingress> {
        pop_queue(&mut self.queue)
    }

    pub(super) fn size(&self) -> usize {
        self.queue.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Call the `filter` on each ingress message in the queue.  Retain the
    /// messages for whom the filter returns `true` and drop the rest.
    pub(super) fn filter_messages<F>(&mut self, filter: F)
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.queue.retain(filter)
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
        Ok(IngressQueue {
            queue: item
                .into_iter()
                .map(|i| i.try_into().map(Arc::new))
                .collect::<Result<VecDeque<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::types::{
        ids::{canister_test_id, message_test_id, user_test_id},
        messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
    };
    use ic_types::{messages::RequestOrResponse, QueueIndex};

    #[test]
    fn input_queue_constructor_test() {
        let capacity: usize = 14;
        let mut queue = InputQueue::new(capacity);
        assert_eq!(queue.num_messages(), 0);
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn input_queue_is_empty() {
        let mut input_queue = InputQueue::new(1);
        assert_eq!(input_queue.num_messages(), 0);
        input_queue
            .push(
                QueueIndex::from(0),
                RequestBuilder::default().build().into(),
            )
            .expect("could push");
        assert_ne!(input_queue.num_messages(), 0);
    }

    /// Test affirming success on successive pushes with incrementing indices.
    #[test]
    fn input_queue_push_succeeds_on_incremented_id() {
        let capacity: usize = 4;
        let mut input_queue = InputQueue::new(capacity);
        for index in 0..capacity {
            assert_eq!(
                Ok(()),
                input_queue.push(
                    QueueIndex::from(index as u64),
                    RequestBuilder::default().build().into()
                )
            );
        }
    }

    /// Test affirming success on popping pushed messages.
    #[test]
    fn input_queue_pushed_messages_get_popped() {
        let capacity: usize = 4;
        let mut input_queue = InputQueue::new(capacity);
        let mut msg_queue = VecDeque::new();
        for index in 0..capacity {
            let req: RequestOrResponse = RequestBuilder::default().build().into();
            msg_queue.push_back(req.clone());
            assert_eq!(
                Ok(()),
                input_queue.push(QueueIndex::from(index as u64), req)
            );
        }
        while !msg_queue.is_empty() {
            assert_eq!(input_queue.pop(), msg_queue.pop_front());
        }
        assert_eq!(None, msg_queue.pop_front());
        assert_eq!(None, input_queue.pop());
    }

    /// Test affirming that non-sequential pushes fail.
    #[test]
    #[should_panic(expected = "Expected queue index 1, got 0. Message: Request")]
    #[allow(unused_must_use)]
    fn input_queue_push_fails_on_non_sequential_id() {
        let capacity: usize = 4;
        let mut input_queue = InputQueue::new(capacity);
        input_queue
            .push(
                QueueIndex::from(0),
                RequestBuilder::default().build().into(),
            )
            .unwrap();

        input_queue.push(
            QueueIndex::from(0),
            RequestBuilder::default().build().into(),
        );
    }

    // Pushing a message with QueueIndex QUEUE_INDEX_NONE succeeds if there is
    // space.
    #[test]
    fn input_queue_push_suceeds_with_queue_index_none() {
        let capacity: usize = 4;
        let mut input_queue = InputQueue::new(capacity);
        input_queue
            .push(
                QueueIndex::from(0),
                RequestBuilder::default().build().into(),
            )
            .unwrap();

        input_queue
            .push(
                super::super::QUEUE_INDEX_NONE,
                RequestBuilder::default().build().into(),
            )
            .unwrap();

        input_queue
            .push(
                QueueIndex::from(1),
                RequestBuilder::default().build().into(),
            )
            .unwrap();

        assert_eq!(QueueIndex::from(2), input_queue.ind);
        assert_eq!(3, input_queue.num_messages());
    }

    /// Test that overfilling an input queue with messages and reservations
    /// results in failed pushes and reservations; also verifies that
    /// pushes and reservations below capacity succeeds.
    #[test]
    fn input_queue_push_to_full_queue_fails() {
        // First fill up the queue.
        let capacity: usize = 4;
        let mut input_queue = InputQueue::new(capacity);
        for index in 0..capacity / 2 {
            input_queue
                .push(
                    QueueIndex::from(index as u64),
                    RequestBuilder::default().build().into(),
                )
                .unwrap();
        }
        for _index in capacity / 2..capacity {
            input_queue.reserve_slot().unwrap();
        }
        assert_eq!(input_queue.num_messages(), capacity / 2);

        // Now push an extraneous message in.
        assert_eq!(
            input_queue
                .push(
                    QueueIndex::from(capacity as u64 / 2),
                    RequestBuilder::default().build().into(),
                )
                .map_err(|(err, _)| err),
            Err(StateError::QueueFull { capacity })
        );
        // With QueueIndex QUEUE_INDEX_NONE.
        assert_eq!(
            input_queue
                .push(
                    super::super::QUEUE_INDEX_NONE,
                    RequestBuilder::default().build().into(),
                )
                .map_err(|(err, _)| err),
            Err(StateError::QueueFull { capacity })
        );
        // Or try to reserve a slot.
        assert_eq!(
            input_queue.reserve_slot(),
            Err(StateError::QueueFull { capacity })
        );
    }

    #[test]
    fn input_push_without_reservation_fails() {
        let mut queue = InputQueue::new(10);
        queue
            .push(
                QueueIndex::from(0),
                ResponseBuilder::default().build().into(),
            )
            .unwrap_err();
    }

    #[test]
    fn output_queue_constructor_test() {
        let capacity: usize = 14;
        let mut queue = OutputQueue::new(capacity);
        assert_eq!(queue.num_messages(), 0);
        assert_eq!(queue.pop(), None);
    }

    /// Test that overfilling an output queue with messages and reservations
    /// results in failed pushes and reservations; also verifies that
    /// pushes and reservations below capacity succeeds.
    #[test]
    fn output_queue_push_to_full_queue_fails() {
        // First fill up the queue.
        let capacity: usize = 4;
        let mut output_queue = OutputQueue::new(capacity);
        for _index in 0..capacity / 2 {
            output_queue
                .push_request(RequestBuilder::default().build())
                .unwrap();
        }
        for _index in capacity / 2..capacity {
            output_queue.reserve_slot().unwrap();
        }
        assert_eq!(output_queue.num_messages(), capacity / 2);

        // Now push an extraneous message in
        assert_eq!(
            output_queue
                .push_request(RequestBuilder::default().build())
                .map_err(|(err, _)| err),
            Err(StateError::QueueFull { capacity })
        );
        // Or try to reserve a slot.
        assert_eq!(
            output_queue.reserve_slot(),
            Err(StateError::QueueFull { capacity })
        );
    }

    /// Test that values returned from pop are increasing by 1.
    #[test]
    fn output_queue_pop_returns_incrementing_indices() {
        // First fill up the queue.
        let capacity: usize = 4;
        let mut output_queue = OutputQueue::new(capacity);
        let mut msgs_list = VecDeque::new();
        for _ in 0..capacity {
            let req = RequestBuilder::default().build();
            msgs_list.push_back(RequestOrResponse::from(req.clone()));
            output_queue.push_request(req).unwrap();
        }

        for expected_index in 0..capacity {
            let (actual_index, queue_msg) = output_queue.pop().unwrap();
            let list_msg = msgs_list.pop_front().unwrap();
            assert_eq!(QueueIndex::from(expected_index as u64), actual_index);
            assert_eq!(list_msg, queue_msg);
        }

        assert_eq!(None, msgs_list.pop_front());
        assert_eq!(None, output_queue.pop());
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
    fn output_push_into_reserved_slot_fails() {
        let mut queue = OutputQueue::new(10);
        queue.push_response(ResponseBuilder::default().build());
    }

    #[test]
    fn ingress_queue_constructor_test() {
        let mut queue = IngressQueue::default();
        assert_eq!(queue.size(), 0);
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.is_empty(), true);
    }

    fn msg_from_number(num: u64) -> Ingress {
        IngressBuilder::default()
            .source(user_test_id(num))
            .receiver(canister_test_id(num))
            .method_name(num.to_string())
            .message_id(message_test_id(num))
            .build()
    }

    #[test]
    fn empty_and_len_agree_on_empty() {
        let q = IngressQueue::default();
        assert_eq!(q.size(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn empty_and_len_agree_on_non_empty() {
        let mut q = IngressQueue::default();
        q.push(msg_from_number(1));
        assert_eq!(q.size(), 1);
        assert!(!q.is_empty());
    }

    #[test]
    fn order_is_fifo() {
        let mut q = IngressQueue::default();
        let msg1 = msg_from_number(1);
        let msg2 = msg_from_number(2);
        q.push(msg1.clone());
        q.push(msg2.clone());

        assert_eq!(q.size(), 2);
        assert_eq!(q.pop(), Some(msg1));

        assert_eq!(q.size(), 1);
        assert_eq!(q.pop(), Some(msg2));

        assert_eq!(q.size(), 0);
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn ingress_filter() {
        let mut queue = IngressQueue::default();
        let msg1 = msg_from_number(1);
        let msg2 = msg_from_number(2);
        let msg3 = msg_from_number(3);
        queue.push(msg1.clone());
        queue.push(msg2.clone());
        queue.push(msg3.clone());

        queue.filter_messages(|ingress| *ingress != Arc::new(msg2.clone()));
        assert_eq!(queue.size(), 2);
        assert_eq!(queue.pop(), Some(msg1));
        assert_eq!(queue.size(), 1);
        assert_eq!(queue.pop(), Some(msg3));
    }
}
