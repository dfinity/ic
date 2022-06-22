use super::*;
use ic_test_utilities::types::{
    arbitrary,
    ids::{canister_test_id, message_test_id, user_test_id},
    messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
};
use ic_types::{messages::RequestOrResponse, QueueIndex};
use proptest::prelude::*;

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
fn input_queue_available_slots_is_correct() {
    let capacity = 2;
    let mut input_queue = InputQueue::new(capacity);
    assert_eq!(input_queue.available_slots(), 2);
    input_queue
        .push(
            QueueIndex::from(0),
            RequestBuilder::default().build().into(),
        )
        .unwrap();
    assert_eq!(input_queue.available_slots(), 1);
    input_queue.reserve_slot().unwrap();
    assert_eq!(input_queue.available_slots(), 0);
    assert!(input_queue.check_has_slot().is_err())
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
            .push_request(RequestBuilder::default().build().into())
            .unwrap();
    }
    for _index in capacity / 2..capacity {
        output_queue.reserve_slot().unwrap();
    }
    assert_eq!(output_queue.num_messages(), capacity / 2);

    // Now push an extraneous message in
    assert_eq!(
        output_queue
            .push_request(RequestBuilder::default().build().into())
            .map_err(|(err, _)| err),
        Err(StateError::QueueFull { capacity })
    );
    // Or try to reserve a slot.
    assert_eq!(
        output_queue.reserve_slot(),
        Err(StateError::QueueFull { capacity })
    );
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
fn output_push_into_reserved_slot_fails() {
    let mut queue = OutputQueue::new(10);
    queue.push_response(ResponseBuilder::default().build().into());
}

#[test]
fn output_queue_available_slots_is_correct() {
    let capacity = 2;
    let mut output_queue = OutputQueue::new(capacity);
    assert_eq!(output_queue.available_slots(), 2);
    output_queue
        .push_request(RequestBuilder::default().build().into())
        .unwrap();
    assert_eq!(output_queue.available_slots(), 1);
    output_queue.reserve_slot().unwrap();
    assert_eq!(output_queue.available_slots(), 0);
    assert!(output_queue.check_has_slot().is_err())
}

prop_compose! {
    /// Generator for an arbitrary Option<RequestOrResponse>.
    fn arb_request_or_response_or_none(
    ) (rand in 0..1000,
       rr in arbitrary::request_or_response()
    ) -> Option<RequestOrResponse> {
        if rand<=666 {
            Some(rr)
        } else {
            None
        }
    }
}

prop_compose! {
    /// Generator for an arbitrary OutputQueue.
    fn arb_output_queue(max_slots_reserved: usize,
                        max_messages: usize,
    ) (excess_capacity in 0..=100_usize,
       num_slots_reserved in 0..=max_slots_reserved,
       rrv in prop::collection::vec(arb_request_or_response_or_none(), 0..=max_messages),
       rr in arbitrary::request_or_response(),
       starting_index in 0..=100_u64,
    ) -> OutputQueue {
        let mut queue = QueueWithReservation::<Option<RequestOrResponse>> {
            capacity: num_slots_reserved + rrv.len() + excess_capacity,
            num_slots_reserved,
            queue: rrv.into_iter().collect(),
        };
        if !queue.queue.is_empty() {
            queue.queue.pop_front();
            queue.queue.push_front(Some(rr));
        }
        OutputQueue {
            queue,
            ind: QueueIndex::from(starting_index)
        }
    }
}

proptest! {
    #[test]
    /// Proptest for invariants on output queues.
    /// Checks the invariant 'always Some at the front' and
    /// 'indices are always increasing', as well as that the final
    /// index has increased by the initial length of the queue when
    /// compared to the initial index.
    fn output_queue_invariants_hold(
        mut q in arb_output_queue(5,10),
    ) {
        let initial_len = q.queue.queue.len();
        let initial_index = q.ind;

        let mut last_index = None;
        while q.num_messages()>0 {
            // Head is always Some(_).
            assert!(q.queue.queue.front().unwrap().is_some());

            // Indices are strictly increasing.
            let (index, msg_ref) = q.peek().unwrap();
            if let Some(last_index) = last_index {
                assert!(index > last_index);
            }
            last_index = Some(index);

            // Second peek() returns what the first peek returned.
            assert_eq!((index, msg_ref), q.peek().unwrap());

            // pop() returns what peek() returned.
            assert_eq!((index, msg_ref.clone()), q.pop().unwrap());
        }
        assert_eq!((q.ind - initial_index).get(), initial_len as u64);
    }

    #[test]
    /// Proptest for arbitrary output queues to check whether
    /// the conversion to and from for protobuf versions works.
    fn output_queue_roundtrip_conversions(
        mut q in arb_output_queue(super::super::DEFAULT_QUEUE_CAPACITY/10,
                                  super::super::DEFAULT_QUEUE_CAPACITY/10),
    ) {
        q.queue.capacity = super::super::DEFAULT_QUEUE_CAPACITY;
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        let cmpq: OutputQueue = proto_queue.try_into().expect("bad conversion");

        assert_eq!(q, cmpq);
    }
}

#[test]
fn output_queue_decode_with_none_head_fails() {
    let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for _ in 0..2 {
        q.push_request(RequestBuilder::default().build().into())
            .unwrap();
    }
    q.queue.queue.front_mut().unwrap().take();

    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(TryInto::<OutputQueue>::try_into(proto_queue).is_err());
}

#[test]
fn ingress_queue_constructor_test() {
    let mut queue = IngressQueue::default();
    assert_eq!(queue.size(), 0);
    assert_eq!(queue.pop(), None);
    assert!(queue.is_empty());
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
    assert_eq!(q.pop(), Some(msg1.into()));

    assert_eq!(q.size(), 1);
    assert_eq!(q.pop(), Some(msg2.into()));

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
    assert_eq!(queue.pop(), Some(msg1.into()));
    assert_eq!(queue.size(), 1);
    assert_eq!(queue.pop(), Some(msg3.into()));
}
