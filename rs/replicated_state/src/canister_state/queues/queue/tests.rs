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
