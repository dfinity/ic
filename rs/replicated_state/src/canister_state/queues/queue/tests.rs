use super::super::message_pool::tests::*;
use super::super::message_pool::{Class, InboundReference};
use super::*;
use crate::canister_state::DEFAULT_QUEUE_CAPACITY;
use crate::canister_state::queues::pb_queues;
use assert_matches::assert_matches;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities_types::ids::{canister_test_id, message_test_id, user_test_id};
use ic_test_utilities_types::messages::IngressBuilder;
use proptest::prelude::*;

#[test]
fn canister_queue_constructor_test() {
    const CAPACITY: usize = 14;
    let mut queue = InputQueue::new(CAPACITY);

    assert_eq!(0, queue.len());
    assert!(!queue.has_used_slots());
    assert_eq!(CAPACITY, queue.capacity);
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(CAPACITY, queue.available_response_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());
    assert_eq!(queue.peek(), None);
    assert_eq!(queue.pop(), None);
}

// Pushing a request succeeds if there is space.
#[test]
fn canister_queue_push_request_succeeds() {
    const CAPACITY: usize = 1;
    let mut queue = InputQueue::new(CAPACITY);

    let reference = new_request_reference(13, Class::BestEffort);
    queue.push_request(reference);

    assert_eq!(1, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(CAPACITY - 1, queue.available_request_slots());
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.check_has_request_slot()
    );
    assert_eq!(CAPACITY, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());

    // Peek, then pop the request.
    assert_eq!(Some(reference), queue.peek());
    assert_eq!(Some(reference), queue.pop());

    assert_eq!(0, queue.len());
    assert!(!queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(CAPACITY, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());
}

// Reserving a slot, then pushing a response succeeds if there is space.
#[test]
fn canister_queue_push_response_succeeds() {
    use Class::*;

    const CAPACITY: usize = 1;
    let mut queue = CanisterQueue::new(CAPACITY);

    // Reserve a slot.
    queue.try_reserve_response_slot().unwrap();

    assert_eq!(0, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(CAPACITY - 1, queue.available_response_slots());
    assert_eq!(1, queue.reserved_slots());
    assert_eq!(Ok(()), queue.check_has_reserved_response_slot());

    // Push response into reseerved slot.
    let reference = new_response_reference(13, GuaranteedResponse);
    queue.push_response(reference);

    assert_eq!(1, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(CAPACITY - 1, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());

    // Peek, then pop the response reference.
    assert_eq!(Some(reference), queue.peek());
    assert_eq!(Some(reference), queue.pop());

    assert_eq!(0, queue.len());
    assert!(!queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(CAPACITY, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());
}

/// Test that overfilling an output queue with requests results in failed
/// pushes; also verifies that pushes below capacity succeed.
#[test]
#[should_panic(expected = "assertion failed: self.request_slots < self.capacity")]
fn canister_queue_push_request_to_full_queue_fails() {
    // First fill up the queue.
    const CAPACITY: usize = 2;
    let mut queue = CanisterQueue::new(CAPACITY);
    for i in 0..CAPACITY {
        queue.push_request(new_request_reference(i as u64, Class::BestEffort));
    }

    assert_eq!(CAPACITY, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(0, queue.available_request_slots());
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.check_has_request_slot()
    );
    assert_eq!(CAPACITY, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());

    queue.push_request(new_request_reference(13, Class::BestEffort));
}

/// Test that overfilling an output queue with slot reservations results in
/// failed slot reservations; also verifies that slot reservations below
/// capacity succeed.
#[test]
fn canister_queue_try_reserve_response_slot_in_full_queue_fails() {
    use Class::*;

    const CAPACITY: usize = 2;
    let mut queue = CanisterQueue::new(CAPACITY);

    // Reserve all response slots.
    for _ in 0..CAPACITY {
        queue.try_reserve_response_slot().unwrap();
    }

    assert_eq!(0, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(0, queue.available_response_slots());
    assert_eq!(CAPACITY, queue.reserved_slots());
    assert_eq!(Ok(()), queue.check_has_reserved_response_slot());

    // Trying to reserve a slot fails.
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.try_reserve_response_slot()
    );

    // Fill the queue with responses.
    for i in 0..CAPACITY {
        let class = if i % 2 == 0 {
            BestEffort
        } else {
            GuaranteedResponse
        };
        queue.push_response(new_response_reference(i as u64, class));
    }

    assert_eq!(2, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(CAPACITY, queue.available_request_slots());
    assert_eq!(Ok(()), queue.check_has_request_slot());
    assert_eq!(0, queue.available_response_slots());
    assert_eq!(0, queue.reserved_slots());
    assert_eq!(Err(()), queue.check_has_reserved_response_slot());

    // Trying to reserve a slot still fails.
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.try_reserve_response_slot()
    );
}

/// Test that a queue can be filled with both requests and responses at the
/// same time.
#[test]
fn canister_queue_full_duplex() {
    // First fill up the queue.
    const CAPACITY: usize = 2;
    let mut queue = InputQueue::new(CAPACITY);
    for i in 0..CAPACITY as u64 {
        queue.push_request(new_request_reference(i * 2, Class::BestEffort));
        queue.try_reserve_response_slot().unwrap();
        queue.push_response(new_response_reference(i * 2 + 1, Class::BestEffort));
    }

    assert_eq!(2 * CAPACITY, queue.len());
    assert!(queue.has_used_slots());
    assert_eq!(0, queue.available_request_slots());
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.check_has_request_slot()
    );
    assert_eq!(0, queue.available_response_slots());
    assert_eq!(
        Err(StateError::QueueFull { capacity: CAPACITY }),
        queue.try_reserve_response_slot(),
    );
}

#[test]
#[should_panic(expected = "No reserved response slot")]
fn canister_queue_push_without_reserved_slot_panics() {
    let mut queue = InputQueue::new(10);
    queue.push_response(new_response_reference(13, Class::BestEffort));
}

/// Generator for an arbitrary inbound message reference.
fn arbitrary_message_reference() -> impl Strategy<Value = InboundReference> + Clone {
    prop_oneof![
        any::<u64>().prop_map(|r#gen| new_request_reference(r#gen, Class::GuaranteedResponse)),
        any::<u64>().prop_map(|r#gen| new_request_reference(r#gen, Class::BestEffort)),
        any::<u64>().prop_map(|r#gen| new_response_reference(r#gen, Class::GuaranteedResponse)),
        any::<u64>().prop_map(|r#gen| new_response_reference(r#gen, Class::BestEffort)),
    ]
}

#[test_strategy::proptest]
fn canister_queue_push_and_pop(
    #[strategy(proptest::collection::vec_deque(arbitrary_message_reference(), 10..20))]
    mut references: VecDeque<InboundReference>,
) {
    // Create a queue with large enough capacity.
    let mut queue = InputQueue::new(20);

    // Push all references onto the queue.
    for reference in references.iter() {
        match reference {
            reference if reference.kind() == Kind::Request => {
                queue.push_request(*reference);
            }
            reference => {
                queue.try_reserve_response_slot().unwrap();
                queue.push_response(*reference);
            }
        }
        prop_assert_eq!(Ok(()), queue.check_invariants());
    }

    // Check the contents of the queue via `peek` and `pop`.
    while let Some(r) = queue.peek() {
        let reference = references.pop_front();
        prop_assert_eq!(reference, Some(r));
        prop_assert_eq!(reference, queue.pop());
    }

    // All references should have been consumed.
    prop_assert!(references.is_empty());
}

#[test_strategy::proptest]
fn encode_roundtrip(
    #[strategy(proptest::collection::vec_deque(arbitrary_message_reference(), 10..20))]
    references: VecDeque<InboundReference>,
    #[strategy(0..3)] reserved_slots: i32,
) {
    let mut queue = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);

    // Push all references onto the queue.
    for reference in references.iter() {
        match reference {
            reference if reference.kind() == Kind::Request => {
                queue.push_request(*reference);
            }
            reference => {
                queue.try_reserve_response_slot().unwrap();
                queue.push_response(*reference);
            }
        }
        prop_assert_eq!(Ok(()), queue.check_invariants());
    }
    // And make `reserved_slots` additional reservations.
    for _ in 0..reserved_slots {
        queue.try_reserve_response_slot().unwrap();
    }
    prop_assert_eq!(Ok(()), queue.check_invariants());

    let encoded: pb_queues::CanisterQueue = (&queue).into();
    let decoded = encoded.try_into().unwrap();

    prop_assert_eq!(queue, decoded);
}

#[test]
fn decode_inbound_message_in_output_queue_fails() {
    // Input queue with a request.
    let mut queue = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
    queue.push_request(new_request_reference(13, Class::BestEffort));
    let encoded: pb_queues::CanisterQueue = (&queue).into();

    // Cannot be decoded as an output queue.
    assert_matches!(
        OutputQueue::try_from(encoded.clone()),
        Err(ProxyDecodeError::Other(_))
    );

    // But can be decoded as an input queue.
    assert_eq!(queue, encoded.try_into().unwrap());
}

#[test]
fn decode_with_invalid_response_slots_fails() {
    // Queue with two inbound responses.
    let mut queue = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
    queue.try_reserve_response_slot().unwrap();
    queue.push_response(new_response_reference(13, Class::BestEffort));
    queue.try_reserve_response_slot().unwrap();
    queue.push_response(new_response_reference(14, Class::BestEffort));
    let encoded: pb_queues::CanisterQueue = (&queue).into();

    // Can be decoded as is.
    assert_eq!(queue, encoded.clone().try_into().unwrap());

    // But fails to decode with a too low `response_slots` value.
    let mut too_few_response_slots = encoded.clone();
    too_few_response_slots.response_slots = 1;
    assert_matches!(
        InputQueue::try_from(too_few_response_slots),
        Err(ProxyDecodeError::Other(_))
    );
}

/// This ensures `debug_asserts` are enabled, because we are passively testing invariants
/// through the function `OutputQueue::check_invariants()`, which is only called when
/// `debug_asserts` are enabled.
#[test]
#[should_panic]
fn ensure_debug_asserts_enabled() {
    debug_assert!(false);
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
        .effective_canister_id(Some(canister_test_id(num)))
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
fn ingress_filter() {
    let mut queue = IngressQueue::default();
    let msg1 = msg_from_number(1);
    let msg2 = msg_from_number(2);
    let msg3 = msg_from_number(3);
    queue.push(msg1.clone());
    queue.push(msg2.clone());
    queue.push(msg3.clone());

    assert_eq!(IngressQueue::size_bytes(&queue.queues), queue.count_bytes());

    queue.filter_messages(|ingress| *ingress != Arc::new(msg2.clone()));
    assert_eq!(queue.size(), 2);
    assert_eq!(IngressQueue::size_bytes(&queue.queues), queue.count_bytes());

    assert_eq!(queue.pop(), Some(msg1.into()));
    assert_eq!(queue.size(), 1);
    assert_eq!(IngressQueue::size_bytes(&queue.queues), queue.count_bytes());

    assert_eq!(queue.pop(), Some(msg3.into()));
    assert_eq!(queue.size(), 0);
    assert_eq!(IngressQueue::size_bytes(&queue.queues), queue.count_bytes());
}

#[test]
fn ingress_queue_empty() {
    let mut queue = IngressQueue::default();
    assert_eq!(queue.peek(), None);
    assert_eq!(queue.pop(), None);
    assert_eq!(queue.size(), 0);
    assert_eq!(queue.ingress_schedule_size(), 0);
    assert!(queue.is_empty());
}

#[test]
fn ingress_queue_round_robin_order() {
    let mut queue = IngressQueue::default();
    // First ingress for canister A
    let mut msg11 = msg_from_number(1);
    msg11.message_id = message_test_id(11);
    queue.push(msg11.clone());
    // First ingress for canister B
    let mut msg21 = msg_from_number(2);
    msg21.message_id = message_test_id(21);
    queue.push(msg21.clone());
    // Second ingress for canister A
    let mut msg22 = msg_from_number(2);
    msg22.message_id = message_test_id(22);
    queue.push(msg22.clone());
    // Second ingress for canister B
    let mut msg12 = msg_from_number(1);
    msg12.message_id = message_test_id(12);
    queue.push(msg12.clone());

    // We have 4 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 4);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is first message for canister A.
    assert_eq!(queue.peek(), Some(msg11.clone().into()));
    assert_eq!(queue.pop(), Some(msg11.into()));

    // We have 3 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 3);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is first message for canister B.
    assert_eq!(queue.peek(), Some(msg21.clone().into()));
    assert_eq!(queue.pop(), Some(msg21.into()));

    // We have 2 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 2);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is second message for canister A.
    assert_eq!(queue.peek(), Some(msg12.clone().into()));
    assert_eq!(queue.pop(), Some(msg12.into()));

    // We have 1 ingress message for 1 canister in the queue.
    assert_eq!(queue.size(), 1);
    assert_eq!(queue.ingress_schedule_size(), 1);
    assert!(!queue.is_empty());

    // The message on the front of queue is second message for canister B.
    assert_eq!(queue.peek(), Some(msg22.clone().into()));
    assert_eq!(queue.pop(), Some(msg22.into()));

    // The queue is empty.
    assert_eq!(queue.size(), 0);
    assert_eq!(queue.ingress_schedule_size(), 0);
    assert!(queue.is_empty());

    assert_eq!(queue.peek(), None);
    assert_eq!(queue.pop(), None);
}

#[test]
fn ingress_queue_round_robin_order_with_skipping_ingress_input() {
    let mut queue = IngressQueue::default();
    // First ingress for canister A
    let mut msg11 = msg_from_number(1);
    msg11.message_id = message_test_id(11);
    queue.push(msg11.clone());
    // First ingress for canister B
    let mut msg21 = msg_from_number(2);
    msg21.message_id = message_test_id(21);
    queue.push(msg21.clone());
    // Second ingress for canister A
    let mut msg22 = msg_from_number(2);
    msg22.message_id = message_test_id(22);
    queue.push(msg22.clone());
    // Second ingress for canister B
    let mut msg12 = msg_from_number(1);
    msg12.message_id = message_test_id(12);
    queue.push(msg12.clone());

    // We have 4 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 4);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is first message for canister A.
    assert_eq!(queue.peek(), Some(msg11.clone().into()));
    assert_eq!(queue.pop(), Some(msg11.into()));

    // We have 3 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 3);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is first message for canister B.
    assert_eq!(queue.peek(), Some(msg21.clone().into()));
    assert_eq!(queue.pop(), Some(msg21.into()));

    // We have 2 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 2);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is second message for canister A.
    assert_eq!(queue.peek(), Some(msg12.clone().into()));

    // We are skipping the canister A.
    queue.skip_ingress_input();

    // We still have 2 ingress messages for 2 canisters in the queue.
    assert_eq!(queue.size(), 2);
    assert_eq!(queue.ingress_schedule_size(), 2);
    assert!(!queue.is_empty());

    // The message on the front of queue is second message for canister B.
    assert_eq!(queue.peek(), Some(msg22.clone().into()));
    assert_eq!(queue.pop(), Some(msg22.into()));

    // We have 1 ingress message for 1 canister in the queue.
    assert_eq!(queue.size(), 1);
    assert_eq!(queue.ingress_schedule_size(), 1);
    assert!(!queue.is_empty());

    // The message on the front of queue is second message for canister A.
    assert_eq!(queue.peek(), Some(msg12.clone().into()));
    assert_eq!(queue.pop(), Some(msg12.into()));

    // The queue is empty.
    assert_eq!(queue.size(), 0);
    assert_eq!(queue.ingress_schedule_size(), 0);
    assert!(queue.is_empty());

    assert_eq!(queue.peek(), None);
    assert_eq!(queue.pop(), None);
}

#[test]
fn serialize_deserialize_ingress_queue() {
    let mut queue = IngressQueue::default();

    let number_of_messages_per_canister = 5;
    let number_of_canisters = 10;

    for i in 0..number_of_messages_per_canister {
        for j in 0..number_of_canisters {
            let mut ingress = msg_from_number(j);
            ingress.message_id = message_test_id(i * number_of_canisters + j);
            queue.push(ingress);
        }
    }

    let pb_vec_ingress: Vec<ic_protobuf::state::ingress::v1::Ingress> = (&queue.clone()).into();
    let mut queue_deserialized = IngressQueue::try_from(pb_vec_ingress).unwrap();

    while !queue.is_empty() {
        assert_eq!(queue.pop(), queue_deserialized.pop());
    }

    assert!(queue_deserialized.is_empty());
}
