use super::*;
use ic_test_utilities::mock_time;
use ic_test_utilities::types::{
    arbitrary,
    ids::{canister_test_id, message_test_id, user_test_id},
    messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
};
use ic_types::{messages::RequestOrResponse, QueueIndex, Time};
use proptest::prelude::*;

#[test]
fn input_queue_constructor_test() {
    let capacity: usize = 14;
    let mut queue = InputQueue::new(capacity);
    assert_eq!(queue.num_messages(), 0);
    assert!(queue.is_empty());
    assert_eq!(queue.pop(), None);
}

#[test]
fn input_queue_with_message_is_not_empty() {
    let mut input_queue = InputQueue::new(1);

    input_queue
        .push(RequestBuilder::default().build().into())
        .expect("could push");
    assert_ne!(input_queue.num_messages(), 0);
    assert!(!input_queue.is_empty());
}

#[test]
fn input_queue_with_reservation_is_not_empty() {
    let mut input_queue = InputQueue::new(1);
    input_queue.reserve_slot().unwrap();

    assert_eq!(input_queue.num_messages(), 0);
    assert!(!input_queue.is_empty());
}

/// Test affirming success on popping pushed messages.
#[test]
fn input_queue_pushed_messages_get_popped() {
    let capacity: usize = 4;
    let mut input_queue = InputQueue::new(capacity);
    let mut msg_queue = VecDeque::new();
    for _ in 0..capacity {
        let req: RequestOrResponse = RequestBuilder::default().build().into();
        msg_queue.push_back(req.clone());
        assert_eq!(Ok(()), input_queue.push(req));
    }
    while !msg_queue.is_empty() {
        assert_eq!(input_queue.pop(), msg_queue.pop_front());
    }
    assert_eq!(None, msg_queue.pop_front());
    assert_eq!(None, input_queue.pop());
}

// Pushing a message succeeds if there is space.
#[test]
fn input_queue_push_succeeds() {
    let capacity: usize = 4;
    let mut input_queue = InputQueue::new(capacity);
    input_queue
        .push(RequestBuilder::default().build().into())
        .unwrap();

    assert_eq!(1, input_queue.num_messages());
}

/// Test that overfilling an input queue with messages and reservations
/// results in failed pushes and reservations; also verifies that
/// pushes and reservations below capacity succeeds.
#[test]
fn input_queue_push_to_full_queue_fails() {
    // First fill up the queue.
    let capacity: usize = 4;
    let mut input_queue = InputQueue::new(capacity);
    for _ in 0..capacity / 2 {
        input_queue
            .push(RequestBuilder::default().build().into())
            .unwrap();
    }
    for _index in capacity / 2..capacity {
        input_queue.reserve_slot().unwrap();
    }
    assert_eq!(input_queue.num_messages(), capacity / 2);

    // Now push an extraneous message in.
    assert_eq!(
        input_queue
            .push(RequestBuilder::default().build().into(),)
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
        .push(ResponseBuilder::default().build().into())
        .unwrap_err();
}

#[test]
fn input_queue_available_slots_is_correct() {
    let capacity = 2;
    let mut input_queue = InputQueue::new(capacity);
    assert_eq!(input_queue.available_slots(), 2);
    input_queue
        .push(RequestBuilder::default().build().into())
        .unwrap();
    assert_eq!(input_queue.available_slots(), 1);
    input_queue.reserve_slot().unwrap();
    assert_eq!(input_queue.available_slots(), 0);
    assert!(input_queue.check_has_slot().is_err())
}

#[test]
fn input_queue_decode_with_non_empty_deadlines_fails() {
    let mut q = InputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for _ in 0..2 {
        let _ = q.push(RequestOrResponse::Request(
            RequestBuilder::default().build().into(),
        ));
    }
    let mut proto_queue: pb_queues::InputOutputQueue = (&q).into();
    proto_queue
        .deadline_range_ends
        .push(pb_queues::MessageDeadline {
            deadline: 0,
            index: 0,
        });
    assert!(TryInto::<InputQueue>::try_into(proto_queue).is_err());
}

#[test]
fn output_queue_constructor_test() {
    let mut queue = OutputQueue::new(14);
    assert_eq!(queue.num_messages(), 0);
    assert_eq!(queue.pop(), None);
}

#[test]
fn output_queue_with_message_is_not_empty() {
    let mut queue = OutputQueue::new(14);

    queue
        .push_request(RequestBuilder::default().build().into(), mock_time())
        .expect("could push");
    assert_eq!(queue.num_messages(), 1);
    assert!(!queue.is_empty());
}

#[test]
fn output_queue_with_reservation_is_not_empty() {
    let mut queue = OutputQueue::new(14);
    queue.reserve_slot().unwrap();

    assert_eq!(queue.num_messages(), 0);
    assert!(!queue.is_empty());
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
            .push_request(RequestBuilder::default().build().into(), mock_time())
            .unwrap();
    }
    for _index in capacity / 2..capacity {
        output_queue.reserve_slot().unwrap();
    }
    assert_eq!(output_queue.num_messages(), capacity / 2);

    // Now push an extraneous message in
    assert_eq!(
        output_queue
            .push_request(RequestBuilder::default().build().into(), mock_time(),)
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
fn output_push_without_reserved_slot_fails() {
    let mut queue = OutputQueue::new(10);
    queue.push_response(ResponseBuilder::default().build().into());
}

#[test]
fn output_queue_available_slots_is_correct() {
    let capacity = 2;
    let mut output_queue = OutputQueue::new(capacity);
    assert_eq!(output_queue.available_slots(), 2);
    output_queue
        .push_request(RequestBuilder::default().build().into(), mock_time())
        .unwrap();
    assert_eq!(output_queue.available_slots(), 1);
    output_queue.reserve_slot().unwrap();
    assert_eq!(output_queue.available_slots(), 0);
    assert!(output_queue.check_has_slot().is_err())
}

/// An explicit example of deadlines in OutputQueue, where we manually fill
/// and empty the queue, while checking whether we find what we'd expect.
/// This also checks whether num_messages is tracked correctly.
/// * Q: request
/// * P: response
/// * _j: num_messages
/// * [qi]: queue index,
/// * (d,i): deadline and index,
/// e.g. QPQ_3, [0], {(0,1), (1,3)}
#[test]
fn output_queue_explicit_push_and_pop_test() {
    let test_request = Arc::<Request>::from(RequestBuilder::default().build());
    let test_response = Arc::<Response>::from(ResponseBuilder::default().build());

    // Two deadlines will be inserted.
    let deadline_1 = Time::from_nanos_since_unix_epoch(3_u64);
    let deadline_2 = Time::from_nanos_since_unix_epoch(7_u64);

    // Create an OutputQueue, its initial state is _0, [0], {}.
    let mut q = OutputQueue::new(100);
    assert_eq!(0_usize, q.num_messages());

    // Push a request, the queue is now Q_1, [0], {(3,1)}.
    let _ = q.push_request(test_request.clone(), deadline_1);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(1_u64))
    );
    assert_eq!(1_usize, q.num_messages());

    // Push a response, the queue is now QP_2, [0], {(3,1)}.
    let _ = q.reserve_slot();
    q.push_response(test_response);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(1_u64))
    );
    assert_eq!(2_usize, q.num_messages());

    // Push a request with the same deadline, the queue is now QPQ_3, [0], {(3,3)}.
    let _ = q.push_request(test_request.clone(), deadline_1);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(3_u64))
    );
    assert_eq!(3_usize, q.num_messages());

    // Push a request with a new deadline, the queue is now QPQQ_4, [0], {(3,3), (7,4)}.
    let _ = q.push_request(test_request, deadline_2);
    assert_eq!(q.deadline_range_ends.len(), 2);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(3_u64))
    );
    assert_eq!(
        q.deadline_range_ends[1],
        (deadline_2, QueueIndex::from(4_u64))
    );
    assert_eq!(4_usize, q.num_messages());

    // Pop a request, the queue is now PQQ_3, [1], {(3,3), (7,4)}
    q.pop();
    assert_eq!(q.deadline_range_ends.len(), 2);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(3_u64))
    );
    assert_eq!(
        q.deadline_range_ends[1],
        (deadline_2, QueueIndex::from(4_u64))
    );
    assert_eq!(3_usize, q.num_messages());

    // Pop a response, the queue is now QQ_2, [2], {(3,3), (7,4)}
    q.pop();
    assert_eq!(q.deadline_range_ends.len(), 2);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(3_u64))
    );
    assert_eq!(
        q.deadline_range_ends[1],
        (deadline_2, QueueIndex::from(4_u64))
    );
    assert_eq!(2_usize, q.num_messages());

    // Pop a request, the queue is now Q_1, [3], {(7,4)}
    q.pop();
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_2, QueueIndex::from(4_u64))
    );
    assert_eq!(1_usize, q.num_messages());

    // Pop a request, the queue is now _0, [4], {}
    // We are back in the initial state, but the index has advanced to 4.
    q.pop();
    assert!(q.deadline_range_ends.is_empty());
    assert_eq!(q.index, QueueIndex::from(4_u64));
    assert_eq!(0_usize, q.num_messages());
}

prop_compose! {
    /// Generator for an arbitrary OutputQueue. This will generate an OutputQueue where the
    /// distribution of requests, responses and None are equal, e.g. 1 in 3. Invariants on
    /// OutputQueue imply num_deadlines <= num_messages. This condition is enforced silently.
    fn arb_output_queue(capacity: usize,
                        num_messages: std::ops::RangeInclusive<usize>,
                        num_deadlines: std::ops::RangeInclusive<usize>,
                        min_deadline_nanos: u64,
    ) (
        (queue, deadline_range_ends, index) in (
            num_messages,
            num_deadlines,
        )
        .prop_map(|(num_messages, mut num_deadlines)| {
            // Ensure num_deadlines <= num_messages.
            if num_deadlines > num_messages {
                num_deadlines = num_messages;
            }
            (num_messages, num_deadlines)
        })
        .prop_flat_map(move |(num_messages, num_deadlines)| {
            (
                // VecDeque of Option<RequestOrResponse> as the basis for the queue along with a
                // single RequestOrResponse to ensure the no 'None' in front invariant.
                (
                    prop::collection::vec_deque(
                        proptest::option::weighted(
                            proptest::option::prob(0.667),
                            arbitrary::request_or_response(),
                        ),
                        num_messages,
                    ),
                    arbitrary::request_or_response(),
                )
                .prop_map(|(mut q, rr)| {
                    // Make sure Some(...) is at the front.
                    if !q.is_empty() {
                        q[0] = Some(rr);
                    }
                    q
                }),

                // BTreeSet of num_deadlines unique sorted u64's as the basis for the deadlines.
                proptest::collection::btree_set(min_deadline_nanos..u64::MAX/2, num_deadlines),

                // BTreeSet of num_deadlines-1 unique sorted u64's as the basis for deadline_ends.
                // These must be in the interval (0, num_deadlines) (relative to the queue index),
                // except the last one which must be at num_deadlines.
                // Shrinking is disabled because that would concentrate the deadline ranges at the
                // front of the queue, which is not helping for our purposes.
                if num_messages == 0 || num_deadlines == 0 {
                    proptest::collection::btree_set(0..1_u64, 0)
                } else {
                    proptest::collection::btree_set(1..num_messages as u64, num_deadlines-1)
                }
                .no_shrink()
                .prop_map(move |mut btr| {
                    btr.insert(num_messages as u64);
                    btr
                }),

                // Random u64 as the basis for the queue index.
                (0..u64::MAX/2).prop_map(|index| QueueIndex::from(index)),
            )
        })
        .prop_map(|(q, deadlines, deadline_ends, index)| {
            // deadline_range_ends is generated by zipping together deadline and deadline_ends,
            // as well shifting the indices such that they start at index + 1.
            (
                q,
                deadlines
                    .into_iter()
                    .zip(deadline_ends.into_iter())
                    .map(|(t, i)| (Time::from_nanos_since_unix_epoch(t), index + i.into()))
                    .collect::<VecDeque<(Time, QueueIndex)>>(),
                index,
            )
        })
    ) -> OutputQueue {
        assert!(capacity >= queue.len());
        let num_messages = queue.iter().filter(|rr| rr.is_some()).count();
        OutputQueue {
            queue: QueueWithReservation::<Option::<RequestOrResponse>> {
                capacity,
                num_slots_reserved: 0,
                queue,
            },
            index,
            deadline_range_ends,
            timeout_index: index,
            num_messages,
        }
    }
}

proptest! {
    /// Check the invariant 'always Some at the front' and
    /// 'indices are always increasing', as well as that the final
    /// index has increased by the initial length of the queue when
    /// compared to the initial index.
    #[test]
    fn output_queue_invariants_hold(
        mut q in arb_output_queue(
            100,        // capacity
            0..=10,     // num_messages
            0..=5,      // num_deadlines
            0,          // min_deadline_nanos
        ),
    ) {
        let initial_len = q.queue.queue.len();
        let initial_index = q.index;

        let mut last_index = None;
        while q.num_messages()>0 {
            // Head is always Some(_).
            prop_assert!(q.queue.queue.front().unwrap().is_some());

            // Indices are strictly increasing.
            let (index, msg_ref) = q.peek().unwrap();
            if let Some(last_index) = last_index {
                prop_assert!(index > last_index);
            }
            last_index = Some(index);

            // Second peek() returns what the first peek returned.
            prop_assert_eq!((index, msg_ref), q.peek().unwrap());

            // pop() returns what peek() returned.
            prop_assert_eq!((index, msg_ref.clone()), q.pop().unwrap());
        }
        prop_assert_eq!((q.index - initial_index).get(), initial_len as u64);
    }
}

proptest! {
    /// Check whether the deadline_range_ends indices in bounds invariant holds
    /// when popping from an arbitrary output queue.
    #[test]
    fn output_queue_deadline_range_ends_indices_in_bounds_on_pop(
        mut q in arb_output_queue(
            100,        // capacity
            10..=20,    // num_messages
            0..=10,     // num_deadlines
            0,          // min_deadline_nanos
        ),
    ) {
        let mut ref_deadline_range_ends = q.deadline_range_ends.clone();
        while q.pop().is_some() {
            if let Some(pos) = ref_deadline_range_ends
                .iter().position(|(_, index)| q.index < *index)
            {
                ref_deadline_range_ends.drain(0..pos);
                prop_assert!(ref_deadline_range_ends
                    .iter().eq(q.deadline_range_ends.iter()));
            } else {
                prop_assert!(q.deadline_range_ends.is_empty());
                break;
            }
        }
    }

    /// Check whether all the invariants for deadline_range_ends hold when
    /// filling up a random output queue and then emptying it out.
    #[test]
    fn output_queue_deadline_range_ends_invariants_hold(
        mut q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            10..=20,                                // num_messages
            1..=10,                                 // num_deadlines
            0,                                      // min_deadline_nanos
        ),
    ) {
        let mut test_q = OutputQueue::new(q.queue.capacity);
        let mut deadlines_tracker = VecDeque::<Time>::new();

        // Fill up the queue and keep track of deadlines inserted.
        loop {
            match q.peek() {
                Some((_, RequestOrResponse::Request(req))) => {
                    let _ = test_q.push_request(req.clone(), q.deadline_range_ends[0].0);
                    deadlines_tracker.push_back(q.deadline_range_ends[0].0);
                }
                Some((_, RequestOrResponse::Response(resp))) => {
                    let _ = test_q.reserve_slot();
                    test_q.push_response(resp.clone());
                }
                None => {
                    // q is empty.
                    break;
                }
            }
            q.pop();
        }

        // Check deadline invariants.
        prop_assert!(test_q
            .deadline_range_ends
            .iter()
            .zip(test_q.deadline_range_ends.iter().skip(1))
            .all(|(a, b)| a.0 < b.0 && a.1 < b.1));
        if let Some((_, deadline_front_index)) = test_q.deadline_range_ends.front() {
            prop_assert!(*deadline_front_index < q.index);
        }
        if let Some((_, deadline_back_index)) = test_q.deadline_range_ends.back() {
            let end = test_q.index + (test_q.queue.queue.len() as u64).into();
            prop_assert!(*deadline_back_index <= end);
        }

        // Check a serialisation/deserialisation round trip, so that we check an
        // OutputQueue actually generated by the production code.
        let proto_queue: pb_queues::InputOutputQueue = (&test_q).into();
        let cmpq: OutputQueue = proto_queue.try_into().expect("bad conversion");
        prop_assert_eq!(test_q.clone(), cmpq);

        // Check number of deadlines in the queue is as expected.
        let mut unique_deadlines: Vec<Time> = deadlines_tracker.clone().into_iter().collect();
        unique_deadlines.dedup();
        prop_assert_eq!(unique_deadlines.len(), test_q.deadline_range_ends.len());

        // Empty out the queue, check deadlines popped are the same entered.
        loop {
            match test_q.peek() {
                Some((_, RequestOrResponse::Request(_))) => {
                    prop_assert_eq!(deadlines_tracker.pop_front().unwrap(),
                                    test_q.deadline_range_ends[0].0);
                    test_q.pop();
                }
                Some((_, RequestOrResponse::Response(_))) => {
                    test_q.pop();
                }
                None => {
                    // test_q is empty.
                    break;
                }
            }
        }
        prop_assert!(deadlines_tracker.is_empty());
    }

    /// Check whether the conversion to and from the protobuf version
    /// works for arbitrary output queues.
    #[test]
    fn output_queue_roundtrip_conversions(
        q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            0..=10,                                 // num_messages
            0..=5,                                  // num_deadlines
            0,                                      // min_deadline_nanos
        )
    ) {
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        let cmpq: OutputQueue = proto_queue.try_into().expect("bad conversion");

        prop_assert_eq!(q, cmpq);
    }

    /// Check the strictly sorted invariant for deadline_range_ends.
    #[test]
    fn output_queue_decode_deadline_range_ends_roundtrip_strictly_sorted_error(
        (
            shuffled_deadlines,
            shuffled_indices,
            mut q,
        ) in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            2..=10,                                 // num_messages
            2..=10,                                 // num_deadlines
            0,                                      // min_deadline_nanos
        )
        .prop_flat_map(|q| {
            // We start by shuffling a copy of the deadline_range_ends from q and a
            // random vector of 0's and 1's, to use for duplications.
            (
                Just(q.deadline_range_ends.clone()).prop_shuffle().no_shrink(),
                proptest::collection::vec(
                    0..=1_u64,
                    q.deadline_range_ends.len()-1,
                ),
                Just(q),
            )
        })
        .prop_map(|(mut shuffled_deadline_range_ends, duplications, q)| {
            // Whenever we encounter a 1, we duplicate the corresponding entry.
            // Together with the shuffling, this will result in a deadline_range_ends
            // that is not sorted and has duplicate entries.
            for i in 1..duplications.len() {
                if duplications[i] == 1_u64 {
                    shuffled_deadline_range_ends[i] = shuffled_deadline_range_ends[i-1];
                }
            }
            (shuffled_deadline_range_ends, q)
        })
        .prop_map(|(shuffled_deadline_range_ends, q)| {
            // Since we have to check both the deadlines as well as the indices
            // individually, we generate two deadline_range_ends by mixing the
            // shuffled entries with those from q.
            (
                shuffled_deadline_range_ends
                    .iter()
                    .map(|(d,_)| *d)
                    .zip(q.deadline_range_ends.iter().map(|(_,i)| *i))
                    .collect::<VecDeque<(Time, QueueIndex)>>(),
                q
                    .deadline_range_ends
                    .iter()
                    .map(|(d,_)| *d)
                    .zip(shuffled_deadline_range_ends.iter().map(|(_,i)| *i))
                    .collect::<VecDeque<(Time, QueueIndex)>>(),
                q
            )
        })
    ) {
        // Check deadlines not strictly sorted error.
        q.deadline_range_ends = shuffled_deadlines;
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        assert!(
            matches!(
                OutputQueue::try_from(proto_queue).err(),
                Some(ProxyDecodeError::ValueOutOfRange {
                    typ: "InputOutputQueue::deadline_range_ends",
                    ..
                })
            )
        );

        // Check indices not strictly sorted error.
        q.deadline_range_ends = shuffled_indices;
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        assert!(
            matches!(
                OutputQueue::try_from(proto_queue).err(),
                Some(ProxyDecodeError::ValueOutOfRange {
                    typ: "InputOutputQueue::deadline_range_ends",
                    ..
                })
            )
        );
    }

    /// Check the index out of bounds invariant for deadline_range_ends.
    #[test]
    fn output_queue_decode_deadline_range_ends_roundtrip_out_of_bounds_error(
        q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            2..=10,                                 // num_messages
            1..=10,                                 // num_deadlines
            0,                                      // min_deadline_nanos
        )
        .prop_flat_map(|q| {
            // Generate a random vector with random u64's in it.
            (
                proptest::collection::btree_set(
                    any::<u64>().prop_map(|index| QueueIndex::from(index)),
                    q.deadline_range_ends.len(),
                ),
                Just(q),
            )
        })
        .prop_filter("All indices in bounds.", |(indices, q)| {
            // Make sure it includes at least 1 entry out of bounds.
            // This will only filter a miniscule number of cases.
            let end = q.index + (q.queue.queue.len() as u64).into();
            !indices.iter().all(|i| q.index < *i && *i <= end)
        })
        .prop_map(|(random_indices, mut q)| {
            // Replace the valid indices in q.deadline_range_ends.
            for i in q.deadline_range_ends
                .iter_mut()
                .map(|(_, i)| i)
                .zip(random_indices.iter())
            {
                *i.0 = *i.1;
            }
            q
        })
    ) {
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        assert!(
            matches!(
                OutputQueue::try_from(proto_queue).err(),
                Some(ProxyDecodeError::ValueOutOfRange {
                    typ: "InputOutputQueue::index",
                    ..
                })
            )
        );
    }
}

#[test]
fn output_queue_decode_with_none_head_fails() {
    let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for _ in 0..2 {
        q.push_request(RequestBuilder::default().build().into(), mock_time())
            .unwrap();
    }
    q.queue.queue.front_mut().unwrap().take();

    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(matches!(
        OutputQueue::try_from(proto_queue).err(),
        Some(ProxyDecodeError::Other(_))
    ));
}

proptest! {
    /// Check timing out requests using an iterator. This uses a random time and then
    /// checks whether the correct entries are removed from deadline_range_ends as well as whether
    /// the correct requests are removed from the queue and returned, i.e. that no requests are lost.
    #[test]
    fn output_queue_test_time_out_requests(
        (time, mut ref_q, mut q) in arb_output_queue(
            100,        // capacity
            10..=20,    // num_messages
            0..=10,     // num_deadlines
            1000,       // min_deadline_nanos
        )
        .prop_flat_map(|q| {
            if let (Some((front_deadline, _)), Some((back_deadline, _))) =
                (q.deadline_range_ends.front(), q.deadline_range_ends.back())
            {
                // If there are deadlines, generate a random time in
                // [front_deadline - 1, back_deadline + 1].
                (
                    front_deadline.as_nanos_since_unix_epoch()-1..=
                    back_deadline.as_nanos_since_unix_epoch()+1,
                    Just(q),
                )
            } else {
                // The case of no deadlines covers the last edge case, where we expect
                // to time out nothing.
                (0..=1000_u64, Just(q))
            }
        })
        .prop_map(|(time, q)| (Time::from_nanos_since_unix_epoch(time), q.clone(), q))
    ) {
        // Time out requests and collect them in a vector manually so we can check
        // queue invariants are intact along the way.
        let mut timed_out_requests = Vec::<Arc<Request>>::new();
        while let Some(request) = q.time_out_requests(time).next() {
            if let Some(msg) = q.queue.queue.front() {
                prop_assert!(msg.is_some());
            }
            if let Some((_, deadline_range_end)) = q.deadline_range_ends.front() {
                prop_assert!(q.index < *deadline_range_end);
                prop_assert!(q.timeout_index < *deadline_range_end);
            }
            timed_out_requests.push(request);
        }

        // Check the number of messages is tracked correctly.
        prop_assert_eq!(ref_q.num_messages(), q.num_messages() + timed_out_requests.len());

        // Check the deadlines used and then those still remaining
        // are the same deadlines that were there initially.
        prop_assert!(ref_q
            .deadline_range_ends
            .iter()
            .filter(|(deadline, deadline_index)| *deadline <= time || *deadline_index <= q.index)
            .chain(q.deadline_range_ends.iter())
            .eq(ref_q.deadline_range_ends.iter()));

        // Check relevant deadlines are still there, and timeout_index is in
        // the corresponding deadline range.
        if let Some((deadline, deadline_index)) = q.deadline_range_ends.front() {
            prop_assert!(time < *deadline);
            prop_assert!(q.timeout_index < *deadline_index);
        }

        // Pop from both queues and compare. Check that as long as there are requests in
        // timed_out_requests we can use those to compare them to the requests in ref_q and
        // once timed_out_requests is empty we can directly compare q and ref_q. Responses
        // should come out naturally from both queues.
        // This ensures timing out happened for all requests with a deadline <= time,
        // but not for any of the requests after that.
        let mut timed_out_requests_iter = timed_out_requests.into_iter();
        while let Some((ref_index, rr)) = ref_q.pop() {
            match rr {
                RequestOrResponse::Response(ref_response) => {
                    if let Some((index, RequestOrResponse::Response(response))) = q.pop() {
                        prop_assert_eq!(ref_index, index);
                        prop_assert_eq!(ref_response, response);
                    } else {
                        prop_assert!(false, "bad queue after time out");
                    }
                }
                RequestOrResponse::Request(ref_request) => {
                    if let Some(request) = timed_out_requests_iter.next() {
                        prop_assert_eq!(ref_request, request);
                    } else if let Some((index, RequestOrResponse::Request(request))) = q.pop() {
                        prop_assert_eq!(ref_index, index);
                        prop_assert_eq!(ref_request, request);
                    } else {
                        prop_assert!(false, "bad queue after time out");
                    }
                }
            }
        }

        // Consistency check, if one queue is empty, the other must also be empty.
        prop_assert_eq!(0, q.num_messages());
    }

    /// Check timing out requests where we reset the timeout_index during
    /// a two stage timing out process to see whether the result is the same as
    /// wituout resetting it. This situation can arise during deserializing
    /// because the timeout_index is not persisted.
    #[test]
    fn output_queue_time_out_requests_with_index_reset(
        (mut ref_q, mut q) in arb_output_queue(
            100,        // capacity
            10..=20,    // num_messages
            2..=2,      // num_deadlines
            0,          // min_deadline_nanos
        )
        .prop_filter(
            // Filter cases where the queue only has None after the first
            // deadline range since for this case, the test makes no sense.
            "Queue with no messages past the first deadline range",
            |q| {
                q
                    .queue
                    .queue
                    .iter()
                    .skip(q.deadline_range_ends.front().unwrap().1.get() as usize)
                    .all(|rr| rr.is_none())
        })
        .prop_map(|q| (q.clone(), q))
    ) {
        // We use the first deadline as the time for the first step.
        let time = q.deadline_range_ends.front().unwrap().0;

        // Time out requests for the first deadline range on both queues.
        ref_q.time_out_requests(time).count();
        q.time_out_requests(time).count();

        // Reset the timeout_index to 0 for q.
        q.timeout_index = QueueIndex::from(0);

        // We use 'eternity' as the time for the second step.
        let time = Time::from_nanos_since_unix_epoch(u64::MAX);

        // Time out the rest of the requests.
        let ref_requests = ref_q.time_out_requests(time).collect::<Vec<Arc<Request>>>();
        let requests = q.time_out_requests(time).collect::<Vec<Arc<Request>>>();

        // Make sure the two queues are the same.
        prop_assert!(q.timeout_index <= ref_q.timeout_index);
        prop_assert_eq!(ref_q, q);

        // Make sure the timed out requests for the second step are the same.
        prop_assert_eq!(ref_requests, requests);
    }
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
