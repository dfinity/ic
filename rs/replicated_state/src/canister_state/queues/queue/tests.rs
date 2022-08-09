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
fn input_queue_push_succeeds_with_queue_index_none() {
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

    assert_eq!(QueueIndex::from(2), input_queue.index);
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
fn input_queue_decode_with_non_empty_deadlines_fails() {
    let mut q = InputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for i in 0..2_u64 {
        let _ = q.push(
            QueueIndex::from(i),
            RequestOrResponse::Request(RequestBuilder::default().build().into()),
        );
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
        .push_request(RequestBuilder::default().build().into(), mock_time())
        .unwrap();
    assert_eq!(output_queue.available_slots(), 1);
    output_queue.reserve_slot().unwrap();
    assert_eq!(output_queue.available_slots(), 0);
    assert!(output_queue.check_has_slot().is_err())
}

/// An explicit example of deadlines in OutputQueue, where we manually fill
/// and empty the queue, while checking whether we find what we'd expect.
/// * Q: request
/// * P: response
/// * [qi]: queue index,
/// * (d,i): deadline and index,
/// e.g. QPQ, [0], {(0,1), (1,3)}
#[test]
fn output_queue_explicit_deadline_range_ends_test() {
    let test_request = Arc::<Request>::from(RequestBuilder::default().build());
    let test_response = Arc::<Response>::from(ResponseBuilder::default().build());

    // Two deadlines will be inserted.
    let deadline_1 = Time::from_nanos_since_unix_epoch(3_u64);
    let deadline_2 = Time::from_nanos_since_unix_epoch(7_u64);

    // Create an OutputQueue, its initial state is _, [0], {}.
    let mut q = OutputQueue::new(100);

    // Push a request, the queue is now Q, [0], {(3,1)}.
    let _ = q.push_request(test_request.clone(), deadline_1);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(1_u64))
    );

    // Push a response, the queue is now QP, [0], {(3,1)}.
    let _ = q.reserve_slot();
    q.push_response(test_response);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(1_u64))
    );

    // Push a request with the same deadline, the queue is now QPQ, [0], {(3,3)}.
    let _ = q.push_request(test_request.clone(), deadline_1);
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_1, QueueIndex::from(3_u64))
    );

    // Push a request with a new deadline, the queue is now QPQQ, [0], {(3,3), (7,4)}.
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

    // Pop a request, the queue is now PQQ, [1], {(3,3), (7,4)}
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

    // Pop a response, the queue is now QQ, [2], {(3,3), (7,4)}
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

    // Pop a request, the queue is now Q, [3], {(7,4)}
    q.pop();
    assert_eq!(q.deadline_range_ends.len(), 1);
    assert_eq!(
        q.deadline_range_ends[0],
        (deadline_2, QueueIndex::from(4_u64))
    );

    // Pop a request, the queue is now _, [4], {}
    // We are back in the initial state, but the index has advanced to 4.
    q.pop();
    assert!(q.deadline_range_ends.is_empty());
    assert_eq!(q.index, QueueIndex::from(4_u64));
}

prop_compose! {
    /// Generator for an arbitrary OutputQueue. This will generate an OutputQueue where the
    /// distribution of requests, responses and None are equal, e.g. 1 in 3. Invariants on
    /// OutputQueue imply num_deadlines <= num_messages. This condition is enforced silently
    /// and min_deadlines is guaranteed only if min_deadlines <= min_messages.
    fn arb_output_queue(capacity: usize,
                        min_messages: usize,
                        max_messages: usize,
                        min_deadlines: usize,
                        max_deadlines: usize,
    ) (
        (queue, index, deadline_range_ends) in (
            prop::collection::vec_deque(
                proptest::option::weighted(
                    proptest::option::prob(0.667),
                    arbitrary::request_or_response(),
                ),
                min_messages..=max_messages,
            ),
            arbitrary::request_or_response(),
        )
        .prop_map(|(mut q, rr)| {
            // OutputQueue has the invariant that None may not be at the front.
            // To keep the statistics, we try to rotate Some(...) in front, only
            // if there are only None, we overwrite the front.
            if let Some(i) = q.iter().position(|rr| rr.is_some()) {
                q.rotate_left(i);
            } else if !q.is_empty() {
                q[0] = Some(rr);
            }
            q
        })
        .prop_flat_map(move |q| {
            // Generate a vector of random times as the basis for deadline_range_ends.
            (proptest::collection::vec(1..1000_u64, min_deadlines..=max_deadlines), Just(q))
        })
        .prop_flat_map(|(mut random_times, q)| {
            // Make sure there are q.len() random times, possibly filling with up with 0's,
            // then shuffle to get a vector of random_times with 0's interspersed randomly.
            random_times.resize(q.len(), 0_u64);
            (
                Just(random_times).prop_shuffle().no_shrink(),
                (0..u64::MAX/2).prop_map(|index| QueueIndex::from(index)),
                Just(q),
            )
        })
        .prop_map(|(mut random_times, index, q)| {
            // We turn random_times into a step function by progressively adding
            // the immediate predecessor.
            if random_times.len() > 1 {
                for i in 1..random_times.len() {
                    random_times[i] += random_times[i-1];
                }
            }
            // Finally, we generate a deadline_range_ends, by pushing in the random_times.
            let mut deadline_range_ends = VecDeque::<(Time, QueueIndex)>::new();
            for (time, index) in random_times
                .iter()
                .enumerate()
                .map(|(i,t)|
                    (Time::from_nanos_since_unix_epoch(*t), index + (i as u64 + 1).into())
                )
            {
                match deadline_range_ends.back_mut() {
                    Some((deadline, end_index)) if *deadline == time => {
                        *end_index = index;
                    }
                    _ => {
                        deadline_range_ends.push_back((time, index));
                    }
                }
            }
            (q, index, deadline_range_ends)
        })
    ) -> OutputQueue {
        assert!(capacity >= queue.len());
        OutputQueue {
            queue: QueueWithReservation::<Option::<RequestOrResponse>> {
                capacity,
                num_slots_reserved: 0,
                queue,
            },
            index,
            deadline_range_ends,
        }
    }
}

proptest! {
    /// Proptest for invariants on output queues.
    /// Checks the invariant 'always Some at the front' and
    /// 'indices are always increasing', as well as that the final
    /// index has increased by the initial length of the queue when
    /// compared to the initial index.
    #[test]
    fn output_queue_invariants_hold(
        mut q in arb_output_queue(
            100,    // capacity
            0,      // min_messages
            10,     // max_messages
            0,      // min_deadlines
            5,      // max_deadlines
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
    /// Proptest to check whether the deadline_range_ends indices in bounds
    /// invariant holds when popping from an arbitrary output queue.
    #[test]
    fn output_queue_deadline_range_ends_indices_in_bounds_on_pop(
        mut q in arb_output_queue(
            100,    // capacity
            10,     // min_messages
            20,     // max_messages
            0,      // min_deadlines
            10,     // max_deadlines
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

    /// Proptest to check whether all the invariants for deadline_range_ends
    /// hold when filling up a random output queue and then emptying it out.
    #[test]
    fn output_queue_deadline_range_ends_invariants_hold(
        mut q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,       // capacity
            10,                                         // min_messages
            20,                                         // max_messages
            1,                                          // min_deadlines
            10,                                         // max_deadlines
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
            let back_index = test_q.index + (test_q.queue.queue.len() as u64).into();
            prop_assert!(*deadline_back_index <= back_index);
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

    /// Proptest for arbitrary output queues to check whether
    /// the conversion to and from for protobuf versions works.
    #[test]
    fn output_queue_roundtrip_conversions(
        q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            0,                                      // min_messages
            10,                                     // max_messages
            0,                                      // min_deadline
            5,                                      // max_deadline
        )
    ) {
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        let cmpq: OutputQueue = proto_queue.try_into().expect("bad conversion");

        prop_assert_eq!(q, cmpq);
    }

    /// Proptest to check the strictly sorted invariant for deadline_range_ends.
    #[test]
    fn output_queue_decode_deadline_range_ends_roundtrip_strictly_sorted_error(
        (
            shuffled_deadlines,
            shuffled_indices,
            mut q,
        ) in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            2,                                      // min_messages
            10,                                     // max_messages
            2,                                      // min_deadlines
            10,                                     // max_deadlines
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

    /// Proptest to check the index out of bounds invariant for deadline_range_ends.
    #[test]
    fn output_queue_decode_deadline_range_ends_roundtrip_out_of_bounds_error(
        q in arb_output_queue(
            super::super::DEFAULT_QUEUE_CAPACITY,   // capacity
            2,                                      // min_messages
            10,                                     // max_messages
            1,                                      // min_deadlines
            10,                                     // max_deadlines
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
            let back_index = q.index + (q.queue.queue.len() as u64).into();
            !indices.iter().all(|i| *i > q.index && *i <= back_index)
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
