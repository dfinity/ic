use super::*;
use ic_test_utilities_types::{
    arbitrary,
    ids::{canister_test_id, message_test_id, user_test_id},
    messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
};
use ic_types::{messages::RequestOrResponse, time::UNIX_EPOCH, Time};
use proptest::prelude::*;

#[test]
fn input_queue_constructor_test() {
    let capacity: usize = 14;
    let mut queue = InputQueue::new(capacity);
    assert_eq!(queue.num_messages(), 0);
    assert!(!queue.has_used_slots());
    assert_eq!(queue.pop(), None);
}

#[test]
fn input_queue_with_message_is_not_empty() {
    let mut input_queue = InputQueue::new(1);

    input_queue
        .push(RequestBuilder::default().build().into())
        .expect("could push");
    assert_ne!(input_queue.num_messages(), 0);
    assert!(input_queue.has_used_slots());
}

#[test]
fn input_queue_with_reservation_is_not_empty() {
    let mut input_queue = InputQueue::new(1);
    input_queue.reserve_slot().unwrap();

    assert_eq!(input_queue.num_messages(), 0);
    assert!(input_queue.has_used_slots());
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

/// Pushing a request succeeds if there is space.
/// Reserving a slot, then pushing a response succeeds if there is space.
#[test]
fn input_queue_push_succeeds() {
    let capacity: usize = 1;
    let mut input_queue = InputQueue::new(capacity);

    // Push request.
    assert_eq!(input_queue.queue.available_request_slots(), 1);
    input_queue
        .push(RequestBuilder::default().build().into())
        .unwrap();
    assert_eq!(input_queue.queue.available_request_slots(), 0);
    assert!(input_queue.check_has_request_slot().is_err());

    // Push response.
    assert_eq!(input_queue.queue.available_response_slots(), 1);
    input_queue.reserve_slot().unwrap();
    assert_eq!(input_queue.queue.available_response_slots(), 0);
    input_queue
        .push(ResponseBuilder::default().build().into())
        .unwrap();
    assert_eq!(input_queue.queue.available_response_slots(), 0);

    assert_eq!(2, input_queue.num_messages());
}

/// Test that overfilling an input queue with messages and reservations
/// results in failed pushes and reservations; also verifies that
/// pushes and reservations below capacity succeed.
#[test]
fn input_queue_push_to_full_queue_fails() {
    // First fill up the queue.
    let capacity: usize = 2;
    let mut input_queue = InputQueue::new(capacity);
    for _ in 0..capacity {
        input_queue
            .push(RequestBuilder::default().build().into())
            .unwrap();
    }
    for _index in 0..capacity {
        input_queue.reserve_slot().unwrap();
    }
    assert_eq!(input_queue.num_messages(), capacity);

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
fn input_queue_push_response_without_reservation_fails() {
    let mut queue = InputQueue::new(10);
    queue
        .push(ResponseBuilder::default().build().into())
        .unwrap_err();
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
        .push_request(RequestBuilder::default().build().into(), UNIX_EPOCH)
        .expect("could push");
    assert_eq!(queue.num_messages(), 1);
    assert!(queue.has_used_slots());
}

#[test]
fn output_queue_with_reservation_is_not_empty() {
    let mut queue = OutputQueue::new(14);
    queue.reserve_slot().unwrap();

    assert_eq!(queue.num_messages(), 0);
    assert!(queue.has_used_slots());
}

// Pushing a request succeeds if there is space.
#[test]
fn output_queue_push_request_succeeds() {
    let capacity: usize = 1;
    let mut output_queue = OutputQueue::new(capacity);

    assert_eq!(output_queue.queue.available_request_slots(), 1);
    output_queue
        .push_request(RequestBuilder::default().build().into(), UNIX_EPOCH)
        .unwrap();
    assert_eq!(output_queue.queue.available_request_slots(), 0);
    assert!(output_queue.check_has_request_slot().is_err());

    assert_eq!(1, output_queue.num_messages());
}

// Reserving a slot, then pushing a response succeeds if there is space.
#[test]
fn output_queue_push_response_succeeds() {
    let capacity: usize = 1;
    let mut output_queue = OutputQueue::new(capacity);

    assert_eq!(output_queue.queue.available_response_slots(), 1);
    output_queue.reserve_slot().unwrap();
    assert_eq!(output_queue.queue.available_response_slots(), 0);
    output_queue.push_response(ResponseBuilder::default().build().into());
    assert_eq!(output_queue.queue.available_response_slots(), 0);

    assert_eq!(1, output_queue.num_messages());
}

/// Test that overfilling an output queue with messages and reservations
/// results in failed pushes and reservations; also verifies that
/// pushes and reservations below capacity succeeds.
#[test]
fn output_queue_push_to_full_queue_fails() {
    // First fill up the queue.
    let capacity: usize = 2;
    let mut output_queue = OutputQueue::new(capacity);
    for _index in 0..capacity {
        output_queue
            .push_request(RequestBuilder::default().build().into(), UNIX_EPOCH)
            .unwrap();
    }
    for _index in 0..capacity {
        output_queue.reserve_slot().unwrap();
    }
    assert_eq!(output_queue.num_messages(), capacity);

    // Now push an extraneous message in
    assert_eq!(
        output_queue
            .push_request(RequestBuilder::default().build().into(), UNIX_EPOCH,)
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

/// An explicit example of deadlines in OutputQueue, where we manually fill
/// and empty the queue, while checking whether we find what we'd expect.
/// This test also ensures `push_request` and `push_response` don't increment
/// the queue begin index, but `pop` does (by 1).
#[test]
fn output_queue_explicit_push_and_pop_test() {
    let mut q = OutputQueue::new(100);
    assert_eq!(0, q.num_messages());

    let test_request = Arc::<Request>::from(RequestBuilder::default().build());
    let test_response = Arc::<Response>::from(ResponseBuilder::default().build());
    let deadline1 = Time::from_nanos_since_unix_epoch(3);
    let deadline2 = Time::from_nanos_since_unix_epoch(7);

    q.push_request(test_request.clone(), deadline1).unwrap();
    q.reserve_slot().unwrap();
    q.push_response(test_response);
    q.push_request(test_request.clone(), deadline1).unwrap();
    q.push_request(test_request, deadline2).unwrap();

    assert_eq!(4, q.num_messages());
    assert_eq!(0, q.begin);
    assert_eq!(
        VecDeque::from(vec![(deadline1, 3), (deadline2, 4)]),
        q.deadline_range_ends
    );

    let timeout_index = q.timeout_index;
    assert!(matches!(q.pop().unwrap(), RequestOrResponse::Request(_)));
    assert_eq!(3, q.num_messages());
    assert_eq!(1, q.begin);
    assert_eq!(timeout_index, q.timeout_index);
}

/// This ensures `debug_asserts` are enabled, because we are passively testing invariants
/// through the function `OutputQueue::check_invariants()`, which is only called when
/// `debug_asserts` are enabled.
#[test]
#[should_panic]
fn ensure_debug_asserts_enabled() {
    debug_assert!(false);
}

proptest! {
    /// Checks `push_request` enforces `OutputQueue` invariants. This is implicitly checked at
    /// the bottom of `OutputQueue::push_request()`. There is another explicit check here after
    /// the fact to ensure this test doesn't just silently pass if the implicit check is removed.
    /// Additionally, an expected `deadline_range_ends` is reconstructed and then compared to
    /// the actual version at at the end.
    #[test]
    fn output_queue_push_request_enforces_invariants(
        (requests, deadlines) in (2..=10_usize)
        .prop_flat_map(|num_requests| {
            (
                proptest::collection::vec(
                    arbitrary::request().prop_map(Arc::from),
                    num_requests,
                ),
                proptest::collection::vec(
                    (0..=1000_u64).prop_map(Time::from_nanos_since_unix_epoch),
                    num_requests,
                ),
            )
        })
    ) {
        let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
        let mut expected_deadline_range_ends = VecDeque::<(Time, usize)>::new();

        let mut index = 1;
        for (request, deadline) in requests
            .into_iter()
            .zip(deadlines.into_iter())
        {
            q.push_request(request, deadline).unwrap();

            match expected_deadline_range_ends.back_mut() {
                Some((back_deadline, end)) if *back_deadline >= deadline => {
                    *end = index;
                }
                _ => {
                    expected_deadline_range_ends.push_back((deadline, index));
                }
            }

            index += 1;
        }

        prop_assert!(q.check_invariants());
        prop_assert_eq!(expected_deadline_range_ends, q.deadline_range_ends);
    }
}

prop_compose! {
    /// Generator for an arbitrary `OutputQueue` where nothing is timed out. An arbitrary number
    /// of execution rounds is simulated by starting with round boundaries (in terms of messages
    /// pushed onto the queue by the end of the respective round) [1, 2, ... num_msgs]; and removing
    /// a random subset thereof.
    fn arb_output_queue_no_timeout(num_msgs: std::ops::RangeInclusive<usize>) (
        begin in 0..10_usize,
        (msgs, indices_to_remove) in num_msgs
        .prop_flat_map(|num_msgs| {
            (
                proptest::collection::vec(arbitrary::request_or_response(), num_msgs),
                proptest::collection::vec(any::<usize>(), 0..=num_msgs),
            )
        })
    ) -> OutputQueue {

        let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
        q.begin = begin;

        // Boundaries of execution rounds.
        let mut range_ends = (0..=msgs.len()).collect::<Vec<usize>>();
        for i in indices_to_remove {
            range_ends.remove(i % range_ends.len());
        }
        range_ends.push(usize::MAX);

        // Push messages on the queue. The deadlines start at 10 so that
        // there is some room to pick a random time from that won't time out
        // anything.
        let mut round = 0;
        for (i, msg) in msgs.into_iter().enumerate() {
            if range_ends[round] == i {
                round += 1;
            }
            match msg {
                RequestOrResponse::Request(request) => {
                    q.push_request(
                        request,
                        Time::from_nanos_since_unix_epoch((10 + round) as u64),
                    ).unwrap();
                }
                RequestOrResponse::Response(response) => {
                    q.reserve_slot().unwrap();
                    q.push_response(response);
                }
            }
        }
        q.check_invariants();

        q
    }
}

prop_compose! {
    /// Generator for an arbitrary time in the interval [min_deadline - 5, max_deadline + 5]
    /// for an arbitrary `OutputQueue`. Returns 0 if there are no deadlines in the queue.
    fn arb_time_for_output_queue_timeouts(q: &OutputQueue) (
        time in {
            // Find time for timing out in [min_deadline-5, max_deadline+5].
            if let (Some((min_deadline, _)), Some((max_deadline, _))) =
                (q.deadline_range_ends.front(), q.deadline_range_ends.back())
            {
                let min_deadline = min_deadline.as_nanos_since_unix_epoch();
                let max_deadline = max_deadline.as_nanos_since_unix_epoch();
                min_deadline - 5 ..= max_deadline + 5
            } else {
                0..=0_u64
            }
        },
    ) -> Time {
        Time::from_nanos_since_unix_epoch(time)
    }
}

prop_compose! {
    /// Generator for an arbitrary `OutputQueue` where requests are (partially) timed out.
    /// The time for timing out is chosen in the interval [min_deadline - 5, max_deadline+ 5]
    /// such that it encompasses edge cases.
    fn arb_output_queue() (
        (time, num_pop, mut q) in arb_output_queue_no_timeout(5..=20)
        .prop_flat_map(|q| (arb_time_for_output_queue_timeouts(&q), 0..3_usize, Just(q)))

    ) -> OutputQueue {
        q.time_out_requests(time).count();
        q.check_invariants();

        // Pop a few messages to somewhat randomize `timeout_index`.
        for _ in 0..num_pop {
            q.pop();
        }

        q
    }
}

proptest! {
    /// Check timing out requests using an iterator. This uses a random time and then
    /// checks that requests whose deadline has expired are extracted from the queue,
    /// but the corresponding responses remain.
    #[test]
    fn output_queue_test_time_out_requests(
        (time, mut q) in arb_output_queue()
        .prop_flat_map(|q| (arb_time_for_output_queue_timeouts(&q), Just(q)))
    ) {
        let mut ref_q = q.clone();

        let mut timed_out_requests = q
            .time_out_requests(time)
            .map(RequestOrResponse::Request)
            .collect::<VecDeque<_>>();

        q.check_invariants();

        // Check there are no `None` at or after `timeout_index`.
        if !timed_out_requests.is_empty() {
            prop_assert!(q
                .queue
                .queue
                .iter()
                .skip(q.timeout_index - q.begin)
                .all(|msg| msg.is_some()));
        }

        while let Some((deadline, _)) = ref_q.deadline_range_ends.front() {
            if *deadline > time {
                break;
            }
            match ref_q.peek() {
                Some(RequestOrResponse::Response(_)) => {
                    prop_assert_eq!(ref_q.pop(), q.pop());
                }
                Some(RequestOrResponse::Request(_)) => {
                    prop_assert_eq!(ref_q.pop(), timed_out_requests.pop_front());
                }
                None => unreachable!(),
            }
        }

        // `ref_q` and `q` must be the same after popping all messages from the
        // time outed section, except `timeout_index` was not updated since we
        // never timed out anything for `ref_q`.
        ref_q.timeout_index = q.timeout_index;
        prop_assert_eq!(ref_q, q);
    }
}

/// Check whether a timed out request produces back pressure.
#[test]
fn output_queue_check_back_pressure_with_timed_out_requests() {
    let mut q = OutputQueue::new(1);

    q.reserve_slot().unwrap();
    q.push_response(Arc::new(ResponseBuilder::default().build()));

    q.push_request(
        Arc::new(RequestBuilder::default().build()),
        Time::from_nanos_since_unix_epoch(1),
    )
    .unwrap();
    q.time_out_requests(Time::from_nanos_since_unix_epoch(u64::MAX))
        .count();

    assert!(q
        .push_request(
            Arc::new(RequestBuilder::default().build()),
            Time::from_nanos_since_unix_epoch(1),
        )
        .is_err());
}

proptest! {
    /// Check whether the conversion to and from the protobuf version
    /// works for arbitrary output queues.
    #[test]
    fn output_queue_roundtrip_conversions(
        q in arb_output_queue()
    ) {
        let proto_queue: pb_queues::InputOutputQueue = (&q).into();
        let deserialized_q: OutputQueue = proto_queue.try_into().expect("bad conversion");

        prop_assert_eq!(q, deserialized_q);
    }
}

/// Generates a simple `OutputQueue` holding a specified number of requests,
/// each with a unique deadline.
fn generate_test_queue(num_requests: usize) -> OutputQueue {
    let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for t in 1..=num_requests {
        q.push_request(
            RequestBuilder::default().build().into(),
            Time::from_nanos_since_unix_epoch(t as u64),
        )
        .unwrap();
    }
    q
}

#[test]
fn output_queue_test_has_expired_deadlines() {
    let end_of_time = Time::from_nanos_since_unix_epoch(u64::MAX);

    let q = generate_test_queue(0);
    assert!(!q.has_expired_deadlines(end_of_time));

    let q = generate_test_queue(1);
    assert!(!q.has_expired_deadlines(Time::from_nanos_since_unix_epoch(0)));
    assert!(q.has_expired_deadlines(end_of_time));
}

#[test]
fn output_queue_decode_with_deadlines_not_strictly_sorted_fails() {
    let mut q = generate_test_queue(2);

    // Check duplicate deadline range end causes error.
    let deadline = q.deadline_range_ends[0].0;
    q.deadline_range_ends[0].0 = q.deadline_range_ends[1].0;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());

    // Check swapped deadline range ends cause error.
    q.deadline_range_ends[1].0 = deadline;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());
}

#[test]
fn output_queue_decode_with_deadline_indices_not_strictly_sorted_fails() {
    let mut q = generate_test_queue(2);

    // Check duplicate deadline range end causes error.
    let index = q.deadline_range_ends[0].1;
    q.deadline_range_ends[0].1 = q.deadline_range_ends[1].1;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());

    // Check swapped deadline range ends cause error.
    q.deadline_range_ends[1].1 = index;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());
}

#[test]
fn output_queue_decode_with_deadlines_index_out_of_bounds_fails() {
    let mut q = generate_test_queue(1);
    q.begin = 1;

    // Check deadline index before the queue causes error.
    q.deadline_range_ends[0].1 = 0;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());

    // Check deadline index after the queue causes error.
    q.deadline_range_ends[0].1 = 3;
    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(OutputQueue::try_from(proto_queue).is_err());
}

#[test]
fn output_queue_decode_with_none_head_fails() {
    let mut q = OutputQueue::new(super::super::DEFAULT_QUEUE_CAPACITY);
    for _ in 0..2 {
        q.push_request(RequestBuilder::default().build().into(), UNIX_EPOCH)
            .unwrap();
    }
    q.queue.queue.front_mut().unwrap().take();

    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    assert!(matches!(
        OutputQueue::try_from(proto_queue).err(),
        Some(ProxyDecodeError::Other(_))
    ));
}

// Creates an `OutputQueue` from a VecDeque directly to allow for roundtrips with
// `queue.len() > capacity`.
fn output_queue_roundtrip_from_vec_deque(
    queue: VecDeque<Option<RequestOrResponse>>,
    num_request_slots: usize,
    num_response_slots: usize,
    num_messages: usize,
) -> Result<OutputQueue, ProxyDecodeError> {
    let q = OutputQueue {
        queue: QueueWithReservation::<Option<RequestOrResponse>> {
            queue,
            capacity: super::super::DEFAULT_QUEUE_CAPACITY,
            num_response_slots,
            num_request_slots,
        },
        begin: 0,
        deadline_range_ends: VecDeque::new(),
        timeout_index: 0,
        num_messages,
    };

    let proto_queue: pb_queues::InputOutputQueue = (&q).into();
    TryInto::<OutputQueue>::try_into(proto_queue)
}

#[test]
fn output_queue_decode_check_num_requests_and_responses() {
    let capacity = super::super::DEFAULT_QUEUE_CAPACITY;
    let half_capacity = capacity / 2;

    let mut queue = VecDeque::new();

    for _ in 0..half_capacity {
        queue.push_back(Some(RequestOrResponse::Request(
            RequestBuilder::default().build().into(),
        )));
    }
    for _ in half_capacity..capacity {
        queue.push_back(None);
    }
    for _ in 0..half_capacity {
        queue.push_back(Some(RequestOrResponse::Response(
            ResponseBuilder::default().build().into(),
        )));
    }
    let num_request_slots = capacity;
    let num_response_slots = capacity;
    let num_messages = 2 * half_capacity;
    assert!(output_queue_roundtrip_from_vec_deque(
        queue.clone(),
        num_request_slots,
        num_response_slots,
        num_messages
    )
    .is_ok());

    // Check we get an error with one more request.
    queue.push_back(Some(RequestOrResponse::Request(
        RequestBuilder::default().build().into(),
    )));
    assert!(output_queue_roundtrip_from_vec_deque(
        queue.clone(),
        num_request_slots + 1,
        num_response_slots,
        num_messages + 1,
    )
    .is_err());
    queue.pop_back();

    // Check we get an error with one more `None`.
    queue.push_back(None);
    assert!(output_queue_roundtrip_from_vec_deque(
        queue.clone(),
        num_request_slots + 1,
        num_response_slots,
        num_messages
    )
    .is_err());
    queue.pop_back();

    // Check we get an error with one more response.
    queue.push_back(Some(RequestOrResponse::Response(
        ResponseBuilder::default().build().into(),
    )));
    assert!(output_queue_roundtrip_from_vec_deque(
        queue.clone(),
        num_request_slots,
        num_response_slots + 1,
        num_messages + 1,
    )
    .is_err());
    queue.pop_back();

    // Check we get an error with one more reservation.
    assert!(output_queue_roundtrip_from_vec_deque(
        queue.clone(),
        num_request_slots,
        num_response_slots + 1,
        num_messages,
    )
    .is_err());
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

    queue.filter_messages(|ingress| *ingress != Arc::new(msg2.clone()));
    assert_eq!(queue.size(), 2);
    assert_eq!(queue.pop(), Some(msg1.into()));
    assert_eq!(queue.size(), 1);
    assert_eq!(queue.pop(), Some(msg3.into()));
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
