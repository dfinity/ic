use super::{
    testing::{new_canister_queues_for_test, CanisterQueuesTesting},
    *,
};
use ic_interfaces::messages::CanisterInputMessage;
use ic_test_utilities::{
    state::{arb_num_receivers, assert_next_eq},
    types::{
        arbitrary,
        ids::{canister_test_id, message_test_id, user_test_id},
        messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
    },
};
use ic_types::time::current_time_and_expiry_time;
use proptest::prelude::*;
use std::convert::TryInto;

/// Can push one request to the output queues.
#[test]
fn can_push_output_request() {
    let this = canister_test_id(13);
    let mut queues = CanisterQueues::default();
    queues
        .push_output_request(RequestBuilder::default().sender(this).build())
        .unwrap();
}

/// Cannot push response to output queues without pushing an input request
/// first.
#[test]
#[should_panic(expected = "pushing response into inexistent output queue")]
fn cannot_push_output_response_without_input_request() {
    let this = canister_test_id(13);
    let mut queues = CanisterQueues::default();
    queues.push_output_response(ResponseBuilder::default().respondent(this).build());
}

#[test]
fn enqueuing_unexpected_response_does_not_panic() {
    let other = canister_test_id(14);
    let this = canister_test_id(13);
    let mut queues = CanisterQueues::default();
    // Enqueue a request to create a queue for `other`.
    queues
        .push_input(
            QueueIndex::from(0),
            RequestBuilder::default()
                .sender(other)
                .receiver(this)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    // Now `other` sends an unexpected `Response`.  We should return an error not
    // panic.
    queues
        .push_input(
            QUEUE_INDEX_NONE,
            ResponseBuilder::default()
                .respondent(other)
                .originator(this)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap_err();
}

/// Can push response to output queues after pushing input request.
#[test]
fn can_push_output_response_after_input_request() {
    let this = canister_test_id(13);
    let other = canister_test_id(14);
    let mut queues = CanisterQueues::default();
    queues
        .push_input(
            QueueIndex::from(0),
            RequestBuilder::default()
                .sender(other)
                .receiver(this)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    queues.push_output_response(
        ResponseBuilder::default()
            .respondent(this)
            .originator(other)
            .build(),
    );
}

/// Can push one request to the induction pool.
#[test]
fn can_push_input_request() {
    let this = canister_test_id(13);
    let mut queues = CanisterQueues::default();
    queues
        .push_input(
            QueueIndex::from(0),
            RequestBuilder::default().receiver(this).build().into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

/// Cannot push response to the induction pool without pushing output
/// request first.
#[test]
fn cannot_push_input_response_without_output_request() {
    let this = canister_test_id(13);
    let mut queues = CanisterQueues::default();
    queues
        .push_input(
            QueueIndex::from(0),
            ResponseBuilder::default().originator(this).build().into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap_err();
}

/// Can push response to input queues after pushing request to output
/// queues.
#[test]
fn can_push_input_response_after_output_request() {
    let this = canister_test_id(13);
    let other = canister_test_id(14);
    let mut queues = CanisterQueues::default();
    queues
        .push_output_request(
            RequestBuilder::default()
                .sender(this)
                .receiver(other)
                .build(),
        )
        .unwrap();
    queues
        .push_input(
            QueueIndex::from(0),
            ResponseBuilder::default()
                .respondent(other)
                .originator(this)
                .build()
                .into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

/// Enqueues 10 ingress messages and pops them.
#[test]
fn test_message_picking_ingress_only() {
    let this = canister_test_id(13);

    let mut queues = CanisterQueues::default();
    assert!(queues.pop_input().is_none());

    for i in 0..10 {
        queues.push_ingress(Ingress {
            source: user_test_id(77),
            receiver: this,
            method_name: String::from("test"),
            method_payload: vec![i as u8],
            message_id: message_test_id(555),
            expiry_time: current_time_and_expiry_time().1,
        });
    }

    let mut expected_byte = 0;
    while queues.has_input() {
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Ingress(msg) => {
                assert_eq!(msg.method_payload, vec![expected_byte])
            }
            msg => panic!("unexpected message popped: {:?}", msg),
        }
        expected_byte += 1;
    }
    assert_eq!(10, expected_byte);

    assert!(queues.pop_input().is_none());
}

/// Enqueues 3 requests for the same canister and consumes them.
#[test]
fn test_message_picking_round_robin_on_one_queue() {
    let this = canister_test_id(13);
    let other = canister_test_id(14);

    let mut queues = CanisterQueues::default();
    assert!(queues.pop_input().is_none());

    let list = vec![(0, other), (1, other), (2, other)];
    for (ix, id) in list.iter() {
        queues
            .push_input(
                QueueIndex::from(*ix),
                RequestBuilder::default()
                    .sender(*id)
                    .receiver(this)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .expect("could not push");
    }

    for _ in 0..list.len() {
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other),
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert!(!queues.has_input());
    assert!(queues.pop_input().is_none());
}

/// Enqueues 3 requests and 1 response, then pops them and verifies the
/// expected order.
#[test]
fn test_message_picking_round_robin() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueues::default();
    assert!(queues.pop_input().is_none());

    for (ix, id) in &[(0, other_1), (1, other_1), (0, other_3)] {
        queues
            .push_input(
                QueueIndex::from(*ix),
                RequestBuilder::default()
                    .sender(*id)
                    .receiver(this)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .expect("could not push");
    }

    queues
        .push_output_request(
            RequestBuilder::default()
                .sender(this)
                .receiver(other_2)
                .build(),
        )
        .unwrap();
    // This succeeds because we pushed a request to other_2 to the output_queue
    // above which reserved a slot for the expected response here.
    queues
        .push_input(
            QueueIndex::from(0),
            ResponseBuilder::default()
                .respondent(other_2)
                .originator(this)
                .build()
                .into(),
            InputQueueType::LocalSubnet,
        )
        .expect("could not push");

    // Another high-priority request
    queues
        .push_input(
            QueueIndex::from(1),
            RequestBuilder::default()
                .sender(other_2)
                .receiver(this)
                .build()
                .into(),
            InputQueueType::LocalSubnet,
        )
        .expect("could not push");

    queues.push_ingress(Ingress {
        source: user_test_id(77),
        receiver: this,
        method_name: String::from("test"),
        method_payload: Vec::new(),
        message_id: message_test_id(555),
        expiry_time: current_time_and_expiry_time().1,
    });

    /* POPPING */
    // Due to the round-robin across Local, Ingress, and Remote Subnet messages,
    // the popping order should be:
    // 1. Local Subnet response (other_2)
    // 3. Ingress message
    // 2. Remote Subnet request (other_1)
    // 1. Local Subnet request (other_2)
    // 4. Remote Subnet request (other_3)
    // 2. Remote Subnet request (other_1)

    // Pop response from other_2
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Response(msg) => assert_eq!(msg.respondent, other_2),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    // Pop ingress
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Ingress(msg) => assert_eq!(msg.source, user_test_id(77)),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    // Pop request from other_1
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_1),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    // Pop request from other_1
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_2),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    // Pop request from other_3
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_3),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    // Pop request from other_1
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_1),
        msg => panic!("unexpected message popped: {:?}", msg),
    }

    assert!(!queues.has_input());
    assert!(queues.pop_input().is_none());
}

/// Enqueues 4 input requests across 3 canisters and consumes them, ensuring
/// correct round-robin scheduling.
#[test]
fn test_input_scheduling() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueues::default();
    assert!(!queues.has_input());

    let push_input_from = |queues: &mut CanisterQueues, sender: &CanisterId, index: u64| {
        queues
            .push_input(
                QueueIndex::from(index),
                RequestBuilder::default()
                    .sender(*sender)
                    .receiver(this)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .expect("could not push");
    };

    let assert_schedule = |queues: &CanisterQueues, expected_schedule: &[&CanisterId]| {
        let schedule: Vec<&CanisterId> = queues.remote_subnet_input_schedule.iter().collect();
        assert_eq!(expected_schedule, schedule.as_slice());
    };

    let assert_sender = |sender: &CanisterId, message: CanisterInputMessage| match message {
        CanisterInputMessage::Request(req) => assert_eq!(*sender, req.sender),
        _ => unreachable!(),
    };

    push_input_from(&mut queues, &other_1, 0);
    assert_schedule(&queues, &[&other_1]);

    push_input_from(&mut queues, &other_2, 0);
    assert_schedule(&queues, &[&other_1, &other_2]);

    push_input_from(&mut queues, &other_1, 1);
    assert_schedule(&queues, &[&other_1, &other_2]);

    push_input_from(&mut queues, &other_3, 0);
    assert_schedule(&queues, &[&other_1, &other_2, &other_3]);

    assert_sender(&other_1, queues.pop_input().unwrap());
    assert_schedule(&queues, &[&other_2, &other_3, &other_1]);

    assert_sender(&other_2, queues.pop_input().unwrap());
    assert_schedule(&queues, &[&other_3, &other_1]);

    assert_sender(&other_3, queues.pop_input().unwrap());
    assert_schedule(&queues, &[&other_1]);

    assert_sender(&other_1, queues.pop_input().unwrap());
    assert_schedule(&queues, &[]);

    assert!(!queues.has_input());
}

/// Enqueues 6 output requests across 3 canisters and consumes them.
#[test]
fn test_output_into_iter() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueues::default();
    assert_eq!(0, queues.output_message_count());

    let destinations = vec![other_1, other_2, other_1, other_3, other_2, other_1];
    for (i, id) in destinations.iter().enumerate() {
        queues
            .push_output_request(
                RequestBuilder::default()
                    .sender(this)
                    .receiver(*id)
                    .method_payload(vec![i as u8])
                    .build(),
            )
            .expect("could not push");
    }

    let expected = vec![
        (&other_1, 0, 0),
        (&other_2, 0, 1),
        (&other_3, 0, 3),
        (&other_1, 1, 2),
        (&other_2, 1, 4),
        (&other_1, 2, 5),
    ];
    assert_eq!(expected.len(), queues.output_message_count());

    for (i, (qid, idx, msg)) in queues.output_into_iter(this).enumerate() {
        assert_eq!(this, qid.src_canister);
        assert_eq!(*expected[i].0, qid.dst_canister);
        assert_eq!(expected[i].1, idx.get());
        match msg {
            RequestOrResponse::Request(msg) => {
                assert_eq!(vec![expected[i].2], msg.method_payload)
            }
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert_eq!(0, queues.output_message_count());
}

/// Tests that an encode-decode roundtrip yields a result equal to the
/// original (and the queue size metrics of an organically constructed
/// `CanisterQueues` match those of a deserialized one).
#[test]
fn encode_roundtrip() {
    let mut queues = CanisterQueues::default();

    let this = canister_test_id(13);
    let other = canister_test_id(14);
    queues
        .push_input(
            QueueIndex::from(0),
            RequestBuilder::default().sender(this).build().into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    queues
        .push_input(
            QueueIndex::from(0),
            RequestBuilder::default().sender(other).build().into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    queues
        .pop_canister_input(InputQueueType::RemoteSubnet)
        .unwrap();
    queues.push_ingress(IngressBuilder::default().receiver(this).build());

    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = encoded.try_into().unwrap();

    assert_eq!(queues, decoded);
}

/// Enqueues requests and responses into input and output queues, verifying that
/// input queue and memory usage stats are accurate along the way.
#[test]
fn test_stats() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);
    const NAME: &str = "abcd";
    let iq_size: usize = InputQueue::new(DEFAULT_QUEUE_CAPACITY).calculate_size_bytes();
    let mut msg_size = [0; 6];

    let mut queues = CanisterQueues::default();
    let mut expected_iq_stats = InputQueuesStats::default();
    let mut expected_oq_stats = OutputQueuesStats::default();
    let mut expected_mu_stats = MemoryUsageStats::default();
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Push 3 requests into 3 input queues.
    for (i, sender) in [other_1, other_2, other_3].iter().enumerate() {
        let msg: RequestOrResponse = RequestBuilder::default()
            .sender(*sender)
            .receiver(this)
            .method_name(&NAME[0..i + 1]) // Vary request size.
            .payment(Cycles::new(5))
            .build()
            .into();
        msg_size[i] = msg.count_bytes();
        queues
            .push_input(QUEUE_INDEX_NONE, msg, InputQueueType::RemoteSubnet)
            .expect("could not push");

        // Added a new input queue and `msg`.
        expected_iq_stats += InputQueuesStats {
            message_count: 1,
            response_count: 0,
            reserved_slots: 0,
            size_bytes: iq_size + msg_size[i],
            cycles: Cycles::new(5),
        };
        assert_eq!(expected_iq_stats, queues.input_queues_stats);
        assert_eq!(expected_oq_stats, queues.output_queues_stats);
        // Pushed a request: one more reserved slot, no reserved response bytes.
        expected_mu_stats.reserved_slots += 1;
        assert_eq!(expected_mu_stats, queues.memory_usage_stats);
    }

    // Pop the first request we just pushed (as if it has started execution).
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_1),
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // We've now removed all messages in the input queue from `other_1`, but the
    // queue is still there.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 0,
        reserved_slots: 0,
        size_bytes: msg_size[0],
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Memory usage stats are unchanged, as the reservation is still there.
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // And push a matching output response.
    let msg = ResponseBuilder::default()
        .respondent(this)
        .originator(other_1)
        .refund(Cycles::new(2))
        .build();
    msg_size[3] = msg.count_bytes();
    queues.push_output_response(msg);
    // Input queue stats are unchanged.
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    expected_oq_stats += OutputQueuesStats {
        message_count: 1,
        cycles: Cycles::new(2),
    };
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Consumed a reservation and added a response.
    expected_mu_stats += MemoryUsageStats {
        reserved_slots: -1,
        responses_size_bytes: msg_size[3],
        oversized_requests_extra_bytes: 0,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Push an oversized request into the same output queue (to `other_1`).
    let msg = RequestBuilder::default()
        .sender(this)
        .receiver(other_1)
        .method_name(NAME)
        .method_payload(vec![13; MAX_RESPONSE_COUNT_BYTES])
        .payment(Cycles::new(5))
        .build();
    msg_size[4] = msg.count_bytes();
    queues.push_output_request(msg).unwrap();
    // One more reserved slot, no reserved response bytes, oversized request.
    expected_iq_stats.reserved_slots += 1;
    expected_mu_stats.reserved_slots += 1;
    expected_mu_stats.oversized_requests_extra_bytes += msg_size[4] - MAX_RESPONSE_COUNT_BYTES;
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    expected_oq_stats += OutputQueuesStats {
        message_count: 1,
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Call `output_into_iter()` but don't consume any messages.
    queues.output_into_iter(this).peek();
    // Stats should stay unchanged.
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Call `output_into_iter()` and consume a single message.
    match queues
        .output_into_iter(this)
        .next()
        .expect("could not pop a message")
    {
        (_, _, RequestOrResponse::Response(msg)) => {
            expected_oq_stats -= OutputQueuesStats {
                message_count: 1,
                cycles: msg.refund,
            };
            assert_eq!(msg.originator, other_1)
        }
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // No input queue changes.
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // But we've consumed the response.
    expected_mu_stats.responses_size_bytes -= msg_size[3];
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Consume the outgoing request.
    match queues
        .output_into_iter(this)
        .next()
        .expect("could not pop a message")
    {
        (_, _, RequestOrResponse::Request(msg)) => {
            expected_oq_stats -= OutputQueuesStats {
                message_count: 1,
                cycles: msg.payment,
            };
            assert_eq!(msg.receiver, other_1)
        }
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // No input queue changes.
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Oversized request was popped.
    expected_mu_stats.oversized_requests_extra_bytes -= msg_size[4] - MAX_RESPONSE_COUNT_BYTES;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Ensure no more outgoing messages.
    assert!(queues.output_into_iter(this).next().is_none());
    expected_oq_stats = OutputQueuesStats {
        message_count: 0,
        cycles: Cycles::new(0),
    };

    // And enqueue a matching incoming response.
    let msg: RequestOrResponse = ResponseBuilder::default()
        .respondent(other_1)
        .originator(this)
        .refund(Cycles::new(5))
        .build()
        .into();
    msg_size[5] = msg.count_bytes();
    queues
        .push_input(QUEUE_INDEX_NONE, msg, InputQueueType::RemoteSubnet)
        .expect("could not push");
    // Added a new input message.
    expected_iq_stats += InputQueuesStats {
        message_count: 1,
        response_count: 1,
        reserved_slots: -1,
        size_bytes: msg_size[5],
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Consumed one reservation, added some response bytes.
    expected_mu_stats += MemoryUsageStats {
        reserved_slots: -1,
        responses_size_bytes: msg_size[5],
        oversized_requests_extra_bytes: 0,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Pop everything.

    // Pop request from other_2
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_2),
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Removed message.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 0,
        reserved_slots: 0,
        size_bytes: msg_size[1],
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Memory usage stats unchanged, as the reservation is still there.
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Pop request from other_3
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_3),
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Removed message.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 0,
        reserved_slots: 0,
        size_bytes: msg_size[2],
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // Memory usage stats unchanged, as the reservation is still there.
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Pop response from other_1
    match queues.pop_input().expect("could not pop a message") {
        CanisterInputMessage::Response(msg) => assert_eq!(msg.respondent, other_1),
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Removed message.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 1,
        reserved_slots: 0,
        size_bytes: msg_size[5],
        cycles: Cycles::new(5),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_oq_stats, queues.output_queues_stats);
    // We have consumed the response.
    expected_mu_stats.responses_size_bytes -= msg_size[5];
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);
}

/// Enqueues requests and responses into input and output queues, verifying that
/// input queue and memory usage stats are accurate along the way.
#[test]
fn test_stats_induct_message_to_self() {
    let this = canister_test_id(13);
    let iq_size: usize = InputQueue::new(DEFAULT_QUEUE_CAPACITY).calculate_size_bytes();

    let mut queues = CanisterQueues::default();
    let mut expected_iq_stats = InputQueuesStats::default();
    let mut expected_mu_stats = MemoryUsageStats::default();
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // No messages to induct.
    assert!(queues.induct_message_to_self(this).is_err());

    // Push a request to self.
    let request = RequestBuilder::default()
        .sender(this)
        .receiver(this)
        .method_name("self")
        .build();
    let request_size = request.count_bytes();
    queues.push_output_request(request).expect("could not push");

    // New input queue was created, with one reservation.
    expected_iq_stats.size_bytes += iq_size;
    expected_iq_stats.reserved_slots += 1;
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Pushed a request: one more reserved slot, no reserved response bytes.
    expected_mu_stats.reserved_slots += 1;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Induct request.
    assert!(queues.induct_message_to_self(this).is_ok());

    // Request is now in the input queue.
    expected_iq_stats += InputQueuesStats {
        message_count: 1,
        response_count: 0,
        reserved_slots: 0,
        size_bytes: request_size,
        cycles: Cycles::from(0),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // We now have reservations (for the same request) in both the input and the
    // output queue.
    expected_mu_stats.reserved_slots += 1;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Pop the request (as if we were executing it).
    queues.pop_input().expect("could not pop request");
    // Request consumed.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 0,
        reserved_slots: 0,
        size_bytes: request_size,
        cycles: Cycles::from(0),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Memory usage stats unchanged, as the reservations are still there.
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // And push a matching output response.
    let response = ResponseBuilder::default()
        .respondent(this)
        .originator(this)
        .build();
    let response_size = response.count_bytes();
    queues.push_output_response(response);
    // Input queue stats are unchanged.
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Consumed output queue reservation and added a response.
    expected_mu_stats += MemoryUsageStats {
        reserved_slots: -1,
        responses_size_bytes: response_size,
        oversized_requests_extra_bytes: 0,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Induct the response.
    assert!(queues.induct_message_to_self(this).is_ok());

    // Response is now in the input queue, reservation is consumed.
    expected_iq_stats += InputQueuesStats {
        message_count: 1,
        response_count: 1,
        reserved_slots: -1,
        size_bytes: response_size,
        cycles: Cycles::from(0),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Consumed input queue reservation but response is still there (in input queue
    // now).
    expected_mu_stats.reserved_slots -= 1;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);

    // Pop the response.
    queues.pop_input().expect("could not pop response");
    // Response consumed.
    expected_iq_stats -= InputQueuesStats {
        message_count: 1,
        response_count: 1,
        reserved_slots: 0,
        size_bytes: response_size,
        cycles: Cycles::from(0),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Zero response bytes, zero reservations.
    expected_mu_stats.responses_size_bytes -= response_size;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);
}

// Must be duplicated here, because the `ic_test_utilities` one pulls in the
// `CanisterQueues` defined by a its `ic_replicated_state`, not the ones from
// `crate` and we wouldn't have access to its non-public methods.
prop_compose! {
    /// Strategy that generates an arbitrary `CanisterQueues` (and a matching
    /// iteration order); with up to `max_requests` requests; addressed to up to
    /// `max_receivers` (if `Some`) or one request per receiver (if `None`).
    pub fn arb_canister_queues(
        max_requests: usize,
        max_receivers: Option<usize>,
    )(
        num_receivers in arb_num_receivers(max_receivers),
        reqs in prop::collection::vec(arbitrary::request(), 0..max_requests)
    ) -> (CanisterQueues, VecDeque<RequestOrResponse>) {
        new_canister_queues_for_test(reqs, canister_test_id(42), num_receivers)
    }
}

proptest! {
    #[test]
    fn peek_and_next_consistent(
        (mut canister_queues, raw_requests) in arb_canister_queues(100, Some(10))
    ) {
        let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

        let mut popped = 0;
        while let Some(peeked) = output_iter.peek() {
            popped += 1;
            assert_next_eq(peeked, output_iter.next());
        }

        assert_eq!(output_iter.next(), None);
        assert_eq!(raw_requests.len(), popped);
    }

    #[test]
    fn peek_and_next_consistent_with_excludes(
        (mut canister_queues, raw_requests) in arb_canister_queues(100, None),
        start in 0..=1,
        exclude_step in 2..=5,
    ) {
        let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

        let mut i = start;
        let mut popped = 0;
        let mut excluded = 0;
        while let Some(peeked) = output_iter.peek() {
            i += 1;
            if i % exclude_step == 0 {
                output_iter.exclude_queue();
                excluded += 1;
                continue;
            }
            popped += 1;
            assert_next_eq(peeked, output_iter.next());
        }
        assert_eq!(output_iter.pop(), None);
        assert_eq!(raw_requests.len(), excluded + popped);
    }

    #[test]
    fn iter_leaves_non_consumed_messages_untouched(
        (mut canister_queues, mut raw_requests) in arb_canister_queues(100, Some(10)),
    ) {
        let num_requests = raw_requests.len();

        // Consume half of the messages in the canister queues and verify whether we pop the
        // expected elements.
        {
            let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

            for _ in 0..num_requests / 2 {
                let (_, _, popped_message) = output_iter.next().unwrap();
                let expected_message = raw_requests.pop_front().unwrap();
                assert_eq!(popped_message, expected_message);
            }

            assert_eq!(canister_queues.output_message_count(), num_requests - num_requests / 2);
        }

        // Ensure that the messages that have not been consumed above are still in the queues
        // after dropping `output_iter`.
        while let Some(raw) = raw_requests.pop_front() {
            if let Some((_, msg)) = canister_queues.pop_canister_output(&raw.receiver()) {
                assert_eq!(raw, msg);
            } else {
                panic!("Not all unconsumed messages left in canister queues");
            }
        }

        // Ensure that there are no messages left in the canister queues.
        assert_eq!(canister_queues.output_message_count(), 0);
    }

    #[test]
    fn iter_with_exclude_leaves_excluded_queues_untouched(
        (mut canister_queues, mut raw_requests) in arb_canister_queues(100, None),
        start in 0..=1,
        exclude_step in 2..=5,
    ) {
        let mut excluded_requests = VecDeque::new();
        // Consume half of the messages in the canister queues and verify whether we pop the
        // expected elements.
        {
            let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

            let mut i = start;
            let mut excluded = 0;
            while output_iter.peek().is_some() {
                i += 1;
                if i % exclude_step == 0 {
                    output_iter.exclude_queue();
                    // We only have one message per queue, so popping this request
                    // should leave us with a consistent expected queue
                    excluded_requests.push_back(raw_requests.pop_front().unwrap());
                    excluded += 1;
                    continue;
                }

                let (_, _, popped_message) = output_iter.pop().unwrap();
                let expected_message = raw_requests.pop_front().unwrap();
                assert_eq!(popped_message, expected_message);
            }

            assert_eq!(canister_queues.output_message_count(), excluded);
        }

        // Ensure that the messages that have not been consumed above are still in the queues
        // after dropping `output_iter`.
        while let Some(raw) = excluded_requests.pop_front() {
            if let Some((_, msg)) = canister_queues.pop_canister_output(&raw.receiver()) {
                assert_eq!(raw, msg, "Popped message does not correspond with expected message. popped: {:?}. expected: {:?}.", msg, raw);
            } else {
                panic!("Not all unconsumed messages left in canister queues");
            }
        }

        // Ensure that there are no messages left in the canister queues.
        assert_eq!(canister_queues.output_message_count(), 0);
    }

    #[test]
    fn iter_yields_correct_elements(
        (mut canister_queues, raw_requests) in arb_canister_queues(100, Some(10))
    ) {
        let recovered: VecDeque<_> = canister_queues
            .output_into_iter(CanisterId::from_u64(0))
            .map(|(_, _, msg)| msg)
            .collect();

        assert_eq!(raw_requests, recovered);
    }

    #[test]
    fn exclude_leaves_state_untouched(
        (mut canister_queues, _) in arb_canister_queues(100, Some(10)),
    ) {
        let expected_canister_queues = canister_queues.clone();
        let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

        while output_iter.peek().is_some() {
            output_iter.exclude_queue();
        }
        // Check that there's nothing left to pop.
        assert!(output_iter.next().is_none());

        assert_eq!(expected_canister_queues, canister_queues);
    }

    #[test]
    fn peek_pop_loop_terminates(
        (mut canister_queues, _) in arb_canister_queues(100, Some(10)),
    ) {
        let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

        while output_iter.peek().is_some() {
            output_iter.next();
        }
    }

    #[test]
    fn peek_pop_loop_with_excludes_terminates(
        (mut canister_queues, _) in arb_canister_queues(100, Some(10)),
        start in 0..=1,
        exclude_step in 2..=5,
    ) {
        let mut output_iter = canister_queues.output_into_iter(CanisterId::from_u64(0));

        let mut i = start;
        while output_iter.peek().is_some() {
            i += 1;
            if i % exclude_step == 0 {
                output_iter.exclude_queue();
                continue;
            }
            output_iter.next();
        }
    }
}
