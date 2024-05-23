use super::{
    message_pool::REQUEST_LIFETIME,
    testing::{new_canister_queues_for_test, CanisterQueuesTesting},
    InputQueueType::*,
    DEFAULT_QUEUE_CAPACITY, *,
};
use crate::{CanisterState, SchedulerState, SystemState};
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_test_utilities_state::arb_num_receivers;
use ic_test_utilities_types::{
    arbitrary,
    ids::{canister_test_id, message_test_id, user_test_id},
    messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{CallbackId, CanisterMessage, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, NO_DEADLINE},
    time::{expiry_time_from_now, CoarseTime, UNIX_EPOCH},
    Cycles,
};
use maplit::{btreemap, btreeset};
use proptest::prelude::*;
use std::{collections::BTreeSet, convert::TryInto, time::Duration};

/// Wrapper for `CanisterQueues` for tests using only one pair of
/// `(InputQueue, OutputQueue)` and arbitrary requests/responses.
struct CanisterQueuesFixture {
    pub queues: CanisterQueues,
    pub this: CanisterId,
    pub other: CanisterId,
}

impl CanisterQueuesFixture {
    fn new() -> CanisterQueuesFixture {
        CanisterQueuesFixture {
            queues: CanisterQueues::default(),
            this: canister_test_id(13),
            other: canister_test_id(11),
        }
    }

    fn push_input_request(&mut self) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            RequestBuilder::default()
                .sender(self.other)
                .receiver(self.this)
                .build()
                .into(),
            InputQueueType::LocalSubnet,
        )
    }

    fn push_input_response(&mut self) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            ResponseBuilder::default()
                .originator(self.this)
                .respondent(self.other)
                .build()
                .into(),
            InputQueueType::LocalSubnet,
        )
    }

    fn pop_input(&mut self) -> Option<CanisterMessage> {
        self.queues.pop_input()
    }

    fn push_output_request(&mut self) -> Result<(), (StateError, Arc<Request>)> {
        self.queues.push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(self.this)
                    .receiver(self.other)
                    .build(),
            ),
            UNIX_EPOCH,
        )
    }

    fn push_output_response(&mut self) {
        self.queues.push_output_response(Arc::new(
            ResponseBuilder::default()
                .originator(self.other)
                .respondent(self.this)
                .build(),
        ));
    }

    fn pop_output(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.queues.output_into_iter(self.this);
        iter.pop()
    }

    /// Times out all requests in the output queue.
    fn time_out_all_output_requests(&mut self) -> usize {
        let local_canisters = maplit::btreemap! {
            self.this => {
                let scheduler_state = SchedulerState::default();
                let system_state = SystemState::new_running_for_testing(
                    CanisterId::from_u64(42),
                    user_test_id(24).get(),
                    Cycles::new(1 << 36),
                    NumSeconds::from(100_000),
                );
                CanisterState::new(system_state, None, scheduler_state)
            }
        };
        // self.queues.time_out_requests(
        self.queues.time_out_messages(
            Time::from_nanos_since_unix_epoch(u64::MAX),
            &self.this,
            &local_canisters,
        )
    }

    fn available_output_request_slots(&self) -> usize {
        *self
            .queues
            .available_output_request_slots()
            .get(&self.other)
            .unwrap()
    }
}

/// Can push one request to the output queues.
#[test]
fn can_push_output_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_output_request().unwrap();
}

/// Cannot push response to output queues without pushing an input request
/// first.
#[test]
#[should_panic(expected = "assertion failed: self.guaranteed_response_memory_reservations > 0")]
fn cannot_push_output_response_without_input_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_output_response();
}

#[test]
fn enqueuing_unexpected_response_does_not_panic() {
    let mut queues = CanisterQueuesFixture::new();
    // Enqueue a request to create a queue for `other`.
    queues.push_input_request().unwrap();
    // Now `other` sends an unexpected `Response`.  We should return an error not
    // panic.
    queues.push_input_response().unwrap_err();
}

/// Can push response to output queues after pushing input request.
#[test]
fn can_push_output_response_after_input_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_input_request().unwrap();
    queues.pop_input().unwrap();
    queues.push_output_response();
}

/// Can push one request to the induction pool.
#[test]
fn can_push_input_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_input_request().unwrap();
}

/// Cannot push response to the induction pool without pushing output
/// request first.
#[test]
fn cannot_push_input_response_without_output_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_input_response().unwrap_err();
}

/// Can push response to input queues after pushing request to output
/// queues.
#[test]
fn can_push_input_response_after_output_request() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_output_request().unwrap();
    queues.pop_output().unwrap();
    queues.push_input_response().unwrap();
}

/// Check that `available_output_request_slots` doesn't count input requests and
/// output reserved slots and responses.
#[test]
fn test_available_output_request_slots_dont_counts() {
    let mut queues = CanisterQueuesFixture::new();
    queues.push_input_request().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        queues.available_output_request_slots()
    );
    queues.pop_input().unwrap();

    queues.push_output_response();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        queues.available_output_request_slots()
    );
}

/// Check that `available_output_request_slots` counts output requests and input
/// reserved slots and responses.
#[test]
fn test_available_output_request_slots_counts() {
    let mut queues = CanisterQueuesFixture::new();

    // Check that output request counts.
    queues.push_output_request().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );

    // Check that input reserved slot counts.
    queues.pop_output().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );

    // Check that input response counts.
    queues.push_input_response().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );
}

/// Check `available_output_request_slots` counts timed out output requests.
#[test]
fn test_available_output_request_slots_counts_timed_out_output_requests() {
    let mut queues = CanisterQueuesFixture::new();

    // Need output response to pin timed out request behind.
    queues.push_input_request().unwrap();
    queues.pop_input().unwrap();
    queues.push_output_response();

    // All output request slots are still available.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        queues.available_output_request_slots()
    );

    // Push output request, then time it out.
    queues.push_output_request().unwrap();
    queues.time_out_all_output_requests();

    // Pop the reject response, to isolate the timed out request.
    queues.pop_input().unwrap();

    // Check timed out request counts.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );
}

#[test]
fn test_back_pressure_with_timed_out_requests() {
    let mut queues = CanisterQueuesFixture::new();

    // Need output response to pin timed out request behind.
    queues.push_input_request().unwrap();
    queues.pop_input();
    queues.push_output_response();

    // Push `DEFAULT_QUEUE_CAPACITY` output requests.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        queues.push_output_request().unwrap();
    }

    // Time out all requests, then check no new request can be pushed.
    queues.time_out_all_output_requests();
    assert!(queues.push_output_request().is_err());
}

#[test]
fn test_shed_largest_message() {
    let this = canister_test_id(13);
    let other = canister_test_id(11);

    let mut queues = CanisterQueues::default();

    // Push an input and an output request.
    queues
        .push_input(
            RequestBuilder::default()
                .sender(other)
                .receiver(this)
                .deadline(CoarseTime::from_secs_since_unix_epoch(17))
                .build()
                .into(),
            RemoteSubnet,
        )
        .unwrap();
    queues
        .push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(this)
                    .receiver(other)
                    .deadline(CoarseTime::from_secs_since_unix_epoch(19))
                    .build(),
            ),
            UNIX_EPOCH,
        )
        .unwrap();

    // Shed the two requests.
    let local_canisters = Default::default();
    assert!(queues.shed_largest_message(&this, &local_canisters));
    assert!(queues.shed_largest_message(&this, &local_canisters));

    // There should be a reject response in an input queue.
    assert_matches!(queues.pop_input(), Some(CanisterMessage::Response(_)));
    assert!(!queues.has_input());
    // But no output.
    assert!(!queues.has_output());
    assert!(queues.output_into_iter(this).next().is_none());
}

/// Enqueues 3 requests for the same canister and consumes them.
#[test]
fn test_message_picking_round_robin_on_one_queue() {
    let mut queues = CanisterQueuesFixture::new();
    assert!(queues.pop_input().is_none());
    for _ in 0..3 {
        queues.push_input_request().expect("could not push");
    }

    for _ in 0..3 {
        match queues.pop_input().expect("could not pop a message") {
            CanisterMessage::Request(msg) => assert_eq!(msg.sender, queues.other),
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert!(!queues.queues.has_input());
    assert!(queues.pop_input().is_none());
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
            effective_canister_id: None,
            method_name: String::from("test"),
            method_payload: vec![i as u8],
            message_id: message_test_id(555),
            expiry_time: expiry_time_from_now(),
        });
    }

    let mut expected_byte = 0;
    while queues.has_input() {
        match queues.pop_input().expect("could not pop a message") {
            CanisterMessage::Ingress(msg) => {
                assert_eq!(msg.method_payload, vec![expected_byte])
            }
            msg => panic!("unexpected message popped: {:?}", msg),
        }
        expected_byte += 1;
    }
    assert_eq!(10, expected_byte);

    assert!(queues.pop_input().is_none());
}

/// Wrapper for `CanisterQueues` for tests using requests/responses to/from
/// arbitrary remote canisters.
struct CanisterQueuesMultiFixture {
    pub queues: CanisterQueues,
    pub this: CanisterId,
}

impl CanisterQueuesMultiFixture {
    fn new() -> CanisterQueuesMultiFixture {
        CanisterQueuesMultiFixture {
            queues: CanisterQueues::default(),
            this: canister_test_id(13),
        }
    }

    fn push_input_request(
        &mut self,
        other: CanisterId,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            RequestBuilder::default()
                .sender(other)
                .receiver(self.this)
                .build()
                .into(),
            input_queue_type,
        )
    }

    fn push_input_response(
        &mut self,
        other: CanisterId,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            ResponseBuilder::default()
                .originator(self.this)
                .respondent(other)
                .build()
                .into(),
            input_queue_type,
        )
    }

    fn push_ingress(&mut self, msg: Ingress) {
        self.queues.push_ingress(msg)
    }

    fn pop_input(&mut self) -> Option<CanisterMessage> {
        self.queues.pop_input()
    }

    fn has_input(&mut self) -> bool {
        self.queues.has_input()
    }

    fn push_output_request(&mut self, other: CanisterId) -> Result<(), (StateError, Arc<Request>)> {
        self.queues.push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(self.this)
                    .receiver(other)
                    .build(),
            ),
            UNIX_EPOCH,
        )
    }

    fn pop_output(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.queues.output_into_iter(self.this);
        iter.pop()
    }

    fn local_schedule(&self) -> Vec<CanisterId> {
        self.queues.local_subnet_input_schedule.clone().into()
    }

    fn remote_schedule(&self) -> Vec<CanisterId> {
        self.queues.remote_subnet_input_schedule.clone().into()
    }

    fn pool_is_empty(&self) -> bool {
        self.queues.pool.len() == 0
    }
}

/// Enqueues 3 requests and 1 response, then pops them and verifies the
/// expected order.
#[test]
fn test_message_picking_round_robin() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueuesMultiFixture::new();
    assert!(!queues.has_input());

    // 3 remote requests from 2 canisters.
    for id in &[other_1, other_1, other_3] {
        queues
            .push_input_request(*id, RemoteSubnet)
            .expect("could not push");
    }

    // Local response from `other_2`.
    // First push then pop a request to `other_2`, in order to get a reserved slot.
    queues.push_output_request(other_2).unwrap();
    queues.pop_output().unwrap();
    queues.push_input_response(other_2, LocalSubnet).unwrap();

    // Local request from `other_2`.
    queues
        .push_input_request(other_2, LocalSubnet)
        .expect("could not push");

    queues.push_ingress(Ingress {
        source: user_test_id(77),
        receiver: this,
        effective_canister_id: None,
        method_name: String::from("test"),
        method_payload: Vec::new(),
        message_id: message_test_id(555),
        expiry_time: expiry_time_from_now(),
    });

    // POPPING
    // Due to the round-robin across Local, Ingress, and Remote subnet messages;
    // and round-robin across input queues within Local and Remote input schedules;
    // the popping order should be:

    // 1. Local Subnet response (other_2)
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Response(msg)) if msg.respondent == other_2
    );

    // 2. Ingress message
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Ingress(msg)) if msg.source == user_test_id(77)
    );

    // 3. Remote Subnet request (other_1)
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_1
    );

    // 4. Local Subnet request (other_2)
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_2
    );

    // 5. Remote Subnet request (other_3)
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_3
    );

    // 6. Remote Subnet request (other_1)
    assert_matches!(
        queues.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_1
    );

    assert!(!queues.has_input());
    assert!(queues.pop_input().is_none());
    assert!(queues.pool_is_empty());
}

/// Enqueues 4 input requests across 3 canisters and consumes them, ensuring
/// correct round-robin scheduling.
#[test]
fn test_input_scheduling() {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueuesMultiFixture::new();
    assert!(!queues.has_input());

    let push_input_from = |queues: &mut CanisterQueuesMultiFixture, sender: CanisterId| {
        queues
            .push_input_request(sender, RemoteSubnet)
            .expect("could not push");
    };

    let assert_sender = |sender: CanisterId, message: CanisterMessage| match message {
        CanisterMessage::Request(req) => assert_eq!(sender, req.sender),
        _ => unreachable!(),
    };

    push_input_from(&mut queues, other_1);
    assert_eq!(vec![other_1], queues.remote_schedule());

    push_input_from(&mut queues, other_2);
    assert_eq!(vec![other_1, other_2], queues.remote_schedule());

    push_input_from(&mut queues, other_1);
    assert_eq!(vec![other_1, other_2], queues.remote_schedule());

    push_input_from(&mut queues, other_3);
    assert_eq!(vec![other_1, other_2, other_3], queues.remote_schedule());

    assert_sender(other_1, queues.pop_input().unwrap());
    assert_eq!(vec![other_2, other_3, other_1], queues.remote_schedule());

    assert_sender(other_2, queues.pop_input().unwrap());
    assert_eq!(vec![other_3, other_1], queues.remote_schedule());

    assert_sender(other_3, queues.pop_input().unwrap());
    assert_eq!(vec![other_1], queues.remote_schedule());

    assert_sender(other_1, queues.pop_input().unwrap());
    assert!(queues.remote_schedule().is_empty());

    assert!(!queues.has_input());
}

#[test]
fn test_split_input_schedules() {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);
    let other_4 = canister_test_id(4);
    let other_5 = canister_test_id(5);

    let mut queues = CanisterQueuesMultiFixture::new();
    let this = queues.this;

    // 4 local input queues (`other_1`, `other_2`, `this`, `other_3`) and 2 remote
    // ones (`other_4`, `other_5`).
    queues.push_input_request(other_1, LocalSubnet).unwrap();
    queues.push_input_request(other_2, LocalSubnet).unwrap();
    queues.push_input_request(this, LocalSubnet).unwrap();
    queues.push_input_request(other_3, LocalSubnet).unwrap();
    queues.push_input_request(other_4, RemoteSubnet).unwrap();
    queues.push_input_request(other_5, RemoteSubnet).unwrap();

    // Schedules before.
    assert_eq!(
        vec![other_1, other_2, this, other_3],
        queues.local_schedule()
    );
    assert_eq!(vec![other_4, other_5], queues.remote_schedule());

    // After the split we only have `other_1` (and `this`) on the subnet.
    let system_state =
        SystemState::new_running_for_testing(other_1, other_1.get(), Cycles::zero(), 0.into());
    let scheduler_state = SchedulerState::new(UNIX_EPOCH);
    let local_canisters = btreemap! {
        other_1 => CanisterState::new(system_state, None, scheduler_state)
    };

    // Act.
    queues.queues.split_input_schedules(&this, &local_canisters);

    // Schedules after: `other_2` and `other_3` have moved to the head of the remote
    // input schedule. Ordering is otherwise retained.
    assert_eq!(vec![other_1, this], queues.local_schedule());
    assert_eq!(
        vec![other_2, other_3, other_4, other_5],
        queues.remote_schedule()
    );
}

#[test]
fn test_peek_round_robin() {
    let mut queues = CanisterQueues::default();
    assert!(!queues.has_input());

    let local_senders = [
        canister_test_id(1),
        canister_test_id(2),
        canister_test_id(1),
    ];
    let remote_senders = [
        canister_test_id(3),
        canister_test_id(3),
        canister_test_id(4),
    ];

    let local_requests = local_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();
    let remote_requests = remote_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();

    push_requests(&mut queues, InputQueueType::LocalSubnet, &local_requests);
    push_requests(&mut queues, InputQueueType::RemoteSubnet, &remote_requests);

    let ingress = Ingress {
        source: user_test_id(77),
        receiver: canister_test_id(13),
        method_name: String::from("test"),
        method_payload: Vec::new(),
        effective_canister_id: None,
        message_id: message_test_id(555),
        expiry_time: expiry_time_from_now(),
    };
    queues.push_ingress(ingress.clone());

    assert!(queues.has_input());
    /* Peek */
    // Due to the round-robin across Local, Ingress, and Remote Subnet messages,
    // the peek order should be:
    // 1. Local Subnet request (index 0)
    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    // Peeking again the queues would return the same result.
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 2. Ingress message
    let peeked_input = CanisterMessage::Ingress(Arc::new(ingress));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 3. Remote Subnet request (index 0)
    let peeked_input = CanisterMessage::Request(Arc::new(remote_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 4. Local Subnet request (index 1)
    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 5. Remote Subnet request (index 2)
    let peeked_input = CanisterMessage::Request(Arc::new(remote_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 6. Local Subnet request (index 2)
    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 7. Remote Subnet request (index 1)
    let peeked_input = CanisterMessage::Request(Arc::new(remote_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    assert!(!queues.has_input());
    assert!(queues.pool.len() == 0);
}

#[test]
fn test_skip_round_robin() {
    let mut queues = CanisterQueues::default();
    assert!(!queues.has_input());

    let local_senders = [
        canister_test_id(1),
        canister_test_id(2),
        canister_test_id(1),
    ];
    let local_requests = local_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();

    push_requests(&mut queues, InputQueueType::LocalSubnet, &local_requests);
    let ingress = Ingress {
        source: user_test_id(77),
        receiver: canister_test_id(13),
        method_name: String::from("test"),
        method_payload: Vec::new(),
        effective_canister_id: None,
        message_id: message_test_id(555),
        expiry_time: expiry_time_from_now(),
    };
    queues.push_ingress(ingress.clone());
    let ingress_input = CanisterMessage::Ingress(Arc::new(ingress));
    assert!(queues.has_input());

    // 1. Pop local subnet request (index 0)
    // 2. Skip ingress message
    // 3. Pop local subnet request (index 1)
    // 4. Skip ingress message
    // 5. Skip local subnet request (index 2)
    // Loop detected.

    let mut loop_detector = CanisterQueuesLoopDetector::default();

    // Pop local queue.
    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // Skip ingress.
    assert_eq!(queues.peek_input().unwrap(), ingress_input);
    queues.skip_input(&mut loop_detector);
    assert_eq!(loop_detector.ingress_queue_skip_count, 1);
    assert!(!loop_detector.detected_loop(&queues));

    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // Skip ingress
    assert_eq!(queues.peek_input().unwrap(), ingress_input);
    queues.skip_input(&mut loop_detector);
    assert!(!loop_detector.detected_loop(&queues));
    assert_eq!(loop_detector.ingress_queue_skip_count, 2);

    // Skip local.
    let peeked_input = CanisterMessage::Request(Arc::new(local_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    queues.skip_input(&mut loop_detector);
    assert_eq!(loop_detector.ingress_queue_skip_count, 2);
    assert!(loop_detector.detected_loop(&queues));
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

    let destinations = [other_1, other_2, other_1, other_3, other_2, other_1];
    for (i, id) in destinations.iter().enumerate() {
        queues
            .push_output_request(
                RequestBuilder::default()
                    .sender(this)
                    .receiver(*id)
                    .method_payload(vec![i as u8])
                    .build()
                    .into(),
                UNIX_EPOCH,
            )
            .expect("could not push");
    }

    let expected = [
        (&other_1, 0),
        (&other_2, 1),
        (&other_3, 3),
        (&other_1, 2),
        (&other_2, 4),
        (&other_1, 5),
    ];
    assert_eq!(expected.len(), queues.output_message_count());

    for (i, (qid, msg)) in queues.output_into_iter(this).enumerate() {
        assert_eq!(this, qid.src_canister);
        assert_eq!(*expected[i].0, qid.dst_canister);
        match msg {
            RequestOrResponse::Request(msg) => {
                assert_eq!(vec![expected[i].1], msg.method_payload)
            }
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert_eq!(0, queues.output_message_count());
    assert!(queues.pool.len() == 0);
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
            RequestBuilder::default().sender(this).build().into(),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
    queues
        .push_input(
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

/// Tests that serializing an empty `CanisterQueues` produces zero bytes.
#[test]
fn encode_empty() {
    use prost::Message;

    let queues = CanisterQueues::default();

    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let mut serialized: Vec<u8> = Vec::new();
    encoded.encode(&mut serialized).unwrap();

    let expected: &[u8] = &[];
    assert_eq!(expected, serialized.as_slice());
}

fn push_requests(queues: &mut CanisterQueues, input_type: InputQueueType, requests: &Vec<Request>) {
    for req in requests {
        queues.push_input(req.clone().into(), input_type).unwrap()
    }
}

#[test]
fn test_peek_canister_input_does_not_affect_schedule() {
    let mut queues = CanisterQueues::default();
    let local_senders = [
        canister_test_id(1),
        canister_test_id(2),
        canister_test_id(1),
    ];
    let remote_senders = [canister_test_id(13), canister_test_id(14)];

    let local_requests = local_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();
    let remote_requests = remote_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();

    push_requests(&mut queues, InputQueueType::LocalSubnet, &local_requests);
    push_requests(&mut queues, InputQueueType::RemoteSubnet, &remote_requests);

    // Schedules before peek.
    let before_local_schedule = queues.local_subnet_input_schedule.clone();
    let before_remote_schedule = queues.remote_subnet_input_schedule.clone();

    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::RemoteSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::LocalSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()))
    );

    // Schedules are not changed.
    assert_eq!(queues.local_subnet_input_schedule, before_local_schedule);
    assert_eq!(queues.remote_subnet_input_schedule, before_remote_schedule);
    assert_eq!(
        queues
            .canister_queues
            .get(&canister_test_id(1))
            .unwrap()
            .0
            .len(),
        2
    );
}

#[test]
fn test_skip_canister_input() {
    let mut queues = CanisterQueues::default();
    let local_senders = [
        canister_test_id(1),
        canister_test_id(2),
        canister_test_id(1),
    ];
    let remote_senders = [canister_test_id(13), canister_test_id(14)];

    let local_requests = local_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();
    let remote_requests = remote_senders
        .iter()
        .map(|sender| RequestBuilder::default().sender(*sender).build())
        .collect::<Vec<_>>();

    push_requests(&mut queues, InputQueueType::LocalSubnet, &local_requests);
    push_requests(&mut queues, InputQueueType::RemoteSubnet, &remote_requests);

    // Peek before skip.
    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::RemoteSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::LocalSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()))
    );

    queues.skip_canister_input(InputQueueType::RemoteSubnet);
    queues.skip_canister_input(InputQueueType::LocalSubnet);

    // Peek will return a different result.
    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::RemoteSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.get(1).unwrap().clone()))
    );
    assert_eq!(queues.remote_subnet_input_schedule.len(), 2);
    assert_eq!(
        queues
            .peek_canister_input(InputQueueType::LocalSubnet)
            .unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.get(1).unwrap().clone()))
    );
    assert_eq!(queues.local_subnet_input_schedule.len(), 2);
    assert_eq!(
        queues
            .canister_queues
            .get(&canister_test_id(1))
            .unwrap()
            .0
            .len(),
        2
    );
}

fn request(deadline: CoarseTime) -> Request {
    request_with_payload(13, deadline)
}

fn request_with_payload(payload_size: usize, deadline: CoarseTime) -> Request {
    RequestBuilder::new()
        .sender(canister_test_id(13))
        .receiver(canister_test_id(13))
        .method_payload(vec![13; payload_size])
        .deadline(deadline)
        .build()
}

fn response(deadline: CoarseTime) -> Response {
    response_with_payload(13, deadline)
}

fn response_with_payload(payload_size: usize, deadline: CoarseTime) -> Response {
    ResponseBuilder::new()
        .respondent(canister_test_id(13))
        .originator(canister_test_id(13))
        .response_payload(Payload::Data(vec![13; payload_size]))
        .deadline(deadline)
        .build()
}

fn time(seconds_since_unix_epoch: u32) -> CoarseTime {
    CoarseTime::from_secs_since_unix_epoch(seconds_since_unix_epoch)
}

#[test]
fn test_stats_best_effort() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // Enqueue one guaranteed response request and one guaranteed response each into
    // an input and an output queue.
    let request = request(time(10));
    let request_size_bytes = request.count_bytes();
    let response = response_with_payload(1000, time(20));
    let response_size_bytes = response.count_bytes();

    // Make reservatuibs for the responses.
    queues
        .push_input(request.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues.pop_input().unwrap();
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter(request.sender).next().unwrap();
    // Actually enqueue the messages.
    queues
        .push_input(request.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues
        .push_input(response.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues.push_output_response(response.clone().into());
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();

    // One input queue slot, one output queue slot, zero memory reservations.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 0,
        input_queues_reserved_slots: 1,
        output_queues_reserved_slots: 1,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two guaranteed response requests, two guaranteed responses.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: 2 * (request_size_bytes + response_size_bytes),
            best_effort_message_bytes: 2 * (request_size_bytes + response_size_bytes),
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: request_size_bytes + response_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 2,
        },
        queues.pool.message_stats()
    );

    // Pop the incoming request and the outgoing response.
    assert_eq!(
        queues.pop_input(),
        Some(CanisterMessage::Request(request.clone().into()))
    );
    assert_eq!(
        queues.output_into_iter(request.sender).next().unwrap().1,
        RequestOrResponse::Response(response.clone().into())
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One guaranteed response request, one guaranteed response.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: request_size_bytes + response_size_bytes,
            best_effort_message_bytes: request_size_bytes + response_size_bytes,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: response_size_bytes,
            inbound_message_count: 1,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 1,
        },
        queues.pool.message_stats()
    );

    // Time out the one message with a deadline of less than 20 (the outgoing
    // request), shed the incoming response and pop the generated reject response.
    assert_eq!(
        1,
        queues.time_out_messages(time(20).into(), &request.sender, &BTreeMap::new())
    );
    assert!(queues.shed_largest_message(&request.sender, &BTreeMap::new()));
    assert!(queues.pop_input().is_some());

    // Input queue slot reservation was consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 0,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 1,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And all-zero message stats.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );
}

#[test]
fn test_stats_guaranteed_response() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // Enqueue one guaranteed response request and one guaranteed response each into
    // an input and an output queue.
    let request = request(NO_DEADLINE);
    let request_size_bytes = request.count_bytes();
    let response = response(NO_DEADLINE);
    let response_size_bytes = response.count_bytes();

    // Make reservatuibs for the responses.
    queues
        .push_input(request.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues.pop_input().unwrap();
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter(request.sender).next().unwrap();
    // Actually enqueue the messages.
    queues
        .push_input(request.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues
        .push_input(response.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues.push_output_response(response.clone().into());
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();

    // One input queue slot, one output queue slot, two memory reservations.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 2,
        input_queues_reserved_slots: 1,
        output_queues_reserved_slots: 1,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two guaranteed response requests, two guaranteed responses.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: 2 * (request_size_bytes + response_size_bytes),
            best_effort_message_bytes: 0,
            guaranteed_responses_size_bytes: 2 * response_size_bytes,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: request_size_bytes + response_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 1,
            inbound_guaranteed_response_count: 1,
            outbound_message_count: 2,
        },
        queues.pool.message_stats()
    );

    // Pop the incoming request and the outgoing response.
    assert_eq!(
        queues.pop_input(),
        Some(CanisterMessage::Request(request.clone().into()))
    );
    assert_eq!(
        queues.output_into_iter(request.sender).next().unwrap().1,
        RequestOrResponse::Response(response.clone().into())
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One guaranteed response request, one guaranteed response.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: request_size_bytes + response_size_bytes,
            best_effort_message_bytes: 0,
            guaranteed_responses_size_bytes: response_size_bytes,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: response_size_bytes,
            inbound_message_count: 1,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 1,
            outbound_message_count: 1,
        },
        queues.pool.message_stats()
    );

    // Time out the one message that has an (implicit) deadline (the outgoing
    // request), pop the incoming response and the generated reject response.
    assert_eq!(
        1,
        queues.time_out_messages(time(u32::MAX).into(), &request.sender, &BTreeMap::new())
    );
    assert_eq!(
        queues.pop_input(),
        Some(CanisterMessage::Response(response.clone().into()))
    );
    assert!(queues.pop_input().is_some());

    // Input queue slot and memory reservations were consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 1,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 1,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And all-zero message stats.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );
}

#[test]
fn test_stats_oversized_requests() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // Enqueue one best-effort and one guaranteed oversized request each into an
    // input and an output queue.
    let best_effort = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 1000,
        time(10),
    );
    let best_effort_size_bytes = best_effort.count_bytes();
    let guaranteed = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 2000,
        NO_DEADLINE,
    );
    let guaranteed_size_bytes = guaranteed.count_bytes();
    // The 2000 bytes we added above; plus the method name provided by
    // `RequestBuilder`; plus any difference in size between the `Request` and
    // `Response` structs, so better compute it.
    let guaranteed_extra_bytes = guaranteed_size_bytes - MAX_RESPONSE_COUNT_BYTES;

    queues
        .push_input(best_effort.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues
        .push_input(guaranteed.clone().into(), InputQueueType::LocalSubnet)
        .unwrap();
    queues
        .push_output_request(best_effort.clone().into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(guaranteed.clone().into(), UNIX_EPOCH)
        .unwrap();

    // Two input queue slots, two output queue slots, two memory reservations.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 2,
        input_queues_reserved_slots: 2,
        output_queues_reserved_slots: 2,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two best-effort requests, two oversized guaranteed requests, 4 requests in all.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: 2 * (best_effort_size_bytes + guaranteed_size_bytes),
            best_effort_message_bytes: 2 * best_effort_size_bytes,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 2 * guaranteed_extra_bytes,
            inbound_size_bytes: best_effort_size_bytes + guaranteed_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 0,
            inbound_guaranteed_request_count: 1,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 2,
        },
        queues.pool.message_stats()
    );

    // Pop the incoming best-effort request and the incoming guaranteed request.
    assert_eq!(
        Some(CanisterMessage::Request(best_effort.clone().into())),
        queues.pop_input()
    );
    assert_eq!(
        Some(CanisterMessage::Request(guaranteed.clone().into())),
        queues.pop_input()
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One best-effort request, one oversized guaranteed request, 2 requests in all.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: best_effort_size_bytes + guaranteed_size_bytes,
            best_effort_message_bytes: best_effort_size_bytes,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: guaranteed_extra_bytes,
            inbound_size_bytes: 0,
            inbound_message_count: 0,
            inbound_response_count: 0,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 2,
        },
        queues.pool.message_stats()
    );

    // Shed the outgoing best-effort request and time out the outgoing guaranteed one.
    assert!(queues.shed_largest_message(&best_effort.sender, &BTreeMap::new()));
    assert_eq!(
        1,
        queues.time_out_messages(time(u32::MAX).into(), &best_effort.sender, &BTreeMap::new())
    );

    // Input queue slots and the input queue memory reservation were consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 1,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 2,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // And pop the two reject responses.
    queues.pop_input().unwrap();
    queues.pop_input().unwrap();

    // No change in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // But back to all-zero message stats.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );
}

/// Enqueues requests and responses into input and output queues, verifying that
/// queue and message stats are accurate along the way.
#[test]
fn test_stats() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);
    const NAME: &str = "abcd";
    let mut msg_size = [0; 6];

    let mut queues = CanisterQueues::default();
    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Push 3 requests into 3 input queues.
    for (i, sender) in [other_1, other_2, other_3].iter().enumerate() {
        let msg: RequestOrResponse = RequestBuilder::default()
            .sender(*sender)
            .receiver(this)
            .method_name(&NAME[0..i + 1]) // Vary request size.
            .build()
            .into();
        msg_size[i] = msg.count_bytes();
        queues
            .push_input(msg, InputQueueType::RemoteSubnet)
            .expect("could not push");
    }
    // 3 slot and memory reservations in input queues.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 3,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 3,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Pop the first request we just pushed (as if it has started execution).
    match queues.pop_input().expect("could not pop a message") {
        CanisterMessage::Request(msg) => assert_eq!(msg.sender, other_1),
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // No change in queue stats.
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // And push a matching output response.
    let msg = ResponseBuilder::default()
        .respondent(this)
        .originator(other_1)
        .refund(Cycles::zero())
        .build();
    msg_size[3] = msg.count_bytes();
    queues.push_output_response(msg.into());
    // Consumed a slot and memory reservation.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 2,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 2,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Push an oversized request into the same output queue (to `other_1`).
    let msg = RequestBuilder::default()
        .sender(this)
        .receiver(other_1)
        .method_name(NAME)
        .method_payload(vec![13; MAX_RESPONSE_COUNT_BYTES])
        .build();
    msg_size[4] = msg.count_bytes();
    queues.push_output_request(msg.into(), UNIX_EPOCH).unwrap();
    // One additional slot and response memory reservation in an input queue.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 3,
        input_queues_reserved_slots: 1,
        output_queues_reserved_slots: 2,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Call `output_into_iter()` but don't consume any messages.
    queues.output_into_iter(this).peek();
    // No change.
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Call `output_into_iter()` and consume a single message.
    match queues
        .output_into_iter(this)
        .next()
        .expect("could not pop a message")
    {
        (_, RequestOrResponse::Response(msg)) if msg.originator == other_1 => {}
        (_, msg) => panic!("unexpected message popped: {:?}", msg),
    }
    // Still no change in reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Consume the outgoing request.
    match queues
        .output_into_iter(this)
        .next()
        .expect("could not pop a message")
    {
        (_, RequestOrResponse::Request(msg)) if msg.receiver == other_1 => {}
        (_, msg) => panic!("unexpected message popped: {:?}", msg),
    }
    // Still no change in reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Ensure no more outgoing messages.
    assert!(queues.output_into_iter(this).next().is_none());

    // Enqueue a matching incoming response.
    let msg: RequestOrResponse = ResponseBuilder::default()
        .respondent(other_1)
        .originator(this)
        .refund(Cycles::zero())
        .build()
        .into();
    msg_size[5] = msg.count_bytes();
    queues
        .push_input(msg, InputQueueType::RemoteSubnet)
        .expect("could not push");
    // Consumed the input queue slot and memory reservation.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 2,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 2,
        transient_stream_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // Pop everything.

    // Pop request from other_2
    match queues.pop_input().expect("could not pop a message") {
        CanisterMessage::Request(msg) => if msg.sender == other_2 {},
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Pop request from other_3
    match queues.pop_input().expect("could not pop a message") {
        CanisterMessage::Request(msg) => if msg.sender == other_3 {},
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Pop response from other_1
    match queues.pop_input().expect("could not pop a message") {
        CanisterMessage::Response(msg) => if msg.respondent == other_1 {},
        msg => panic!("unexpected message popped: {:?}", msg),
    }
    // Still no change in reservations (2 output queue slot and memory reservations).
    assert_eq!(expected_queue_stats, queues.queue_stats);
}

/// Enqueues requests and responses into input and output queues, verifying that
/// queue and message stats are accurate along the way.
#[test]
fn test_stats_induct_message_to_self() {
    let this = canister_test_id(13);

    let mut queues = CanisterQueues::default();

    assert_eq!(QueueStats::default(), queues.queue_stats);
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // No messages to induct.
    assert!(queues.induct_message_to_self(this).is_err());

    // Push a request to self.
    let request = RequestBuilder::default()
        .sender(this)
        .receiver(this)
        .method_name("self")
        .build();
    let request_size = request.count_bytes();
    queues
        .push_output_request(request.into(), UNIX_EPOCH)
        .expect("could not push");

    // One slot and memory reservation in an input queue.
    assert_eq!(
        QueueStats {
            guaranteed_response_memory_reservations: 1,
            input_queues_reserved_slots: 1,
            output_queues_reserved_slots: 0,
            transient_stream_responses_size_bytes: 0
        },
        queues.queue_stats
    );

    // Induct request.
    assert!(queues.induct_message_to_self(this).is_ok());

    // Additional slot and memory reservation, now in an output queue.
    assert_eq!(
        QueueStats {
            guaranteed_response_memory_reservations: 2,
            input_queues_reserved_slots: 1,
            output_queues_reserved_slots: 1,
            transient_stream_responses_size_bytes: 0
        },
        queues.queue_stats
    );
    // One inbound guaranteed response request.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: request_size,
            best_effort_message_bytes: 0,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: request_size,
            inbound_message_count: 1,
            inbound_response_count: 0,
            inbound_guaranteed_request_count: 1,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 0,
        },
        queues.pool.message_stats()
    );

    // Pop the request (as if we were executing it).
    queues.pop_input().expect("could not pop request");

    // No change in reservations.
    assert_eq!(
        QueueStats {
            guaranteed_response_memory_reservations: 2,
            input_queues_reserved_slots: 1,
            output_queues_reserved_slots: 1,
            transient_stream_responses_size_bytes: 0
        },
        queues.queue_stats
    );
    // No messages.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // Push the matching output response.
    let response = ResponseBuilder::default()
        .respondent(this)
        .originator(this)
        .build();
    let response_size = response.count_bytes();
    queues.push_output_response(response.into());

    // Consumed the output queue slot and memory reservation.
    assert_eq!(
        QueueStats {
            guaranteed_response_memory_reservations: 1,
            input_queues_reserved_slots: 1,
            output_queues_reserved_slots: 0,
            transient_stream_responses_size_bytes: 0
        },
        queues.queue_stats
    );
    // One outbound guaranteed response.
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: response_size,
            best_effort_message_bytes: 0,
            guaranteed_responses_size_bytes: response_size,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: 0,
            inbound_message_count: 0,
            inbound_response_count: 0,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 1,
        },
        queues.pool.message_stats()
    );

    // Induct the response.
    assert!(queues.induct_message_to_self(this).is_ok());

    // Input queue slot and memory reservation are consumed.
    assert_eq!(QueueStats::default(), queues.queue_stats);

    // Pop the response.
    queues.pop_input().expect("could not pop response");

    // No change in stats.
    assert_eq!(QueueStats::default(), queues.queue_stats);
    // And no messages.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );
}

/// Simulates sending an outgoing request and receiving an incoming response,
/// calling `garbage_collect()` throughout. This is always a no-op, until after
/// the response was consumed, when the queue pair is GC-ed and all fields are
/// reset to their default values.
#[test]
fn test_garbage_collect() {
    let this = canister_test_id(1);
    let other = canister_test_id(2);

    // A matching request and response pair.
    let request = RequestBuilder::default()
        .sender(this)
        .receiver(other)
        .build();
    let response = ResponseBuilder::default()
        .respondent(other)
        .originator(this)
        .build();

    // Empty `CanisterQueues`.
    let mut queues = CanisterQueues::default();
    assert!(queues.canister_queues.is_empty());
    // No-op.
    queues.garbage_collect();
    assert_eq!(CanisterQueues::default(), queues);

    // Push output request.
    queues
        .push_output_request(request.into(), UNIX_EPOCH)
        .unwrap();
    // No-op.
    queues.garbage_collect();
    assert!(queues.has_output());
    assert_eq!(1, queues.canister_queues.len());

    // "Route" output request.
    queues.output_into_iter(this).next();
    // No-op.
    queues.garbage_collect();
    // No messages, but the queue pair is not GC-ed (due to the reserved slot).
    assert!(!queues.has_output());
    assert_eq!(1, queues.canister_queues.len());

    // Push input response.
    queues
        .push_input(response.into(), InputQueueType::LocalSubnet)
        .unwrap();
    // Before popping any input, `queue.next_input_queue` has default value.
    assert_eq!(NextInputQueue::default(), queues.next_input_queue);
    // No-op.
    queues.garbage_collect();
    // Still one queue pair.
    assert!(queues.has_input());
    assert_eq!(1, queues.canister_queues.len());

    // "Process" response.
    queues.pop_input();
    // After having popped an input, `next_input_queue` has advanced.
    assert_ne!(NextInputQueue::default(), queues.next_input_queue);
    // No more inputs, but we still have the queue pair.
    assert!(!queues.has_input());
    assert_eq!(1, queues.canister_queues.len());

    // Queue pair can finally be GC-ed.
    queues.garbage_collect();
    // No canister queues left.
    assert!(queues.canister_queues.is_empty());
    // And all fields have been reset to their default values.
    assert_eq!(CanisterQueues::default(), queues);
}

/// Tests that even when `garbage_collect()` would otherwise be a no-op, fields
/// are always reset to default.
#[test]
fn test_garbage_collect_restores_defaults() {
    let this = canister_test_id(1);

    // Empty `CanisterQueues`.
    let mut queues = CanisterQueues::default();
    assert_eq!(CanisterQueues::default(), queues);

    // Push and pop an ingress message.
    queues.push_ingress(IngressBuilder::default().receiver(this).build());
    assert!(queues.pop_input().is_some());
    // `next_input_queue` has now advanced to `RemoteSubnet`.
    assert_ne!(CanisterQueues::default(), queues);

    // But `garbage_collect()` should restore the struct to its default value.
    queues.garbage_collect();
    assert_eq!(CanisterQueues::default(), queues);
}

#[test]
fn test_reject_subnet_output_request() {
    let this = canister_test_id(1);

    let request = RequestBuilder::default()
        .sender(this)
        .receiver(IC_00)
        .build();
    let reject_context = RejectContext::new(ic_error_types::RejectCode::DestinationInvalid, "");

    let mut queues = CanisterQueues::default();

    // Reject an output request without having enqueued it first.
    queues
        .reject_subnet_output_request(request, reject_context.clone(), &[])
        .unwrap();

    // There is now a reject response.
    assert_eq!(
        CanisterMessage::Response(Arc::new(
            ResponseBuilder::default()
                .respondent(IC_00)
                .originator(this)
                .response_payload(Payload::Reject(reject_context))
                .build()
        )),
        queues.pop_input().unwrap()
    );

    // And after popping it, there are no messages or reserved slots left.
    queues.garbage_collect();
    assert!(queues.canister_queues.is_empty());
    assert!(queues.pool.len() == 0);
}

#[test]
fn test_output_queues_for_each() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);

    // 3 requests to `other_1`, one to `other_2`.
    let request_1 = RequestBuilder::default()
        .sender(this)
        .receiver(other_1)
        .method_name("request_1")
        .build();
    let request_2 = RequestBuilder::default()
        .sender(this)
        .receiver(other_1)
        .method_name("request_2")
        .build();
    let request_3 = RequestBuilder::default()
        .sender(this)
        .receiver(other_1)
        .method_name("request_3")
        .build();
    let request_4 = RequestBuilder::default()
        .sender(this)
        .receiver(other_2)
        .method_name("request_4")
        .build();

    let mut queues = CanisterQueues::default();
    queues
        .push_output_request(request_1.into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request_2.into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request_3.into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request_4.into(), UNIX_EPOCH)
        .unwrap();

    // Should have 2 queue pairs (one for `other_1`, one for `other_2`).
    assert_eq!(2, queues.canister_queues.len());

    let mut seen = Vec::new();
    queues.output_queues_for_each(|canister_id, msg| match msg {
        RequestOrResponse::Request(req) => {
            seen.push((*canister_id, req.method_name.clone()));
            // Turn down `request_2`, accept everything else.
            if req.method_name == "request_2" {
                return Err(());
            }
            Ok(())
        }
        _ => unreachable!(),
    });

    // Ensure we've seen `request_1` and `request_2` to `other_1`; and
    // `request_4` to `other_2`; but not `request_3`.
    assert_eq!(
        vec![
            (other_1, "request_1".into()),
            (other_1, "request_2".into()),
            (other_2, "request_4".into())
        ],
        seen
    );

    // `request_2` and `request_3` should have been left in place.
    let mut seen = Vec::new();
    queues.output_queues_for_each(|canister_id, msg| match msg {
        RequestOrResponse::Request(req) => {
            seen.push((*canister_id, req.method_name.clone()));
            Ok(())
        }
        _ => unreachable!(),
    });
    assert_eq!(
        vec![(other_1, "request_2".into()), (other_1, "request_3".into())],
        seen
    );

    // No output left.
    assert!(!queues.has_output());
    // And the pool is also empty.
    assert!(queues.pool.len() == 0);
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
        while let Some((queue_id, msg)) = output_iter.peek() {
            popped += 1;
            assert_eq!(Some((queue_id, msg.clone())), output_iter.next());
        }

        assert_eq!(output_iter.next(), None);
        assert_eq!(raw_requests.len(), popped);
        assert!(canister_queues.pool.len() == 0);
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
        while let Some((queue_id, msg)) = output_iter.peek() {
            i += 1;
            if i % exclude_step == 0 {
                output_iter.exclude_queue();
                excluded += 1;
                continue;
            }
            popped += 1;
            assert_eq!(Some((queue_id, msg.clone())), output_iter.next());
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
                let (_, popped_message) = output_iter.next().unwrap();
                let expected_message = raw_requests.pop_front().unwrap();
                assert_eq!(popped_message, expected_message);
            }

            assert_eq!(canister_queues.output_message_count(), num_requests - num_requests / 2);
        }

        // Ensure that the messages that have not been consumed above are still in the queues
        // after dropping `output_iter`.
        while let Some(raw) = raw_requests.pop_front() {
            if let Some(msg) = canister_queues.pop_canister_output(&raw.receiver()) {
                assert_eq!(raw, msg);
            } else {
                panic!("Not all unconsumed messages left in canister queues");
            }
        }

        // Ensure that there are no messages left in the canister queues.
        assert_eq!(canister_queues.output_message_count(), 0);
        // And the pool is empty.
        assert!(canister_queues.pool.len() == 0);
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

                let (_, popped_message) = output_iter.pop().unwrap();
                let expected_message = raw_requests.pop_front().unwrap();
                assert_eq!(popped_message, expected_message);
            }

            assert_eq!(canister_queues.output_message_count(), excluded);
        }

        // Ensure that the messages that have not been consumed above are still in the queues
        // after dropping `output_iter`.
        while let Some(raw) = excluded_requests.pop_front() {
            if let Some(msg) = canister_queues.pop_canister_output(&raw.receiver()) {
                assert_eq!(raw, msg, "Popped message does not correspond with expected message. popped: {:?}. expected: {:?}.", msg, raw);
            } else {
                panic!("Not all unconsumed messages left in canister queues");
            }
        }

        // Ensure that there are no messages left in the canister queues.
        assert_eq!(canister_queues.output_message_count(), 0);
        // And the pool is empty.
        assert!(canister_queues.pool.len() == 0);
    }

    #[test]
    fn iter_yields_correct_elements(
        (mut canister_queues, raw_requests) in arb_canister_queues(100, Some(10))
    ) {
        let recovered: VecDeque<_> = canister_queues
            .output_into_iter(CanisterId::from_u64(0))
            .map(|(_, msg)| msg)
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

/// Tests 'has_expired_deadlines` reports
/// - false for an empty `CanisterQueues`.
/// - false for a non-empty `CanisterQueues` using a current time < all deadlines.
/// - true for a non-empty `CanisterQueues` using a current time >= at least one deadline.
#[test]
fn has_expired_deadlines_reports_correctly() {
    let mut canister_queues = CanisterQueues::default();

    let time0 = Time::from_secs_since_unix_epoch(0).unwrap();
    assert!(!canister_queues.has_expired_deadlines(time0 + REQUEST_LIFETIME));

    let time1 = Time::from_secs_since_unix_epoch(1).unwrap();
    canister_queues
        .push_output_request(Arc::new(RequestBuilder::default().build()), time0)
        .unwrap();

    let current_time = time0 + REQUEST_LIFETIME;
    assert!(!canister_queues.has_expired_deadlines(current_time));

    let current_time = time1 + REQUEST_LIFETIME;
    assert!(canister_queues.has_expired_deadlines(current_time));
}

/// Tests `time_out_requests` on an instance of `CanisterQueues` that contains exactly 4 output messages.
/// - An output request addressed to self.
/// - An output request addressed to a local canister.
/// - Two output requests adressed to a remote canister.
#[test]
fn time_out_requests_pushes_correct_reject_responses() {
    let mut canister_queues = CanisterQueues::default();

    let own_canister_id = canister_test_id(67);
    let local_canister_id = canister_test_id(79);
    let remote_canister_id = canister_test_id(97);

    let deadline1 = Time::from_secs_since_unix_epoch(0).unwrap();
    let deadline2 = Time::from_secs_since_unix_epoch(1).unwrap();

    for (canister_id, callback_id, deadline) in [
        (own_canister_id, 0, deadline1),
        (local_canister_id, 1, deadline1),
        (remote_canister_id, 2, deadline1),
        (remote_canister_id, 3, deadline2),
    ] {
        canister_queues
            .push_output_request(
                Arc::new(Request {
                    receiver: canister_id,
                    sender: own_canister_id,
                    sender_reply_callback: CallbackId::from(callback_id),
                    payment: Cycles::zero(),
                    method_name: "No-Op".to_string(),
                    method_payload: vec![],
                    metadata: None,
                    deadline: NO_DEADLINE,
                }),
                deadline,
            )
            .unwrap();
    }

    let local_canisters = maplit::btreemap! {
        local_canister_id => {
            let scheduler_state = SchedulerState::default();
            let system_state = SystemState::new_running_for_testing(
                CanisterId::from_u64(42),
                user_test_id(24).get(),
                Cycles::new(1 << 36),
                NumSeconds::from(100_000),
            );
            CanisterState::new(system_state, None, scheduler_state)
        }
    };

    let current_time = deadline1 + REQUEST_LIFETIME + Duration::from_secs(1);
    assert_eq!(
        3,
        // canister_queues.time_out_requests(current_time, &own_canister_id, &local_canisters),
        canister_queues.time_out_messages(current_time, &own_canister_id, &local_canisters),
    );

    // Check that each canister has one request timed out in the output queue and one
    // reject response in the corresponding input queue.
    for (canister_id, num_output_messages) in [
        (&own_canister_id, 0),
        (&local_canister_id, 0),
        (&remote_canister_id, 1),
    ] {
        if let Some((input_queue, output_queue)) = canister_queues.canister_queues.get(canister_id)
        {
            assert_eq!(
                num_output_messages,
                output_queue.calculate_message_count(&canister_queues.pool)
            );
            assert_eq!(1, input_queue.len());
        }
    }

    // FIXME
    // // Explicitly check contents of a reject response.
    // if let Some(RequestOrResponse::Response(reject_response)) = canister_queues
    //     .canister_queues
    //     .get(&remote_canister_id)
    //     .and_then(|(input_queue, _)| input_queue.peek())
    // {
    //     assert_eq!(
    //         Arc::new(Response {
    //             originator: own_canister_id,
    //             respondent: remote_canister_id,
    //             originator_reply_callback: CallbackId::from(2),
    //             refund: Cycles::from(7_u64),
    //             response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
    //                 RejectCode::SysTransient,
    //                 "Request timed out.",
    //                 MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN
    //             )),
    //             deadline: NO_DEADLINE,
    //         }),
    //         *reject_response,
    //     );
    // }

    // Check that subnet input schedules contain the relevant canister IDs exactly once.
    assert_eq!(
        canister_queues
            .local_subnet_input_schedule
            .iter()
            .collect::<BTreeSet<_>>(),
        btreeset! {&own_canister_id, &local_canister_id}
    );
    assert_eq!(
        canister_queues.remote_subnet_input_schedule,
        VecDeque::from(vec![remote_canister_id]),
    );

    let current_time = deadline2 + REQUEST_LIFETIME + Duration::from_secs(1);
    assert_eq!(
        1,
        // canister_queues.time_out_requests(current_time, &own_canister_id, &local_canisters),
        canister_queues.time_out_messages(current_time, &own_canister_id, &local_canisters),
    );

    if let Some((input_queue, output_queue)) =
        canister_queues.canister_queues.get(&remote_canister_id)
    {
        assert_eq!(
            0,
            output_queue.calculate_message_count(&canister_queues.pool)
        );
        assert_eq!(2, input_queue.len());
    }
    // Check that timing out twice does not lead to duplicate entries in subnet input schedules.
    assert_eq!(
        canister_queues.remote_subnet_input_schedule,
        VecDeque::from(vec![remote_canister_id]),
    );
}
