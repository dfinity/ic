use super::{
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
    messages::{CallbackId, CanisterMessage, NO_DEADLINE},
    time::expiry_time_from_now,
    time::UNIX_EPOCH,
};
use maplit::btreemap;
use proptest::prelude::*;
use std::convert::TryInto;

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
        let mut iter = self.queues.output_into_iter(self.other);
        iter.pop()
    }

    /// Times out all requests in the output queue.
    fn time_out_all_output_requests(&mut self) -> u64 {
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
        self.queues.time_out_requests(
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
#[should_panic(expected = "pushing response into inexistent output queue")]
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

/// Check `available_output_request_slots` doesn't count input requests and
/// output reservations and responses.
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

/// Check `available_output_request_slots` counts output requests and input
/// reservations and responses.
#[test]
fn test_available_output_request_slots_counts() {
    let mut queues = CanisterQueuesFixture::new();

    // Check output request counts.
    queues.push_output_request().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );

    // Check input reservation counts.
    queues.pop_output().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        queues.available_output_request_slots()
    );

    // Check input response counts.
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

    fn pop_output(&mut self, other: CanisterId) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.queues.output_into_iter(other);
        iter.pop()
    }

    fn local_schedule(&self) -> Vec<CanisterId> {
        self.queues.local_subnet_input_schedule.clone().into()
    }

    fn remote_schedule(&self) -> Vec<CanisterId> {
        self.queues.remote_subnet_input_schedule.clone().into()
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
    // First push then pop a request to `other_2`, in order to get a reservation.
    queues.push_output_request(other_2).unwrap();
    queues.pop_output(other_2).unwrap();
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
            .num_messages(),
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
            .num_messages(),
        2
    );
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
            .push_input(msg, InputQueueType::RemoteSubnet)
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
        CanisterMessage::Request(msg) => assert_eq!(msg.sender, other_1),
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
    queues.push_output_response(msg.into());
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
    queues.push_output_request(msg.into(), UNIX_EPOCH).unwrap();
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
        (_, RequestOrResponse::Response(msg)) => {
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
        (_, RequestOrResponse::Request(msg)) => {
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
        .push_input(msg, InputQueueType::RemoteSubnet)
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
        CanisterMessage::Request(msg) => assert_eq!(msg.sender, other_2),
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
        CanisterMessage::Request(msg) => assert_eq!(msg.sender, other_3),
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
        CanisterMessage::Response(msg) => assert_eq!(msg.respondent, other_1),
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
    queues
        .push_output_request(request.into(), UNIX_EPOCH)
        .expect("could not push");

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
        cycles: Cycles::zero(),
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
        cycles: Cycles::zero(),
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
    queues.push_output_response(response.into());
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
        cycles: Cycles::zero(),
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
        cycles: Cycles::zero(),
    };
    assert_eq!(expected_iq_stats, queues.input_queues_stats);
    // Zero response bytes, zero reservations.
    expected_mu_stats.responses_size_bytes -= response_size;
    assert_eq!(expected_mu_stats, queues.memory_usage_stats);
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
    // No messages, but the queue pair is not GC-ed (due to the reservation).
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

    // And after popping it, there are no messages or reservations left.
    queues.garbage_collect();
    assert!(queues.canister_queues.is_empty());
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

    let time0 = Time::from_nanos_since_unix_epoch(0);
    assert!(!canister_queues.has_expired_deadlines(time0 + REQUEST_LIFETIME));

    let time1 = Time::from_nanos_since_unix_epoch(1);
    canister_queues
        .push_output_request(Arc::new(RequestBuilder::default().build()), time1)
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

    let deadline1 = Time::from_nanos_since_unix_epoch(1);
    let deadline2 = Time::from_nanos_since_unix_epoch(2);

    for (canister_id, cycles, callback_id, deadline) in [
        (own_canister_id, 3, 0, deadline1),
        (local_canister_id, 5, 1, deadline1),
        (remote_canister_id, 7, 2, deadline1),
        (remote_canister_id, 14, 3, deadline2),
    ] {
        canister_queues
            .push_output_request(
                Arc::new(Request {
                    receiver: canister_id,
                    sender: own_canister_id,
                    sender_reply_callback: CallbackId::from(callback_id),
                    payment: Cycles::from(cycles as u64),
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

    let current_time = deadline1 + REQUEST_LIFETIME;
    assert_eq!(
        3,
        canister_queues.time_out_requests(current_time, &own_canister_id, &local_canisters),
    );

    // Check that each canister has one request timed out and removed from the output queue and one
    // reject response in the corresponding input queue.
    for (canister_id, num_output_messages) in [
        (&own_canister_id, 0),
        (&local_canister_id, 0),
        (&remote_canister_id, 1),
    ] {
        if let Some((input_queue, output_queue)) = canister_queues.canister_queues.get(canister_id)
        {
            assert_eq!(num_output_messages, output_queue.num_messages());
            assert_eq!(1, input_queue.num_messages());
        }
    }

    // Explicitly check contents of a reject response.
    if let Some(RequestOrResponse::Response(reject_response)) = canister_queues
        .canister_queues
        .get(&remote_canister_id)
        .and_then(|(input_queue, _)| input_queue.peek())
    {
        assert_eq!(
            Arc::new(Response {
                originator: own_canister_id,
                respondent: remote_canister_id,
                originator_reply_callback: CallbackId::from(2),
                refund: Cycles::from(7_u64),
                response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
                    RejectCode::SysTransient,
                    "Request timed out.",
                    MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN
                )),
                deadline: NO_DEADLINE,
            }),
            *reject_response,
        );
    }

    // Check that subnet input schedules contain the relevant canister IDs exactly once.
    assert_eq!(
        canister_queues.local_subnet_input_schedule,
        VecDeque::from(vec![own_canister_id, local_canister_id])
    );
    assert_eq!(
        canister_queues.remote_subnet_input_schedule,
        VecDeque::from(vec![remote_canister_id]),
    );

    let current_time = deadline2 + REQUEST_LIFETIME;
    assert_eq!(
        1,
        canister_queues.time_out_requests(current_time, &own_canister_id, &local_canisters),
    );

    if let Some((input_queue, output_queue)) =
        canister_queues.canister_queues.get(&remote_canister_id)
    {
        assert_eq!(0, output_queue.num_messages());
        assert_eq!(2, input_queue.num_messages());
    }
    // Check that timing out twice does not lead to duplicate entries in subnet input schedules.
    assert_eq!(
        canister_queues.remote_subnet_input_schedule,
        VecDeque::from(vec![remote_canister_id]),
    );
}
