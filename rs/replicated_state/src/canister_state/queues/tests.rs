use super::input_schedule::testing::InputScheduleTesting;
use super::testing::{new_canister_output_queues_for_test, CanisterQueuesTesting};
use super::InputQueueType::*;
use super::*;
use crate::{CanisterState, SchedulerState, SystemState};
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_test_utilities_state::arb_num_receivers;
use ic_test_utilities_types::arbitrary;
use ic_test_utilities_types::ids::{canister_test_id, message_test_id, user_test_id};
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, ResponseBuilder};
use ic_types::messages::{
    CallbackId, CanisterMessage, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, NO_DEADLINE,
};
use ic_types::time::{expiry_time_from_now, CoarseTime, UNIX_EPOCH};
use ic_types::{Cycles, UserId};
use maplit::btreemap;
use message_pool::REQUEST_LIFETIME;
use proptest::prelude::*;
use queue::{InputQueue, OutputQueue};
use std::cell::RefCell;
use std::convert::TryInto;
use std::time::Duration;

/// Wrapper for `CanisterQueues` for tests using only one pair of
/// `(InputQueue, OutputQueue)` and arbitrary requests/responses.
struct CanisterQueuesFixture {
    pub queues: CanisterQueues,
    pub this: CanisterId,
    pub other: CanisterId,

    /// The last callback ID used for outbound requests / inbound responses. Ensures
    /// that all inbound responses have unique callback IDs.
    last_callback_id: u64,
}

impl CanisterQueuesFixture {
    fn new() -> CanisterQueuesFixture {
        CanisterQueuesFixture {
            queues: CanisterQueues::default(),
            this: canister_test_id(13),
            other: canister_test_id(11),
            last_callback_id: 0,
        }
    }

    fn new_with_ids(this: CanisterId, other: CanisterId) -> CanisterQueuesFixture {
        CanisterQueuesFixture {
            queues: CanisterQueues::default(),
            this,
            other,
            last_callback_id: 0,
        }
    }

    fn push_input_request(&mut self) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            RequestBuilder::default()
                .sender(self.other)
                .receiver(self.this)
                .build()
                .into(),
            LocalSubnet,
        )
    }

    fn push_input_response(&mut self) -> Result<(), (StateError, RequestOrResponse)> {
        self.last_callback_id += 1;
        self.queues.push_input(
            ResponseBuilder::default()
                .originator(self.this)
                .respondent(self.other)
                .originator_reply_callback(CallbackId::from(self.last_callback_id))
                .build()
                .into(),
            LocalSubnet,
        )
    }

    fn pop_input(&mut self) -> Option<CanisterMessage> {
        self.queues.pop_input()
    }

    fn push_output_request(&mut self) -> Result<(), (StateError, Arc<Request>)> {
        self.last_callback_id += 1;
        self.queues.push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(self.this)
                    .receiver(self.other)
                    .sender_reply_callback(CallbackId::from(self.last_callback_id))
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

    fn pop_output(&mut self) -> Option<RequestOrResponse> {
        let mut iter = self.queues.output_into_iter();
        iter.pop()
    }

    /// Times out all messages with deadlines: all requests in output queues (best
    /// effort or guaranteed response); and all best effort messages, except
    /// responses in input queues.
    fn time_out_all_messages_with_deadlines(&mut self) -> usize {
        self.queues.time_out_messages(
            Time::from_nanos_since_unix_epoch(u64::MAX),
            &self.this,
            &BTreeMap::default(),
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

fn push_requests(queues: &mut CanisterQueues, input_type: InputQueueType, requests: &Vec<Request>) {
    for req in requests {
        queues.push_input(req.clone().into(), input_type).unwrap()
    }
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

fn coarse_time(seconds_since_unix_epoch: u32) -> CoarseTime {
    CoarseTime::from_secs_since_unix_epoch(seconds_since_unix_epoch)
}

/// Generates an `input_queue_type_fn` that returns `LocalSubnet` for
/// `local_canisters` and `RemoteSubnet` otherwise.
pub fn input_queue_type_from_local_canisters(
    local_canisters: Vec<CanisterId>,
) -> impl Fn(&CanisterId) -> InputQueueType {
    move |sender| {
        if local_canisters.contains(sender) {
            LocalSubnet
        } else {
            RemoteSubnet
        }
    }
}

/// Can push one request to the output queues.
#[test]
fn can_push_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_request().unwrap();
}

/// Cannot push guaranteed response to output queues without having pushed an
/// input request first.
#[test]
#[should_panic(expected = "assertion failed: self.guaranteed_response_memory_reservations > 0")]
fn cannot_push_output_response_guaranteed_without_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_response();
}

/// Cannot push best-effort response to output queues without having pushed an
/// input request first.
#[test]
#[should_panic(expected = "assertion failed: self.output_queues_reserved_slots > 0")]
fn cannot_push_output_response_best_effort_without_input_request() {
    let mut queues = CanisterQueues::default();
    queues.push_output_response(Arc::new(
        ResponseBuilder::default()
            .originator(canister_test_id(11))
            .respondent(canister_test_id(13))
            .deadline(coarse_time(1000))
            .build(),
    ));
}

#[test]
fn enqueuing_unexpected_response_does_not_panic() {
    let mut fixture = CanisterQueuesFixture::new();
    // Enqueue a request to create a queue for `other`.
    fixture.push_input_request().unwrap();
    // Now `other` sends an unexpected `Response`. We should return an error, not
    // panic.
    fixture.push_input_response().unwrap_err();
}

/// Can push response to output queues after pushing input request.
#[test]
fn can_push_output_response_after_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request().unwrap();
    fixture.pop_input().unwrap();
    fixture.push_output_response();
}

/// Can push one request to the induction pool.
#[test]
fn can_push_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request().unwrap();
}

/// Cannot push response to the induction pool without pushing output
/// request first.
#[test]
fn cannot_push_input_response_without_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_response().unwrap_err();
}

/// Can push response to input queues after pushing request to output
/// queues.
#[test]
fn can_push_input_response_after_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_request().unwrap();
    fixture.pop_output().unwrap();
    fixture.push_input_response().unwrap();
}

/// Checks that `available_output_request_slots` doesn't count input requests and
/// output reserved slots and responses.
#[test]
fn test_available_output_request_slots_dont_counts() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );
    fixture.pop_input().unwrap();

    fixture.push_output_response();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );
}

/// Checks that `available_output_request_slots` counts output requests and input
/// reserved slots and responses.
#[test]
fn test_available_output_request_slots_counts() {
    let mut fixture = CanisterQueuesFixture::new();

    // Check that output request counts.
    fixture.push_output_request().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        fixture.available_output_request_slots()
    );

    // Check that input reserved slot counts.
    fixture.pop_output().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        fixture.available_output_request_slots()
    );

    // Check that input response counts.
    fixture.push_input_response().unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        fixture.available_output_request_slots()
    );
}

/// Checks that `available_output_request_slots` counts timed out output
/// requests.
#[test]
fn test_available_output_request_slots_counts_timed_out_output_requests() {
    let mut fixture = CanisterQueuesFixture::new();

    // Need output response to pin timed out request behind.
    fixture.push_input_request().unwrap();
    fixture.pop_input().unwrap();
    fixture.push_output_response();

    // All output request slots are still available.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );

    // Push output request, then time it out.
    fixture.push_output_request().unwrap();
    fixture.time_out_all_messages_with_deadlines();

    // Pop the reject response, to isolate the timed out request.
    fixture.pop_input().unwrap();

    // Check timed out request counts.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 1,
        fixture.available_output_request_slots()
    );
}

#[test]
fn test_backpressure_with_timed_out_requests() {
    let mut fixture = CanisterQueuesFixture::new();

    // Need output response to pin timed out requests behind.
    fixture.push_input_request().unwrap();
    fixture.pop_input();
    fixture.push_output_response();

    // Push `DEFAULT_QUEUE_CAPACITY` output requests and time them all out.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture.push_output_request().unwrap();
    }
    fixture.time_out_all_messages_with_deadlines();

    // Check that no new request can be pushed.
    assert!(fixture.push_output_request().is_err());
}

/// Checks that `available_output_request_slots` counts timed out output
/// requests.
#[test]
fn test_has_output() {
    let mut fixture = CanisterQueuesFixture::new();

    // Fill the output queue with requests.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture.push_output_request().unwrap();
    }
    // No output request slots are available.
    assert_eq!(0, fixture.available_output_request_slots());

    // Time out all output requests.
    fixture.time_out_all_messages_with_deadlines();
    // Still no output request slots available.
    assert_eq!(0, fixture.available_output_request_slots());

    // Consume the reject responses, to free up input queue response slots.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture.pop_input().unwrap();
    }

    // There is no output.
    assert!(!fixture.queues.has_output());
    // All output request slots are now available.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );
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
    assert!(queues.output_into_iter().next().is_none());

    // And nothing else to shed.
    assert!(!queues.shed_largest_message(&this, &local_canisters));
}

/// Enqueues 3 requests for the same canister and consumes them.
#[test]
fn test_message_picking_round_robin_on_one_queue() {
    let mut fixture = CanisterQueuesFixture::new();
    assert!(fixture.pop_input().is_none());
    for _ in 0..3 {
        fixture.push_input_request().expect("could not push");
    }

    for _ in 0..3 {
        match fixture.pop_input().expect("could not pop a message") {
            CanisterMessage::Request(msg) => assert_eq!(msg.sender, fixture.other),
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert!(!fixture.queues.has_input());
    assert!(fixture.pop_input().is_none());
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

    /// The last callback ID used for outbound requests / inbound responses. Ensures
    /// that all inbound responses have unique callback IDs.
    last_callback_id: u64,
}

impl CanisterQueuesMultiFixture {
    fn new() -> CanisterQueuesMultiFixture {
        CanisterQueuesMultiFixture {
            queues: CanisterQueues::default(),
            this: canister_test_id(13),
            last_callback_id: 0,
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

    fn push_input_request_with_deadline(
        &mut self,
        other: CanisterId,
        deadline: CoarseTime,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues.push_input(
            RequestBuilder::default()
                .sender(other)
                .receiver(self.this)
                .deadline(deadline)
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
        self.last_callback_id += 1;
        self.queues.push_input(
            ResponseBuilder::default()
                .originator(self.this)
                .respondent(other)
                .originator_reply_callback(CallbackId::from(self.last_callback_id))
                .build()
                .into(),
            input_queue_type,
        )
    }

    fn reserve_and_push_input_response(
        &mut self,
        other: CanisterId,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.push_output_request(other)
            .map_err(|(se, req)| (se, (*req).clone().into()))?;
        self.pop_output()
            .expect("Just pushed an output request, but nothing popped");
        self.push_input_response(other, input_queue_type)
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
        self.last_callback_id += 1;
        self.queues.push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(self.this)
                    .receiver(other)
                    .sender_reply_callback(CallbackId::from(self.last_callback_id))
                    .build(),
            ),
            UNIX_EPOCH,
        )
    }

    fn pop_output(&mut self) -> Option<RequestOrResponse> {
        let mut iter = self.queues.output_into_iter();
        iter.pop()
    }

    /// Times out all messages with deadlines: all requests in output queues (best
    /// effort or guaranteed response); and all best effort messages, except
    /// responses in input queues.
    fn time_out_all_messages_with_deadlines(&mut self) -> usize {
        self.queues.time_out_messages(
            Time::from_nanos_since_unix_epoch(u64::MAX),
            &self.this,
            &BTreeMap::default(),
        )
    }

    fn local_schedule(&self) -> Vec<CanisterId> {
        self.queues
            .input_schedule
            .local_sender_schedule()
            .clone()
            .into()
    }

    fn remote_schedule(&self) -> Vec<CanisterId> {
        self.queues
            .input_schedule
            .remote_sender_schedule()
            .clone()
            .into()
    }

    fn schedules_ok(&self) -> Result<(), String> {
        self.queues
            .schedules_ok(&input_queue_type_from_local_canisters(vec![self.this]))
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

    let mut fixture = CanisterQueuesMultiFixture::new();
    assert!(!fixture.has_input());

    // 3 remote requests from 2 canisters.
    for id in &[other_1, other_1, other_3] {
        fixture
            .push_input_request(*id, RemoteSubnet)
            .expect("could not push");
    }

    // Local response from `other_2`.
    // First push then pop a request to `other_2`, in order to get a reserved slot.
    fixture.push_output_request(other_2).unwrap();
    fixture.pop_output().unwrap();
    fixture.push_input_response(other_2, LocalSubnet).unwrap();

    // Local request from `other_2`.
    fixture
        .push_input_request(other_2, LocalSubnet)
        .expect("could not push");

    fixture.push_ingress(Ingress {
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
        fixture.pop_input(),
        Some(CanisterMessage::Response(msg)) if msg.respondent == other_2
    );

    // 2. Ingress message
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Ingress(msg)) if msg.source == user_test_id(77)
    );

    // 3. Remote Subnet request (other_1)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_1
    );

    // 4. Local Subnet request (other_2)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_2
    );

    // 5. Remote Subnet request (other_3)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_3
    );

    // 6. Remote Subnet request (other_1)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Request(msg)) if msg.sender == other_1
    );

    assert!(!fixture.has_input());
    assert!(fixture.pop_input().is_none());
    assert!(fixture.pool_is_empty());
}

/// Enqueues 4 input requests across 3 canisters and consumes them, ensuring
/// correct round-robin scheduling.
#[test]
fn test_input_scheduling() {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut fixture = CanisterQueuesMultiFixture::new();
    assert!(!fixture.has_input());

    let push_input_from = |queues_fixture: &mut CanisterQueuesMultiFixture, sender: CanisterId| {
        queues_fixture
            .push_input_request(sender, RemoteSubnet)
            .expect("could not push");
    };

    let assert_sender = |sender: CanisterId, message: CanisterMessage| match message {
        CanisterMessage::Request(req) => assert_eq!(sender, req.sender),
        _ => unreachable!(),
    };

    push_input_from(&mut fixture, other_1);
    assert_eq!(vec![other_1], fixture.remote_schedule());

    push_input_from(&mut fixture, other_2);
    assert_eq!(vec![other_1, other_2], fixture.remote_schedule());

    push_input_from(&mut fixture, other_1);
    assert_eq!(vec![other_1, other_2], fixture.remote_schedule());

    push_input_from(&mut fixture, other_3);
    assert_eq!(vec![other_1, other_2, other_3], fixture.remote_schedule());

    assert_sender(other_1, fixture.pop_input().unwrap());
    assert_eq!(vec![other_2, other_3, other_1], fixture.remote_schedule());

    assert_sender(other_2, fixture.pop_input().unwrap());
    assert_eq!(vec![other_3, other_1], fixture.remote_schedule());

    assert_sender(other_3, fixture.pop_input().unwrap());
    assert_eq!(vec![other_1], fixture.remote_schedule());

    assert_sender(other_1, fixture.pop_input().unwrap());
    assert!(fixture.remote_schedule().is_empty());

    assert!(!fixture.has_input());
}

#[test]
fn test_split_input_schedules() {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);
    let other_4 = canister_test_id(4);
    let other_5 = canister_test_id(5);

    let mut fixture = CanisterQueuesMultiFixture::new();
    let this = fixture.this;

    // 4 local input queues (`other_1`, `other_2`, `this`, `other_3`) and 2 remote
    // ones (`other_4`, `other_5`).
    fixture.push_input_request(other_1, LocalSubnet).unwrap();
    fixture.push_input_request(other_2, LocalSubnet).unwrap();
    fixture.push_input_request(this, LocalSubnet).unwrap();
    fixture.push_input_request(other_3, LocalSubnet).unwrap();
    fixture.push_input_request(other_4, RemoteSubnet).unwrap();
    fixture.push_input_request(other_5, RemoteSubnet).unwrap();

    // Schedules before.
    assert_eq!(
        vec![other_1, other_2, this, other_3],
        fixture.local_schedule()
    );
    assert_eq!(vec![other_4, other_5], fixture.remote_schedule());

    // After the split we only have `other_1` (and `this`) on the subnet.
    let system_state =
        SystemState::new_running_for_testing(other_1, other_1.get(), Cycles::zero(), 0.into());
    let scheduler_state = SchedulerState::new(UNIX_EPOCH);
    let local_canisters = btreemap! {
        other_1 => CanisterState::new(system_state, None, scheduler_state)
    };

    // Act.
    fixture
        .queues
        .split_input_schedules(&this, &local_canisters);

    // Schedules after: `other_2` and `other_3` have moved to the head of the remote
    // input schedule. Ordering is otherwise retained.
    assert_eq!(vec![other_1, this], fixture.local_schedule());
    assert_eq!(
        vec![other_2, other_3, other_4, other_5],
        fixture.remote_schedule()
    );
}

#[test]
fn test_peek_input_round_robin() {
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

    push_requests(&mut queues, LocalSubnet, &local_requests);
    push_requests(&mut queues, RemoteSubnet, &remote_requests);

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
fn test_skip_input_round_robin() {
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

    push_requests(&mut queues, LocalSubnet, &local_requests);
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

#[test]
fn test_peek_input_with_stale_references() {
    let mut queues = CanisterQueues::default();

    // 5 requests, with the given senders and deadlines.
    let requests = [(1, 1000), (2, 1001), (2, 1003), (3, 1004), (2, 1002)]
        .into_iter()
        .map(|(sender, deadline)| {
            RequestBuilder::default()
                .sender(canister_test_id(sender))
                .deadline(coarse_time(deadline as u32))
                .build()
        })
        .collect::<Vec<_>>();

    push_requests(&mut queues, LocalSubnet, &requests);

    let own_canister_id = canister_test_id(13);
    let local_canisters = BTreeMap::new();

    // Time out requests @0, @1 and @4 (deadlines 1000, 1001, 1002), including the
    // only request from canister 1; and the first and last request from canister 2.
    assert_eq!(
        3,
        queues.time_out_messages(coarse_time(1003).into(), &own_canister_id, &local_canisters)
    );

    assert!(queues.has_input());

    // 1. Request @2.
    let expected = CanisterMessage::Request(Arc::new(requests.get(2).unwrap().clone()));
    assert_eq!(expected, queues.peek_input().unwrap());
    assert_eq!(expected, queues.pop_input().unwrap());

    // 2. Request @3.
    let expected = CanisterMessage::Request(Arc::new(requests.get(3).unwrap().clone()));
    assert_eq!(expected, queues.peek_input().unwrap());
    assert_eq!(expected, queues.pop_input().unwrap());

    assert!(!queues.has_input());
    assert!(queues.pool.len() == 0);
}

#[test]
fn test_pop_input_with_stale_references() {
    let mut queues = CanisterQueues::default();

    // 5 requests, with the given senders and deadlines.
    let requests = [(1, 1000), (2, 1001), (2, 1003), (3, 1004), (2, 1002)]
        .into_iter()
        .map(|(sender, deadline)| {
            RequestBuilder::default()
                .sender(canister_test_id(sender))
                .deadline(coarse_time(deadline as u32))
                .build()
        })
        .collect::<Vec<_>>();

    push_requests(&mut queues, LocalSubnet, &requests);

    let own_canister_id = canister_test_id(13);
    let local_canisters = BTreeMap::new();

    // Time out requests @0, @1 and @4 (deadlines 1000, 1001, 1002), including the
    // only request from canister 1; and the first and last request from canister 2.
    assert_eq!(
        3,
        queues.time_out_messages(coarse_time(1003).into(), &own_canister_id, &local_canisters)
    );

    assert!(queues.has_input());

    // 1. Request @2.
    let expected = CanisterMessage::Request(Arc::new(requests.get(2).unwrap().clone()));
    assert_eq!(expected, queues.pop_input().unwrap());

    // 2. Request @3.
    let expected = CanisterMessage::Request(Arc::new(requests.get(3).unwrap().clone()));
    assert_eq!(expected, queues.pop_input().unwrap());

    assert!(!queues.has_input());
    assert!(queues.pool.len() == 0);
}

/// Produces a `CanisterQueues` with 3 local input queues and 3 remote input
/// queues, all enqueued in their resepective input schedules, but only the
/// middle one still containing any messages.
fn canister_queues_with_empty_queues_in_input_schedules() -> CanisterQueues {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);
    let other_4 = canister_test_id(4);
    let other_5 = canister_test_id(5);
    let other_6 = canister_test_id(6);

    let mut fixture = CanisterQueuesMultiFixture::new();

    // 3 local input queues (from `other_1` through `other_3`) and 3 remote ones
    // (from `other_4` through `other_6`). Queues from `other_2` and `other_5` hold
    // guaranteed response requests; the other queues contain best-effort requests.
    fixture
        .push_input_request_with_deadline(other_1, coarse_time(1), LocalSubnet)
        .unwrap();
    fixture.push_input_request(other_2, LocalSubnet).unwrap();
    fixture
        .push_input_request_with_deadline(other_3, coarse_time(1), LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_4, coarse_time(1), RemoteSubnet)
        .unwrap();
    fixture.push_input_request(other_5, RemoteSubnet).unwrap();
    fixture
        .push_input_request_with_deadline(other_6, coarse_time(1), RemoteSubnet)
        .unwrap();
    assert_eq!(Ok(()), fixture.schedules_ok());

    // Time out the messages from `other_1`, `other_3`, `other_4` and `other_6`.
    fixture.time_out_all_messages_with_deadlines();
    assert_eq!(Ok(()), fixture.queues.test_invariants());
    assert_eq!(Ok(()), fixture.schedules_ok());

    let queues = fixture.queues;

    // Ensure that we only have the messages from `other_2` and `other_5` left.
    assert_eq!(2, queues.input_queues_message_count());
    // And no messages and only 2 reserved slots in output queues.
    assert_eq!(0, queues.output_queues_message_count());
    assert_eq!(2, queues.output_queues_reserved_slots());

    // But both schedules still have length 3.
    assert_eq!(3, queues.input_schedule.local_sender_schedule().len());
    assert_eq!(3, queues.input_schedule.remote_sender_schedule().len());

    queues
}

#[test]
fn test_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    assert!(!queues.has_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
    assert_eq!(
        Ok(()),
        queues.schedules_ok(&input_queue_type_from_local_canisters(vec![
            canister_test_id(1),
            canister_test_id(2),
            canister_test_id(3)
        ]))
    );
}

#[test]
fn test_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    assert!(!queues.has_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
    assert_eq!(Ok(()), queues.schedules_ok(&|_| RemoteSubnet));
}

#[test]
fn test_peek_input_with_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
}

#[test]
fn test_peek_input_with_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
}

#[test]
fn test_skip_input_with_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
}

#[test]
fn test_skip_input_with_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(5));

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.peek_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterMessage::Request(request) if request.sender == canister_test_id(2));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.pool.len() == 0);
}

#[test]
fn roundtrip_encode_empty_queue_in_input_schedule() {
    let queues = canister_queues_with_empty_queues_in_input_schedules();

    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)
        .try_into()
        .unwrap();

    assert_eq!(queues, decoded);
}

#[test]
fn roundtrip_encode_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)
        .try_into()
        .unwrap();

    assert_eq!(queues, decoded);
}

#[test]
fn test_push_into_empty_queue_in_input_schedule() {
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);

    let mut fixture = CanisterQueuesMultiFixture::new();

    // 1 local and 1 remote input queue holding best-effort requests.
    fixture
        .push_input_request_with_deadline(other_1, coarse_time(1), LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_2, coarse_time(1), RemoteSubnet)
        .unwrap();

    // Time out all messages.
    fixture.time_out_all_messages_with_deadlines();
    assert_eq!(Ok(()), fixture.queues.test_invariants());
    assert_eq!(Ok(()), fixture.schedules_ok());
    assert!(!fixture.has_input());

    // Also garbage collect the empty queue pairs, for good measure.
    fixture.queues.garbage_collect();
    assert!(fixture.queues.canister_queues.is_empty());
    assert_eq!(Ok(()), fixture.queues.test_invariants());
    assert_eq!(Ok(()), fixture.schedules_ok());
    assert!(!fixture.has_input());

    // Push another round of messages into the 2 queues.
    fixture
        .push_input_request_with_deadline(other_1, coarse_time(1), LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_2, coarse_time(1), RemoteSubnet)
        .unwrap();

    assert_eq!(Ok(()), fixture.schedules_ok());
    assert!(fixture.has_input());

    assert!(fixture.pop_input().is_some());
    assert!(fixture.pop_input().is_some());
    assert!(fixture.pop_input().is_none());
    assert!(!fixture.has_input());
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

    for (i, msg) in queues.output_into_iter().enumerate() {
        match msg {
            RequestOrResponse::Request(msg) => {
                assert_eq!(this, msg.sender);
                assert_eq!(*expected[i].0, msg.receiver);
                assert_eq!(vec![expected[i].1], msg.method_payload)
            }
            msg => panic!("unexpected message popped: {:?}", msg),
        }
    }

    assert_eq!(0, queues.output_message_count());
    assert!(queues.pool.len() == 0);
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

    push_requests(&mut queues, LocalSubnet, &local_requests);
    push_requests(&mut queues, RemoteSubnet, &remote_requests);

    // Schedules before peek.
    let input_schedule_before = queues.input_schedule.clone();

    assert_eq!(
        queues.peek_canister_input(RemoteSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()))
    );

    // Schedules are not changed.
    assert_eq!(input_schedule_before, queues.input_schedule);
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

    push_requests(&mut queues, LocalSubnet, &local_requests);
    push_requests(&mut queues, RemoteSubnet, &remote_requests);

    // Peek before skip.
    assert_eq!(
        queues.peek_canister_input(RemoteSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.first().unwrap().clone()))
    );

    queues.skip_canister_input(RemoteSubnet);
    queues.skip_canister_input(LocalSubnet);

    // Peek will return a different result.
    assert_eq!(
        queues.peek_canister_input(RemoteSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(remote_requests.get(1).unwrap().clone()))
    );
    assert_eq!(queues.input_schedule.remote_sender_schedule().len(), 2);
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterMessage::Request(Arc::new(local_requests.get(1).unwrap().clone()))
    );
    assert_eq!(queues.input_schedule.local_sender_schedule().len(), 2);
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

struct StrictMetrics;
impl CheckpointLoadingMetrics for StrictMetrics {
    fn observe_broken_soft_invariant(&self, msg: String) {
        panic!("{}", msg);
    }
}

struct CountingMetrics(RefCell<usize>);
impl CheckpointLoadingMetrics for CountingMetrics {
    fn observe_broken_soft_invariant(&self, _: String) {
        *self.0.borrow_mut() += 1;
    }
}

/// Tests that an encode-decode roundtrip yields a result equal to the original
/// (and that the stats of an organically constructed `CanisterQueues` match
/// those of a deserialized one).
#[test]
fn encode_roundtrip() {
    let mut queues = CanisterQueues::default();

    let this = canister_test_id(13);
    let other = canister_test_id(14);
    queues
        .push_input(
            RequestBuilder::default().sender(this).build().into(),
            LocalSubnet,
        )
        .unwrap();
    queues
        .push_input(
            RequestBuilder::default().sender(other).build().into(),
            RemoteSubnet,
        )
        .unwrap();
    queues.pop_canister_input(RemoteSubnet).unwrap();
    queues.push_ingress(IngressBuilder::default().receiver(this).build());

    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)
        .try_into()
        .unwrap();

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

/// Tests decoding a `CanisterQueues` with an invalid input schedule.
#[test]
fn decode_invalid_input_schedule() {
    let mut queues = CanisterQueues::default();

    let this = canister_test_id(13);
    let other = canister_test_id(14);
    queues
        .push_input(
            RequestBuilder::default().sender(this).build().into(),
            LocalSubnet,
        )
        .unwrap();
    queues
        .push_input(
            RequestBuilder::default().sender(other).build().into(),
            RemoteSubnet,
        )
        .unwrap();
    queues.push_ingress(IngressBuilder::default().receiver(this).build());

    let mut encoded: pb_queues::CanisterQueues = (&queues).into();
    // Wipe the local sender schedule.
    encoded.local_sender_schedule.clear();

    // Decoding should succeed.
    let metrics = CountingMetrics(RefCell::new(0));
    let mut decoded =
        CanisterQueues::try_from((encoded, &metrics as &dyn CheckpointLoadingMetrics)).unwrap();
    // Even though the input schedules are not valid.
    assert_matches!(
        decoded.schedules_ok(&input_queue_type_from_local_canisters(vec![this])),
        Err(_)
    );
    assert_eq!(1, *metrics.0.borrow());

    // If we enqueue `this` into the local sender queue, the rest should be equal.
    decoded.input_schedule.schedule(this, LocalSubnet);
    assert_eq!(queues, decoded);
}

/// Tests that serializing a `CanisterQueues` with an empty but non-default pool
/// preserves the non-default pool.
#[test]
fn encode_non_default_pool() {
    let mut queues = CanisterQueues::default();

    let this = canister_test_id(13);
    queues
        .push_input(
            RequestBuilder::default().sender(this).build().into(),
            RemoteSubnet,
        )
        .unwrap();
    queues.pop_canister_input(RemoteSubnet).unwrap();
    // Sanity check that the pool is empty but not equal to the default.
    assert_eq!(0, queues.pool.len());
    assert_ne!(MessagePool::default(), queues.pool);

    // And a roundtrip encode preserves the `CanisterQueues` unaltered.
    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)
        .try_into()
        .unwrap();
    assert_eq!(queues, decoded);
}

/// Tests decoding `CanisterQueues` from `input_queues` + `output_queues`
/// (instead of `canister_queues` + `pool`).
#[test]
fn decode_backward_compatibility() {
    let local_canister = canister_test_id(13);
    let remote_canister = canister_test_id(14);

    let mut queues_proto = pb_queues::CanisterQueues::default();
    let mut expected_queues = CanisterQueues::default();

    let req = RequestBuilder::default()
        .sender(local_canister)
        .receiver(local_canister)
        .build();
    let rep = ResponseBuilder::default()
        .originator(local_canister)
        .respondent(local_canister)
        .build();
    let t1 = Time::from_secs_since_unix_epoch(12345).unwrap();
    let t2 = t1 + Duration::from_secs(1);
    let d1 = t1 + REQUEST_LIFETIME;
    let d2 = t2 + REQUEST_LIFETIME;

    //
    // `local_canister`'s queues.
    //

    // An `InputQueue` with a request, a response and a reserved slot.
    let mut iq1 = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
    iq1.push(req.clone().into()).unwrap();
    iq1.reserve_slot().unwrap();
    iq1.push(rep.clone().into()).unwrap();
    iq1.reserve_slot().unwrap();

    // Expected input queue.
    let mut expected_iq1 = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
    // Enqueue a request and a response.
    expected_iq1.push_request(expected_queues.pool.insert_inbound(req.clone().into()));
    expected_iq1.try_reserve_response_slot().unwrap();
    expected_iq1.push_response(expected_queues.pool.insert_inbound(rep.clone().into()));
    // Make an extra response reservation.
    expected_iq1.try_reserve_response_slot().unwrap();

    // An output queue with a response, a timed out request, a non-timed out request
    // and a reserved slot.
    let mut oq1 = OutputQueue::new(DEFAULT_QUEUE_CAPACITY);
    oq1.reserve_slot().unwrap();
    oq1.push_response(rep.clone().into());
    oq1.push_request(req.clone().into(), d1).unwrap();
    oq1.time_out_requests(d2).count();
    oq1.push_request(req.clone().into(), d2).unwrap();
    oq1.reserve_slot().unwrap();

    // Expected output queue. The timed out request is gone.
    let mut expected_oq1 = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
    expected_oq1.try_reserve_response_slot().unwrap();
    expected_oq1.push_response(
        expected_queues
            .pool
            .insert_outbound_response(rep.clone().into()),
    );
    expected_oq1.push_request(
        expected_queues
            .pool
            .insert_outbound_request(req.clone().into(), t2),
    );
    expected_oq1.try_reserve_response_slot().unwrap();

    queues_proto.input_queues.push(pb_queues::QueueEntry {
        canister_id: Some(local_canister.into()),
        queue: Some((&iq1).into()),
    });
    queues_proto.output_queues.push(pb_queues::QueueEntry {
        canister_id: Some(local_canister.into()),
        queue: Some((&oq1).into()),
    });
    queues_proto
        .local_sender_schedule
        .push(local_canister.into());
    queues_proto.guaranteed_response_memory_reservations += 2;
    expected_queues
        .canister_queues
        .insert(local_canister, (expected_iq1, expected_oq1));
    expected_queues
        .input_schedule
        .schedule(local_canister, LocalSubnet);

    //
    // `remote_canister`'s queues.
    //

    // Input queue with a reserved slot.
    let mut iq2 = InputQueue::new(DEFAULT_QUEUE_CAPACITY);
    iq2.reserve_slot().unwrap();

    // Expected input queue.
    let mut expected_iq2 = CanisterQueue::new(DEFAULT_QUEUE_CAPACITY);
    expected_iq2.try_reserve_response_slot().unwrap();

    // Empty output queue.
    let oq2 = OutputQueue::new(DEFAULT_QUEUE_CAPACITY);

    queues_proto.input_queues.push(pb_queues::QueueEntry {
        canister_id: Some(remote_canister.into()),
        queue: Some((&iq2).into()),
    });
    queues_proto.output_queues.push(pb_queues::QueueEntry {
        canister_id: Some(remote_canister.into()),
        queue: Some((&oq2).into()),
    });
    queues_proto.guaranteed_response_memory_reservations += 1;
    expected_queues.canister_queues.insert(
        remote_canister,
        (expected_iq2, CanisterQueue::new(DEFAULT_QUEUE_CAPACITY)),
    );

    //
    // Adjust stats.
    //

    expected_queues.queue_stats = CanisterQueues::calculate_queue_stats(
        &expected_queues.canister_queues,
        queues_proto.guaranteed_response_memory_reservations as usize,
        0,
    );

    let queues = (
        queues_proto,
        &StrictMetrics as &dyn CheckpointLoadingMetrics,
    )
        .try_into()
        .unwrap();
    assert_eq!(expected_queues, queues);
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

    // Enqueue one best-effort response request and one best-effort response each
    // into an input and an output queue.
    let request = request(coarse_time(10));
    let request_size_bytes = request.count_bytes();
    let response = response_with_payload(1000, coarse_time(20));
    let response_size_bytes = response.count_bytes();

    // Make reservations for the responses.
    queues
        .push_input(request.clone().into(), LocalSubnet)
        .unwrap();
    queues.pop_input().unwrap();
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().next().unwrap();
    // Actually enqueue the messages.
    queues
        .push_input(request.clone().into(), LocalSubnet)
        .unwrap();
    queues
        .push_input(response.clone().into(), LocalSubnet)
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
        transient_stream_guaranteed_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two best-effort response requests, two best-effort responses.
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
        queues.output_into_iter().next().unwrap(),
        RequestOrResponse::Response(response.clone().into())
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One best-effort response request, one best-effort response.
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
        queues.time_out_messages(coarse_time(20).into(), &request.sender, &BTreeMap::new())
    );
    assert!(queues.shed_largest_message(&request.sender, &BTreeMap::new()));
    assert!(queues.pop_input().is_some());

    // Input queue slot reservation was consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 0,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 1,
        transient_stream_guaranteed_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And we have all-zero message stats.
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

    // Make reservations for the responses.
    queues
        .push_input(request.clone().into(), LocalSubnet)
        .unwrap();
    queues.pop_input().unwrap();
    queues
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().next().unwrap();
    // Actually enqueue the messages.
    queues
        .push_input(request.clone().into(), LocalSubnet)
        .unwrap();
    queues
        .push_input(response.clone().into(), LocalSubnet)
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
        transient_stream_guaranteed_responses_size_bytes: 0,
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
        queues.output_into_iter().next().unwrap(),
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
        queues.time_out_messages(
            coarse_time(u32::MAX).into(),
            &request.sender,
            &BTreeMap::new()
        )
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
        transient_stream_guaranteed_responses_size_bytes: 0,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And we have all-zero message stats.
    assert_eq!(
        &message_pool::MessageStats::default(),
        queues.pool.message_stats()
    );

    // Consume the output queue slot reservation.
    queues.push_output_response(response.clone().into());
    queues.output_into_iter().next().unwrap();

    // Default stats throughout.
    assert_eq!(QueueStats::default(), queues.queue_stats);
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
        coarse_time(10),
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
        .push_input(best_effort.clone().into(), LocalSubnet)
        .unwrap();
    queues
        .push_input(guaranteed.clone().into(), LocalSubnet)
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
        transient_stream_guaranteed_responses_size_bytes: 0,
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
        queues.time_out_messages(
            coarse_time(u32::MAX).into(),
            &best_effort.sender,
            &BTreeMap::new()
        )
    );

    // Input queue slots and the input queue memory reservation were consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 1,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 2,
        transient_stream_guaranteed_responses_size_bytes: 0,
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
    queues.output_into_iter().next();
    // No-op.
    queues.garbage_collect();
    // No messages, but the queue pair is not GC-ed (due to the reserved slot).
    assert!(!queues.has_output());
    assert_eq!(1, queues.canister_queues.len());

    // Push input response.
    queues.push_input(response.into(), LocalSubnet).unwrap();
    // Before popping any input, `next_input_source` has default value.
    assert_eq!(InputSource::default(), queues.input_schedule.input_source());
    // No-op.
    queues.garbage_collect();
    // Still one queue pair.
    assert!(queues.has_input());
    assert_eq!(1, queues.canister_queues.len());

    // "Process" response.
    queues.pop_input();
    // After having popped an input, `next_input_source` has advanced.
    assert_ne!(InputSource::default(), queues.input_schedule.input_source());
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
    // `next_input_source` has now advanced to `RemoteSubnet`.
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

#[test]
fn test_peek_output_with_stale_references() {
    let mut queues = CanisterQueues::default();
    let canister1 = canister_test_id(1);
    let canister2 = canister_test_id(2);
    let canister3 = canister_test_id(3);

    let receivers = [canister1, canister2, canister1, canister3];
    let requests = receivers
        .iter()
        .enumerate()
        .map(|(i, receiver)| {
            RequestBuilder::default()
                .receiver(*receiver)
                .deadline(coarse_time(1000 + i as u32))
                .build()
        })
        .collect::<Vec<_>>();

    for request in requests.iter() {
        queues
            .push_output_request(request.clone().into(), UNIX_EPOCH)
            .unwrap();
    }

    let own_canister_id = canister_test_id(13);
    let local_canisters = BTreeMap::new();
    // Time out the first two requests, including the only request to canister 2.
    queues.time_out_messages(coarse_time(1002).into(), &own_canister_id, &local_canisters);

    assert!(queues.has_output());

    // One message to canister 1.
    let peeked = requests.get(2).unwrap().clone().into();
    assert_eq!(Some(&peeked), queues.peek_output(&canister1));
    assert_eq!(Some(peeked), queues.pop_canister_output(&canister1));
    assert_eq!(None, queues.peek_output(&canister1));

    // No message to canister 2.
    assert_eq!(None, queues.peek_output(&canister2));

    // One message to canister 3.
    let peeked = requests.get(3).unwrap().clone().into();
    assert_eq!(Some(&peeked), queues.peek_output(&canister3));
    assert_eq!(Some(peeked), queues.pop_canister_output(&canister3));
    assert_eq!(None, queues.peek_output(&canister3));

    assert!(!queues.has_output());
    assert!(queues.pool.len() == 2);
}

// Must be duplicated here, because the `ic_test_utilities` one pulls in the
// `CanisterQueues` defined by its `ic_replicated_state`, not the ones from
// `crate` and we wouldn't have access to its non-public methods.
prop_compose! {
    /// Strategy that generates an arbitrary `CanisterQueues` (and a matching
    /// iteration order); with up to `max_requests` outbound requests; addressed to
    /// up to `max_receivers` (if `Some`) or one request per receiver (if `None`).
    fn arb_canister_output_queues(
        max_requests: usize,
        max_receivers: Option<usize>,
    )(
        num_receivers in arb_num_receivers(max_receivers),
        reqs in prop::collection::vec(arbitrary::request(), 0..max_requests)
    ) -> (CanisterQueues, VecDeque<RequestOrResponse>) {
        new_canister_output_queues_for_test(reqs, canister_test_id(42), num_receivers)
    }
}

#[test_strategy::proptest]
fn output_into_iter_peek_and_next_consistent(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
) {
    let (mut canister_queues, raw_requests) = test;
    let mut output_iter = canister_queues.output_into_iter();

    let mut popped = 0;
    while let Some(msg) = output_iter.peek() {
        popped += 1;
        prop_assert_eq!(Some(msg.clone()), output_iter.next());
    }

    prop_assert_eq!(output_iter.next(), None);
    prop_assert_eq!(raw_requests.len(), popped);
    prop_assert!(canister_queues.pool.len() == 0);
}

#[test_strategy::proptest]
fn output_into_iter_peek_and_next_consistent_with_excludes(
    #[strategy(arb_canister_output_queues(10, None))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
    #[strategy(0..=1_u64)] start: u64,
    #[strategy(2..=5_u64)] exclude_step: u64,
) {
    let (mut canister_queues, raw_requests) = test;
    let mut output_iter = canister_queues.output_into_iter();

    let mut i = start;
    let mut popped = 0;
    let mut excluded = 0;
    while let Some(msg) = output_iter.peek() {
        i += 1;
        if i % exclude_step == 0 {
            output_iter.exclude_queue();
            excluded += 1;
            continue;
        }
        popped += 1;
        prop_assert_eq!(Some(msg.clone()), output_iter.next());
    }
    prop_assert_eq!(output_iter.pop(), None);
    prop_assert_eq!(raw_requests.len(), excluded + popped);
}

#[test_strategy::proptest]
fn output_into_iter_leaves_non_consumed_messages_untouched(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
) {
    let (mut canister_queues, mut raw_requests) = test;
    let num_requests = raw_requests.len();

    // Consume half of the messages in the canister queues and verify whether we pop the
    // expected elements.
    {
        let mut output_iter = canister_queues.output_into_iter();

        for _ in 0..num_requests / 2 {
            let popped_message = output_iter.next().unwrap();
            let expected_message = raw_requests.pop_front().unwrap();
            prop_assert_eq!(popped_message, expected_message);
        }

        prop_assert_eq!(
            canister_queues.output_message_count(),
            num_requests - num_requests / 2
        );
    }

    // Ensure that the messages that have not been consumed above are still in the queues
    // after dropping `output_iter`.
    while let Some(raw) = raw_requests.pop_front() {
        if let Some(msg) = canister_queues.pop_canister_output(&raw.receiver()) {
            prop_assert_eq!(raw, msg);
        } else {
            prop_assert!(false, "Not all unconsumed messages left in canister queues");
        }
    }

    // Ensure that there are no messages left in the canister queues.
    prop_assert_eq!(canister_queues.output_message_count(), 0);
    // And the pool is empty.
    prop_assert!(canister_queues.pool.len() == 0);
}

#[test_strategy::proptest]
fn output_into_iter_with_exclude_leaves_excluded_queues_untouched(
    #[strategy(arb_canister_output_queues(10, None))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
    #[strategy(0..=1_u64)] start: u64,
    #[strategy(2..=5_u64)] exclude_step: u64,
) {
    let (mut canister_queues, mut raw_requests) = test;
    let mut excluded_requests = VecDeque::new();
    // Consume half of the messages in the canister queues and verify whether we pop the
    // expected elements.
    {
        let mut output_iter = canister_queues.output_into_iter();

        let mut i = start;
        let mut excluded = 0;
        while let Some(peeked_message) = output_iter.peek() {
            i += 1;
            if i % exclude_step == 0 {
                output_iter.exclude_queue();
                // We only have one message per queue, so popping this request
                // should leave us with a consistent expected queue
                excluded_requests.push_back(raw_requests.pop_front().unwrap());
                excluded += 1;
                continue;
            }

            let peeked_message = peeked_message.clone();
            let popped_message = output_iter.pop().unwrap();
            prop_assert_eq!(&popped_message, &peeked_message);
            let expected_message = raw_requests.pop_front().unwrap();
            prop_assert_eq!(&popped_message, &expected_message);
        }

        prop_assert_eq!(canister_queues.output_message_count(), excluded);
    }

    // Ensure that the messages that have not been consumed above are still in the queues
    // after dropping `output_iter`.
    while let Some(raw) = excluded_requests.pop_front() {
        if let Some(msg) = canister_queues.pop_canister_output(&raw.receiver()) {
            prop_assert_eq!(&raw, &msg, "Popped message does not correspond with expected message. popped: {:?}. expected: {:?}.", msg, raw);
        } else {
            prop_assert!(false, "Not all unconsumed messages left in canister queues");
        }
    }

    // Ensure that there are no messages left in the canister queues.
    prop_assert_eq!(canister_queues.output_message_count(), 0);
    // And the pool is empty.
    prop_assert!(canister_queues.pool.len() == 0);
}

#[test_strategy::proptest]
fn output_into_iter_yields_correct_elements(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
) {
    let (mut canister_queues, raw_requests) = test;
    let recovered: VecDeque<_> = canister_queues.output_into_iter().collect();

    prop_assert_eq!(raw_requests, recovered);
}

#[test_strategy::proptest]
fn output_into_iter_exclude_leaves_state_untouched(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
) {
    let (mut canister_queues, _raw_requests) = test;
    let expected_canister_queues = canister_queues.clone();
    let mut output_iter = canister_queues.output_into_iter();

    while output_iter.peek().is_some() {
        output_iter.exclude_queue();
    }
    // Check that there's nothing left to pop.
    prop_assert!(output_iter.next().is_none());

    prop_assert_eq!(expected_canister_queues, canister_queues);
}

#[test_strategy::proptest]
fn output_into_iter_peek_pop_loop_terminates(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
) {
    let (mut canister_queues, _raw_requests) = test;
    let mut output_iter = canister_queues.output_into_iter();

    while let Some(msg) = output_iter.peek() {
        prop_assert_eq!(Some(msg.clone()), output_iter.next());
    }
    prop_assert_eq!(None, output_iter.next());
}

#[test_strategy::proptest]
fn output_into_iter_peek_pop_loop_with_excludes_terminates(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
    #[strategy(0..=1_u64)] start: u64,
    #[strategy(2..=5_u64)] exclude_step: u64,
) {
    let (mut canister_queues, _raw_requests) = test;
    let mut output_iter = canister_queues.output_into_iter();

    let mut i = start;
    while let Some(msg) = output_iter.peek() {
        i += 1;
        if i % exclude_step == 0 {
            output_iter.exclude_queue();
            continue;
        }
        prop_assert_eq!(Some(msg.clone()), output_iter.next());
    }
}

#[test_strategy::proptest]
fn output_into_iter_peek_with_stale_references(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
    #[any] deadline: u32,
) {
    let (mut canister_queues, _raw_requests) = test;
    let own_canister_id = canister_test_id(13);
    let local_canisters = BTreeMap::new();
    // Time out some messages.
    canister_queues.time_out_messages(
        coarse_time(deadline).into(),
        &own_canister_id,
        &local_canisters,
    );
    // And shed one more.
    canister_queues.shed_largest_message(&own_canister_id, &local_canisters);

    // Peek and pop until the output queues are empty.
    let mut output_iter = canister_queues.output_into_iter();
    while let Some(msg) = output_iter.peek() {
        prop_assert_eq!(Some(msg.clone()), output_iter.next());
    }
    prop_assert_eq!(None, output_iter.next());
}

#[test_strategy::proptest]
fn output_into_iter_pop_with_stale_references(
    #[strategy(arb_canister_output_queues(10, Some(5)))] test: (
        CanisterQueues,
        VecDeque<RequestOrResponse>,
    ),
    #[any] deadline: u32,
) {
    let (mut canister_queues, _raw_requests) = test;
    let own_canister_id = canister_test_id(13);
    let local_canisters = BTreeMap::new();
    // Time out some messages.
    canister_queues.time_out_messages(
        coarse_time(deadline).into(),
        &own_canister_id,
        &local_canisters,
    );
    // And shed one more.
    canister_queues.shed_largest_message(&own_canister_id, &local_canisters);

    // Pop (after optionally peeking) a few times.
    let mut output_iter = canister_queues.output_into_iter();
    let mut should_peek = deadline % 2 == 0;
    for _ in 0..3 {
        if should_peek {
            output_iter.peek();
        }
        if output_iter.next() == None {
            break;
        };
        should_peek = !should_peek;
    }

    // Invariants should hold.
    prop_assert_eq!(Ok(()), canister_queues.test_invariants());
}

/// Tests that 'has_expired_deadlines` reports:
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
        .push_output_request(request(NO_DEADLINE).into(), time0)
        .unwrap();

    let current_time = time0 + REQUEST_LIFETIME;
    assert!(!canister_queues.has_expired_deadlines(current_time));

    let current_time = time1 + REQUEST_LIFETIME;
    assert!(canister_queues.has_expired_deadlines(current_time));

    // Pop the output request.
    canister_queues.output_into_iter().next().unwrap();
    assert!(!canister_queues.has_expired_deadlines(current_time));

    let time100 = coarse_time(100);
    let time101 = Time::from_secs_since_unix_epoch(101).unwrap();

    // Enqueue an inbound best-effort response. No expired deadlines, as inbound
    // responses don't expire.
    canister_queues
        .push_input(response(time100).into(), LocalSubnet)
        .unwrap();
    assert!(!canister_queues.has_expired_deadlines(time101));

    // But an inbound best-effort request does expire.
    canister_queues
        .push_input(request(time100).into(), LocalSubnet)
        .unwrap();
    assert!(canister_queues.has_expired_deadlines(time101));
}

/// Tests `time_out_messages` on an instance of `CanisterQueues` that contains exactly 4 output messages.
/// - A guaranteed response output request addressed to self.
/// - A best-effort output request addressed to a local canister.
/// - Two output requests adressed to a remote canister.
#[test]
fn time_out_messages_pushes_correct_reject_responses() {
    let mut canister_queues = CanisterQueues::default();

    let own_canister_id = canister_test_id(67);
    let local_canister_id = canister_test_id(79);
    let remote_canister_id = canister_test_id(97);

    let t0 = Time::from_secs_since_unix_epoch(0).unwrap();
    let t1 = Time::from_secs_since_unix_epoch(1).unwrap();
    let d1 = CoarseTime::floor(t1);

    for (canister_id, callback_id, time, deadline) in [
        (own_canister_id, 0, t0, NO_DEADLINE),
        (local_canister_id, 1, t0, d1),
        (remote_canister_id, 2, t0, NO_DEADLINE),
        (remote_canister_id, 3, t1, NO_DEADLINE),
    ] {
        canister_queues
            .push_output_request(
                Arc::new(Request {
                    receiver: canister_id,
                    sender: own_canister_id,
                    sender_reply_callback: CallbackId::from(callback_id),
                    payment: Cycles::from(7_u64),
                    method_name: "No-Op".to_string(),
                    method_payload: vec![],
                    metadata: None,
                    deadline,
                }),
                time,
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

    let current_time = t0 + REQUEST_LIFETIME + Duration::from_secs(1);
    assert_eq!(
        3,
        canister_queues.time_out_messages(current_time, &own_canister_id, &local_canisters),
    );

    // Check that each canister has one request timed out in the output queue and one
    // reject response in the corresponding input queue.
    assert_eq!(1, canister_queues.queue_stats.input_queues_reserved_slots);
    let message_stats = canister_queues.pool.message_stats();
    assert_eq!(3, message_stats.inbound_message_count);
    assert_eq!(2, message_stats.inbound_guaranteed_response_count);
    assert_eq!(1, message_stats.outbound_message_count);

    // Explicitly check the contents of the reject responses.
    let check_reject_response = |from_canister: CanisterId,
                                 callback_id: u64,
                                 deadline: CoarseTime| {
        let input_queue_from_canister = &canister_queues
            .canister_queues
            .get(&from_canister)
            .unwrap()
            .0;
        assert_eq!(1, input_queue_from_canister.len());
        let id = input_queue_from_canister.peek().unwrap().id();
        let reject_response = canister_queues.pool.get(id).unwrap();
        assert_eq!(
            RequestOrResponse::from(Response {
                originator: own_canister_id,
                respondent: from_canister,
                originator_reply_callback: CallbackId::from(callback_id),
                refund: Cycles::from(7_u64),
                response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
                    RejectCode::SysTransient,
                    "Request timed out.",
                    MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN
                )),
                deadline,
            }),
            *reject_response,
        );
    };
    check_reject_response(own_canister_id, 0, NO_DEADLINE);
    check_reject_response(local_canister_id, 1, d1);
    check_reject_response(remote_canister_id, 2, NO_DEADLINE);

    // Check that subnet input schedules contain the relevant canister IDs exactly once.
    assert_eq!(
        canister_queues.input_schedule.local_sender_schedule(),
        &VecDeque::from(vec![local_canister_id, own_canister_id]),
    );
    assert_eq!(
        canister_queues.input_schedule.remote_sender_schedule(),
        &VecDeque::from(vec![remote_canister_id]),
    );

    let current_time = t1 + REQUEST_LIFETIME + Duration::from_secs(1);
    assert_eq!(
        1,
        canister_queues.time_out_messages(current_time, &own_canister_id, &local_canisters),
    );

    // Zero input queue reserved slots, 4 inbound responses,
    assert_eq!(0, canister_queues.queue_stats.input_queues_reserved_slots);
    let message_stats = canister_queues.pool.message_stats();
    assert_eq!(4, message_stats.inbound_message_count);
    assert_eq!(3, message_stats.inbound_guaranteed_response_count);
    assert_eq!(0, message_stats.outbound_message_count);
    // Check that timing out twice does not lead to duplicate entries in subnet input schedules.
    assert_eq!(
        canister_queues.input_schedule.remote_sender_schedule(),
        &VecDeque::from(vec![remote_canister_id]),
    );
    assert_eq!(Ok(()), canister_queues.test_invariants());
    assert_eq!(
        Ok(()),
        canister_queues.schedules_ok(&input_queue_type_from_local_canisters(vec![
            own_canister_id
        ]))
    );
}

/// These tests are used to check the compatibility with the mainnet version.
/// They are not meant to be run as part of the regular test suite (hence the ignore attributes),
/// but instead invoked from the compiled test binary by a separate compatibility test.
mod mainnet_compatibility_tests {
    use prost::Message;
    use std::fs::File;
    use std::io::Write;

    #[cfg(test)]
    mod basic_test {

        use super::super::*;
        use super::*;

        const OUTPUT_NAME: &str = "queues.pbuf";
        const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
        const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);

        #[test]
        #[ignore]
        fn serialize() {
            let mut fixture = CanisterQueuesFixture::new_with_ids(CANISTER_ID, OTHER_CANISTER_ID);

            fixture.push_input_request().unwrap();
            fixture.push_output_request().unwrap();
            fixture.push_input_response().unwrap();
            fixture.push_output_response();

            let pb_queues: pb_queues::CanisterQueues = (&fixture.queues).into();
            let serialized = pb_queues.encode_to_vec();

            let output_path = std::path::Path::new(OUTPUT_NAME);
            File::create(output_path)
                .unwrap()
                .write_all(&serialized)
                .unwrap();
        }

        #[test]
        #[ignore]
        fn deserialize() {
            let serialized = std::fs::read(OUTPUT_NAME).expect("Could not read file");
            let pb_queues = pb_queues::CanisterQueues::decode(&serialized as &[u8])
                .expect("Failed to deserialize the protobuf");
            let queues = CanisterQueues::try_from((
                pb_queues,
                &StrictMetrics as &dyn CheckpointLoadingMetrics,
            ))
            .expect("Failed to convert the protobuf to CanisterQueues");
            let mut fixture = CanisterQueuesFixture {
                queues,
                this: CANISTER_ID,
                other: OTHER_CANISTER_ID,
                last_callback_id: 0,
            };
            assert_matches!(fixture.pop_input(), Some(CanisterMessage::Request(_)));
            assert_matches!(fixture.pop_input(), Some(CanisterMessage::Response(_)));
            assert_eq!(fixture.pop_input(), None);
            assert!(!fixture.queues.has_input());

            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Request(_)));
            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Response(_)));
            assert_eq!(fixture.pop_input(), None);
            assert!(!fixture.queues.has_output());
        }
    }

    /// Test that, with multiple input queues of different types, the order in which they
    /// are consumed stays the same
    mod input_order_test {
        use super::super::*;
        use super::*;

        const OUTPUT_NAME: &str = "queues.pbuf";
        const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
        const LOCAL_CANISTER_ID: CanisterId = CanisterId::from_u64(13);
        const REMOTE_CANISTER_ID: CanisterId = CanisterId::from_u64(666);
        const USER_ID: UserId = user_test_id(7);

        #[test]
        #[ignore]
        fn serialize() {
            let mut queues = CanisterQueuesMultiFixture::new();
            queues.this = CANISTER_ID;

            // Put a request and a response from a local canister in the input queues
            queues
                .push_input_request(LOCAL_CANISTER_ID, LocalSubnet)
                .unwrap();
            queues
                .reserve_and_push_input_response(LOCAL_CANISTER_ID, LocalSubnet)
                .unwrap();

            // Put a request and a response from a remote canister in the input queues
            queues
                .push_input_request(REMOTE_CANISTER_ID, RemoteSubnet)
                .unwrap();
            queues
                .reserve_and_push_input_response(REMOTE_CANISTER_ID, RemoteSubnet)
                .unwrap();

            // Put a request from the canister itself in the input queues
            queues.push_input_request(CANISTER_ID, LocalSubnet).unwrap();

            // Put an ingress message in the input queues
            queues.push_ingress(
                IngressBuilder::default()
                    .source(USER_ID)
                    .receiver(CANISTER_ID)
                    .build(),
            );

            let pb_queues: pb_queues::CanisterQueues = (&queues.queues).into();
            let serialized = pb_queues.encode_to_vec();

            let output_path = std::path::Path::new(OUTPUT_NAME);
            File::create(output_path)
                .unwrap()
                .write_all(&serialized)
                .unwrap();
        }

        #[test]
        #[ignore]
        fn deserialize() {
            let serialized = std::fs::read(OUTPUT_NAME).expect("Could not read file");
            let pb_queues = pb_queues::CanisterQueues::decode(&serialized as &[u8])
                .expect("Failed to deserialize the protobuf");
            let c_queues = CanisterQueues::try_from((
                pb_queues,
                &StrictMetrics as &dyn CheckpointLoadingMetrics,
            ))
            .expect("Failed to convert the protobuf to CanisterQueues");

            let mut queues = CanisterQueuesMultiFixture::new();
            queues.queues = c_queues;
            queues.this = CANISTER_ID;

            assert_matches!(queues.pop_input(), Some(CanisterMessage::Request(ref req)) if req.sender == LOCAL_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterMessage::Ingress(ref ing)) if ing.source == USER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterMessage::Request(ref req)) if req.sender == REMOTE_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterMessage::Request(ref req)) if req.sender == CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterMessage::Response(ref req)) if req.respondent == REMOTE_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterMessage::Response(ref req)) if req.respondent == LOCAL_CANISTER_ID);

            assert_eq!(queues.pop_input(), None);
            assert!(!queues.has_input());
        }
    }
}
