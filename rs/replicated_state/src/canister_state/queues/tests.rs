use super::input_schedule::testing::InputScheduleTesting;
use super::message_pool::{MessageStats, REQUEST_LIFETIME};
use super::testing::new_canister_output_queues_for_test;
use super::*;
use crate::testing::FakeDropMessageMetrics;
use crate::{CanisterState, InputQueueType::*, SchedulerState, SystemState};
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities_state::arb_num_receivers;
use ic_test_utilities_types::arbitrary;
use ic_test_utilities_types::ids::{canister_test_id, message_test_id, user_test_id};
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, ResponseBuilder};
use ic_types::messages::{CallbackId, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, NO_DEADLINE};
use ic_types::time::{CoarseTime, UNIX_EPOCH, expiry_time_from_now};
use ic_types::{Cycles, UserId};
use maplit::btreemap;
use proptest::prelude::*;
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

    fn push_input_request(
        &mut self,
        deadline: CoarseTime,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues
            .push_input(
                RequestBuilder::default()
                    .sender(self.other)
                    .receiver(self.this)
                    .deadline(deadline)
                    .build()
                    .into(),
                LocalSubnet,
            )
            .map(|dropped_response| {
                assert!(dropped_response.is_none());
            })
    }

    fn push_input_response(
        &mut self,
        deadline: CoarseTime,
    ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
        self.last_callback_id += 1;
        self.queues.push_input(
            ResponseBuilder::default()
                .originator(self.this)
                .respondent(self.other)
                .originator_reply_callback(CallbackId::from(self.last_callback_id))
                .deadline(deadline)
                .build()
                .into(),
            LocalSubnet,
        )
    }

    fn try_push_deadline_expired_input(&mut self) -> Result<bool, String> {
        self.last_callback_id += 1;
        self.queues.try_push_deadline_expired_input(
            CallbackId::from(self.last_callback_id),
            &self.other,
            &self.this,
            &BTreeMap::new(),
        )
    }

    fn peek_input(&mut self) -> Option<CanisterInput> {
        self.queues.peek_input()
    }

    fn pop_input(&mut self) -> Option<CanisterInput> {
        self.queues.pop_input()
    }

    fn push_output_request(
        &mut self,
        deadline: CoarseTime,
    ) -> Result<(), (StateError, Arc<Request>)> {
        self.last_callback_id += 1;
        self.queues.push_output_request(
            Arc::new(
                RequestBuilder::default()
                    .sender(self.this)
                    .receiver(self.other)
                    .sender_reply_callback(CallbackId::from(self.last_callback_id))
                    .deadline(deadline)
                    .build(),
            ),
            UNIX_EPOCH,
        )
    }

    fn push_output_response(&mut self, deadline: CoarseTime) {
        self.queues.push_output_response(Arc::new(
            ResponseBuilder::default()
                .originator(self.other)
                .respondent(self.this)
                .deadline(deadline)
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
    fn time_out_all_messages_with_deadlines(&mut self) -> RefundPool {
        let mut refunds = RefundPool::default();
        self.queues.time_out_messages(
            Time::from_nanos_since_unix_epoch(u64::MAX),
            &self.this,
            &BTreeMap::default(),
            &mut refunds,
            &FakeDropMessageMetrics::default(),
        );
        refunds
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
        assert_eq!(Ok(None), queues.push_input(req.clone().into(), input_type));
    }
}

fn request(callback: u64, deadline: CoarseTime) -> Request {
    request_with_payload(13, callback, deadline)
}

fn request_with_payload(payload_size: usize, callback: u64, deadline: CoarseTime) -> Request {
    RequestBuilder::new()
        .sender(canister_test_id(13))
        .receiver(canister_test_id(13))
        .method_payload(vec![13; payload_size])
        .sender_reply_callback(CallbackId::from(callback))
        .deadline(deadline)
        .payment(Cycles::new(100))
        .build()
}

fn request_with_payment(callback: u64, deadline: CoarseTime, payment: u128) -> Request {
    Request {
        payment: Cycles::new(payment),
        ..request(callback, deadline)
    }
}

fn response(callback: u64, deadline: CoarseTime) -> Response {
    response_with_payload(13, callback, deadline)
}

fn response_with_payload(payload_size: usize, callback: u64, deadline: CoarseTime) -> Response {
    ResponseBuilder::new()
        .respondent(canister_test_id(13))
        .originator(canister_test_id(13))
        .response_payload(Payload::Data(vec![13; payload_size]))
        .originator_reply_callback(CallbackId::from(callback))
        .deadline(deadline)
        .refund(Cycles::new(10))
        .build()
}

fn response_with_refund(callback: u64, deadline: CoarseTime, refund: u128) -> Response {
    Response {
        refund: Cycles::new(refund),
        ..response(callback, deadline)
    }
}

const fn coarse_time(seconds_since_unix_epoch: u32) -> CoarseTime {
    CoarseTime::from_secs_since_unix_epoch(seconds_since_unix_epoch)
}

/// A non-zero deadline, for use when a single deadline is needed.
const SOME_DEADLINE: CoarseTime = coarse_time(1);

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

fn time_out_messages(
    queues: &mut CanisterQueues,
    current_time: Time,
    own_canister_id: &CanisterId,
    local_canisters: &BTreeMap<CanisterId, CanisterState>,
) -> (usize, RefundPool) {
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    queues.time_out_messages(
        current_time,
        own_canister_id,
        local_canisters,
        &mut refunds,
        &metrics,
    );
    let timed_out_messages = metrics.timed_out_messages.borrow().values().sum();
    (timed_out_messages, refunds)
}

fn shed_largest_message(
    queues: &mut CanisterQueues,
    own_canister_id: &CanisterId,
    local_canisters: &BTreeMap<CanisterId, CanisterState>,
) -> (bool, RefundPool) {
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    let message_shed =
        queues.shed_largest_message(own_canister_id, local_canisters, &mut refunds, &metrics);

    let shed_messages: usize = metrics.shed_messages.borrow().values().sum();
    assert_eq!(message_shed as usize, shed_messages);

    (message_shed, refunds)
}

fn refund_pool(refunds: &[(CanisterId, Cycles)]) -> RefundPool {
    let mut refund_pool = RefundPool::new();
    for (canister_id, cycles) in refunds {
        refund_pool.add(*canister_id, *cycles);
    }
    refund_pool
}

/// Can push one request to the output queues.
#[test]
fn can_push_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_request(NO_DEADLINE).unwrap();
}

/// Cannot push guaranteed response to output queues without having pushed an
/// input request first.
#[test]
#[should_panic(expected = "assertion failed: self.guaranteed_response_memory_reservations > 0")]
fn cannot_push_output_response_guaranteed_without_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_response(NO_DEADLINE);
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
            .deadline(SOME_DEADLINE)
            .build(),
    ));
}

#[test]
fn enqueuing_unexpected_response_does_not_panic() {
    let mut fixture = CanisterQueuesFixture::new();
    // Enqueue a request to create a queue for `other`.
    fixture.push_input_request(NO_DEADLINE).unwrap();
    // Now `other` sends an unexpected `Response`. We should return an error, not
    // panic.
    fixture.push_input_response(NO_DEADLINE).unwrap_err();
}

/// Can push response to output queues after pushing input request.
#[test]
fn can_push_output_response_after_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request(NO_DEADLINE).unwrap();
    fixture.pop_input().unwrap();
    fixture.push_output_response(NO_DEADLINE);
}

/// Can push one request to the induction pool.
#[test]
fn can_push_input_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request(NO_DEADLINE).unwrap();
}

/// Cannot push response to the induction pool without pushing output
/// request first.
#[test]
fn cannot_push_input_response_without_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_response(NO_DEADLINE).unwrap_err();
}

/// Can push response to input queues after pushing request to output
/// queues.
#[test]
fn can_push_input_response_after_output_request() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_output_request(NO_DEADLINE).unwrap();
    fixture.pop_output().unwrap();
    assert_eq!(Ok(None), fixture.push_input_response(NO_DEADLINE));
}

#[test]
fn push_input_response_duplicate_guaranteed_response() {
    let mut queues = CanisterQueues::default();

    // Enqueue two output requests (callback IDs 1 and 2), reserving 2 input queue
    // slots.
    queues
        .push_output_request(request(1, NO_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().pop().unwrap();
    queues
        .push_output_request(request(2, NO_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().pop().unwrap();
    assert_eq!(2, queues.input_queues_reserved_slots());
    assert_eq!(0, queues.input_queues_response_count());

    // Try enqueuing two responses with the same callback ID. The second attempt
    // should fail.
    assert_eq!(
        Ok(None),
        queues.push_input(response(1, NO_DEADLINE).into(), LocalSubnet)
    );
    queues
        .push_input(response(1, NO_DEADLINE).into(), LocalSubnet)
        .unwrap_err();
    assert_eq!(1, queues.input_queues_reserved_slots());
    assert_eq!(1, queues.input_queues_response_count());

    // But enqueuing a response with a different callback ID succeeds.
    assert_eq!(
        Ok(None),
        queues.push_input(response(2, NO_DEADLINE).into(), LocalSubnet)
    );
    assert_eq!(0, queues.input_queues_reserved_slots());
    assert_eq!(2, queues.input_queues_response_count());
}

#[test]
fn push_input_response_duplicate_best_effort_response() {
    let mut queues = CanisterQueues::default();

    // Enqueue two output requests (callback IDs 1 and 2), reserving 2 input queue
    // slots.
    queues
        .push_output_request(request(1, SOME_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().pop().unwrap();
    queues
        .push_output_request(request(2, SOME_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().pop().unwrap();
    assert_eq!(2, queues.input_queues_reserved_slots());
    assert_eq!(0, queues.input_queues_response_count());

    // Try enqueuing two responses with the same callback ID. The second attempt
    // should not return an error, but should be a no-op.
    let best_effort_response = response(1, SOME_DEADLINE);
    assert_eq!(
        Ok(None),
        queues.push_input(best_effort_response.clone().into(), LocalSubnet)
    );
    assert_eq!(
        Ok(Some(Arc::new(best_effort_response.clone()))),
        queues.push_input(best_effort_response.into(), LocalSubnet)
    );
    assert_eq!(1, queues.input_queues_reserved_slots());
    assert_eq!(1, queues.input_queues_response_count());

    // But enqueuing a response with a different callback ID succeeds.
    assert_eq!(
        Ok(None),
        queues.push_input(response(2, SOME_DEADLINE).into(), LocalSubnet)
    );
    assert_eq!(0, queues.input_queues_reserved_slots());
    assert_eq!(2, queues.input_queues_response_count());
}

/// Checks that `available_output_request_slots` doesn't count input requests and
/// output reserved slots and responses.
#[test]
fn test_available_output_request_slots_dont_counts() {
    let mut fixture = CanisterQueuesFixture::new();
    fixture.push_input_request(NO_DEADLINE).unwrap();
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );
    fixture.pop_input().unwrap();

    fixture.push_output_response(NO_DEADLINE);
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
    fixture.push_output_request(NO_DEADLINE).unwrap();
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
    assert_eq!(Ok(None), fixture.push_input_response(NO_DEADLINE));
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
    fixture.push_input_request(NO_DEADLINE).unwrap();
    fixture.pop_input().unwrap();
    fixture.push_output_response(NO_DEADLINE);

    // All output request slots are still available.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY,
        fixture.available_output_request_slots()
    );

    // Push output request, then time it out.
    fixture.push_output_request(NO_DEADLINE).unwrap();
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
    fixture.push_input_request(NO_DEADLINE).unwrap();
    fixture.pop_input();
    fixture.push_output_response(NO_DEADLINE);

    // Push `DEFAULT_QUEUE_CAPACITY` output requests and time them all out.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture.push_output_request(NO_DEADLINE).unwrap();
    }
    fixture.time_out_all_messages_with_deadlines();

    // Check that no new request can be pushed.
    assert!(fixture.push_output_request(NO_DEADLINE).is_err());
}

/// Checks that `available_output_request_slots` counts timed out output
/// requests.
#[test]
fn test_available_output_request_slots() {
    let mut fixture = CanisterQueuesFixture::new();

    // Fill the output queue with requests.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture.push_output_request(NO_DEADLINE).unwrap();
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
fn test_deadline_expired_input() {
    let mut fixture = CanisterQueuesFixture::new();

    // Enqueue a "deadline expired" compact reject response.
    fixture.push_output_request(NO_DEADLINE).unwrap();
    fixture.pop_output().unwrap();
    assert_eq!(Ok(true), fixture.try_push_deadline_expired_input());

    // We have one input (compact) response.
    assert_eq!(1, fixture.queues.input_queues_message_count());
    assert_eq!(1, fixture.queues.input_queues_response_count());
    assert_eq!(0, fixture.queues.input_queues_reserved_slots());
    assert!(fixture.queues.has_input());
    assert!(!fixture.queues.has_output());
    assert!(!fixture.queues.store.is_empty());

    // Peek, then pop the "deadline expired" compact reject response. This also
    // implicitly checks that the input schedule was correctly updated.
    let expected_callback_id = CallbackId::from(fixture.last_callback_id);
    assert_eq!(
        Some(CanisterInput::DeadlineExpired(expected_callback_id)),
        fixture.peek_input()
    );
    assert_eq!(
        Some(CanisterInput::DeadlineExpired(expected_callback_id)),
        fixture.pop_input()
    );

    // No inputs and no outputs left.
    assert_eq!(0, fixture.queues.input_queues_message_count());
    assert_eq!(0, fixture.queues.input_queues_response_count());
    assert_eq!(0, fixture.queues.input_queues_reserved_slots());
    assert!(!fixture.queues.has_input());
    assert!(!fixture.queues.has_output());
    assert!(fixture.queues.store.is_empty());
}

#[test]
fn test_try_push_deadline_expired_input_no_queue() {
    let mut fixture = CanisterQueuesFixture::new();

    // Pushing a deadline expired input into a non-existent queue signals a bug.
    assert_eq!(
        Err("No input queue for expired callback: 1".to_string()),
        fixture.try_push_deadline_expired_input()
    );
}

#[test]
fn test_try_push_deadline_expired_input_no_reserved_slot() {
    let mut fixture = CanisterQueuesFixture::new();

    // Enqueue an input request, to create the input queue.
    fixture.push_input_request(NO_DEADLINE).unwrap();

    // Pushing a deadline expired input without a reserved slot signals a bug.
    assert_eq!(
        Err("No reserved response slot for expired callback: 1".to_string()),
        fixture.try_push_deadline_expired_input()
    );
}

#[test]
fn test_try_push_deadline_expired_input_with_same_callback_id() {
    let mut fixture = CanisterQueuesFixture::new();

    // Push an input response.
    fixture.push_output_request(NO_DEADLINE).unwrap();
    fixture.pop_output().unwrap();
    assert_eq!(Ok(None), fixture.push_input_response(NO_DEADLINE));

    // Sanity check.
    assert_eq!(1, fixture.queues.input_queues_message_count());
    assert_eq!(1, fixture.queues.input_queues_response_count());
    assert_eq!(0, fixture.queues.input_queues_reserved_slots());
    assert!(fixture.queues.has_input());
    assert!(!fixture.queues.store.is_empty());

    // Pushing a deadline expired input with the same callback ID is a no-op.
    let callback_id = fixture.last_callback_id.into();
    assert_eq!(
        Ok(false),
        fixture.queues.try_push_deadline_expired_input(
            callback_id,
            &fixture.other,
            &fixture.this,
            &BTreeMap::new(),
        )
    );

    // Nothing has changed.
    assert_eq!(1, fixture.queues.input_queues_message_count());
    assert_eq!(1, fixture.queues.input_queues_response_count());
    assert_eq!(0, fixture.queues.input_queues_reserved_slots());
    assert!(fixture.queues.has_input());
    assert!(!fixture.queues.store.is_empty());

    // Pop the response.
    assert_matches!(fixture.pop_input(), Some(CanisterInput::Response(_)));

    // Nothing left.
    assert_eq!(0, fixture.queues.input_queues_message_count());
    assert_eq!(0, fixture.queues.input_queues_response_count());
    assert_eq!(0, fixture.queues.input_queues_reserved_slots());
    assert!(!fixture.queues.has_input());
    assert!(fixture.queues.store.is_empty());
}

#[test]
fn test_shed_largest_message() {
    let this = canister_test_id(13);
    let other = canister_test_id(11);

    let mut queues = CanisterQueues::default();

    // Push an input and an output request.
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default()
                .sender(other)
                .receiver(this)
                .deadline(CoarseTime::from_secs_since_unix_epoch(17))
                .build()
                .into(),
            RemoteSubnet,
        )
    );
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
    assert_eq!(
        (true, RefundPool::default()),
        shed_largest_message(&mut queues, &this, &local_canisters)
    );
    assert_eq!(
        (true, RefundPool::default()),
        shed_largest_message(&mut queues, &this, &local_canisters)
    );

    // There should be a reject response in an input queue.
    assert_matches!(queues.pop_input(), Some(CanisterInput::Response(_)));
    assert!(!queues.has_input());
    // But no output.
    assert!(!queues.has_output());
    assert!(queues.output_into_iter().next().is_none());

    // And nothing else to shed.
    assert_eq!(
        (false, RefundPool::default()),
        shed_largest_message(&mut queues, &this, &local_canisters)
    );
}

#[test]
fn test_shed_inbound_response() {
    let mut queues = CanisterQueues::default();

    // Enqueue three output requests, reserving 3 input queue slots.
    for callback in 1..=3 {
        queues
            .push_output_request(request(callback, SOME_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
    }
    assert_eq!(3, queues.output_into_iter().count());
    assert_eq!(3, queues.input_queues_reserved_slots());
    assert_eq!(0, queues.input_queues_response_count());

    // Enqueue three inbound responses with increasing payload sizes.
    for callback in 1..=3 {
        assert_eq!(
            Ok(None),
            queues.push_input(
                response_with_payload(1000 * callback as usize, callback, SOME_DEADLINE).into(),
                LocalSubnet,
            )
        );
    }
    assert_eq!(0, queues.input_queues_reserved_slots());
    assert_eq!(3, queues.input_queues_response_count());

    let this = canister_test_id(13);
    const NO_LOCAL_CANISTERS: BTreeMap<CanisterId, CanisterState> = BTreeMap::new();

    // Shed the largest response (callback ID 3).
    let memory_usage3 = queues.best_effort_message_memory_usage();
    assert_eq!(
        (true, refund_pool(&[(this, Cycles::new(10))])),
        shed_largest_message(&mut queues, &this, &NO_LOCAL_CANISTERS)
    );
    let memory_usage2 = queues.best_effort_message_memory_usage();
    assert!(memory_usage2 < memory_usage3);

    // Shed the next largest response (callback ID 2).
    assert_eq!(
        (true, refund_pool(&[(this, Cycles::new(10))])),
        shed_largest_message(&mut queues, &this, &NO_LOCAL_CANISTERS)
    );
    let memory_usage1 = queues.best_effort_message_memory_usage();
    assert!(memory_usage1 < memory_usage2);

    // Pop the response for callback ID 1.
    assert_matches!(queues.pop_input(), Some(CanisterInput::Response(response)) if response.originator_reply_callback.get() == 1);
    assert_eq!(2, queues.input_queues_response_count());
    assert_eq!(0, queues.best_effort_message_memory_usage());

    // There's nothing else to shed.
    assert_eq!(
        (false, RefundPool::default()),
        shed_largest_message(&mut queues, &this, &NO_LOCAL_CANISTERS)
    );

    // Peek then pop the response for callback ID 2.
    assert_matches!(
        queues.peek_input(),
        Some(CanisterInput::ResponseDropped(callback_id)) if callback_id.get() == 2
    );
    assert_matches!(
        queues.pop_input(),
        Some(CanisterInput::ResponseDropped(callback_id)) if callback_id.get() == 2
    );
    assert_eq!(1, queues.input_queues_response_count());

    // Pop the response for callback ID 3.
    assert_matches!(
        queues.pop_input(),
        Some(CanisterInput::ResponseDropped(callback_id)) if callback_id.get() == 3
    );
    assert_eq!(0, queues.input_queues_response_count());
}

#[test]
fn test_shed_largest_message_generates_refunds() {
    let mut canister_queues = CanisterQueues::default();

    // Cartesian product of best-effort inbound / outbound, request / response; with
    // cycle amounts that can be used as bit masks.
    //
    // Cycles attached to a shed outbound best-effort requests are refunded (in the
    // generated reject response). Cycles attached to all other best-effort messages
    // are lost when the message is shed.
    let inbound_request = request_with_payment(0, SOME_DEADLINE, 1 << 0);
    let inbound_response = response_with_refund(1, SOME_DEADLINE, 1 << 1);
    let outbound_request = request_with_payment(2, SOME_DEADLINE, 1 << 2);
    let outbound_response = response_with_refund(3, SOME_DEADLINE, 1 << 3);

    // Inbound best-effort request: refund message enqueued.
    let own_canister_id = inbound_request.receiver;
    canister_queues
        .push_input(inbound_request.clone().into(), LocalSubnet)
        .unwrap();
    assert_eq!(
        (
            true,
            refund_pool(&[(inbound_request.sender, inbound_request.payment)])
        ),
        shed_largest_message(&mut canister_queues, &own_canister_id, &BTreeMap::new())
    );

    // Inbound best-effort response: refund message enqueued.
    canister_queues
        .push_output_request(request(0, SOME_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    canister_queues.output_into_iter().next().unwrap();
    canister_queues
        .push_input(inbound_response.clone().into(), LocalSubnet)
        .unwrap();
    assert_eq!(
        (
            true,
            refund_pool(&[(inbound_response.originator, inbound_response.refund)])
        ),
        shed_largest_message(&mut canister_queues, &own_canister_id, &BTreeMap::new())
    );
    assert_eq!(
        Some(CanisterInput::ResponseDropped(
            inbound_response.originator_reply_callback
        )),
        canister_queues.pop_input()
    );

    // Outbound best-effort request: reject response with refund enqueued.
    canister_queues
        .push_output_request(outbound_request.clone().into(), UNIX_EPOCH)
        .unwrap();
    assert_eq!(
        (true, RefundPool::default()),
        shed_largest_message(&mut canister_queues, &own_canister_id, &BTreeMap::new())
    );
    assert_matches!(
        canister_queues.pop_input(),
        Some(CanisterInput::Response(response)) if response.refund == outbound_request.payment
    );

    // Outbound best-effort response: refund message enqueued.
    canister_queues
        .push_input(request(0, SOME_DEADLINE).into(), LocalSubnet)
        .unwrap();
    canister_queues.pop_input().unwrap();
    canister_queues.push_output_response(outbound_response.clone().into());
    assert_eq!(
        (
            true,
            refund_pool(&[(outbound_response.originator, outbound_response.refund)])
        ),
        shed_largest_message(&mut canister_queues, &own_canister_id, &BTreeMap::new())
    );
}

/// Enqueues 3 requests for the same canister and consumes them.
#[test]
fn test_message_picking_round_robin_on_one_queue() {
    let mut fixture = CanisterQueuesFixture::new();
    assert!(fixture.pop_input().is_none());
    for _ in 0..3 {
        fixture.push_input_request(NO_DEADLINE).unwrap();
    }

    for _ in 0..3 {
        match fixture.pop_input().expect("could not pop a message") {
            CanisterInput::Request(msg) => assert_eq!(msg.sender, fixture.other),
            msg => panic!("unexpected message popped: {msg:?}"),
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
            CanisterInput::Ingress(msg) => {
                assert_eq!(msg.method_payload, vec![expected_byte])
            }
            msg => panic!("unexpected message popped: {msg:?}"),
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
        self.push_input_request_with_deadline(other, NO_DEADLINE, input_queue_type)
    }

    fn push_input_request_with_deadline(
        &mut self,
        other: CanisterId,
        deadline: CoarseTime,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.queues
            .push_input(
                RequestBuilder::default()
                    .sender(other)
                    .receiver(self.this)
                    .deadline(deadline)
                    .build()
                    .into(),
                input_queue_type,
            )
            .map(|dropped_response| assert!(dropped_response.is_none()))
    }

    fn push_input_response(
        &mut self,
        other: CanisterId,
        input_queue_type: InputQueueType,
    ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
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
    ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
        self.push_output_request(other)
            .map_err(|(se, req)| (se, (*req).clone().into()))?;
        self.pop_output()
            .expect("Just pushed an output request, but nothing popped");
        self.push_input_response(other, input_queue_type)
    }

    fn push_ingress(&mut self, msg: Ingress) {
        self.queues.push_ingress(msg)
    }

    fn pop_input(&mut self) -> Option<CanisterInput> {
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
    fn time_out_all_messages_with_deadlines(&mut self) -> (usize, RefundPool) {
        time_out_messages(
            &mut self.queues,
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
        self.queues.store.is_empty()
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
        fixture.push_input_request(*id, RemoteSubnet).unwrap();
    }

    // Local response from `other_2`.
    // First push then pop a request to `other_2`, in order to get a reserved slot.
    fixture.push_output_request(other_2).unwrap();
    fixture.pop_output().unwrap();
    assert_eq!(Ok(None), fixture.push_input_response(other_2, LocalSubnet));

    // Local request from `other_2`.
    fixture.push_input_request(other_2, LocalSubnet).unwrap();

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
        Some(CanisterInput::Response(msg)) if msg.respondent == other_2
    );

    // 2. Ingress message
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterInput::Ingress(msg)) if msg.source == user_test_id(77)
    );

    // 3. Remote Subnet request (other_1)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterInput::Request(msg)) if msg.sender == other_1
    );

    // 4. Local Subnet request (other_2)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterInput::Request(msg)) if msg.sender == other_2
    );

    // 5. Remote Subnet request (other_3)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterInput::Request(msg)) if msg.sender == other_3
    );

    // 6. Remote Subnet request (other_1)
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterInput::Request(msg)) if msg.sender == other_1
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

    let push_input_from = |fixture: &mut CanisterQueuesMultiFixture, sender: CanisterId| {
        fixture.push_input_request(sender, RemoteSubnet).unwrap();
    };

    let assert_sender = |sender: CanisterId, message: CanisterInput| match message {
        CanisterInput::Request(req) => assert_eq!(sender, req.sender),
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
    assert!(fixture.pop_input().is_none());
    assert!(fixture.pool_is_empty());
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

    // Schedules after: `other_2` and `other_3` have moved to the front of the
    // remote input schedule. Ordering is otherwise retained.
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
    let peeked_input = CanisterInput::Request(Arc::new(local_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    // Peeking again the queues would return the same result.
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 2. Ingress message
    let peeked_input = CanisterInput::Ingress(Arc::new(ingress));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 3. Remote Subnet request (index 0)
    let peeked_input = CanisterInput::Request(Arc::new(remote_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 4. Local Subnet request (index 1)
    let peeked_input = CanisterInput::Request(Arc::new(local_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 5. Remote Subnet request (index 2)
    let peeked_input = CanisterInput::Request(Arc::new(remote_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 6. Local Subnet request (index 2)
    let peeked_input = CanisterInput::Request(Arc::new(local_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // 7. Remote Subnet request (index 1)
    let peeked_input = CanisterInput::Request(Arc::new(remote_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    assert!(!queues.has_input());
    assert!(queues.store.is_empty());
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
    let ingress_input = CanisterInput::Ingress(Arc::new(ingress));
    assert!(queues.has_input());

    // 1. Pop local subnet request (index 0)
    // 2. Skip ingress message
    // 3. Pop local subnet request (index 1)
    // 4. Skip ingress message
    // 5. Skip local subnet request (index 2)
    // Loop detected.

    let mut loop_detector = CanisterQueuesLoopDetector::default();

    // Pop local queue.
    let peeked_input = CanisterInput::Request(Arc::new(local_requests.first().unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // Skip ingress.
    assert_eq!(queues.peek_input().unwrap(), ingress_input);
    queues.skip_input(&mut loop_detector);
    assert_eq!(loop_detector.ingress_queue_skip_count, 1);
    assert!(!loop_detector.detected_loop(&queues));

    let peeked_input = CanisterInput::Request(Arc::new(local_requests.get(1).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    assert_eq!(queues.pop_input().unwrap(), peeked_input);

    // Skip ingress
    assert_eq!(queues.peek_input().unwrap(), ingress_input);
    queues.skip_input(&mut loop_detector);
    assert!(!loop_detector.detected_loop(&queues));
    assert_eq!(loop_detector.ingress_queue_skip_count, 2);

    // Skip local.
    let peeked_input = CanisterInput::Request(Arc::new(local_requests.get(2).unwrap().clone()));
    assert_eq!(queues.peek_input().unwrap(), peeked_input);
    queues.skip_input(&mut loop_detector);
    assert_eq!(loop_detector.ingress_queue_skip_count, 2);
    assert!(loop_detector.detected_loop(&queues));
}

/// Generates a `CanisterQueues` with 3 input queues: one empty; one holding one
/// message; and one queue with a stale reference, followed by a message,
/// followed by another stale reference. This is so that we can test all edge
/// cases: empty queue, (already popped) stale reference before message and
/// stale reference after message.
///
/// Returns the queues and copies of the requests that were enqueued (with only
/// requests @2 and @3 non-stale).
fn new_queues_with_stale_references() -> (CanisterQueues, Vec<Request>) {
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
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    queues.time_out_messages(
        coarse_time(1003).into(),
        &own_canister_id,
        &local_canisters,
        &mut refunds,
        &metrics,
    );
    assert!(refunds.is_empty());
    assert_eq!(
        btreemap! {
            ("request", "inbound", "best-effort") => 3,
        },
        *metrics.timed_out_messages.borrow(),
    );

    assert!(queues.has_input());
    (queues, requests)
}

#[test]
fn test_peek_input_with_stale_references() {
    let (mut queues, requests) = new_queues_with_stale_references();

    // 1. Request @2.
    let expected = CanisterInput::Request(Arc::new(requests.get(2).unwrap().clone()));
    assert_eq!(expected, queues.peek_input().unwrap());
    assert_eq!(expected, queues.pop_input().unwrap());

    // 2. Request @3.
    let expected = CanisterInput::Request(Arc::new(requests.get(3).unwrap().clone()));
    assert_eq!(expected, queues.peek_input().unwrap());
    assert_eq!(expected, queues.pop_input().unwrap());

    assert!(!queues.has_input());
    assert!(queues.store.is_empty());
}

#[test]
fn test_pop_input_with_stale_references() {
    let (mut queues, requests) = new_queues_with_stale_references();

    // 1. Request @2.
    let expected = CanisterInput::Request(Arc::new(requests.get(2).unwrap().clone()));
    assert_eq!(expected, queues.pop_input().unwrap());

    // 2. Request @3.
    let expected = CanisterInput::Request(Arc::new(requests.get(3).unwrap().clone()));
    assert_eq!(expected, queues.pop_input().unwrap());

    assert!(!queues.has_input());
    assert!(queues.store.is_empty());
}

#[test]
fn test_skip_input_with_stale_references() {
    let (mut queues, requests) = new_queues_with_stale_references();
    let request_2 = CanisterInput::Request(Arc::new(requests.get(2).unwrap().clone()));
    let request_3 = CanisterInput::Request(Arc::new(requests.get(3).unwrap().clone()));
    let mut loop_detector = CanisterQueuesLoopDetector::default();

    // Skip the request @2. Expect request @3.
    //
    // Don't peek before skipping, we want to test `skip_input()` dealing with stale
    // references.
    queues.skip_input(&mut loop_detector);
    assert!(!loop_detector.detected_loop(&queues));
    assert_eq!(request_3, queues.peek_input().unwrap());

    // Skip the request @3. Expect request @2.
    queues.skip_input(&mut loop_detector);
    assert!(loop_detector.detected_loop(&queues));
    assert_eq!(request_2, queues.peek_input().unwrap());

    // Pop the two messages.
    assert_eq!(request_2, queues.pop_input().unwrap());
    assert_eq!(request_3, queues.pop_input().unwrap());

    assert!(!queues.has_input());
    assert!(queues.store.is_empty());
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
        .push_input_request_with_deadline(other_1, SOME_DEADLINE, LocalSubnet)
        .unwrap();
    fixture.push_input_request(other_2, LocalSubnet).unwrap();
    fixture
        .push_input_request_with_deadline(other_3, SOME_DEADLINE, LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_4, SOME_DEADLINE, RemoteSubnet)
        .unwrap();
    fixture.push_input_request(other_5, RemoteSubnet).unwrap();
    fixture
        .push_input_request_with_deadline(other_6, SOME_DEADLINE, RemoteSubnet)
        .unwrap();
    assert_eq!(Ok(()), fixture.schedules_ok());

    // Time out the messages from `other_1`, `other_3`, `other_4` and `other_6`.
    assert_eq!(
        (4, RefundPool::default()),
        fixture.time_out_all_messages_with_deadlines()
    );
    assert_eq!(Ok(()), fixture.queues.test_invariants());
    assert_eq!(Ok(()), fixture.schedules_ok());

    let queues = fixture.queues;
    assert_eq!(
        Ok(()),
        queues.schedules_ok(&input_queue_type_from_local_canisters(vec![
            canister_test_id(1),
            canister_test_id(2),
            canister_test_id(3)
        ]))
    );

    // Ensure that we only have the messages from `other_2` and `other_5` left.
    assert_eq!(2, queues.input_queues_message_count());
    for canister in [1, 3, 4, 6] {
        let canister_id = canister_test_id(canister);
        assert_eq!(0, queues.canister_queues.get(&canister_id).unwrap().0.len());
    }
    // And no messages and only 2 reserved slots in output queues.
    assert_eq!(0, queues.output_queues_message_count());
    assert_eq!(2, queues.output_queues_reserved_slots());

    // But both schedules still have length 3.
    assert_eq!(3, queues.input_schedule.local_sender_schedule().len());
    assert_eq!(3, queues.input_schedule.remote_sender_schedule().len());

    queues
}

#[test]
fn test_pop_input_with_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    assert!(!queues.has_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
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
fn test_pop_input_with_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert!(queues.has_input());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    assert!(!queues.has_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
    assert_eq!(Ok(()), queues.schedules_ok(&|_| RemoteSubnet));
}

#[test]
fn test_peek_input_with_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
}

#[test]
fn test_peek_input_with_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
}

#[test]
fn test_skip_input_with_empty_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
}

#[test]
fn test_skip_input_with_gced_queue_in_input_schedule() {
    let mut queues = canister_queues_with_empty_queues_in_input_schedules();

    // Garbage collect the empty queue pairs.
    queues.garbage_collect();
    // Only 2 queue pairs should be left.
    assert_eq!(2, queues.canister_queues.len());

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(5));

    queues.skip_input(&mut CanisterQueuesLoopDetector::default());
    assert_matches!(queues.peek_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));
    assert_matches!(queues.pop_input().unwrap(), CanisterInput::Request(request) if request.sender == canister_test_id(2));

    assert_eq!(None, queues.peek_input());
    assert_eq!(None, queues.pop_input());

    assert!(queues.store.is_empty());
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
        .push_input_request_with_deadline(other_1, SOME_DEADLINE, LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_2, SOME_DEADLINE, RemoteSubnet)
        .unwrap();

    // Time out all messages.
    assert_eq!(
        (2, RefundPool::default()),
        fixture.time_out_all_messages_with_deadlines()
    );
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
        .push_input_request_with_deadline(other_1, SOME_DEADLINE, LocalSubnet)
        .unwrap();
    fixture
        .push_input_request_with_deadline(other_2, SOME_DEADLINE, RemoteSubnet)
        .unwrap();

    assert_eq!(Ok(()), fixture.schedules_ok());
    assert!(fixture.has_input());

    assert!(fixture.pop_input().is_some());
    assert!(fixture.pop_input().is_some());

    assert!(!fixture.has_input());
    assert!(fixture.pop_input().is_none());
    assert!(fixture.pool_is_empty());
}

/// Enqueues 6 output requests across 3 canisters and consumes them.
#[test]
fn test_output_into_iter() {
    let this = canister_test_id(13);
    let other_1 = canister_test_id(1);
    let other_2 = canister_test_id(2);
    let other_3 = canister_test_id(3);

    let mut queues = CanisterQueues::default();
    assert_eq!(0, queues.output_queues_message_count());

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
    assert_eq!(expected.len(), queues.output_queues_message_count());

    for (i, msg) in queues.output_into_iter().enumerate() {
        match msg {
            RequestOrResponse::Request(msg) => {
                assert_eq!(this, msg.sender);
                assert_eq!(*expected[i].0, msg.receiver);
                assert_eq!(vec![expected[i].1], msg.method_payload)
            }
            msg => panic!("unexpected message popped: {msg:?}"),
        }
    }

    assert_eq!(0, queues.output_queues_message_count());
    assert!(queues.store.is_empty());
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
        CanisterInput::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterInput::Request(Arc::new(local_requests.first().unwrap().clone()))
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
        CanisterInput::Request(Arc::new(remote_requests.first().unwrap().clone()))
    );
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterInput::Request(Arc::new(local_requests.first().unwrap().clone()))
    );

    queues.skip_canister_input(RemoteSubnet);
    queues.skip_canister_input(LocalSubnet);

    // Peek will return a different result.
    assert_eq!(
        queues.peek_canister_input(RemoteSubnet).unwrap(),
        CanisterInput::Request(Arc::new(remote_requests.get(1).unwrap().clone()))
    );
    assert_eq!(queues.input_schedule.remote_sender_schedule().len(), 2);
    assert_eq!(
        queues.peek_canister_input(LocalSubnet).unwrap(),
        CanisterInput::Request(Arc::new(local_requests.get(1).unwrap().clone()))
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
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default().sender(this).build().into(),
            LocalSubnet,
        )
    );
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default().sender(other).build().into(),
            RemoteSubnet,
        )
    );
    queues.pop_canister_input(RemoteSubnet).unwrap();

    let response_callback = CallbackId::from(42);
    queues
        .push_output_request(
            RequestBuilder::default()
                .receiver(other)
                .sender_reply_callback(response_callback)
                .build()
                .into(),
            UNIX_EPOCH,
        )
        .unwrap();
    queues.output_into_iter().next().unwrap();
    assert_eq!(
        Ok(None),
        queues.push_input(
            ResponseBuilder::default()
                .respondent(other)
                .originator_reply_callback(response_callback)
                .build()
                .into(),
            RemoteSubnet,
        )
    );

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
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default().sender(this).build().into(),
            LocalSubnet,
        )
    );
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default().sender(other).build().into(),
            RemoteSubnet,
        )
    );
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
    assert_eq!(
        Ok(None),
        queues.push_input(
            RequestBuilder::default().sender(this).build().into(),
            RemoteSubnet,
        )
    );
    queues.pop_canister_input(RemoteSubnet).unwrap();
    // Sanity check that the pool is empty but not equal to the default.
    assert!(queues.store.is_empty());
    assert_ne!(MessageStoreImpl::default(), queues.store);

    // And a roundtrip encode preserves the `CanisterQueues` unaltered.
    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)
        .try_into()
        .unwrap();
    assert_eq!(queues, decoded);
}

/// Constructs an encoded `CanisterQueues` with 2 inbound responses (callbacks 1
/// and 2), one shed inbound response (callback 3) and one expired callback
/// response (4).
fn canister_queues_proto_with_inbound_responses() -> pb_queues::CanisterQueues {
    let mut queues = CanisterQueues::default();

    let canister_id = canister_test_id(13);

    // Make 4 input queue reservations.
    let deadline = coarse_time(1);
    queues
        .push_output_request(request(1, NO_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request(2, deadline).into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request(3, deadline).into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request(4, deadline).into(), UNIX_EPOCH)
        .unwrap();
    assert_eq!(4, queues.output_into_iter().count());

    // Enqueue 3 inbound responses plus a deadine expired compact reject response.
    assert_eq!(
        Ok(None),
        queues.push_input(response(1, NO_DEADLINE).into(), LocalSubnet)
    );
    assert_eq!(
        Ok(None),
        queues.push_input(response(2, deadline).into(), LocalSubnet)
    );
    let response3 = response(3, deadline);
    assert_eq!(
        Ok(None),
        queues.push_input(response3.clone().into(), LocalSubnet)
    );
    assert_eq!(
        Ok(true),
        queues.try_push_deadline_expired_input(
            4.into(),
            &canister_id,
            &canister_id,
            &BTreeMap::new()
        )
    );

    // Shed the response for callback 3.
    assert_eq!(
        (
            true,
            refund_pool(&[(response3.originator, response3.refund)])
        ),
        shed_largest_message(&mut queues, &canister_id, &BTreeMap::new())
    );
    assert_eq!(
        Some(&CallbackId::from(3)),
        queues.store.shed_responses.values().next()
    );

    // Sanity check: roundtrip encode succeeds.
    let encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (
        encoded.clone(),
        &StrictMetrics as &dyn CheckpointLoadingMetrics,
    )
        .try_into()
        .unwrap();
    assert_eq!(queues, decoded);

    encoded
}

#[test]
fn decode_with_duplicate_response_callback_in_pool() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Tweak the pool so both responses have the same `CallbackId`.
    for entry in &mut encoded.pool.as_mut().unwrap().messages {
        let message = entry.message.as_mut().unwrap().r.as_mut().unwrap();
        let pb_queues::request_or_response::R::Response(response) = message else {
            panic!("Expected only responses");
        };
        response.originator_reply_callback = 1;
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Duplicate inbound response callback: 1"
    );
}

#[test]
fn decode_with_duplicate_response_callback_in_shed_responses() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Have the callback ID of the shed response match that of one of the responses.
    for shed_response in &mut encoded.shed_responses {
        shed_response.callback_id = 1;
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Duplicate inbound response callback: 1"
    );
}

#[test]
fn decode_with_duplicate_response_callback_in_expired_callbacks() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Have the callback ID of the expired callback match that of one of the
    // responses.
    for expired_callback in &mut encoded.expired_callbacks {
        expired_callback.callback_id = 1;
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Duplicate inbound response callback: 1"
    );
}

#[test]
fn decode_with_duplicate_reference() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Replace the reference to the second response with a duplicate reference to
    // the third.
    let input_queue = encoded.canister_queues[0].input_queue.as_mut().unwrap();
    input_queue.queue[1] = input_queue.queue[2];

    let metrics = CountingMetrics(RefCell::new(0));
    assert_matches!(
        CanisterQueues::try_from((encoded, &metrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Duplicate inbound response callback: 3"
    );
    // A critical error should also have been observed.
    assert_eq!(1, *metrics.0.borrow());
}

#[test]
fn decode_with_both_response_and_shed_response_for_reference() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Make the the shed response have the same reference as one of the responses.
    let input_queue = encoded.canister_queues[0].input_queue.as_ref().unwrap();
    for shed_response in &mut encoded.shed_responses {
        shed_response.id = input_queue.queue[1];
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if msg.contains("CanisterQueues: Multiple responses for Reference(")
    );
}

#[test]
fn decode_with_both_response_and_expired_callback_for_reference() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Make the the shed response have the same reference as one of the responses.
    let input_queue = encoded.canister_queues[0].input_queue.as_ref().unwrap();
    let response_id = input_queue.queue[1];
    for expired_callback in &mut encoded.expired_callbacks {
        expired_callback.id = response_id;
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if msg.contains("CanisterQueues: Multiple responses for Reference(")
    );
}

#[test]
fn decode_with_both_shed_response_and_expired_callback_for_reference() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Make the the expired callback have the same reference as the shed response.
    let response_id = encoded.shed_responses[0].id;
    for expired_callback in &mut encoded.expired_callbacks {
        expired_callback.id = response_id;
    }

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if msg.contains("CanisterQueues: Multiple responses for Reference(")
    );
}

#[test]
fn decode_with_unreferenced_inbound_response() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Remove the reference to the second response.
    let input_queue = encoded.canister_queues[0].input_queue.as_mut().unwrap();
    input_queue.queue.remove(1);

    let metrics = CountingMetrics(RefCell::new(0));
    assert_matches!(
        CanisterQueues::try_from((encoded, &metrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Have 4 inbound responses, but only 3 are enqueued"
    );
    // A critical error should also have been observed.
    assert_eq!(1, *metrics.0.borrow());
}

#[test]
fn decode_with_unreferenced_shed_response() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Remove the reference to the third (shed) response.
    let input_queue = encoded.canister_queues[0].input_queue.as_mut().unwrap();
    input_queue.queue.remove(2);

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Have 4 inbound responses, but only 3 are enqueued"
    );
}

#[test]
fn decode_with_unreferenced_expired_callback() {
    let mut encoded = canister_queues_proto_with_inbound_responses();

    // Remove the reference to the fourth (expired callback) response.
    let input_queue = encoded.canister_queues[0].input_queue.as_mut().unwrap();
    input_queue.queue.remove(3);

    assert_matches!(
        CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics)),
        Err(ProxyDecodeError::Other(msg)) if &msg == "CanisterQueues: Have 4 inbound responses, but only 3 are enqueued"
    );
}

#[test]
fn decode_with_duplicate_inbound_response() {
    let mut queues = CanisterQueues::default();

    // Make 2 input queue reservations.
    queues
        .push_output_request(request(1, NO_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    queues
        .push_output_request(request(2, SOME_DEADLINE).into(), UNIX_EPOCH)
        .unwrap();
    assert_eq!(2, queues.output_into_iter().count());

    // Enqueue 2 inbound responses.
    assert_eq!(
        Ok(None),
        queues.push_input(response(1, NO_DEADLINE).into(), LocalSubnet)
    );
    assert_eq!(
        Ok(None),
        queues.push_input(response(2, SOME_DEADLINE).into(), LocalSubnet)
    );

    // Sanity check: roundtrip encode succeeds.
    let mut encoded: pb_queues::CanisterQueues = (&queues).into();
    let decoded = (
        encoded.clone(),
        &StrictMetrics as &dyn CheckpointLoadingMetrics,
    )
        .try_into()
        .unwrap();
    assert_eq!(queues, decoded);

    // Tweak the encoded queues so both responses have the same `CallbackId`.
    for entry in &mut encoded.pool.as_mut().unwrap().messages {
        let message = entry.message.as_mut().unwrap().r.as_mut().unwrap();
        let pb_queues::request_or_response::R::Response(response) = message else {
            panic!("Expected only responses");
        };
        response.originator_reply_callback = 1;
    }

    // Decoding should now fail because of the duplicate `CallbackId`.
    let err = CanisterQueues::try_from((encoded, &StrictMetrics as &dyn CheckpointLoadingMetrics))
        .unwrap_err();
    assert_matches!(err, ProxyDecodeError::Other(msg) if &msg == "CanisterQueues: Duplicate inbound response callback: 1");
}

#[test]
fn test_stats_best_effort() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(&MessageStats::default(), queues.message_stats());

    // Best-effort requests and best-effort responses, to be enqueued one each into
    // an input and an output queue.
    let t10 = coarse_time(10);
    let t20 = coarse_time(20);
    let request1_ = request(1, t10);
    let request2_ = request(2, t10);
    let request3 = request(3, t10);
    let request4 = request(4, t10);
    let request_size_bytes = request1_.count_bytes();
    assert_eq!(request_size_bytes, request2_.count_bytes());
    assert_eq!(request_size_bytes, request3.count_bytes());
    assert_eq!(request_size_bytes, request4.count_bytes());
    let response1 = response_with_payload(1000, 1, t20);
    let response2 = response_with_payload(1000, 2, t20);
    let response_size_bytes = response1.count_bytes();
    assert_eq!(response_size_bytes, response2.count_bytes());

    // Make reservations for the responses.
    assert_eq!(Ok(None), queues.push_input(request1_.into(), LocalSubnet));
    queues.pop_input().unwrap();
    queues
        .push_output_request(request2_.into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().next().unwrap();

    // Actually enqueue the messages.
    assert_eq!(
        Ok(None),
        queues.push_input(request3.clone().into(), LocalSubnet)
    );
    assert_eq!(
        Ok(None),
        queues.push_input(response2.clone().into(), LocalSubnet)
    );
    queues.push_output_response(response1.clone().into());
    queues
        .push_output_request(request4.clone().into(), UNIX_EPOCH)
        .unwrap();

    // One input queue slot, one output queue slot, zero memory reservations.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 0,
        input_queues_reserved_slots: 1,
        output_queues_reserved_slots: 1,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two best-effort response requests, two best-effort responses.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(220),
        },
        queues.message_stats()
    );

    // Pop the incoming request and the outgoing response.
    assert_eq!(
        queues.pop_input(),
        Some(CanisterInput::Request(request3.clone().into()))
    );
    assert_eq!(
        queues.output_into_iter().next().unwrap(),
        RequestOrResponse::Response(response1.clone().into())
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One best-effort response request, one best-effort response.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(110),
        },
        queues.message_stats()
    );

    // Time out the one message with a deadline of less than 20 (the outgoing
    // request; generating a reject response) and shed the incoming response.
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    queues.time_out_messages(
        t20.into(),
        &request4.sender,
        &BTreeMap::new(),
        &mut refunds,
        &metrics,
    );
    assert_eq!(
        btreemap! {
            ("request", "outbound", "best-effort") => 1,
        },
        *metrics.timed_out_messages.borrow(),
    );
    assert!(refunds.is_empty());
    assert_eq!(
        (
            true,
            refund_pool(&[(response2.originator, response2.refund)])
        ),
        shed_largest_message(&mut queues, &response2.respondent, &BTreeMap::new())
    );

    // Input queue slot reservation was consumed by reject response.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 0,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 1,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Only one best-effort reject response (the dropped response is no longer in
    // the pool).
    let reject_response = generate_timeout_response(&request4);
    let reject_response_size_bytes = reject_response.count_bytes();
    assert_eq!(
        &message_pool::MessageStats {
            size_bytes: reject_response_size_bytes,
            best_effort_message_bytes: reject_response_size_bytes,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: reject_response_size_bytes,
            inbound_message_count: 1,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 0,
            cycles: Cycles::new(100),
        },
        queues.message_stats()
    );
    // But the `CanisterQueues` getter methods know that there are two responses.
    assert_eq!(2, queues.input_queues_message_count());
    assert_eq!(2, queues.input_queues_response_count());

    // Pop the dropped response and the generated reject response.
    assert_eq!(
        Some(CanisterInput::ResponseDropped(
            response2.originator_reply_callback
        )),
        queues.pop_input()
    );
    assert_eq!(
        Some(CanisterInput::Response(reject_response.into())),
        queues.pop_input(),
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And we have all-zero message stats.
    assert_eq!(&MessageStats::default(), queues.message_stats());
}

#[test]
fn test_stats_guaranteed_response() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(&MessageStats::default(), queues.message_stats());

    // Guaranteed response requests and guaranteed responses, to be enqueued one
    // each into an input and an output queue.
    let request1_ = request_with_payload(100, 1, NO_DEADLINE);
    let request2_ = request_with_payload(100, 2, NO_DEADLINE);
    let request3 = request_with_payload(100, 3, NO_DEADLINE);
    let request4 = request_with_payload(100, 4, NO_DEADLINE);
    let request_size_bytes = request1_.count_bytes();
    assert_eq!(request_size_bytes, request2_.count_bytes());
    assert_eq!(request_size_bytes, request3.count_bytes());
    assert_eq!(request_size_bytes, request4.count_bytes());
    let response1 = response(1, NO_DEADLINE);
    let response2 = response(2, NO_DEADLINE);
    let response4_ = response(4, NO_DEADLINE);
    let response_size_bytes = response1.count_bytes();
    assert_eq!(response_size_bytes, response2.count_bytes());
    assert_eq!(response_size_bytes, response4_.count_bytes());

    // Make reservations for the responses.
    assert_eq!(Ok(None), queues.push_input(request1_.into(), LocalSubnet));
    queues.pop_input().unwrap();
    queues
        .push_output_request(request2_.into(), UNIX_EPOCH)
        .unwrap();
    queues.output_into_iter().next().unwrap();

    // Actually enqueue the messages.
    assert_eq!(
        Ok(None),
        queues.push_input(request3.clone().into(), LocalSubnet)
    );
    assert_eq!(
        Ok(None),
        queues.push_input(response2.clone().into(), LocalSubnet)
    );
    queues.push_output_response(response1.clone().into());
    queues
        .push_output_request(request4.clone().into(), UNIX_EPOCH)
        .unwrap();

    // One input queue slot, one output queue slot, two memory reservations.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 2,
        input_queues_reserved_slots: 1,
        output_queues_reserved_slots: 1,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two guaranteed response requests, two guaranteed responses.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(220),
        },
        queues.message_stats()
    );

    // Pop the incoming request and the outgoing response.
    assert_eq!(
        queues.pop_input(),
        Some(CanisterInput::Request(request3.clone().into()))
    );
    assert_eq!(
        queues.output_into_iter().next().unwrap(),
        RequestOrResponse::Response(response1.clone().into())
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One guaranteed response request, one guaranteed response.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(110),
        },
        queues.message_stats()
    );

    // Time out the one message that has an (implicit) deadline (the outgoing
    // request), pop the incoming response and the generated reject response.
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    queues.time_out_messages(
        coarse_time(u32::MAX).into(),
        &request4.sender,
        &BTreeMap::new(),
        &mut refunds,
        &metrics,
    );
    assert!(refunds.is_empty());
    assert_eq!(
        btreemap! {
            ("request", "outbound", "guaranteed response") => 1,
        },
        *metrics.timed_out_messages.borrow(),
    );
    assert_eq!(
        queues.pop_input(),
        Some(CanisterInput::Response(response2.clone().into()))
    );
    assert!(queues.pop_input().is_some());

    // Input queue slot and memory reservations were consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 1,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 1,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // And we have all-zero message stats.
    assert_eq!(&MessageStats::default(), queues.message_stats());

    // Consume the output queue slot reservation.
    queues.push_output_response(response4_.clone().into());
    queues.output_into_iter().next().unwrap();

    // Default stats throughout.
    assert_eq!(QueueStats::default(), queues.queue_stats);
    assert_eq!(&MessageStats::default(), queues.message_stats());
}

#[test]
fn test_stats_oversized_requests() {
    let mut queues = CanisterQueues::default();

    let mut expected_queue_stats = QueueStats::default();
    assert_eq!(expected_queue_stats, queues.queue_stats);
    assert_eq!(&MessageStats::default(), queues.message_stats());

    // One oversized best-effort request and one oversized guaranteed response
    // request, to be enqueued into both an input and an output queue.
    let best_effort = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 1000,
        1,
        SOME_DEADLINE,
    );
    let best_effort_size_bytes = best_effort.count_bytes();
    let guaranteed = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 2000,
        2,
        NO_DEADLINE,
    );
    let guaranteed_size_bytes = guaranteed.count_bytes();
    // The 2000 bytes we added above; plus the method name provided by
    // `RequestBuilder`; plus any difference in size between the `Request` and
    // `Response` structs, so better compute it.
    let guaranteed_extra_bytes = guaranteed_size_bytes - MAX_RESPONSE_COUNT_BYTES;

    assert_eq!(
        Ok(None),
        queues.push_input(best_effort.clone().into(), LocalSubnet)
    );
    assert_eq!(
        Ok(None),
        queues.push_input(guaranteed.clone().into(), LocalSubnet)
    );
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
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // Two best-effort requests, two oversized guaranteed requests, 4 requests in all.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(400),
        },
        queues.message_stats()
    );

    // Pop the incoming best-effort request and the incoming guaranteed request.
    assert_eq!(
        Some(CanisterInput::Request(best_effort.clone().into())),
        queues.pop_input()
    );
    assert_eq!(
        Some(CanisterInput::Request(guaranteed.clone().into())),
        queues.pop_input()
    );

    // No changes in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // One best-effort request, one oversized guaranteed request, 2 requests in all.
    assert_eq!(
        &MessageStats {
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
            cycles: Cycles::new(200),
        },
        queues.message_stats()
    );

    // Shed the outgoing best-effort request and time out the outgoing guaranteed one.
    assert_eq!(
        (true, RefundPool::default()),
        shed_largest_message(&mut queues, &best_effort.sender, &BTreeMap::new())
    );
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    queues.time_out_messages(
        coarse_time(u32::MAX).into(),
        &best_effort.sender,
        &BTreeMap::new(),
        &mut refunds,
        &metrics,
    );
    assert!(refunds.is_empty());
    assert_eq!(
        btreemap! {
            ("request", "outbound", "guaranteed response") => 1,
        },
        *metrics.timed_out_messages.borrow(),
    );

    // Input queue slots and the input queue memory reservation were consumed.
    expected_queue_stats = QueueStats {
        guaranteed_response_memory_reservations: 1,
        input_queues_reserved_slots: 0,
        output_queues_reserved_slots: 2,
    };
    assert_eq!(expected_queue_stats, queues.queue_stats);

    // And pop the two reject responses.
    queues.pop_input().unwrap();
    queues.pop_input().unwrap();

    // No change in slot and memory reservations.
    assert_eq!(expected_queue_stats, queues.queue_stats);
    // But back to all-zero message stats.
    assert_eq!(&MessageStats::default(), queues.message_stats());
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
    assert_eq!(Ok(None), queues.push_input(response.into(), LocalSubnet));
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
    assert_eq!(0, pb_queues::CanisterQueues::from(&queues).encoded_len());
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
        .reject_subnet_output_request(request, reject_context.clone(), &BTreeSet::new())
        .unwrap();

    // There is now a reject response.
    assert_eq!(
        CanisterInput::Response(Arc::new(
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
    assert!(queues.store.is_empty());
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
    assert!(queues.store.is_empty());
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
                .sender_reply_callback(CallbackId::from(i as u64))
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
    time_out_messages(
        &mut queues,
        coarse_time(1002).into(),
        &own_canister_id,
        &local_canisters,
    );

    assert!(queues.has_output());

    // One message to canister 1.
    let request2: RequestOrResponse = requests.get(2).unwrap().clone().into();
    assert_eq!(Some(&request2), queues.peek_output(&canister1));
    assert_eq!(Some(request2), queues.pop_canister_output(&canister1));
    assert_eq!(None, queues.peek_output(&canister1));

    // No message to canister 2.
    assert_eq!(None, queues.peek_output(&canister2));

    // One message to canister 3.
    let request3: RequestOrResponse = requests.get(3).unwrap().clone().into();
    assert_eq!(Some(&request3), queues.peek_output(&canister3));
    assert_eq!(Some(request3), queues.pop_canister_output(&canister3));
    assert_eq!(None, queues.peek_output(&canister3));

    assert!(!queues.has_output());
    assert!(queues.store.pool.len() == 2);
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
    prop_assert!(canister_queues.store.is_empty());
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
            canister_queues.output_queues_message_count(),
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
    prop_assert_eq!(canister_queues.output_queues_message_count(), 0);
    // And the pool is empty.
    prop_assert!(canister_queues.store.is_empty());
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

        prop_assert_eq!(canister_queues.output_queues_message_count(), excluded);
    }

    // Ensure that the messages that have not been consumed above are still in the queues
    // after dropping `output_iter`.
    while let Some(raw) = excluded_requests.pop_front() {
        if let Some(msg) = canister_queues.pop_canister_output(&raw.receiver()) {
            prop_assert_eq!(
                &raw,
                &msg,
                "Popped message does not correspond with expected message. popped: {:?}. expected: {:?}.",
                msg,
                raw
            );
        } else {
            prop_assert!(false, "Not all unconsumed messages left in canister queues");
        }
    }

    // Ensure that there are no messages left in the canister queues.
    prop_assert_eq!(canister_queues.output_queues_message_count(), 0);
    // And the pool is empty.
    prop_assert!(canister_queues.store.is_empty());
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
    time_out_messages(
        &mut canister_queues,
        coarse_time(deadline).into(),
        &own_canister_id,
        &local_canisters,
    );
    // And shed one more.
    shed_largest_message(&mut canister_queues, &own_canister_id, &local_canisters);

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
    time_out_messages(
        &mut canister_queues,
        coarse_time(deadline).into(),
        &own_canister_id,
        &local_canisters,
    );
    // And shed one more.
    shed_largest_message(&mut canister_queues, &own_canister_id, &local_canisters);

    // Pop (after optionally peeking) a few times.
    let mut output_iter = canister_queues.output_into_iter();
    let mut should_peek = deadline % 2 == 0;
    for _ in 0..3 {
        if should_peek {
            output_iter.peek();
        }
        if output_iter.next().is_none() {
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
        .push_output_request(request(1, NO_DEADLINE).into(), time0)
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
    assert_eq!(
        Ok(None),
        canister_queues.push_input(response(1, time100).into(), LocalSubnet)
    );
    assert!(!canister_queues.has_expired_deadlines(time101));

    // But an inbound best-effort request does expire.
    assert_eq!(
        Ok(None),
        canister_queues.push_input(request(2, time100).into(), LocalSubnet)
    );
    assert!(canister_queues.has_expired_deadlines(time101));
}

/// Tests `time_out_messages` on an instance of `CanisterQueues` that contains
/// exactly 4 output messages:
/// - A guaranteed response request addressed to self.
/// - A best-effort request addressed to a local canister.
/// - Two guaranteed response requests adressed to a remote canister.
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
                    metadata: Default::default(),
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

    // 3 messages dropped. Zero cycles lost (all were refunded).
    let current_time = t0 + REQUEST_LIFETIME + Duration::from_secs(1);
    assert_eq!(
        (3, RefundPool::default()),
        time_out_messages(
            &mut canister_queues,
            current_time,
            &own_canister_id,
            &local_canisters
        ),
    );

    // Check that each canister has one request timed out in the output queue and one
    // reject response in the corresponding input queue.
    assert_eq!(1, canister_queues.queue_stats.input_queues_reserved_slots);
    let message_stats = canister_queues.message_stats();
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
        let reference = input_queue_from_canister.peek().unwrap();
        let reject_response = canister_queues.store.get(reference);
        assert_eq!(
            CanisterInput::from(RequestOrResponse::from(Response {
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
            })),
            reject_response,
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
        (1, RefundPool::default()),
        time_out_messages(
            &mut canister_queues,
            current_time,
            &own_canister_id,
            &local_canisters
        ),
    );

    // Zero input queue reserved slots, 4 inbound responses,
    assert_eq!(0, canister_queues.queue_stats.input_queues_reserved_slots);
    let message_stats = canister_queues.message_stats();
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

#[test]
fn time_out_messages_produces_refunds() {
    let mut canister_queues = CanisterQueues::default();

    // Cartesian product of inbound / outbound, best-effort / guaranteed, request /
    // response; with cycle amounts that can be used as bit masks.
    //
    // `*` messages time out, but attached cycles are refunded. `**` messages time
    // out and attached cycles are lost.
    let inbound_best_effort_request = request_with_payment(0, SOME_DEADLINE, 1 << 0); // **
    let inbound_guaranteed_request = request_with_payment(1, NO_DEADLINE, 1 << 1);
    let inbound_best_effort_response = response_with_refund(2, SOME_DEADLINE, 1 << 2);
    let inbound_guaranteed_response = response_with_refund(3, NO_DEADLINE, 1 << 3);
    let outbound_best_effort_request = request_with_payment(4, SOME_DEADLINE, 1 << 4); // *
    let outbound_guaranteed_request = request_with_payment(5, NO_DEADLINE, 1 << 5); // *
    let outbound_best_effort_response = response_with_refund(6, SOME_DEADLINE, 1 << 6); // **
    let outbound_guaranteed_response = response_with_refund(7, NO_DEADLINE, 1 << 7);

    // Reserve slots for the 2 inbound and 2 outbound responses.
    for _ in 0..2 {
        canister_queues
            .push_output_request(request(0, NO_DEADLINE).into(), UNIX_EPOCH)
            .unwrap();
        canister_queues.output_into_iter().next().unwrap();

        canister_queues
            .push_input(request(0, NO_DEADLINE).into(), LocalSubnet)
            .unwrap();
        canister_queues.pop_input().unwrap();
    }

    // Enqueue the 8 messages.
    for message in [
        RequestOrResponse::from(inbound_best_effort_request.clone()),
        RequestOrResponse::from(inbound_guaranteed_request.clone()),
        RequestOrResponse::from(inbound_best_effort_response.clone()),
        RequestOrResponse::from(inbound_guaranteed_response.clone()),
    ] {
        canister_queues.push_input(message, LocalSubnet).unwrap();
    }
    for request in [
        outbound_best_effort_request.clone(),
        outbound_guaranteed_request.clone(),
    ] {
        canister_queues
            .push_output_request(request.into(), UNIX_EPOCH)
            .unwrap();
    }
    for response in [
        outbound_best_effort_response.clone(),
        outbound_guaranteed_response.clone(),
    ] {
        // Reserve a slot.
        canister_queues.push_output_response(response.into());
    }

    // 4 messages dropped:
    //  1. `inbound_best_effort_request`
    //  2. `outbound_best_effort_request`
    //  3. `outbound_guaranteed_request`
    //  4. `outbound_best_effort_response`
    //
    // From among these, only the cycles attached to (1) and (4) produce refund
    // messages (reject responses with refunds are generated for both outbound
    // requests).
    let current_time = UNIX_EPOCH + 2 * REQUEST_LIFETIME;
    let own_canister_id = inbound_best_effort_request.sender;
    let mut refunds = RefundPool::default();
    let metrics = FakeDropMessageMetrics::default();
    canister_queues.time_out_messages(
        current_time,
        &own_canister_id,
        &BTreeMap::new(),
        &mut refunds,
        &metrics,
    );
    assert_eq!(
        btreemap! {
            ("request", "inbound", "best-effort") => 1,
            ("request", "outbound", "best-effort") => 1,
            ("request", "outbound", "guaranteed response") => 1,
            ("response", "outbound", "best-effort") => 1,
        },
        *metrics.timed_out_messages.borrow(),
    );
    assert_eq!(
        refund_pool(&[
            (
                inbound_best_effort_request.sender,
                inbound_best_effort_request.payment
            ),
            (
                outbound_best_effort_response.originator,
                outbound_best_effort_response.refund
            )
        ]),
        refunds
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

            fixture.push_input_request(NO_DEADLINE).unwrap();
            fixture.push_output_request(NO_DEADLINE).unwrap();
            assert_eq!(Ok(None), fixture.push_input_response(NO_DEADLINE));
            fixture.push_output_response(NO_DEADLINE);

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
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Request(req)) if req.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Response(rep)) if rep.deadline == NO_DEADLINE);
            assert_eq!(fixture.pop_input(), None);
            assert!(!fixture.queues.has_input());

            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Request(req)) if req.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Response(rep)) if rep.deadline == NO_DEADLINE);
            assert_eq!(fixture.pop_input(), None);
            assert!(!fixture.queues.has_output());
        }
    }

    #[cfg(test)]
    mod best_effort_test {

        use super::super::*;
        use super::*;

        const OUTPUT_NAME: &str = "queues.pbuf";
        const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
        const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);

        #[test]
        #[ignore]
        fn serialize() {
            let mut fixture = CanisterQueuesFixture::new_with_ids(CANISTER_ID, OTHER_CANISTER_ID);

            fixture.push_input_request(NO_DEADLINE).unwrap();
            fixture.push_output_request(NO_DEADLINE).unwrap();
            assert_eq!(Ok(None), fixture.push_input_response(NO_DEADLINE));
            fixture.push_output_response(NO_DEADLINE);

            fixture.push_input_request(SOME_DEADLINE).unwrap();
            fixture.push_output_request(SOME_DEADLINE).unwrap();
            assert_eq!(Ok(None), fixture.push_input_response(SOME_DEADLINE));
            fixture.push_output_response(SOME_DEADLINE);

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
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Request(req)) if req.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Response(rep)) if rep.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Request(req)) if req.deadline == SOME_DEADLINE);
            assert_matches!(fixture.pop_input(), Some(CanisterInput::Response(rep)) if rep.deadline == SOME_DEADLINE);
            assert_eq!(fixture.pop_input(), None);
            assert!(!fixture.queues.has_input());

            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Request(req)) if req.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Response(rep)) if rep.deadline == NO_DEADLINE);
            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Request(req)) if req.deadline == SOME_DEADLINE);
            assert_matches!(fixture.pop_output(), Some(RequestOrResponse::Response(rep)) if rep.deadline == SOME_DEADLINE);
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
            assert_eq!(
                Ok(None),
                queues.reserve_and_push_input_response(LOCAL_CANISTER_ID, LocalSubnet)
            );

            // Put a request and a response from a remote canister in the input queues
            queues
                .push_input_request(REMOTE_CANISTER_ID, RemoteSubnet)
                .unwrap();
            assert_eq!(
                Ok(None),
                queues.reserve_and_push_input_response(REMOTE_CANISTER_ID, RemoteSubnet)
            );

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

            assert_matches!(queues.pop_input(), Some(CanisterInput::Request(ref req)) if req.sender == LOCAL_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterInput::Ingress(ref ing)) if ing.source == USER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterInput::Request(ref req)) if req.sender == REMOTE_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterInput::Request(ref req)) if req.sender == CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterInput::Response(ref req)) if req.respondent == REMOTE_CANISTER_ID);
            assert_matches!(queues.pop_input(), Some(CanisterInput::Response(ref req)) if req.respondent == LOCAL_CANISTER_ID);

            assert_eq!(queues.pop_input(), None);
            assert!(!queues.has_input());
        }
    }

    #[cfg(test)]
    mod refunds_test {

        use super::super::*;
        use super::*;

        const OUTPUT_NAME: &str = "refunds.pbuf";
        const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
        const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);

        fn make_refund_pool() -> refunds::RefundPool {
            let mut refund_pool = refunds::RefundPool::new();

            refund_pool.add(CANISTER_ID, Cycles::new(100));
            refund_pool.add(OTHER_CANISTER_ID, Cycles::new(200));
            refund_pool.add(CANISTER_ID, Cycles::new(200));

            refund_pool
        }

        #[test]
        #[ignore]
        fn serialize() {
            let refund_pool = make_refund_pool();

            let proto_refunds: pb_queues::Refunds = (&refund_pool).into();
            let serialized = proto_refunds.encode_to_vec();

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
            let proto_refunds = pb_queues::Refunds::decode(&serialized as &[u8])
                .expect("Failed to deserialize the protobuf");
            let refunds = refunds::RefundPool::try_from((
                proto_refunds,
                &StrictMetrics as &dyn CheckpointLoadingMetrics,
            ))
            .expect("Failed to convert the protobuf to RefundPool");

            assert_eq!(make_refund_pool(), refunds);
        }
    }
}
