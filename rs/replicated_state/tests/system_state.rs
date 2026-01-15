use assert_matches::assert_matches;
use ic_base_types::{NumBytes, NumSeconds};
use ic_error_types::RejectCode;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::testing::{CanisterQueuesTesting, SystemStateTesting};
use ic_replicated_state::{ExecutionTask, InputQueueType, StateError, SystemState};
use ic_test_utilities_types::ids::{canister_test_id, user_test_id};
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_types::messages::{
    CanisterMessage, CanisterMessageOrTask, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE, Payload,
    RejectContext, Request, RequestOrResponse, Response,
};
use ic_types::time::{CoarseTime, UNIX_EPOCH};
use ic_types::{CanisterId, Cycles};
use std::{collections::BTreeMap, sync::Arc};

/// Figure out how many cycles a canister should have so that it can support the
/// given amount of storage for the given amount of time, given the storage fee.
fn mock_freeze_threshold_cycles(
    freeze_threshold: NumSeconds,
    gib_storage_per_second_fee: Cycles,
    expected_canister_size: NumBytes,
) -> Cycles {
    let one_gib = 1024 * 1024 * 1024;
    Cycles::from(
        expected_canister_size.get() as u128
            * gib_storage_per_second_fee.get()
            * freeze_threshold.get() as u128
            / one_gib,
    )
}

const CANISTER_ID: CanisterId = CanisterId::from_u64(0);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
const SUBNET_AVAILABLE_MEMORY: i64 = 300 << 30;
const SOME_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(1);

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::default()
        .sender(OTHER_CANISTER_ID)
        .receiver(CANISTER_ID)
        .payment(Cycles::new(2))
        .build()
        .into()
}

fn default_output_response() -> Arc<Response> {
    ResponseBuilder::default()
        .respondent(CANISTER_ID)
        .originator(OTHER_CANISTER_ID)
        .refund(Cycles::new(1))
        .build()
        .into()
}

fn default_request_to_self() -> Arc<Request> {
    RequestBuilder::default()
        .sender(CANISTER_ID)
        .receiver(CANISTER_ID)
        .payment(Cycles::new(3))
        .build()
        .into()
}

struct SystemStateFixture {
    pub system_state: SystemState,
}

impl SystemStateFixture {
    fn running() -> SystemStateFixture {
        SystemStateFixture {
            system_state: SystemState::new_running_for_testing(
                CANISTER_ID,
                user_test_id(1).get(),
                Cycles::new(5_000_000_000_000),
                NumSeconds::new(0),
            ),
        }
    }

    fn stopping() -> SystemStateFixture {
        SystemStateFixture {
            system_state: SystemState::new_stopping_for_testing(
                CANISTER_ID,
                user_test_id(1).get(),
                Cycles::new(5_000_000_000_000),
                NumSeconds::new(0),
            ),
        }
    }

    fn stopped() -> SystemStateFixture {
        SystemStateFixture {
            system_state: SystemState::new_stopped_for_testing(
                CANISTER_ID,
                user_test_id(1).get(),
                Cycles::new(5_000_000_000_000),
                NumSeconds::new(0),
            ),
        }
    }

    /// Produces a request and response pair for a call to `callee`, backed by a
    /// registered callback.
    fn prepare_call(
        &mut self,
        callee: CanisterId,
        deadline: CoarseTime,
    ) -> (Arc<Request>, Arc<Response>) {
        // Register a callback.
        let callback = self.system_state.with_callback(callee, deadline);

        let request = RequestBuilder::default()
            .sender(CANISTER_ID)
            .receiver(callee)
            .sender_reply_callback(callback)
            .deadline(deadline)
            .payment(Cycles::new(10))
            .build()
            .into();
        let response = ResponseBuilder::default()
            .respondent(callee)
            .originator(CANISTER_ID)
            .originator_reply_callback(callback)
            .deadline(deadline)
            .refund(Cycles::new(5))
            .build()
            .into();
        (request, response)
    }

    fn push_input(
        &mut self,
        msg: RequestOrResponse,
        input_queue_type: InputQueueType,
    ) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
        self.system_state
            .queues_mut()
            .push_input(msg, input_queue_type)
    }

    fn pop_input(&mut self) -> Option<CanisterMessage> {
        self.system_state.pop_input()
    }

    fn push_output_response(&mut self, response: Arc<Response>) {
        self.system_state.push_output_response(response);
    }

    fn push_output_request(
        &mut self,
        request: Arc<Request>,
    ) -> Result<(), (StateError, Arc<Request>)> {
        self.system_state.push_output_request(request, UNIX_EPOCH)
    }

    fn pop_output(&mut self) -> Option<RequestOrResponse> {
        self.system_state.output_into_iter().pop()
    }

    fn induct_messages_to_self(&mut self) {
        self.system_state.induct_messages_to_self(
            &mut SUBNET_AVAILABLE_MEMORY.clone(),
            SubnetType::Application,
        );
    }

    /// Times out all callbacks with deadlines before `current_time`. Returns the
    /// number of expired callbacks.
    fn time_out_callbacks(&mut self, current_time: CoarseTime) -> (usize, Vec<StateError>) {
        let input_responses_before = self.system_state.queues().input_queues_response_count();
        let (expired, errors) =
            self.system_state
                .time_out_callbacks(current_time, &CANISTER_ID, &BTreeMap::new());
        let input_responses_after = self.system_state.queues().input_queues_response_count();

        assert_eq!(
            input_responses_after - input_responses_before + errors.len(),
            expired
        );
        (expired, errors)
    }
}

#[test]
fn correct_charging_target_canister_for_a_response() {
    let freeze_threshold = NumSeconds::new(30 * 24 * 60 * 60);
    let initial_cycles = mock_freeze_threshold_cycles(
        freeze_threshold,
        Cycles::new(2_000_000),
        NumBytes::from(4 << 30),
    ) + Cycles::new(5_000_000_000_000);
    let mut fixture = SystemStateFixture {
        system_state: SystemState::new_running_for_testing(
            canister_test_id(0),
            user_test_id(1).get(),
            initial_cycles,
            freeze_threshold,
        ),
    };
    let initial_cycles_balance = fixture.system_state.balance();

    // Enqueue the request.
    assert_eq!(
        Ok(None),
        fixture.push_input(default_input_request(), InputQueueType::RemoteSubnet)
    );
    // Pop the Request, as if processing it.
    fixture.pop_input();
    // Assume it was processed and enqueue a response.
    fixture.push_output_response(default_output_response());

    // Target canister should not be charged for receiving the request or sending
    // the response
    assert_eq!(initial_cycles_balance, fixture.system_state.balance());
}

#[test]
fn induct_messages_to_self_in_running_status_works() {
    let mut fixture = SystemStateFixture::running();

    let (request_to_self, _) = fixture.prepare_call(CANISTER_ID, NO_DEADLINE);
    fixture.push_output_request(request_to_self).unwrap();
    fixture.induct_messages_to_self();

    assert!(fixture.system_state.has_input());
    assert!(!fixture.system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_in_stopped_status_does_not_work() {
    let mut fixture = SystemStateFixture::stopped();

    fixture
        .push_output_request(default_request_to_self())
        .unwrap();
    fixture.induct_messages_to_self();

    assert!(!fixture.system_state.has_input());
    assert!(fixture.system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_in_stopping_status_does_not_work() {
    let mut fixture = SystemStateFixture::stopping();

    fixture
        .push_output_request(default_request_to_self())
        .unwrap();
    fixture.induct_messages_to_self();

    assert!(!fixture.system_state.has_input());
    assert!(fixture.system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_respects_subnet_memory_limit() {
    let mut subnet_available_guaranteed_response_memory = 0;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_guaranteed_response_memory,
        SubnetType::Application,
        0,
        true,
    );

    assert_eq!(0, subnet_available_guaranteed_response_memory);
}

#[test]
fn application_subnet_induct_messages_to_self_best_effort_ignores_subnet_memory_limit() {
    let mut subnet_available_guaranteed_response_memory = 0;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_guaranteed_response_memory,
        SubnetType::Application,
        1,
        false,
    );

    assert_eq!(0, subnet_available_guaranteed_response_memory);
}

#[test]
fn system_subnet_induct_messages_to_self_ignores_subnet_memory_limit() {
    let mut subnet_available_guaranteed_response_memory = 0;
    let mut expected_subnet_available_guaranteed_response_memory =
        subnet_available_guaranteed_response_memory;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_guaranteed_response_memory,
        SubnetType::System,
        0,
        false,
    );
    expected_subnet_available_guaranteed_response_memory -= MAX_RESPONSE_COUNT_BYTES as i64;

    assert_eq!(
        expected_subnet_available_guaranteed_response_memory,
        subnet_available_guaranteed_response_memory
    );
}

fn induct_messages_to_self_memory_limit_test_impl(
    subnet_available_guaranteed_response_memory: &mut i64,
    own_subnet_type: SubnetType,
    deadline: u32,
    should_enforce_limit: bool,
) {
    let mut fixture = SystemStateFixture::running();

    // One guaranteed response self-call response and one self-call request.
    let (request0, response) = fixture.prepare_call(CANISTER_ID, NO_DEADLINE);
    let (request, _) = fixture.prepare_call(CANISTER_ID, NO_DEADLINE);

    // A second request that might exceed the available memory (if guaranteed
    // response; and on an application subnet).
    let (second_request, _) = fixture.prepare_call(
        CANISTER_ID,
        CoarseTime::from_secs_since_unix_epoch(deadline),
    );

    // Make a slot reservation for `response``.
    assert_eq!(
        Ok(None),
        fixture.push_input(
            RequestOrResponse::Request(request0),
            InputQueueType::RemoteSubnet,
        )
    );
    fixture.pop_input().unwrap();

    // Pushing an outgoing response will release `MAX_RESPONSE_COUNT_BYTES`.
    fixture.push_output_response(response.clone());
    // So there should be memory for this request.
    fixture.push_output_request(request.clone()).unwrap();
    // But potentially not for this one (if guaranteed response; and on an
    // application subnet).
    fixture.push_output_request(second_request.clone()).unwrap();

    fixture
        .system_state
        .induct_messages_to_self(subnet_available_guaranteed_response_memory, own_subnet_type);

    // Expect the response and first request to have been inducted.
    assert_eq!(
        Some(CanisterMessage::Response(response)),
        fixture.pop_input(),
    );
    assert_eq!(Some(CanisterMessage::Request(request)), fixture.pop_input(),);

    if should_enforce_limit {
        assert_eq!(None, fixture.pop_input());

        // Expect the second request to still be in the output queue.
        assert_eq!(
            Some(RequestOrResponse::Request(second_request)),
            fixture.pop_output(),
        );
    } else {
        assert_eq!(
            Some(CanisterMessage::Request(second_request)),
            fixture.pop_input()
        );
    }

    // Expect both the input and the output queues to be empty.
    assert!(!fixture.system_state.queues().has_input());
    assert!(!fixture.system_state.queues().has_output());
}

/// Inducting messages to self works up to capacity.
#[test]
fn induct_messages_to_self_full_queue() {
    let mut fixture = SystemStateFixture::running();

    // Push`DEFAULT_QUEUE_CAPACITY` requests.
    let mut requests = Vec::new();
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        let (request, _) = fixture.prepare_call(CANISTER_ID, NO_DEADLINE);
        requests.push(request.clone());
        assert_eq!(
            Ok(None),
            fixture.push_input(
                RequestOrResponse::Request(request),
                InputQueueType::LocalSubnet,
            )
        );
    }

    fixture.induct_messages_to_self();

    // Expect all requests to have been inducted.
    for request in requests {
        assert_eq!(Some(CanisterMessage::Request(request)), fixture.pop_input());
    }

    assert_eq!(None, fixture.pop_input());
    assert_eq!(
        0,
        fixture.system_state.queues().output_queues_message_count()
    );
}

/// Induct a best-effort response to self for a callback that already has a
/// response enqueued. The response should be silently dropped.
#[test]
fn induct_messages_to_self_duplicate_best_effort_response() {
    let mut fixture = SystemStateFixture::running();

    let (request, response) = fixture.prepare_call(CANISTER_ID, SOME_DEADLINE);
    let callback = response.originator_reply_callback;

    // Enqueue the outgoing request.
    fixture.push_output_request(request.clone()).unwrap();

    // Induct it into the input queue.
    fixture.induct_messages_to_self();

    // Pop and start executing it (pretend it's waiting multiple rounds for
    // downstream calls).
    assert_eq!(Some(CanisterMessage::Request(request)), fixture.pop_input());

    // Expire the callback.
    assert_eq!(
        (1, Vec::new()),
        fixture.time_out_callbacks(CoarseTime::from_secs_since_unix_epoch(u32::MAX))
    );

    // A few rounds later, have the running call context produce a response.
    fixture.push_output_response(response);

    // Try inducting the response and check that it was consumed.
    fixture.induct_messages_to_self();
    assert!(!fixture.system_state.queues().has_output());

    // Pop the timeout reject response and execute it (consuming the callback).
    // The late response was silently dropped, as a duplicate.
    assert_matches!(fixture.pop_input(), Some(CanisterMessage::Response(resp)) if resp.response_payload == Payload::Reject(RejectContext::new(RejectCode::SysUnknown, "Call deadline has expired.")));
    assert_matches!(
        fixture.system_state.unregister_callback(callback),
        Ok(Some(_))
    );

    // There should now be zero messages and reserved slots in the canister queues.
    let queues = fixture.system_state.queues();
    assert!(!queues.has_input());
    assert!(!queues.has_output());
    assert_eq!(0, queues.input_queues_reserved_slots());
    assert_eq!(0, queues.output_queues_reserved_slots());
}

/// Induct a best-effort response to self for a callback that has already been
/// consumed. The response should be silently dropped.
#[test]
fn induct_messages_to_self_best_effort_callback_gone() {
    let mut fixture = SystemStateFixture::running();

    let (request, response) = fixture.prepare_call(CANISTER_ID, SOME_DEADLINE);
    let callback = response.originator_reply_callback;

    // Enqueue the outgoing request.
    fixture.push_output_request(request.clone()).unwrap();

    // Induct it into the input queue.
    fixture.induct_messages_to_self();

    // Pop and start executing it (pretend it's waiting multiple rounds for
    // downstream calls).
    assert_eq!(Some(CanisterMessage::Request(request)), fixture.pop_input());

    // Expire the callback.
    fixture.time_out_callbacks(CoarseTime::from_secs_since_unix_epoch(u32::MAX));

    // Pop the resulting reject response and execute it (consuming the callback).
    assert_matches!(fixture.pop_input(), Some(CanisterMessage::Response(_)));
    assert_matches!(
        fixture.system_state.unregister_callback(callback),
        Ok(Some(_))
    );

    // A few rounds later, have the running call context produce a response.
    fixture.push_output_response(response);

    // Try inducting the response before it times out.
    fixture.induct_messages_to_self();

    // Response should have been silently dropped.
    assert_eq!(None, fixture.pop_input());

    // And there should be zero messages and reserved slots in the canister queues.
    let queues = fixture.system_state.queues();
    assert!(!queues.has_input());
    assert!(!queues.has_output());
    assert_eq!(0, queues.input_queues_reserved_slots());
    assert_eq!(0, queues.output_queues_reserved_slots());
}

/// Induct a guaranteed response to self for a callback that has already been
/// consumed. `induct_messages_to_self()` should panic.
#[test]
#[should_panic(expected = "Failed to induct message to self: NonMatchingResponse")]
fn induct_messages_to_self_guaranteed_response_callback_gone() {
    let mut fixture = SystemStateFixture::running();

    let (request, response) = fixture.prepare_call(CANISTER_ID, NO_DEADLINE);
    let callback = response.originator_reply_callback;

    // Enqueue the outgoing request.
    fixture.push_output_request(request.clone()).unwrap();

    // Induct it into the input queue.
    fixture.induct_messages_to_self();

    // Pop and execute it, producing a response.
    assert_eq!(Some(CanisterMessage::Request(request)), fixture.pop_input());
    fixture.push_output_response(response.clone());

    // Pretend that a duplicate response has consumed the callback.
    assert_matches!(
        fixture.system_state.unregister_callback(callback),
        Ok(Some(_))
    );

    // Trying to induct the response should panic (or bail out in release mode).
    fixture.induct_messages_to_self();
}

/// Simulates an outbound call with the given deadline, by registering a
/// callback and reserving a response slot.
fn simulate_outbound_call(fixture: &mut SystemStateFixture, deadline: CoarseTime) -> Arc<Response> {
    let (request, response) = fixture.prepare_call(OTHER_CANISTER_ID, deadline);

    // Reserve a response slot.
    fixture.push_output_request(request).unwrap();
    fixture.pop_output().unwrap();

    response
}

#[test]
fn time_out_callbacks() {
    let mut fixture = SystemStateFixture::running();

    let deadline_expired_reject_payload = Payload::Reject(RejectContext::new(
        RejectCode::SysUnknown,
        "Call deadline has expired.",
    ));

    let d1 = CoarseTime::from_secs_since_unix_epoch(1);
    let d2 = CoarseTime::from_secs_since_unix_epoch(2);
    let d3 = CoarseTime::from_secs_since_unix_epoch(3);

    let rep1 = simulate_outbound_call(&mut fixture, d1);
    let rep2 = simulate_outbound_call(&mut fixture, d1);
    let c3 = simulate_outbound_call(&mut fixture, d1).originator_reply_callback;
    let c4 = simulate_outbound_call(&mut fixture, d2).originator_reply_callback;

    // Simulate a paused execution for `rep1`.
    assert_eq!(
        Ok(None),
        fixture.push_input(
            RequestOrResponse::Response(rep1),
            InputQueueType::RemoteSubnet,
        )
    );
    let response1 = fixture.pop_input().unwrap();
    fixture
        .system_state
        .task_queue
        .enqueue(ExecutionTask::PausedExecution {
            id: PausedExecutionId(1),
            input: CanisterMessageOrTask::Message(response1),
        });

    // And enqueue `rep2`.
    assert_eq!(
        Ok(None),
        fixture.push_input(
            RequestOrResponse::Response(rep2.clone()),
            InputQueueType::RemoteSubnet,
        )
    );

    // Time out callbacks with deadlines before `d2` (only applicable to `c3` now).
    assert!(!fixture.system_state.has_expired_callbacks(d1));
    assert!(fixture.system_state.has_expired_callbacks(d2));
    assert_eq!((1, Vec::new()), fixture.time_out_callbacks(d2));
    assert!(!fixture.system_state.has_expired_callbacks(d2));

    // Pop `rep2`.
    assert_eq!(Some(CanisterMessage::Response(rep2)), fixture.pop_input());

    // Pop the reject response for `c3`.
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Response(response))
            if response.originator_reply_callback == c3 && response.response_payload == deadline_expired_reject_payload
    );
    assert_eq!(None, fixture.pop_input());

    // Time out callbacks with deadlines before `d3` (i.e. `c4`).
    assert!(fixture.system_state.has_expired_callbacks(d3));
    assert_eq!((1, Vec::new()), fixture.time_out_callbacks(d3));
    assert!(!fixture.system_state.has_expired_callbacks(d3));

    // Pop the reject responses for `c4`.
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Response(response))
            if response.originator_reply_callback == c4 && response.response_payload == deadline_expired_reject_payload
    );
    assert_eq!(None, fixture.pop_input());

    assert!(!fixture.system_state.has_input());
    assert!(!fixture.system_state.queues().has_output());
}

#[test]
fn time_out_callbacks_no_reserved_slot() {
    let mut fixture = SystemStateFixture::running();

    let deadline_expired_reject_payload = Payload::Reject(RejectContext::new(
        RejectCode::SysUnknown,
        "Call deadline has expired.",
    ));

    let d1 = CoarseTime::from_secs_since_unix_epoch(1);
    let d2 = CoarseTime::from_secs_since_unix_epoch(2);

    // Register 3 callbacks, but only make one slot reservation.
    let c1 = simulate_outbound_call(&mut fixture, d1).originator_reply_callback;
    let c2 = fixture.system_state.with_callback(OTHER_CANISTER_ID, d1);
    let c3 = fixture.system_state.with_callback(OTHER_CANISTER_ID, d1);

    // Time out callbacks with deadlines before `d2`.
    assert!(fixture.system_state.has_expired_callbacks(d2));
    let (expired_callbacks, errors) = fixture.time_out_callbacks(d2);
    assert!(!fixture.system_state.has_expired_callbacks(d2));

    // Three callbacks expired.
    assert_eq!(3, expired_callbacks);

    // Only one timeout reject for `c1` was enqueued before we ran out of slots.
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Response(response))
            if response.originator_reply_callback == c1 && response.response_payload == deadline_expired_reject_payload
    );
    assert_eq!(None, fixture.pop_input());

    // And two errors were produced: one for `c2` and one for `c3`.
    assert_eq!(2, errors.len());
    assert_matches!(errors[0], StateError::NonMatchingResponse { callback_id, deadline, .. } if callback_id == c2 && deadline == d1);
    assert_matches!(errors[1], StateError::NonMatchingResponse { callback_id, deadline, .. } if callback_id == c3 && deadline == d1);

    assert!(!fixture.system_state.has_input());
    assert!(!fixture.system_state.queues().has_output());
}
