use assert_matches::assert_matches;
use ic_base_types::{NumBytes, NumSeconds};
use ic_error_types::RejectCode;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
use ic_replicated_state::testing::{CanisterQueuesTesting, SystemStateTesting};
use ic_replicated_state::{CallOrigin, ExecutionTask, InputQueueType, StateError, SystemState};
use ic_test_utilities_types::ids::{canister_test_id, user_test_id};
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_types::messages::{
    CallbackId, CanisterMessage, CanisterMessageOrTask, Payload, RejectContext, Request,
    RequestMetadata, RequestOrResponse, Response, MAX_RESPONSE_COUNT_BYTES,
};
use ic_types::methods::{Callback, WasmClosure};
use ic_types::time::{CoarseTime, UNIX_EPOCH};
use ic_types::{CanisterId, Cycles, Time};
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

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::default()
        .sender(OTHER_CANISTER_ID)
        .receiver(CANISTER_ID)
        .build()
        .into()
}

fn default_output_response() -> Arc<Response> {
    ResponseBuilder::default()
        .respondent(CANISTER_ID)
        .originator(OTHER_CANISTER_ID)
        .build()
        .into()
}

fn output_request(deadline: CoarseTime) -> Arc<Request> {
    RequestBuilder::default()
        .sender(CANISTER_ID)
        .receiver(OTHER_CANISTER_ID)
        .deadline(deadline)
        .build()
        .into()
}

fn input_response(callback_id: CallbackId, deadline: CoarseTime) -> RequestOrResponse {
    ResponseBuilder::default()
        .respondent(OTHER_CANISTER_ID)
        .originator(CANISTER_ID)
        .originator_reply_callback(callback_id)
        .deadline(deadline)
        .build()
        .into()
}

fn default_request_to_self() -> Arc<Request> {
    RequestBuilder::default()
        .sender(CANISTER_ID)
        .receiver(CANISTER_ID)
        .build()
        .into()
}

fn default_response_to_self() -> Arc<Response> {
    ResponseBuilder::default()
        .respondent(CANISTER_ID)
        .originator(CANISTER_ID)
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

    fn push_input(
        &mut self,
        msg: RequestOrResponse,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
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
        let ret =
            self.system_state
                .time_out_callbacks(current_time, &CANISTER_ID, &BTreeMap::new());
        let input_responses_after = self.system_state.queues().input_queues_response_count();

        assert_eq!(
            input_responses_after - input_responses_before + ret.1.len(),
            ret.0
        );
        ret
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
    fixture
        .push_input(default_input_request(), InputQueueType::RemoteSubnet)
        .unwrap();
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

    fixture
        .push_output_request(default_request_to_self())
        .unwrap();
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
    let mut subnet_available_memory = 0;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_memory,
        SubnetType::Application,
        0,
        true,
    );

    assert_eq!(0, subnet_available_memory);
}

#[test]
fn application_subnet_induct_messages_to_self_best_effort_ignores_subnet_memory_limit() {
    let mut subnet_available_memory = 0;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_memory,
        SubnetType::Application,
        1,
        false,
    );

    assert_eq!(0, subnet_available_memory);
}

#[test]
fn system_subnet_induct_messages_to_self_ignores_subnet_memory_limit() {
    let mut subnet_available_memory = 0;
    let mut expected_subnet_available_memory = subnet_available_memory;

    induct_messages_to_self_memory_limit_test_impl(
        &mut subnet_available_memory,
        SubnetType::System,
        0,
        false,
    );
    expected_subnet_available_memory -= MAX_RESPONSE_COUNT_BYTES as i64;

    assert_eq!(expected_subnet_available_memory, subnet_available_memory);
}

fn induct_messages_to_self_memory_limit_test_impl(
    subnet_available_memory: &mut i64,
    own_subnet_type: SubnetType,
    deadline: u32,
    should_enforce_limit: bool,
) {
    // Request and response to self.
    let request = default_request_to_self();
    let response = default_response_to_self();

    // A second request that might exceed the available memory (if guaranteed
    // response; and on an application subnet).
    let second_request: Arc<Request> = RequestBuilder::default()
        .sender(CANISTER_ID)
        .receiver(CANISTER_ID)
        .deadline(CoarseTime::from_secs_since_unix_epoch(deadline))
        .build()
        .into();

    // A system state with a slot reservation for an outgoing response.
    let mut fixture = SystemStateFixture {
        system_state: SystemState::new_running_for_testing(
            CANISTER_ID,
            user_test_id(1).get(),
            Cycles::new(5_000_000_000_000),
            NumSeconds::new(0),
        ),
    };
    fixture
        .push_input(
            RequestOrResponse::Request(request.clone()),
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
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
        .induct_messages_to_self(subnet_available_memory, own_subnet_type);

    // Expect the response and first request to have been inducted.
    assert_eq!(
        Some(CanisterMessage::Response(response)),
        fixture.pop_input(),
    );
    assert_eq!(
        Some(CanisterMessage::Request(request.clone())),
        fixture.pop_input(),
    );

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
        assert_eq!(None, fixture.pop_input());
    }

    // Expect the output queue to be empty.
    assert!(!fixture.system_state.queues().has_output());
}

// Inducting messages to self works up to capacity.
#[test]
fn induct_messages_to_self_full_queue() {
    let mut fixture = SystemStateFixture::running();

    // Push`DEFAULT_QUEUE_CAPACITY` requests.
    let request = default_request_to_self();
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        fixture
            .push_input(
                RequestOrResponse::Request(request.clone()),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    }

    fixture.induct_messages_to_self();

    // Expect all requests to have been inducted.
    for _ in 0..DEFAULT_QUEUE_CAPACITY {
        assert_eq!(
            Some(CanisterMessage::Request(request.clone())),
            fixture.pop_input()
        );
    }

    assert_eq!(None, fixture.pop_input());
    assert_eq!(0, fixture.system_state.queues().output_message_count());
}

/// Registers a callback with the given deadline.
fn register_callback(fixture: &mut SystemStateFixture, deadline: CoarseTime) -> CallbackId {
    let call_context_manager = fixture.system_state.call_context_manager_mut().unwrap();
    let time = Time::from_nanos_since_unix_epoch(1);
    let call_context_id = call_context_manager.new_call_context(
        CallOrigin::SystemTask,
        Cycles::zero(),
        time,
        RequestMetadata::new(0, time),
    );

    call_context_manager.register_callback(Callback::new(
        call_context_id,
        CANISTER_ID,
        OTHER_CANISTER_ID,
        Cycles::zero(),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 2),
        WasmClosure::new(0, 2),
        None,
        deadline,
    ))
}

/// Simulates an outbound call with the given deadline, by registering a
/// callback and reserving a response slot.
fn simulate_outbound_call(fixture: &mut SystemStateFixture, deadline: CoarseTime) -> CallbackId {
    // Reserve a response slot.
    fixture
        .push_output_request(output_request(deadline))
        .unwrap();
    fixture.pop_output().unwrap();

    // Register a callback.
    register_callback(fixture, deadline)
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

    let c1 = simulate_outbound_call(&mut fixture, d1);
    let c2 = simulate_outbound_call(&mut fixture, d1);
    let c3 = simulate_outbound_call(&mut fixture, d1);
    let c4 = simulate_outbound_call(&mut fixture, d2);

    // Simulate a paused execution for `c1`.
    fixture
        .push_input(input_response(c1, d1), InputQueueType::RemoteSubnet)
        .unwrap();
    let response1 = fixture.pop_input().unwrap();
    fixture
        .system_state
        .task_queue
        .push_front(ExecutionTask::PausedExecution {
            id: PausedExecutionId(1),
            input: CanisterMessageOrTask::Message(response1),
        });

    // And enqueue a response for `c2`.
    fixture
        .push_input(input_response(c2, d1), InputQueueType::RemoteSubnet)
        .unwrap();

    // Time out callbacks with deadlines before `d2` (only applicable to `c3` now).
    assert!(!fixture.system_state.has_expired_callbacks(d1));
    assert!(fixture.system_state.has_expired_callbacks(d2));
    assert_eq!((1, Vec::new()), fixture.time_out_callbacks(d2));
    assert!(!fixture.system_state.has_expired_callbacks(d2));

    // Pop the response for `c2`.
    assert_matches!(
        fixture.pop_input(),
        Some(CanisterMessage::Response(response))
            if response.originator_reply_callback == c2
    );

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
    let c1 = simulate_outbound_call(&mut fixture, d1);
    let c2 = register_callback(&mut fixture, d1);
    let c3 = register_callback(&mut fixture, d1);

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
