use std::collections::BTreeMap;
use std::path::PathBuf;

use super::*;
use crate::CallContext;
use crate::CallOrigin;
use crate::Memory;
use crate::canister_state::execution_state::CustomSection;
use crate::canister_state::execution_state::CustomSectionType;
use crate::canister_state::execution_state::WasmMetadata;
use crate::canister_state::system_state::testing::SystemStateTesting;
use crate::canister_state::system_state::{
    CallContextManager, CanisterHistory, CanisterStatus, CyclesUseCase,
    MAX_CANISTER_HISTORY_CHANGES,
};
use crate::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::Global;
use ic_management_canister_types_private::{
    BoundedAllowedViewers, CanisterChange, CanisterChangeDetails, CanisterChangeOrigin,
    CanisterLogRecord, LogVisibilityV2,
};
use ic_metrics::MetricsRegistry;
use ic_test_utilities_types::ids::{canister_test_id, message_test_id, user_test_id};
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterMessageOrTask, MAX_RESPONSE_COUNT_BYTES,
    NO_DEADLINE, StopCanisterCallId, StopCanisterContext,
};
use ic_types::methods::{Callback, WasmClosure};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::time::CoarseTime;
use ic_types::{CountBytes, Cycles, Time};
use ic_wasm_types::CanisterModule;
use prometheus::IntCounter;
use strum::IntoEnumIterator;
use system_state::PausedExecutionId;
use system_state::testing::CallContextManagerTesting;

const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);
const SUBNET_AVAILABLE_MEMORY: i64 = i64::MAX / 2;
const SOME_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(1);

fn default_input_request(deadline: CoarseTime) -> RequestOrResponse {
    RequestBuilder::default()
        .sender(OTHER_CANISTER_ID)
        .receiver(CANISTER_ID)
        .deadline(deadline)
        .payment(Cycles::new(2))
        .build()
        .into()
}

fn default_input_response(callback_id: CallbackId, deadline: CoarseTime) -> Response {
    ResponseBuilder::default()
        .originator(CANISTER_ID)
        .respondent(OTHER_CANISTER_ID)
        .originator_reply_callback(callback_id)
        .deadline(deadline)
        .refund(Cycles::new(1))
        .build()
}

fn default_output_request() -> Arc<Request> {
    Arc::new(
        RequestBuilder::default()
            .sender(CANISTER_ID)
            .receiver(OTHER_CANISTER_ID)
            .payment(Cycles::new(3))
            .build(),
    )
}

fn mock_metrics() -> IntCounter {
    MetricsRegistry::new().int_counter("error_counter", "Test error counter")
}

struct CanisterStateFixture {
    pub canister_state: CanisterState,
}

impl CanisterStateFixture {
    fn new() -> CanisterStateFixture {
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            CANISTER_ID,
            user_test_id(24).get(),
            Cycles::new(1 << 36),
            NumSeconds::from(100_000),
        );

        CanisterStateFixture {
            canister_state: CanisterState::new(system_state, None, scheduler_state),
        }
    }

    fn make_callback(&mut self, deadline: CoarseTime) -> CallbackId {
        self.make_callback_to(OTHER_CANISTER_ID, deadline)
    }

    fn make_callback_to(&mut self, respondent: CanisterId, deadline: CoarseTime) -> CallbackId {
        let call_context_id = self
            .canister_state
            .system_state
            .new_call_context(
                CallOrigin::CanisterUpdate(
                    CANISTER_ID,
                    CallbackId::from(1),
                    NO_DEADLINE,
                    String::from(""),
                ),
                Cycles::zero(),
                Time::from_nanos_since_unix_epoch(0),
                Default::default(),
            )
            .unwrap();
        self.canister_state
            .system_state
            .register_callback(Callback::new(
                call_context_id,
                CANISTER_ID,
                respondent,
                Cycles::zero(),
                Cycles::new(42),
                Cycles::new(84),
                WasmClosure::new(0, 2),
                WasmClosure::new(0, 2),
                None,
                deadline,
            ))
            .unwrap()
    }

    fn push_input(
        &mut self,
        msg: RequestOrResponse,
        subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<bool, (StateError, RequestOrResponse)> {
        self.canister_state.push_input(
            msg,
            &mut SUBNET_AVAILABLE_MEMORY.clone(),
            subnet_type,
            input_queue_type,
        )
    }

    fn pop_output(&mut self) -> Option<RequestOrResponse> {
        let mut iter = self.canister_state.output_into_iter();
        iter.pop()
    }

    fn with_input_slot_reservation(&mut self) {
        self.canister_state
            .push_output_request(default_output_request(), UNIX_EPOCH)
            .unwrap();
        self.pop_output().unwrap();
    }

    fn with_paused_response_execution(&mut self, deadline: CoarseTime) -> RequestOrResponse {
        // Reserve a slot in the input queue.
        self.with_input_slot_reservation();

        // Enqueue the response.
        let response = RequestOrResponse::from(default_input_response(
            self.make_callback(deadline),
            deadline,
        ));
        assert!(
            self.push_input(
                response.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
        );

        // Pop the response and make it into a paused response execution task.
        assert_eq!(
            Some(response.clone().into()),
            self.canister_state.pop_input()
        );
        self.canister_state
            .system_state
            .task_queue
            .enqueue(ExecutionTask::PausedExecution {
                id: PausedExecutionId(13),
                input: CanisterMessageOrTask::Message(response.clone().into()),
            });

        response
    }
}

#[test]
fn canister_state_push_input_request_success() {
    let mut fixture = CanisterStateFixture::new();
    assert!(
        fixture
            .push_input(
                default_input_request(NO_DEADLINE),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
    // Request was enqueued.
    assert!(fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_response_success() {
    let mut fixture = CanisterStateFixture::new();
    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    // Pushing input response should succeed.
    let response = default_input_response(fixture.make_callback(NO_DEADLINE), NO_DEADLINE).into();
    assert!(
        fixture
            .push_input(
                response,
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
    // Response was enqueued.
    assert!(fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_guaranteed_response_no_reserved_slot() {
    let mut fixture = CanisterStateFixture::new();
    let response = default_input_response(fixture.make_callback(NO_DEADLINE), NO_DEADLINE);
    assert_eq!(
        Err((
            StateError::non_matching_response("No reserved response slot", &response),
            response.clone().into(),
        )),
        fixture.push_input(
            response.into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
    );
    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_best_effort_response_no_reserved_slot() {
    let mut fixture = CanisterStateFixture::new();
    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    let response = default_input_response(fixture.make_callback(SOME_DEADLINE), SOME_DEADLINE);
    // Push a matching response into the slot.
    assert!(
        fixture
            .push_input(
                response.clone().into(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
    // Pushing a second best-effort response without a reserved slot should fail
    // silently.
    assert!(
        !fixture
            .push_input(
                response.clone().into(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
    // Only one response was enqueued.
    assert_eq!(
        Some(CanisterMessage::Response(response.into())),
        fixture.canister_state.pop_input()
    );
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_best_effort_response_canister_stopped() {
    let mut fixture = CanisterStateFixture::new();

    fixture.with_input_slot_reservation();
    let response = default_input_response(fixture.make_callback(SOME_DEADLINE), SOME_DEADLINE);

    // Stop the canister.
    fixture
        .canister_state
        .system_state
        .set_status(CanisterStatus::Stopped);

    // The best-effort response should be dropped silently.
    assert_eq!(
        Ok(false),
        fixture.push_input(
            response.into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        )
    );
}

#[test]
fn canister_state_push_input_guaranteed_response_no_matching_callback() {
    let mut fixture = CanisterStateFixture::new();
    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    // Pushing an input response with a mismatched callback should fail.
    let response = default_input_response(CallbackId::from(1), NO_DEADLINE).into();
    assert_matches!(
        fixture.push_input(
            response,
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
        Err((StateError::NonMatchingResponse { .. }, _))
    );

    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_best_effort_response_no_matching_callback() {
    let mut fixture = CanisterStateFixture::new();
    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    // Push a best-effort input response with a nonexistent callback.
    let response = default_input_response(CallbackId::from(1), SOME_DEADLINE).into();
    assert!(
        !fixture
            .push_input(
                response,
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );

    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_guaranteed_response_mismatched_callback() {
    let mut fixture = CanisterStateFixture::new();
    let response = default_input_response(fixture.make_callback(SOME_DEADLINE), NO_DEADLINE);
    assert_matches!(
        fixture.push_input(
            response.clone().into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
        Err((
            StateError::NonMatchingResponse { err_str, .. },
            r,
        )) if err_str.contains("invalid details") && r == response.into()
    );
    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_best_effort_response_mismatched_callback() {
    let mut fixture = CanisterStateFixture::new();
    let response = default_input_response(fixture.make_callback(NO_DEADLINE), SOME_DEADLINE);
    assert_matches!(
        fixture.push_input(
            response.clone().into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
        Err((
            StateError::NonMatchingResponse { err_str, .. },
            r,
        )) if err_str.contains("invalid details") && r == response.into()
    );
    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_request_mismatched_receiver() {
    let mut fixture = CanisterStateFixture::new();
    let _ = fixture.push_input(
        RequestBuilder::default()
            .sender(OTHER_CANISTER_ID)
            .receiver(OTHER_CANISTER_ID)
            .build()
            .into(),
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_response_mismatched_originator() {
    let mut fixture = CanisterStateFixture::new();
    let _ = fixture.push_input(
        ResponseBuilder::default()
            .originator(OTHER_CANISTER_ID)
            .respondent(OTHER_CANISTER_ID)
            .build()
            .into(),
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
fn canister_state_push_input_guaranteed_response_duplicate_of_paused_response() {
    let mut fixture = CanisterStateFixture::new();

    // Create a paused guaranteed response execution task.
    let response = fixture.with_paused_response_execution(NO_DEADLINE);

    // Enqueuing a duplicate response should fail with an error.
    assert_matches!(
        fixture.push_input(
            response.clone(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        ),
        Err((StateError::NonMatchingResponse { err_str, .. }, r))
            if err_str == "unknown callback ID" && r == response
    );
    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
fn canister_state_push_input_best_effort_response_duplicate_of_paused_response() {
    let mut fixture = CanisterStateFixture::new();

    // Create a paused best-effort response execution task.
    let response = fixture.with_paused_response_execution(SOME_DEADLINE);

    // Enqueuing a duplicate response should fail silently.
    assert!(
        !fixture
            .push_input(
                response.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap()
    );
    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
}

#[test]
#[should_panic(expected = "Failed to induct message to self: NonMatchingResponse")]
fn canister_state_induct_messages_to_self_guaranteed_response_duplicate_of_paused_response() {
    canister_state_induct_messages_to_self_duplicate_of_paused_response(NO_DEADLINE);
}

#[test]
fn canister_state_induct_messages_to_self_best_effort_duplicate_of_paused_response() {
    canister_state_induct_messages_to_self_duplicate_of_paused_response(SOME_DEADLINE);
}

fn canister_state_induct_messages_to_self_duplicate_of_paused_response(deadline: CoarseTime) {
    let mut fixture = CanisterStateFixture::new();

    // Pair of request and response to self.
    let callback_id = fixture.make_callback_to(CANISTER_ID, deadline);
    let request = RequestBuilder::default()
        .sender(CANISTER_ID)
        .receiver(CANISTER_ID)
        .sender_reply_callback(callback_id)
        .deadline(deadline)
        .payment(Cycles::new(2))
        .build();
    let response = ResponseBuilder::default()
        .originator(CANISTER_ID)
        .respondent(CANISTER_ID)
        .originator_reply_callback(callback_id)
        .deadline(deadline)
        .refund(Cycles::new(1))
        .build();

    // Make an input queue slot reservation.
    fixture
        .canister_state
        .push_output_request(request.clone().into(), UNIX_EPOCH)
        .unwrap();
    fixture.pop_output().unwrap();

    // Enqueue the inbound response.
    assert!(
        fixture
            .push_input(
                response.clone().into(),
                SubnetType::Application,
                InputQueueType::LocalSubnet,
            )
            .unwrap()
    );

    // Pop the response and make it into a paused response execution task.
    let response_canister_message = CanisterMessage::Response(response.clone().into());
    assert_eq!(
        Some(response_canister_message.clone()),
        fixture.canister_state.pop_input()
    );
    fixture
        .canister_state
        .system_state
        .task_queue
        .enqueue(ExecutionTask::PausedExecution {
            id: PausedExecutionId(13),
            input: CanisterMessageOrTask::Message(response_canister_message),
        });

    // Make an output queue slot reservation.
    assert!(
        fixture
            .push_input(
                request.clone().into(),
                SubnetType::Application,
                InputQueueType::LocalSubnet,
            )
            .unwrap()
    );
    fixture.canister_state.pop_input().unwrap();

    // Emqueue the response in the output queue.
    fixture
        .canister_state
        .push_output_response(response.clone().into());

    fixture.canister_state.induct_messages_to_self(
        &mut SUBNET_AVAILABLE_MEMORY.clone(),
        SubnetType::Application,
    );

    // Nothing was enqueued.
    assert!(!fixture.canister_state.has_input());
    // And the response should be silently consumed if best-effort; retained if
    // guaranteed response.
    assert_eq!(deadline == NO_DEADLINE, fixture.canister_state.has_output());
}

#[test]
fn application_subnet_remote_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        NO_DEADLINE,
        13,
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn application_subnet_local_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        NO_DEADLINE,
        13,
        SubnetType::Application,
        InputQueueType::LocalSubnet,
        true,
    );
}

#[test]
fn system_subnet_remote_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        NO_DEADLINE,
        13,
        SubnetType::System,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn system_subnet_local_push_input_request_ignores_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        NO_DEADLINE,
        13,
        SubnetType::System,
        InputQueueType::LocalSubnet,
        false,
    );
}

#[test]
fn application_subnet_push_input_best_effort_request_ignores_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SOME_DEADLINE,
        -13,
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
        false,
    );
}

#[test]
fn system_subnet_push_input_best_effort_request_ignores_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SOME_DEADLINE,
        -13,
        SubnetType::System,
        InputQueueType::RemoteSubnet,
        false,
    );
}

/// Common implementation for `CanisterState::push_input()` memory limit tests
/// for `Requests`. Expects a subnet memory limit that is below
/// `MAX_RESPONSE_COUNT_BYTES`.
///
/// Calls `push_input()` with a `Request` and the provided subnet type and input
/// queue type; and ensures that the limits are / are not enforced, depending on
/// the value of the `should_enforce_limit` parameter.
fn canister_state_push_input_request_memory_limit_test_impl(
    deadline: CoarseTime,
    initial_subnet_available_memory: i64,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
    should_enforce_limit: bool,
) {
    let mut canister_state = CanisterStateFixture::new().canister_state;

    let request = default_input_request(deadline);
    let mut subnet_available_memory = initial_subnet_available_memory;

    let result = canister_state.push_input(
        request.clone(),
        &mut subnet_available_memory,
        own_subnet_type,
        input_queue_type,
    );
    if should_enforce_limit {
        assert_eq!(
            Err((
                StateError::OutOfMemory {
                    requested: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
                    available: initial_subnet_available_memory,
                },
                request,
            )),
            result
        );
        assert_eq!(initial_subnet_available_memory, subnet_available_memory);
    } else {
        assert!(result.unwrap());

        // Guaranteed response requests consume `MAX_RESPONSE_COUNT_BYTES` guaranteed
        // response memory. Best-effort requests consume no guaranteed response memory.
        let expected_subnet_available_memory = if deadline == NO_DEADLINE {
            initial_subnet_available_memory - MAX_RESPONSE_COUNT_BYTES as i64
        } else {
            initial_subnet_available_memory
        };
        assert_eq!(expected_subnet_available_memory, subnet_available_memory);
    }
}

/// On system subnets we disregard memory reservations and execution memory usage.
#[test]
fn system_subnet_remote_push_input_request_ignores_memory_reservation_and_execution_memory_usage() {
    let mut canister_state = CanisterStateFixture::new().canister_state;

    // Remote message inducted into system subnet.
    let own_subnet_type = SubnetType::System;
    let input_queue_type = InputQueueType::RemoteSubnet;

    // Tiny explicit allocation, not enough for a request.
    canister_state.system_state.memory_allocation = MemoryAllocation::from(NumBytes::new(13));
    // And an execution state with non-zero size.
    canister_state.execution_state = Some(ExecutionState::new(
        Default::default(),
        execution_state::WasmBinary::new(CanisterModule::new(vec![1, 2, 3])),
        ExportedFunctions::new(Default::default()),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        vec![Global::I64(14)],
        WasmMetadata::default(),
    ));
    assert!(canister_state.memory_usage().get() > 0);
    let initial_memory_usage = canister_state.execution_memory_usage()
        + canister_state
            .system_state
            .guaranteed_response_message_memory_usage();
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;

    let request = default_input_request(NO_DEADLINE);

    assert!(
        canister_state
            .push_input(
                request,
                &mut subnet_available_memory,
                own_subnet_type,
                input_queue_type,
            )
            .unwrap()
    );

    assert_eq!(
        initial_memory_usage + NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
        canister_state.execution_memory_usage()
            + canister_state
                .system_state
                .guaranteed_response_message_memory_usage(),
    );
    assert_eq!(
        SUBNET_AVAILABLE_MEMORY - MAX_RESPONSE_COUNT_BYTES as i64,
        subnet_available_memory,
    );
}

#[test]
fn application_subnet_remote_push_input_response_ignores_memory_limits() {
    canister_state_push_input_response_memory_limit_test_impl(
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
fn application_subnet_local_push_input_response_ignores_memory_limits() {
    canister_state_push_input_response_memory_limit_test_impl(
        SubnetType::Application,
        InputQueueType::LocalSubnet,
    );
}

#[test]
fn system_subnet_remote_push_input_response_ignores_memory_limits() {
    canister_state_push_input_response_memory_limit_test_impl(
        SubnetType::System,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
fn system_subnet_local_push_input_response_ignores_memory_limits() {
    canister_state_push_input_response_memory_limit_test_impl(
        SubnetType::System,
        InputQueueType::LocalSubnet,
    );
}

/// Common implementation for `CanisterState::push_input()` memory limit tests
/// for `Responses`. Expects a subnet and/or canister memory limit that is below
/// `MAX_RESPONSE_COUNT_BYTES`.
///
/// Calls `push_input()` with a `Response` and the provided subnet type and input
/// queue type; and ensures that the limits are not enforced (because responses
/// always return memory).
fn canister_state_push_input_response_memory_limit_test_impl(
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
) {
    let mut fixture = CanisterStateFixture::new();

    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    let response: RequestOrResponse =
        default_input_response(fixture.make_callback(NO_DEADLINE), NO_DEADLINE).into();

    let mut subnet_available_memory = -13;
    assert!(
        fixture
            .canister_state
            .push_input(
                response.clone(),
                &mut subnet_available_memory,
                own_subnet_type,
                input_queue_type,
            )
            .unwrap()
    );

    assert_eq!(
        -13 + MAX_RESPONSE_COUNT_BYTES as i64 - response.count_bytes() as i64,
        subnet_available_memory
    );
}

#[test]
#[should_panic(expected = "Expected `Request` to have been sent by canister ID")]
fn canister_state_push_output_request_mismatched_sender() {
    let mut fixture = CanisterStateFixture::new();
    fixture
        .canister_state
        .push_output_request(
            Arc::new(RequestBuilder::default().sender(OTHER_CANISTER_ID).build()),
            UNIX_EPOCH,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "Expected `Response` to have been sent by canister ID")]
fn canister_state_push_output_response_mismatched_respondent() {
    let mut fixture = CanisterStateFixture::new();
    fixture.canister_state.push_output_response(
        ResponseBuilder::default()
            .respondent(OTHER_CANISTER_ID)
            .build()
            .into(),
    );
}

#[test]
fn canister_state_ingress_induction_cycles_debit() {
    let system_state = &mut CanisterStateFixture::new().canister_state.system_state;
    let initial_balance = system_state.balance();
    let ingress_induction_debit = Cycles::new(42);
    system_state.add_postponed_charge_to_ingress_induction_cycles_debit(ingress_induction_debit);
    assert_eq!(
        ingress_induction_debit,
        system_state.ingress_induction_cycles_debit()
    );
    assert_eq!(initial_balance, system_state.balance());
    assert_eq!(
        initial_balance - ingress_induction_debit,
        system_state.debited_balance()
    );

    system_state.apply_ingress_induction_cycles_debit(
        system_state.canister_id(),
        &no_op_logger(),
        &mock_metrics(),
    );
    assert_eq!(
        Cycles::zero(),
        system_state.ingress_induction_cycles_debit()
    );
    assert_eq!(
        initial_balance - ingress_induction_debit,
        system_state.balance()
    );
    assert_eq!(
        initial_balance - ingress_induction_debit,
        system_state.debited_balance()
    );
    // Check that 'ingress_induction_cycles_debit' is added
    // to consumed cycles.
    assert_eq!(
        system_state.canister_metrics.consumed_cycles,
        ingress_induction_debit.into()
    );
    assert_eq!(
        *system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .get(&CyclesUseCase::IngressInduction)
            .unwrap(),
        ingress_induction_debit.into()
    );
}
const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

#[test]
fn update_balance_and_consumed_cycles_correctly() {
    let mut system_state = CanisterStateFixture::new().canister_state.system_state;
    let initial_consumed_cycles = NominalCycles::from(1000);
    system_state.canister_metrics.consumed_cycles = initial_consumed_cycles;

    let cycles = Cycles::new(100);
    system_state.add_cycles(cycles, CyclesUseCase::Memory);
    assert_eq!(system_state.balance(), INITIAL_CYCLES + cycles);
    assert_eq!(
        system_state.canister_metrics.consumed_cycles,
        initial_consumed_cycles - NominalCycles::from(cycles)
    );
}

#[test]
fn update_balance_and_consumed_cycles_by_use_case_correctly() {
    let mut system_state = CanisterStateFixture::new().canister_state.system_state;
    let cycles_to_consume = Cycles::from(1000u128);
    system_state.remove_cycles(cycles_to_consume, CyclesUseCase::Memory);

    let cycles_to_add = Cycles::from(100u128);
    system_state.add_cycles(cycles_to_add, CyclesUseCase::Memory);
    assert_eq!(
        system_state.balance(),
        INITIAL_CYCLES - cycles_to_consume + cycles_to_add
    );
    assert_eq!(
        *system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .get(&CyclesUseCase::Memory)
            .unwrap(),
        NominalCycles::from(cycles_to_consume - cycles_to_add)
    );
}

#[test]
fn canister_state_callback_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    let minimal_callback = Callback::new(
        CallContextId::new(1),
        CANISTER_ID,
        OTHER_CANISTER_ID,
        Cycles::zero(),
        Cycles::zero(),
        Cycles::zero(),
        WasmClosure::new(0, 2),
        WasmClosure::new(0, 2),
        None,
        NO_DEADLINE,
    );
    let maximal_callback = Callback::new(
        CallContextId::new(1),
        CANISTER_ID,
        OTHER_CANISTER_ID,
        Cycles::new(21),
        Cycles::new(42),
        Cycles::new(84),
        WasmClosure::new(0, 2),
        WasmClosure::new(1, 2),
        Some(WasmClosure::new(2, 2)),
        ic_types::time::CoarseTime::from_secs_since_unix_epoch(329),
    );
    let u64_callback = Callback::new(
        CallContextId::new(u64::MAX - 1),
        CanisterId::from_u64(u64::MAX - 2),
        CanisterId::from_u64(u64::MAX - 3),
        Cycles::new(u128::MAX - 4),
        Cycles::new(u128::MAX - 5),
        Cycles::new(u128::MAX - 6),
        WasmClosure::new(u32::MAX - 7, u64::MAX - 8),
        WasmClosure::new(u32::MAX - 9, u64::MAX - 10),
        Some(WasmClosure::new(u32::MAX - 11, u64::MAX - 12)),
        ic_types::time::CoarseTime::from_secs_since_unix_epoch(u32::MAX - 13),
    );

    for callback in [minimal_callback, maximal_callback, u64_callback] {
        let pb_callback = pb::Callback::from(&callback);
        let round_trip = Callback::try_from(pb_callback).unwrap();

        assert_eq!(callback, round_trip);
    }
}

#[test]
fn canister_state_log_visibility_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    for initial in LogVisibilityV2::iter() {
        let encoded = pb::LogVisibilityV2::from(&initial);
        let round_trip = LogVisibilityV2::try_from(encoded).unwrap();

        assert_eq!(initial, round_trip);
    }

    // Check `allowed_viewers` case with non-empty principals.
    let initial = LogVisibilityV2::AllowedViewers(BoundedAllowedViewers::new(vec![
        user_test_id(1).get(),
        user_test_id(2).get(),
    ]));
    let encoded = pb::LogVisibilityV2::from(&initial);
    let round_trip = LogVisibilityV2::try_from(encoded).unwrap();

    assert_eq!(initial, round_trip);
}

#[test]
fn long_execution_mode_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    for initial in LongExecutionMode::iter() {
        let encoded = pb::LongExecutionMode::from(initial);
        let round_trip = LongExecutionMode::from(encoded);

        assert_eq!(initial, round_trip);
    }

    // Backward compatibility check.
    assert_eq!(
        LongExecutionMode::from(pb::LongExecutionMode::Unspecified),
        LongExecutionMode::Opportunistic
    );
}

#[test]
fn long_execution_mode_decoding() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;
    fn test(code: i32, decoded: LongExecutionMode) {
        let encoded = pb::LongExecutionMode::try_from(code).unwrap_or_default();
        assert_eq!(LongExecutionMode::from(encoded), decoded);
    }
    test(-1, LongExecutionMode::Opportunistic);
    test(0, LongExecutionMode::Opportunistic);
    test(1, LongExecutionMode::Opportunistic);
    test(2, LongExecutionMode::Prioritized);
    test(3, LongExecutionMode::Opportunistic);
}

#[test]
fn compatibility_for_log_visibility() {
    // If this fails, you are making a potentially incompatible change to `LogVisibilityV2`.
    // See note [Handling changes to Enums in Replicated State] for how to proceed.
    assert_eq!(
        LogVisibilityV2::iter().collect::<Vec<_>>(),
        [
            LogVisibilityV2::Controllers,
            LogVisibilityV2::Public,
            LogVisibilityV2::AllowedViewers(BoundedAllowedViewers::new(vec![]))
        ]
    );
}

#[test]
fn canister_state_canister_log_record_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    let initial = CanisterLogRecord {
        idx: 42,
        timestamp_nanos: 27,
        content: vec![1, 2, 3],
    };
    let encoded = pb::CanisterLogRecord::from(&initial);
    let round_trip = CanisterLogRecord::from(encoded);

    assert_eq!(initial, round_trip);
}

#[test]
fn execution_state_test_partial_eq() {
    let state_1 = ExecutionState::new(
        Default::default(),
        execution_state::WasmBinary::new(CanisterModule::new(vec![1, 2, 3])),
        ExportedFunctions::new(Default::default()),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        vec![Global::I64(14)],
        WasmMetadata::default(),
    );

    assert_eq!(state_1, state_1.clone());

    assert_eq!(
        ExecutionState {
            canister_root: PathBuf::new(),
            ..state_1.clone()
        },
        state_1
    );

    assert_eq!(ExecutionState { ..state_1.clone() }, state_1);

    assert_ne!(
        ExecutionState {
            wasm_binary: execution_state::WasmBinary::new(CanisterModule::new(vec![1, 2, 4])),
            ..state_1.clone()
        },
        state_1
    );

    assert_ne!(
        ExecutionState {
            exports: ExportedFunctions::new(BTreeSet::from([WasmMethod::System(
                SystemMethod::CanisterGlobalTimer
            )])),
            ..state_1.clone()
        },
        state_1
    );
    let mut memory = Memory::new_for_testing();
    memory.size = NumWasmPages::from(1);
    assert_ne!(
        ExecutionState {
            wasm_memory: memory.clone(),
            ..state_1.clone()
        },
        state_1
    );
    assert_ne!(
        ExecutionState {
            stable_memory: memory,
            ..state_1.clone()
        },
        state_1
    );

    assert_ne!(
        ExecutionState {
            exported_globals: vec![Global::I64(13)],
            ..state_1.clone()
        },
        state_1
    );
    let mut custom_sections: BTreeMap<String, CustomSection> = BTreeMap::new();
    custom_sections.insert(
        String::from("candid"),
        CustomSection::new(CustomSectionType::Private, vec![0; 10 * 1024]),
    );
    assert_ne!(
        ExecutionState {
            metadata: WasmMetadata::new(custom_sections),
            ..state_1.clone()
        },
        state_1
    );

    assert_ne!(
        ExecutionState {
            last_executed_round: ExecutionRound::from(12345),
            ..state_1.clone()
        },
        state_1
    );

    assert_ne!(
        ExecutionState {
            next_scheduled_method: NextScheduledMethod::Heartbeat,
            ..state_1.clone()
        },
        state_1
    );
}

/// Performs operations with canister history and thus exercises
/// ```
///   debug_assert_eq!(
///       self.get_memory_usage(),
///       compute_total_canister_change_size(&self.changes),
///   );
/// ```
/// in the functions `CanisterHistory::add_canister_change` and
/// `CanisterHistory::clear`.
#[test]
fn canister_history_operations() {
    let mut canister_history = CanisterHistory::default();
    let mut total_num_changes = 0;
    let mut reference_change_entries: Vec<CanisterChange> = vec![];
    let num_requested_changes = (MAX_CANISTER_HISTORY_CHANGES as usize) + 42;

    for i in 0..8 {
        let c = CanisterChange::new(
            42,
            0,
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::controllers_change(vec![canister_test_id(i).get()]),
        );
        canister_history.add_canister_change(c.clone());
        reference_change_entries.push(c);
        // keep only the last MAX_CANISTER_HISTORY_CHANGES changes
        reference_change_entries = reference_change_entries
            .into_iter()
            .rev()
            .take(MAX_CANISTER_HISTORY_CHANGES as usize)
            .rev()
            .collect();
        assert_eq!(
            canister_history
                .get_changes(num_requested_changes)
                .map(|c| (*c.clone()).clone())
                .collect::<Vec<CanisterChange>>(),
            reference_change_entries
        );
        total_num_changes += 1;
        assert_eq!(canister_history.get_total_num_changes(), total_num_changes);
    }

    canister_history.clear();
    reference_change_entries.clear();

    for i in 0..(MAX_CANISTER_HISTORY_CHANGES + 8) {
        let c = CanisterChange::new(
            42,
            0,
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::controllers_change(vec![canister_test_id(i).get()]),
        );
        canister_history.add_canister_change(c.clone());
        reference_change_entries.push(c);
        // keep only the last MAX_CANISTER_HISTORY_CHANGES changes
        reference_change_entries = reference_change_entries
            .into_iter()
            .rev()
            .take(MAX_CANISTER_HISTORY_CHANGES as usize)
            .rev()
            .collect();
        assert_eq!(
            canister_history
                .get_changes(num_requested_changes)
                .map(|c| (*c.clone()).clone())
                .collect::<Vec<CanisterChange>>(),
            reference_change_entries
        );
        total_num_changes += 1;
        assert_eq!(canister_history.get_total_num_changes(), total_num_changes);
    }

    canister_history.clear();
    reference_change_entries.clear();

    for i in 0..(MAX_CANISTER_HISTORY_CHANGES + 8) {
        let c = CanisterChange::new(
            42,
            0,
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::controllers_change(vec![canister_test_id(i).get()]),
        );
        canister_history.add_canister_change(c.clone());
        reference_change_entries.push(c);
        // keep only the last MAX_CANISTER_HISTORY_CHANGES changes
        reference_change_entries = reference_change_entries
            .into_iter()
            .rev()
            .take(MAX_CANISTER_HISTORY_CHANGES as usize)
            .rev()
            .collect();
        assert_eq!(
            canister_history
                .get_changes(num_requested_changes)
                .map(|c| (*c.clone()).clone())
                .collect::<Vec<CanisterChange>>(),
            reference_change_entries
        );
        total_num_changes += 1;
        assert_eq!(canister_history.get_total_num_changes(), total_num_changes);
    }
}

#[test]
fn drops_aborted_canister_install_after_split() {
    let mut canister_state = CanisterStateFixture::new().canister_state;
    canister_state
        .system_state
        .task_queue
        .enqueue(ExecutionTask::Heartbeat);

    canister_state
        .system_state
        .task_queue
        .enqueue(ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Request(Arc::new(RequestBuilder::new().build())),
            call_id: InstallCodeCallId::new(0),
            prepaid_execution_cycles: Cycles::from(0u128),
        });

    // Expected canister state is identical, minus the `AbortedInstallCode` task.
    let mut expected_state = canister_state.clone();
    expected_state.system_state.task_queue.pop_front();

    canister_state.drop_in_progress_management_calls_after_split();

    assert_eq!(expected_state, canister_state);
}

#[test]
fn reverts_stopping_status_after_split() {
    let mut canister_state = CanisterStateFixture::new().canister_state;
    let mut call_context_manager = CallContextManager::default();
    call_context_manager.with_call_context(CallContext::new(
        CallOrigin::Ingress(user_test_id(1), message_test_id(2), String::from("")),
        false,
        false,
        Cycles::from(0u128),
        Time::from_nanos_since_unix_epoch(0),
        Default::default(),
    ));
    canister_state
        .system_state
        .set_status(CanisterStatus::Stopping {
            call_context_manager: call_context_manager.clone(),
            stop_contexts: vec![StopCanisterContext::Ingress {
                sender: user_test_id(1),
                message_id: message_test_id(1),
                call_id: Some(StopCanisterCallId::new(0)),
            }],
        });

    // Expected canister state is identical, except it is `Running`.
    let mut expected_state = canister_state.clone();
    expected_state
        .system_state
        .set_status(CanisterStatus::Running {
            call_context_manager,
        });

    canister_state.drop_in_progress_management_calls_after_split();

    assert_eq!(expected_state, canister_state);
}
