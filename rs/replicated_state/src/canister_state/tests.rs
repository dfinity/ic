use super::*;
use crate::canister_state::execution_state::WasmMetadata;
use crate::CallOrigin;
use crate::Memory;
use ic_base_types::NumSeconds;
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities::mock_time;
use ic_test_utilities::types::{
    ids::user_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::messages::CallContextId;
use ic_types::{
    messages::CallbackId,
    methods::{Callback, WasmClosure},
    Time,
};
use ic_types::{
    messages::MAX_RESPONSE_COUNT_BYTES, nominal_cycles::NominalCycles, xnet::QueueId, CountBytes,
    Cycles,
};
use ic_wasm_types::CanisterModule;

const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);
const MAX_CANISTER_MEMORY_SIZE: NumBytes = NumBytes::new(u64::MAX / 2);
const SUBNET_AVAILABLE_MEMORY: i64 = i64::MAX / 2;

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::default()
        .receiver(CANISTER_ID)
        .build()
        .into()
}

fn default_input_response(callback_id: CallbackId) -> RequestOrResponse {
    ResponseBuilder::default()
        .originator(CANISTER_ID)
        .respondent(OTHER_CANISTER_ID)
        .originator_reply_callback(callback_id)
        .build()
        .into()
}

fn default_output_request() -> Arc<Request> {
    Arc::new(
        RequestBuilder::default()
            .sender(CANISTER_ID)
            .receiver(OTHER_CANISTER_ID)
            .build(),
    )
}

struct CanisterStateFixture {
    pub canister_state: CanisterState,
}

impl CanisterStateFixture {
    fn new() -> CanisterStateFixture {
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running(
            CANISTER_ID,
            user_test_id(24).get(),
            Cycles::new(1 << 36),
            NumSeconds::from(100_000),
        );

        CanisterStateFixture {
            canister_state: CanisterState::new(system_state, None, scheduler_state),
        }
    }

    fn make_callback(&mut self) -> CallbackId {
        let call_context_id = self
            .canister_state
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(CANISTER_ID, CallbackId::from(1)),
                Cycles::zero(),
                Time::from_nanos_since_unix_epoch(0),
            );
        self.canister_state
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .register_callback(Callback::new(
                call_context_id,
                Some(CANISTER_ID),
                Some(OTHER_CANISTER_ID),
                Cycles::zero(),
                Some(Cycles::new(42)),
                Some(Cycles::new(84)),
                WasmClosure::new(0, 2),
                WasmClosure::new(0, 2),
                None,
            ))
    }

    fn push_input(
        &mut self,
        msg: RequestOrResponse,
        subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.canister_state.push_input(
            msg,
            MAX_CANISTER_MEMORY_SIZE,
            &mut SUBNET_AVAILABLE_MEMORY.clone(),
            subnet_type,
            input_queue_type,
        )
    }

    fn pop_output(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.canister_state.output_into_iter();
        iter.pop()
    }

    fn with_input_reservation(&mut self) {
        self.canister_state
            .push_output_request(default_output_request(), mock_time())
            .unwrap();
        self.pop_output().unwrap();
    }
}

#[test]
fn canister_state_push_input_request_success() {
    let mut fixture = CanisterStateFixture::new();
    fixture
        .push_input(
            default_input_request(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

#[test]
fn canister_state_push_input_response_no_reservation() {
    let mut fixture = CanisterStateFixture::new();
    let response = default_input_response(fixture.make_callback());
    assert_eq!(
        Err((StateError::QueueFull { capacity: 0 }, response.clone(),)),
        fixture.push_input(
            response,
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
    );
}

#[test]
fn canister_state_push_input_response_success() {
    let mut fixture = CanisterStateFixture::new();
    // Make an input queue reservation.
    fixture.with_input_reservation();
    // Pushing input response should succeed.
    let response = default_input_response(fixture.make_callback());
    fixture
        .push_input(
            response,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_request_mismatched_receiver() {
    let mut fixture = CanisterStateFixture::new();
    fixture
        .push_input(
            RequestBuilder::default()
                .receiver(OTHER_CANISTER_ID)
                .build()
                .into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_response_mismatched_originator() {
    let mut fixture = CanisterStateFixture::new();
    fixture
        .push_input(
            ResponseBuilder::default()
                .originator(OTHER_CANISTER_ID)
                .build()
                .into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

#[test]
fn application_subnet_remote_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        MAX_CANISTER_MEMORY_SIZE,
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn application_subnet_local_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        MAX_CANISTER_MEMORY_SIZE,
        SubnetType::Application,
        InputQueueType::LocalSubnet,
        true,
    );
}

#[test]
fn application_subnet_remote_push_input_request_not_enough_canister_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SUBNET_AVAILABLE_MEMORY,
        NumBytes::new(13),
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn application_subnet_local_push_input_request_not_enough_canister_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SUBNET_AVAILABLE_MEMORY,
        NumBytes::new(13),
        SubnetType::Application,
        InputQueueType::LocalSubnet,
        true,
    );
}

#[test]
fn system_subnet_remote_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        MAX_CANISTER_MEMORY_SIZE,
        SubnetType::System,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn system_subnet_local_push_input_request_ignores_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        MAX_CANISTER_MEMORY_SIZE,
        SubnetType::System,
        InputQueueType::LocalSubnet,
        false,
    );
}

#[test]
fn system_subnet_remote_push_input_request_not_enough_canister_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SUBNET_AVAILABLE_MEMORY,
        NumBytes::new(13),
        SubnetType::System,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn system_subnet_local_push_input_request_ignores_canister_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        SUBNET_AVAILABLE_MEMORY,
        NumBytes::new(13),
        SubnetType::System,
        InputQueueType::LocalSubnet,
        false,
    );
}

/// Common implementation for `CanisterState::push_input()` memory limit tests
/// for `Requests`. Expects a subnet and/or canister memory limit that is below
/// `MAX_RESPONSE_COUNT_BYTES`.
///
/// Calls `push_input()` with a `Request` and the provided subnet type and input
/// queue type; and ensures that the limits are / are not enforced, depending on
/// the value of the `should_enforce_limit` parameter.
fn canister_state_push_input_request_memory_limit_test_impl(
    subnet_available_memory: i64,
    max_canister_memory_size: NumBytes,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
    should_enforce_limit: bool,
) {
    let mut canister_state = CanisterStateFixture::new().canister_state;

    let request = default_input_request();
    let mut subnet_available_memory_ = subnet_available_memory;

    let result = canister_state.push_input(
        request.clone(),
        max_canister_memory_size,
        &mut subnet_available_memory_,
        own_subnet_type,
        input_queue_type,
    );
    if should_enforce_limit {
        assert_eq!(
            Err((
                StateError::OutOfMemory {
                    requested: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
                    available: subnet_available_memory.min(max_canister_memory_size.get() as i64)
                },
                request,
            )),
            result
        );
        assert_eq!(subnet_available_memory, subnet_available_memory_);
    } else {
        result.unwrap();
    }
}

/// On system subnets we disregard memory reservations and execution memory
/// usage and allow up to `max_canister_memory_size` worth of messages.
#[test]
fn system_subnet_remote_push_input_request_ignores_memory_reservation_and_execution_memory_usage() {
    let mut canister_state = CanisterStateFixture::new().canister_state;

    // Remote message inducted into system subnet.
    let own_subnet_type = SubnetType::System;
    let input_queue_type = InputQueueType::RemoteSubnet;

    // Only enough memory for one request, no space for wasm or globals.
    let max_canister_memory_size = NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64);

    // Tiny explicit allocation, not enough for a request.
    canister_state.system_state.memory_allocation = MemoryAllocation::Reserved(NumBytes::new(13));
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
    assert!(canister_state.memory_usage(own_subnet_type).get() > 0);
    let initial_memory_usage =
        canister_state.raw_memory_usage() + canister_state.message_memory_usage();
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;

    let request = default_input_request();

    canister_state
        .push_input(
            request,
            max_canister_memory_size,
            &mut subnet_available_memory,
            own_subnet_type,
            input_queue_type,
        )
        .unwrap();

    assert_eq!(
        initial_memory_usage + NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
        canister_state.raw_memory_usage() + canister_state.message_memory_usage(),
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

    // Make an input queue reservation.
    fixture.with_input_reservation();
    let response = default_input_response(fixture.make_callback());

    let mut subnet_available_memory = -13;
    fixture
        .canister_state
        .push_input(
            response.clone(),
            NumBytes::new(14),
            &mut subnet_available_memory,
            own_subnet_type,
            input_queue_type,
        )
        .unwrap();

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
            mock_time(),
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
fn wasm_can_be_loaded_from_a_file() {
    use std::io::Write;

    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
    let wasm_in_memory = CanisterModule::new(vec![0x00, 0x61, 0x73, 0x6d]);
    tmp.write_all(wasm_in_memory.as_slice())
        .expect("failed to write Wasm to a temporary file");
    let wasm_on_disk = CanisterModule::new_from_file(tmp.path().to_owned(), None)
        .expect("failed to read Wasm from disk");
    let wasm_hash = wasm_in_memory.module_hash();
    let wasm_on_disk_with_hash =
        CanisterModule::new_from_file(tmp.path().to_owned(), Some(wasm_hash.into()))
            .expect("failed to read Wasm from disk");

    assert_eq!(wasm_in_memory.file(), None);
    assert_eq!(wasm_on_disk.file(), Some(tmp.path()));
    assert_eq!(wasm_in_memory, wasm_on_disk);
    assert_eq!(wasm_in_memory, wasm_on_disk_with_hash);
}

#[test]
fn canister_state_cycles_debit() {
    let system_state = &mut CanisterStateFixture::new().canister_state.system_state;
    let initial_balance = system_state.balance();

    system_state.add_postponed_charge_to_cycles_debit(Cycles::new(42));
    assert_eq!(Cycles::new(42), system_state.cycles_debit());
    assert_eq!(initial_balance, system_state.balance());
    assert_eq!(
        initial_balance - Cycles::new(42),
        system_state.debited_balance()
    );

    system_state.apply_cycles_debit(system_state.canister_id(), &no_op_logger());
    assert_eq!(Cycles::zero(), system_state.cycles_debit());
    assert_eq!(initial_balance - Cycles::new(42), system_state.balance());
    assert_eq!(
        initial_balance - Cycles::new(42),
        system_state.debited_balance()
    );
}
const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

#[test]
fn update_balance_and_consumed_cycles_correctly() {
    let mut system_state = CanisterStateFixture::new().canister_state.system_state;
    let initial_consumed_cycles = NominalCycles::from(1000);
    system_state
        .canister_metrics
        .consumed_cycles_since_replica_started = initial_consumed_cycles;

    let cycles = Cycles::new(100);
    system_state.increment_balance_and_decrement_consumed_cycles(cycles);
    assert_eq!(system_state.balance(), INITIAL_CYCLES + cycles);
    assert_eq!(
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started,
        initial_consumed_cycles - NominalCycles::from(cycles)
    );
}

#[test]
fn canister_state_callback_round_trip() {
    use ic_protobuf::state::canister_state_bits::v1 as pb;

    let callback = Callback::new(
        CallContextId::new(1),
        Some(CANISTER_ID),
        Some(OTHER_CANISTER_ID),
        Cycles::zero(),
        Some(Cycles::new(42)),
        Some(Cycles::new(84)),
        WasmClosure::new(0, 2),
        WasmClosure::new(0, 2),
        None,
    );

    let pb_callback = pb::Callback::from(&callback);

    let round_trip = Callback::try_from(pb_callback).unwrap();

    assert_eq!(callback, round_trip);
}
