use std::collections::BTreeMap;
use std::path::PathBuf;

use super::*;
use crate::canister_state::execution_state::CustomSection;
use crate::canister_state::execution_state::CustomSectionType;
use crate::canister_state::execution_state::WasmMetadata;
use crate::canister_state::system_state::{
    CallContextManager, CanisterHistory, CanisterStatus, CyclesUseCase,
    MAX_CANISTER_HISTORY_CHANGES,
};
use crate::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use crate::CallOrigin;
use crate::Memory;
use ic_base_types::NumSeconds;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types::{
    BoundedAllowedViewers, CanisterChange, CanisterChangeDetails, CanisterChangeOrigin,
    CanisterLogRecord, LogVisibilityV2,
};
use ic_metrics::MetricsRegistry;
use ic_test_utilities_types::{
    ids::canister_test_id,
    ids::message_test_id,
    ids::user_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{
        CallContextId, CallbackId, CanisterCall, RequestMetadata, StopCanisterCallId,
        StopCanisterContext, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE,
    },
    methods::{Callback, WasmClosure},
    nominal_cycles::NominalCycles,
    CountBytes, Cycles, Time,
};
use ic_wasm_types::CanisterModule;
use prometheus::IntCounter;
use strum::IntoEnumIterator;

const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);
const SUBNET_AVAILABLE_MEMORY: i64 = i64::MAX / 2;

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::default()
        .receiver(CANISTER_ID)
        .build()
        .into()
}

fn default_input_response(callback_id: CallbackId) -> Response {
    ResponseBuilder::default()
        .originator(CANISTER_ID)
        .respondent(OTHER_CANISTER_ID)
        .originator_reply_callback(callback_id)
        .build()
}

fn default_output_request() -> Arc<Request> {
    Arc::new(
        RequestBuilder::default()
            .sender(CANISTER_ID)
            .receiver(OTHER_CANISTER_ID)
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

    fn make_callback(&mut self) -> CallbackId {
        let call_context_id = self
            .canister_state
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(CANISTER_ID, CallbackId::from(1), NO_DEADLINE),
                Cycles::zero(),
                Time::from_nanos_since_unix_epoch(0),
                RequestMetadata::new(0, UNIX_EPOCH),
            );
        self.canister_state
            .system_state
            .call_context_manager_mut()
            .unwrap()
            .register_callback(Callback::new(
                call_context_id,
                CANISTER_ID,
                OTHER_CANISTER_ID,
                Cycles::zero(),
                Cycles::new(42),
                Cycles::new(84),
                WasmClosure::new(0, 2),
                WasmClosure::new(0, 2),
                None,
                NO_DEADLINE,
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
fn canister_state_push_input_response_no_reserved_slot() {
    let mut fixture = CanisterStateFixture::new();
    let response = default_input_response(fixture.make_callback());
    assert_eq!(
        Err((
            StateError::NonMatchingResponse {
                err_str: "No reserved response slot".to_string(),
                originator: response.originator,
                callback_id: response.originator_reply_callback,
                respondent: response.respondent,
                deadline: response.deadline,
            },
            response.clone().into(),
        )),
        fixture.push_input(
            response.into(),
            SubnetType::Application,
            InputQueueType::RemoteSubnet
        ),
    );
}

#[test]
fn canister_state_push_input_response_success() {
    let mut fixture = CanisterStateFixture::new();
    // Reserve a slot in the input queue.
    fixture.with_input_slot_reservation();
    // Pushing input response should succeed.
    let response = default_input_response(fixture.make_callback()).into();
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
        SubnetType::Application,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn application_subnet_local_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        SubnetType::Application,
        InputQueueType::LocalSubnet,
        true,
    );
}

#[test]
fn system_subnet_remote_push_input_request_not_enough_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        SubnetType::System,
        InputQueueType::RemoteSubnet,
        true,
    );
}

#[test]
fn system_subnet_local_push_input_request_ignores_subnet_memory() {
    canister_state_push_input_request_memory_limit_test_impl(
        13,
        SubnetType::System,
        InputQueueType::LocalSubnet,
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
    initial_subnet_available_memory: i64,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
    should_enforce_limit: bool,
) {
    let mut canister_state = CanisterStateFixture::new().canister_state;

    let request = default_input_request();
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
        result.unwrap();

        let expected_subnet_available_memory =
            initial_subnet_available_memory - MAX_RESPONSE_COUNT_BYTES as i64;
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
    assert!(canister_state.memory_usage().get() > 0);
    let initial_memory_usage = canister_state.execution_memory_usage()
        + canister_state
            .system_state
            .guaranteed_response_message_memory_usage();
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;

    let request = default_input_request();

    canister_state
        .push_input(
            request,
            &mut subnet_available_memory,
            own_subnet_type,
            input_queue_type,
        )
        .unwrap();

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
    let response: RequestOrResponse = default_input_response(fixture.make_callback()).into();

    let mut subnet_available_memory = -13;
    fixture
        .canister_state
        .push_input(
            response.clone(),
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
        .push_back(ExecutionTask::Heartbeat);

    canister_state
        .system_state
        .task_queue
        .push_back(ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Request(Arc::new(RequestBuilder::new().build())),
            call_id: InstallCodeCallId::new(0),
            prepaid_execution_cycles: Cycles::from(0u128),
        });

    // Expected canister state is identical, minus the `AbortedInstallCode` task.
    let mut expected_state = canister_state.clone();
    expected_state.system_state.task_queue.pop_back();

    canister_state.drop_in_progress_management_calls_after_split();

    assert_eq!(expected_state, canister_state);
}

#[test]
fn reverts_stopping_status_after_split() {
    let mut canister_state = CanisterStateFixture::new().canister_state;
    let mut call_context_manager = CallContextManager::default();
    call_context_manager.new_call_context(
        CallOrigin::Ingress(user_test_id(1), message_test_id(2)),
        Cycles::from(0u128),
        Time::from_nanos_since_unix_epoch(0),
        RequestMetadata::new(0, UNIX_EPOCH),
    );
    canister_state.system_state.status = CanisterStatus::Stopping {
        call_context_manager: call_context_manager.clone(),
        stop_contexts: vec![StopCanisterContext::Ingress {
            sender: user_test_id(1),
            message_id: message_test_id(1),
            call_id: Some(StopCanisterCallId::new(0)),
        }],
    };

    // Expected canister state is identical, except it is `Running`.
    let mut expected_state = canister_state.clone();
    expected_state.system_state.status = CanisterStatus::Running {
        call_context_manager,
    };

    canister_state.drop_in_progress_management_calls_after_split();

    assert_eq!(expected_state, canister_state);
}
