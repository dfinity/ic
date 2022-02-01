use super::*;
use ic_base_types::NumSeconds;
use ic_test_utilities::types::{
    ids::user_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{messages::MAX_RESPONSE_COUNT_BYTES, CountBytes, Cycles};
use ic_wasm_types::BinaryEncodedWasm;

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);
const MAX_CANISTER_MEMORY_SIZE: NumBytes = NumBytes::new(u64::MAX / 2);
const SUBNET_AVAILABLE_MEMORY: i64 = i64::MAX / 2;
const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);

fn canister_state_test<F, R>(f: F) -> R
where
    F: FnOnce(CanisterState) -> R,
{
    let scheduler_state = SchedulerState::default();
    let system_state = SystemState::new_running(
        CANISTER_ID,
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let canister_state = CanisterState::new(system_state, None, scheduler_state);
    f(canister_state)
}

#[test]
fn canister_state_push_input_request_success() {
    canister_state_test(|mut canister_state| {
        canister_state
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .receiver(CANISTER_ID)
                    .build()
                    .into(),
                MAX_CANISTER_MEMORY_SIZE,
                &mut SUBNET_AVAILABLE_MEMORY.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    })
}

#[test]
fn canister_state_push_input_response_no_reservation() {
    canister_state_test(|mut canister_state| {
        let response: RequestOrResponse = ResponseBuilder::default()
            .originator(CANISTER_ID)
            .build()
            .into();

        assert_eq!(
            Err((StateError::QueueFull { capacity: 0 }, response.clone())),
            canister_state.push_input(
                QueueIndex::from(0),
                response,
                MAX_CANISTER_MEMORY_SIZE,
                &mut SUBNET_AVAILABLE_MEMORY.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
        );
    })
}

#[test]
fn canister_state_push_input_response_success() {
    canister_state_test(|mut canister_state| {
        // Make an input queue reservation.
        canister_state
            .push_output_request(
                RequestBuilder::default()
                    .sender(CANISTER_ID)
                    .receiver(OTHER_CANISTER_ID)
                    .build(),
            )
            .unwrap();
        canister_state.output_into_iter().count();

        canister_state
            .push_input(
                QueueIndex::from(0),
                ResponseBuilder::default()
                    .respondent(OTHER_CANISTER_ID)
                    .originator(CANISTER_ID)
                    .build()
                    .into(),
                MAX_CANISTER_MEMORY_SIZE,
                &mut SUBNET_AVAILABLE_MEMORY.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    })
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_request_mismatched_receiver() {
    canister_state_test(|mut canister_state| {
        canister_state
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .receiver(OTHER_CANISTER_ID)
                    .build()
                    .into(),
                MAX_CANISTER_MEMORY_SIZE,
                &mut SUBNET_AVAILABLE_MEMORY.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    })
}

#[test]
#[should_panic(expected = "Expected `RequestOrResponse` to be targeted to canister ID")]
fn canister_state_push_input_response_mismatched_originator() {
    canister_state_test(|mut canister_state| {
        canister_state
            .push_input(
                QueueIndex::from(0),
                ResponseBuilder::default()
                    .originator(OTHER_CANISTER_ID)
                    .build()
                    .into(),
                MAX_CANISTER_MEMORY_SIZE,
                &mut SUBNET_AVAILABLE_MEMORY.clone(),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    })
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
    canister_state_test(|mut canister_state| {
        let request: RequestOrResponse = RequestBuilder::default()
            .sender(OTHER_CANISTER_ID)
            .receiver(CANISTER_ID)
            .build()
            .into();

        let mut subnet_available_memory_ = subnet_available_memory;
        let res = canister_state.push_input(
            QueueIndex::from(0),
            request.clone(),
            max_canister_memory_size,
            &mut subnet_available_memory_,
            own_subnet_type,
            input_queue_type,
        );

        if ENFORCE_MESSAGE_MEMORY_USAGE && should_enforce_limit {
            assert_eq!(
                Err((
                    StateError::OutOfMemory {
                        requested: NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
                        available: subnet_available_memory
                            .min(max_canister_memory_size.get() as i64)
                    },
                    request
                )),
                res
            );
            assert_eq!(subnet_available_memory, subnet_available_memory_);
        } else {
            res.unwrap();
        }
    })
}

/// On system subnets we disregard memory reservations and execution memory
/// usage and allow up to `max_canister_memory_size` worth of messages.
#[test]
fn system_subnet_remote_push_input_request_ignores_memory_reservation_and_execution_memory_usage() {
    canister_state_test(|mut canister_state| {
        // Remote message inducted into system subnet.
        let own_subnet_type = SubnetType::System;
        let input_queue_type = InputQueueType::RemoteSubnet;

        // Only enough memory for one request, no space for wasm or globals.
        let max_canister_memory_size = NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64);

        // Tiny explicit allocation, not enough for a request.
        canister_state.system_state.memory_allocation =
            MemoryAllocation::Reserved(NumBytes::new(13));
        // And an execution state with non-zero size.
        canister_state.execution_state = Some(ExecutionState::new(
            Default::default(),
            execution_state::WasmBinary::new(BinaryEncodedWasm::new(vec![1, 2, 3])),
            ExportedFunctions::new(Default::default()),
            Default::default(),
            Default::default(),
            vec![Global::I64(14)],
        ));
        assert!(canister_state.memory_usage(own_subnet_type).get() > 0);
        let initial_memory_usage = canister_state.memory_usage_impl(true);

        let request: RequestOrResponse = RequestBuilder::default()
            .sender(OTHER_CANISTER_ID)
            .receiver(CANISTER_ID)
            .build()
            .into();

        let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;
        canister_state
            .push_input(
                QueueIndex::from(0),
                request,
                max_canister_memory_size,
                &mut subnet_available_memory,
                own_subnet_type,
                input_queue_type,
            )
            .unwrap();

        assert_eq!(
            initial_memory_usage + NumBytes::new(MAX_RESPONSE_COUNT_BYTES as u64),
            canister_state.memory_usage_impl(true)
        );
        assert_eq!(
            SUBNET_AVAILABLE_MEMORY - MAX_RESPONSE_COUNT_BYTES as i64,
            subnet_available_memory
        );
    })
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
    canister_state_test(|mut canister_state| {
        // Make an input queue reservation.
        canister_state
            .push_output_request(
                RequestBuilder::default()
                    .sender(CANISTER_ID)
                    .receiver(OTHER_CANISTER_ID)
                    .build(),
            )
            .unwrap();
        canister_state.output_into_iter().count();

        let response: RequestOrResponse = ResponseBuilder::default()
            .respondent(OTHER_CANISTER_ID)
            .originator(CANISTER_ID)
            .build()
            .into();

        let mut subnet_available_memory = -13;
        canister_state
            .push_input(
                QueueIndex::from(0),
                response.clone(),
                NumBytes::new(14),
                &mut subnet_available_memory,
                own_subnet_type,
                input_queue_type,
            )
            .unwrap();

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            assert_eq!(
                -13 + MAX_RESPONSE_COUNT_BYTES as i64 - response.count_bytes() as i64,
                subnet_available_memory
            );
        } else {
            assert_eq!(-13, subnet_available_memory);
        }
    })
}

#[test]
#[should_panic(expected = "Expected `Request` to have been sent by canister ID")]
fn canister_state_push_output_request_mismatched_sender() {
    canister_state_test(|mut canister_state| {
        canister_state
            .push_output_request(RequestBuilder::default().sender(OTHER_CANISTER_ID).build())
            .unwrap();
    })
}

#[test]
#[should_panic(expected = "Expected `Response` to have been sent by canister ID")]
fn canister_state_push_output_response_mismatched_respondent() {
    canister_state_test(|mut canister_state| {
        canister_state.push_output_response(
            ResponseBuilder::default()
                .respondent(OTHER_CANISTER_ID)
                .build(),
        );
    })
}

#[test]
fn wasm_can_be_loaded_from_a_file() {
    use std::io::Write;

    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
    let wasm_in_memory = BinaryEncodedWasm::new(vec![0x00, 0x61, 0x73, 0x6d]);
    tmp.write_all(wasm_in_memory.as_slice())
        .expect("failed to write Wasm to a temporary file");
    let wasm_on_disk = BinaryEncodedWasm::new_from_file(tmp.path().to_owned())
        .expect("failed to read Wasm from disk");

    assert_eq!(wasm_in_memory.file(), None);
    assert_eq!(wasm_on_disk.file(), Some(tmp.path()));
    assert_eq!(wasm_in_memory, wasm_on_disk);
}
