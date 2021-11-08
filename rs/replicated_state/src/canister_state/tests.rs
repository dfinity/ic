use super::*;
use ic_base_types::NumSeconds;
use ic_test_utilities::types::{
    ids::user_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::Cycles;
use ic_wasm_types::BinaryEncodedWasm;

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);
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
            canister_state.push_input(QueueIndex::from(0), response,)
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
            )
            .unwrap();
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
