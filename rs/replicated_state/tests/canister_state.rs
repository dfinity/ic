use ic_base_types::CanisterId;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, InputQueueType, StateError};
use ic_test_utilities_state::{
    get_running_canister, get_stopped_canister, get_stopping_canister, register_callback,
};
use ic_test_utilities_types::{
    ids::canister_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{CallbackId, Request, RequestOrResponse, NO_DEADLINE},
    time::UNIX_EPOCH,
    xnet::QueueId,
};
use std::sync::Arc;

const CANISTER_ID: CanisterId = CanisterId::from_u64(0);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
const CALLBACK_ID_RAW: u64 = 1;

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::new()
        .receiver(CANISTER_ID)
        .sender(OTHER_CANISTER_ID)
        .build()
        .into()
}

fn input_response_from(respondent: CanisterId, callback_id: CallbackId) -> RequestOrResponse {
    ResponseBuilder::new()
        .originator(CANISTER_ID)
        .respondent(respondent)
        .originator_reply_callback(callback_id)
        .build()
        .into()
}

fn default_input_response() -> RequestOrResponse {
    input_response_from(OTHER_CANISTER_ID, CallbackId::from(CALLBACK_ID_RAW))
}

fn output_request_to(canister_id: CanisterId, callback_id: CallbackId) -> Request {
    RequestBuilder::new()
        .sender(CANISTER_ID)
        .receiver(canister_id)
        .sender_reply_callback(callback_id)
        .build()
}

/// Fixture for `CanisterState` for use in tests. This always assumes two canisters,
/// one with a canister id set to `CANISTER_ID` and a remote canister with canister id
/// set to `OTHER_CANISTER_ID`. The remote canister is always assumed to be located on
/// a remote subnet.
struct CanisterFixture {
    canister_state: CanisterState,
}

impl CanisterFixture {
    fn running() -> CanisterFixture {
        CanisterFixture {
            canister_state: get_running_canister(CANISTER_ID),
        }
    }

    fn stopping() -> CanisterFixture {
        CanisterFixture {
            canister_state: get_stopping_canister(CANISTER_ID),
        }
    }

    fn stopped() -> CanisterFixture {
        CanisterFixture {
            canister_state: get_stopped_canister(CANISTER_ID),
        }
    }

    fn register_default_callback(&mut self) {
        register_callback(
            &mut self.canister_state,
            CANISTER_ID,
            OTHER_CANISTER_ID,
            CallbackId::from(CALLBACK_ID_RAW),
            NO_DEADLINE,
        );
    }

    fn push_input(
        &mut self,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let mut subnet_available_memory = i64::MAX / 2;
        self.canister_state.push_input(
            msg,
            &mut subnet_available_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
    }

    fn push_output_request(&mut self, request: Request) -> Result<(), (StateError, Arc<Request>)> {
        self.canister_state
            .push_output_request(request.into(), UNIX_EPOCH)
    }

    fn pop_output(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.canister_state.output_into_iter();
        iter.pop()
    }

    fn with_input_reservation(&mut self) {
        self.push_output_request(output_request_to(
            OTHER_CANISTER_ID,
            CallbackId::from(CALLBACK_ID_RAW),
        ))
        .unwrap();
        self.pop_output().unwrap();
    }
}

#[test]
fn running_canister_accepts_requests() {
    let mut fixture = CanisterFixture::running();
    fixture.push_input(default_input_request()).unwrap();
}

#[test]
fn running_canister_accepts_responses() {
    let mut fixture = CanisterFixture::running();
    fixture.register_default_callback();
    fixture.with_input_reservation();
    fixture.push_input(default_input_response()).unwrap();
}

#[test]
fn stopping_canister_rejects_requests() {
    let mut fixture = CanisterFixture::stopping();
    assert_eq!(
        fixture.push_input(default_input_request()),
        Err((
            StateError::CanisterStopping(CANISTER_ID),
            default_input_request(),
        )),
    );
}

#[test]
fn stopping_canister_accepts_responses() {
    let mut fixture = CanisterFixture::stopping();
    fixture.register_default_callback();
    fixture.with_input_reservation();
    fixture.push_input(default_input_response()).unwrap();
}

#[test]
fn stopped_canister_rejects_requests() {
    let mut fixture = CanisterFixture::stopped();
    assert_eq!(
        fixture.push_input(default_input_request()),
        Err((
            StateError::CanisterStopped(CANISTER_ID),
            default_input_request(),
        )),
    );
}

#[test]
fn stopped_canister_rejects_responses() {
    let mut fixture = CanisterFixture::stopped();
    // A stopped canister can't make a callback id.
    fixture.with_input_reservation();
    assert_eq!(
        fixture.push_input(default_input_response()),
        Err((
            StateError::CanisterStopped(CANISTER_ID),
            default_input_response(),
        )),
    );
}

#[test]
fn validate_response_fails_when_unknown_callback_id() {
    let mut fixture = CanisterFixture::running();
    let response = input_response_from(OTHER_CANISTER_ID, CallbackId::from(13));

    assert_eq!(
        fixture.push_input(response.clone()),
        Err((
            StateError::NonMatchingResponse {
                err_str: "unknown callback id".to_string(),
                originator: CANISTER_ID,
                callback_id: CallbackId::from(13),
                respondent: OTHER_CANISTER_ID,
            },
            response,
        ))
    );
}

#[test]
fn validate_responses_against_callback_details() {
    let mut fixture = CanisterFixture::running();

    let canister_b_id = canister_test_id(13);
    let canister_c_id = canister_test_id(17);

    // Creating the CallContext and registering the callback for a request from this canister -> canister B.
    let callback_id_1 = CallbackId::from(1);
    register_callback(
        &mut fixture.canister_state,
        CANISTER_ID,
        canister_b_id,
        callback_id_1,
        NO_DEADLINE,
    );

    // Creating the CallContext and registering the callback for a request from this canister -> canister C.
    let callback_id_2 = CallbackId::from(2);
    register_callback(
        &mut fixture.canister_state,
        CANISTER_ID,
        canister_c_id,
        callback_id_2,
        NO_DEADLINE,
    );

    // Reserving slots in the input queue for the corresponding responses.
    // Request from this canister to canister B.
    fixture
        .push_output_request(output_request_to(canister_b_id, callback_id_1))
        .unwrap();
    fixture.pop_output();
    // Request from this canister to canister C.
    fixture
        .push_output_request(output_request_to(canister_c_id, callback_id_2))
        .unwrap();
    fixture.pop_output();

    // Creating invalid response from canister C to this canister.
    // Using the callback_id from this canister -> canister B.
    let response = input_response_from(canister_c_id, callback_id_1);
    assert_eq!(
        fixture.push_input(response.clone()),
        Err((StateError::NonMatchingResponse { err_str: format!(
            "invalid details, expected => [originator => {}, respondent => {}], but got response with",
            CANISTER_ID, canister_b_id,
        ), originator: response.receiver(), callback_id: callback_id_1, respondent: response.sender()}, response)),
    );

    // Creating valid response from canister C to this canister.
    // Pushing the response in this canister's input queue is successful.
    fixture
        .push_input(input_response_from(canister_c_id, callback_id_2))
        .unwrap();

    // Creating valid response from canister B to this canister.
    // Pushing the response in this canister's input queue is successful.
    fixture
        .push_input(input_response_from(canister_b_id, callback_id_1))
        .unwrap();
}
