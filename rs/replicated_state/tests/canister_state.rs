use ic_base_types::{CanisterId, NumBytes};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin,
    //    testing::{CanisterQueuesTesting, SystemStateTesting},
    CanisterState,
    InputQueueType,
    StateError,
};
use ic_test_utilities::{
    mock_time,
    state::{get_running_canister, get_stopped_canister, get_stopping_canister},
    types::messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{CallbackId, Request, RequestOrResponse},
    methods::{Callback, WasmClosure},
    xnet::QueueId,
    Cycles, Time,
};

const CANISTER_ID: CanisterId = CanisterId::from_u64(0);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(1);

fn default_input_request() -> RequestOrResponse {
    RequestBuilder::new()
        .receiver(CANISTER_ID)
        .sender(OTHER_CANISTER_ID)
        .build()
        .into()
}

fn default_input_response(callback_id: CallbackId) -> RequestOrResponse {
    ResponseBuilder::new()
        .originator(CANISTER_ID)
        .respondent(OTHER_CANISTER_ID)
        .originator_reply_callback(callback_id)
        .build()
        .into()
}

fn default_output_request() -> Request {
    RequestBuilder::new()
        .sender(CANISTER_ID)
        .receiver(OTHER_CANISTER_ID)
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
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let mut subnet_available_memory = i64::MAX / 2;
        self.canister_state.push_input(
            msg,
            NumBytes::new(u64::MAX / 2),
            &mut subnet_available_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
    }

    fn pop_output(&mut self) -> Option<(QueueId, RequestOrResponse)> {
        let mut iter = self.canister_state.output_into_iter();
        iter.pop()
    }

    fn with_input_reservation(&mut self) {
        self.canister_state
            .push_output_request(default_output_request().into(), mock_time())
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
    fixture.with_input_reservation();
    let response = default_input_response(fixture.make_callback());
    fixture.push_input(response).unwrap();
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
    fixture.with_input_reservation();
    let response = default_input_response(fixture.make_callback());
    fixture.push_input(response).unwrap();
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
    fixture.with_input_reservation();
    // A stopped canister can't make a callback id.
    let response = default_input_response(CallbackId::from(0));
    assert_eq!(
        fixture.push_input(response.clone()),
        Err((StateError::CanisterStopped(CANISTER_ID), response,)),
    );
}
