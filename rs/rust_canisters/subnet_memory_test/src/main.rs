use candid::{Decode, Encode};
use dfn_core::api;
use ic_base_types::{CanisterId, NumBytes};
use ic_types::NumInstructions;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use subnet_memory_test::*;

thread_local! {
    static REQUESTS: RefCell<VecDeque<(NumBytes, CanisterId)>> = RefCell::default();
    static RETRY: Cell<Option<(NumBytes, CanisterId)>> = Cell::default();
    static RESPONSES: RefCell<BTreeMap<CanisterId, VecDeque<(NumBytes, NumInstructions)>>> = RefCell::default();
    static REQUESTS_PER_ROUND: Cell<u32> = Cell::default();
    static MESSAGE_ID: Cell<u32> = Cell::default();
    static RECORDS: RefCell<BTreeMap<u32, Record>> = RefCell::default();
}

fn next_message_id() -> u32 {
    let id = MESSAGE_ID.take();
    MESSAGE_ID.set(id + 1);
    id
}

/// Extracts the next payload size and receiver for the next request.
fn next_request() -> Option<(NumBytes, CanisterId)> {
    REQUESTS.with_borrow_mut(|q| q.pop_front())
}

/// Extracts the next payload size and number of instructions for the next response.
fn next_response(originator: &CanisterId) -> Option<(NumBytes, NumInstructions)> {
    RESPONSES.with_borrow_mut(|map| {
        if let Some(mut q) = map.remove(originator) {
            if let Some((num_bytes, num_instructions)) = q.pop_front() {
                map.insert(*originator, q);
                return Some((num_bytes, num_instructions));
            }
        }
        None
    })
}

#[export_name = "canister_init"]
fn main() {}

/// Sets the canister state according to `f` by parsing `arg_data` of type `T`.
fn set_state<T, F>(f: F) -> ()
where
    T: candid::CandidType + for<'a> serde::Deserialize<'a>,
    F: FnOnce(T) -> (),
{
    let msg = match candid::Decode!(&api::arg_data()[..], T) {
        Ok(item) => {
            f(item);
            "accepted"
        }
        Err(_) => "rejected",
    };

    let msg = candid::Encode!(&msg.to_string()).unwrap();
    api::reply(&msg[..]);
}

/// Sets the request and response payload sizes.
#[export_name = "canister_update set_payloads"]
fn set_payloads() {
    set_state(|config: Config| {
        REQUESTS.set(config.request_payloads);
        RESPONSES.set(config.response_payloads);
    });
}

/// Sets the requests per round to be sent each heart beat.
#[export_name = "canister_update set_requests_per_round"]
fn set_requests_per_round() {
    set_state(|requests_per_round: u32| {
        REQUESTS_PER_ROUND.set(requests_per_round);
    });
}

#[export_name = "canister_query work_done"]
fn work_done() {
    let requests_sent = REQUESTS.with_borrow(|requests| requests.is_empty());
    let responses_sent =
        RESPONSES.with_borrow(|responses| responses.values().all(|vec| vec.is_empty()));
    let msg = candid::Encode!(&(requests_sent, responses_sent)).unwrap();
    api::reply(&msg[..]);
}

fn insert_sent_record(message_id: u32, record: Request) {
    RECORDS.with_borrow_mut(|records| {
        records.insert(
            message_id,
            Record {
                sent: record,
                received: None,
            },
        );
    })
}

fn set_received_record(message_id: u32, record: Response) {
    RECORDS.with_borrow_mut(|records| {
        records.get_mut(&message_id).unwrap().received = Some(record);
    });
}

/// Returns the canister records.
#[export_name = "canister_query records"]
fn records() {
    let records = RECORDS.with_borrow(|records| records.values().cloned().collect::<Vec<_>>());
    let msg = match candid::Encode!(&records) {
        Ok(msg) => msg,
        Err(_) => candid::Encode!(&"bad records".to_string()).unwrap(),
    };
    api::reply(&msg[..]);
}

/// Receives a payload, tracks stats, then sends a different payload back.
#[export_name = "canister_update handle_request"]
fn handle_request() {
    let caller: CanisterId = api::caller().try_into().unwrap();
    let msg = match next_response(&caller) {
        Some((num_bytes, num_instructions)) => {
            // Do some thinking.
            let counts = api::performance_counter(0) + num_instructions.get();
            while counts > api::performance_counter(0) {}

            candid::Encode!(&vec![0_u8; num_bytes.get() as usize]).unwrap()
        }
        None => candid::Encode!(&"out of response payloads".to_string()).unwrap(),
    };

    api::reply(&msg[..]);
}

/// Tries to send a request. Increments an error counter on failure.
fn try_send_request(
    payload_bytes: NumBytes,
    receiver: CanisterId,
) -> Result<(), (NumBytes, CanisterId)> {
    let message_id = next_message_id();
    let on_reply = move || {
        if let Ok(reply) = candid::Decode!(&api::arg_data()[..], Vec<u8>) {
            set_received_record(message_id, Response::Data((reply.len() as u64).into()));
        } else {
            set_received_record(message_id, Response::DecodeFailed);
        }
    };
    let on_reject = move || {
        set_received_record(message_id, Response::Rejected(api::reject_message()));
    };

    match candid::Encode!(&vec![0_u8; payload_bytes.get() as usize]) {
        Ok(msg) => match api::call_with_callbacks(
            api::CanisterId::try_from(receiver).unwrap(),
            "handle_request",
            &msg[..],
            on_reply,
            on_reject,
        ) {
            0 => {
                insert_sent_record(message_id, Request::Data((msg.len() as u64).into()));
                Ok(())
            }
            error_code => {
                insert_sent_record(message_id, Request::Rejected(error_code));
                Err((payload_bytes, receiver))
            }
        },
        Err(_) => {
            insert_sent_record(message_id, Request::EncodeFailed);
            Err((payload_bytes, receiver))
        }
    }
}

/// Attempts to send requests to other canisters. Stops once
/// - the maximum number of requests per round is reached.
/// - sending a request fails due to exhausted capacity.
#[export_name = "canister_heartbeat"]
fn heartbeat() {
    // Send requests until it fails for a systemic reason (queue full, out of memory).
    for _ in 0..REQUESTS_PER_ROUND.get() {
        if let Err((num_bytes, receiver)) = match RETRY.take() {
            Some((num_bytes, receiver)) => try_send_request(num_bytes, receiver),
            None => match next_request() {
                Some((num_bytes, receiver)) => try_send_request(num_bytes, receiver),
                None => Ok(()),
            },
        } {
            RETRY.set(Some((num_bytes, receiver)));
            return;
        }
    }
}
