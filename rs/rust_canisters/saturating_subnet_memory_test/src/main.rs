use candid::{Decode, Encode};
use dfn_core::api;
use ic_base_types::CanisterId;
use saturating_subnet_memory_test::{Config, Metrics, RequestConfig};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

thread_local! {
    /// A queue of canister ID and a vector of payload sizes for requests.
    static REQUEST_CONFIGS: RefCell<VecDeque<RequestConfig>> = RefCell::default();
    /// A buffer for failed calls, such that the call can be attempted again.
    static RETRY: Cell<Option<(CanisterId, u32)>> = Cell::default();
    /// A queue of payload sizes for responses.
    static RESPONSE_PAYLOADS: RefCell<VecDeque<u32>> = RefCell::default();
    /// The number of requests we try to send per round.
    static REQUESTS_PER_ROUND: Cell<u32> = Cell::default();
    /// Sending/Receiving stats.
    static METRICS: RefCell<Metrics> = RefCell::default();
}

/// Extracts the next canister ID and payload size from the queue. Each time a payload size and
/// canister ID is returned, the queue is rotated to the left by 1; the total number of payload
/// sizes shrinks by 1 each time until the queue is empty.
fn next_request() -> Option<(CanisterId, u32)> {
    REQUEST_CONFIGS.with_borrow_mut(|configs| {
        while let Some(mut config) = configs.pop_front() {
            if let Some(num_bytes) = config.payload_bytes.pop() {
                let receiver = config.receiver;
                configs.push_back(config);
                return Some((receiver, num_bytes));
            }
        }
        None
    })
}

/// Extracts the next payload size for the next response from the queue. Each time a payload size
/// is returned, the queue is rotated the left by 1. Since we always have to be able to send a
/// response, the queue never shrinks and just rotates forever.
fn next_response() -> u32 {
    RESPONSE_PAYLOADS.with_borrow_mut(|payloads| match payloads.pop_front() {
        Some(payload) => {
            payloads.push_back(payload);
            payload
        }
        None => 0,
    })
}

#[export_name = "canister_init"]
fn main() {}

/// Sets the request and response payload sizes. Returns a message including basic stats of the
/// request payloads sent to the canister.
#[export_name = "canister_update start"]
fn start() {
    let config = Decode!(&api::arg_data()[..], Config).expect("failed to decode request");

    let mut num_requests_total = 0_u32;
    let mut num_bytes_total = 0_u32;
    for cfg in config.request_configs.iter() {
        num_requests_total += cfg.payload_bytes.len() as u32;
        num_bytes_total += cfg.payload_bytes.iter().sum::<u32>();
    }
    let msg = Encode!(&format!(
        "Sending {} bytes in {} requests, {} requests per round",
        num_bytes_total, num_requests_total, config.requests_per_round,
    ))
    .unwrap();

    REQUESTS_PER_ROUND.set(config.requests_per_round);
    REQUEST_CONFIGS.set(config.request_configs.into());
    RESPONSE_PAYLOADS.set(config.response_bytes.into());

    api::reply(&msg[..]);
}

/// Returns stats tracked by the canister.
#[export_name = "canister_query metrics"]
fn metrics() {
    let msg = METRICS.with_borrow(|metrics| Encode!(metrics).unwrap());
    api::reply(&msg[..]);
}

/// Receives a payload, tracks stats, then sends a different payload back.
#[export_name = "canister_update rebound"]
fn rebound() {
    let request_payload = Decode!(&api::arg_data()[..], Vec<u8>).expect("failed to decode request");
    let response_payload = vec![0_u8; next_response() as usize];

    METRICS.with_borrow_mut(|metrics| {
        // Record the received request.
        metrics.received_request_count += 1;
        metrics.request_bytes_received += request_payload.len() as u32;
        // Record the sent response.
        metrics.sent_response_count += 1;
        metrics.response_bytes_sent += response_payload.len() as u32;
    });

    let msg = Encode!(&response_payload).expect("failed to encode response");
    api::reply(&msg[..]);
}

/// Callback for handling replies from "rebound".
fn on_reply(_env: *mut ()) {
    let reply = candid::Decode!(&api::arg_data()[..], Vec<u8>).expect("failed to decode response");

    METRICS.with_borrow_mut(|metrics| {
        metrics.received_response_count += 1;
        metrics.response_bytes_received += reply.len() as u32;
    });
}

/// Callback for handling reject responses from "rebound".
fn on_reject(_env: *mut ()) {
    METRICS.with_borrow_mut(|metrics| {
        metrics.send_request_success_count += 1;
    });
}

/// Tries to send a request. Increments an error counter on failure.
fn send_request(receiver: CanisterId, bytes: u32) -> Result<(), (CanisterId, u32)> {
    let msg = Encode!(&vec![0_u8; bytes as usize]).expect("failed to encode payload");
    let error_code = api::call_raw(
        api::CanisterId::try_from(receiver).unwrap(),
        "rebound",
        &msg[..],
        on_reply,
        on_reject,
        None,
        std::ptr::null_mut(),
        api::Funds::zero(),
    );

    match error_code {
        0 => Ok(()),
        _ => {
            METRICS.with_borrow_mut(|metrics| {
                metrics.send_request_error_count += 1;
            });
            Err((receiver, bytes))
        }
    }
}

/// Attempts to send requests to other canisters. Stops once
/// - the maximum number of requests per round is reached.
/// - sending a request fails due to exhausted capacity.
#[export_name = "canister_heartbeat"]
fn heartbeat() {
    // Tries to send a request using `RETRY` first, otherwise using the next config for a
    // request.
    fn try_send_request() -> Result<(), (CanisterId, u32)> {
        match RETRY.take() {
            Some((receiver, bytes)) => send_request(receiver, bytes),
            None => match next_request() {
                Some((receiver, bytes)) => send_request(receiver, bytes),
                None => Ok(()),
            },
        }
    }

    // Send requests until it fails for a systemic reason (queue full, out of memory).
    for _ in 0..REQUESTS_PER_ROUND.get() {
        if let Err((receiver, bytes)) = try_send_request() {
            RETRY.set(Some((receiver, bytes)));
            return;
        }
    }
}
