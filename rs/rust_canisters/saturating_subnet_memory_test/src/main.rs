use candid::{Decode, Encode};
use dfn_core::api;
use saturating_subnet_memory_test::{
    Config, Metrics, RequestConfig, RequestStats, Response, ResponseConfig,
};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::time::Duration;

thread_local! {
    /// A queue of canister ID and a vector of payload sizes for requests.
    static REQUEST_CONFIGS: RefCell<Vec<RequestConfig>> = RefCell::default();
    /// A buffer for failed calls, such that the call can be attempted again.
    static RETRY: Cell<Option<RequestConfig>> = Cell::default();
    /// A queue of payload sizes and delay for responses.
    static RESPONSE_CONFIGS: RefCell<VecDeque<ResponseConfig>> = RefCell::default();
    /// The number of requests we try to send per round.
    static REQUESTS_PER_ROUND: Cell<u32> = Cell::default();
    /// Sending/Receiving stats.
    static METRICS: RefCell<Metrics> = RefCell::default();
}

/// Extracts the next canister ID and payload size from the stack of request configs.
fn next_request() -> Option<RequestConfig> {
    REQUEST_CONFIGS.with_borrow_mut(|configs| configs.pop())
}

/// Extracts the next config for the next response from the queue. Each time a config is returned,
/// the queue is rotated to the left by 1. Since we always have to be able to send a response,
/// the queue never shrinks and just rotates forever.
fn next_response() -> ResponseConfig {
    RESPONSE_CONFIGS.with_borrow_mut(|configs| match configs.pop_front() {
        Some(config) => {
            configs.push_back(config);
            config
        }
        None => ResponseConfig::default(),
    })
}

#[export_name = "canister_init"]
fn main() {}

/// Sets the request and response payload sizes. Returns a message including basic stats of the
/// request payloads sent to the canister.
#[export_name = "canister_update start"]
fn start() {
    let test_config = Decode!(&api::arg_data()[..], Config).expect("failed to decode");
    let msg = Encode!(&format!(
        "Sending {} bytes in {} requests, {} request(s) per round",
        test_config
            .request_configs
            .iter()
            .map(|config| config.payload_bytes)
            .sum::<u32>(),
        test_config.request_configs.len(),
        test_config.requests_per_round,
    ))
    .unwrap();

    REQUESTS_PER_ROUND.set(test_config.requests_per_round);
    REQUEST_CONFIGS.set(test_config.request_configs);
    RESPONSE_CONFIGS.set(test_config.response_configs.into());

    api::reply(&msg[..]);
}

/// Returns stats tracked by the canister.
#[export_name = "canister_query metrics"]
fn metrics() {
    let msg = METRICS.with_borrow(|metrics| Encode!(metrics).unwrap());
    api::reply(&msg[..]);
}

/// Receives a payload, tracks stats, then sends a different payload back.
#[export_name = "canister_update handle_request"]
fn handle_request() {
    let config = next_response();

    // Do some thinking.
    let counts = api::performance_counter(0) + config.instructions_count;
    while counts > api::performance_counter(0) {}

    let response_payload = vec![0_u8; config.payload_bytes as usize];
    let msg = Encode!(&response_payload).expect("failed to encode response");
    api::reply(&msg[..]);
}

/// Tries to send a request. Increments an error counter on failure.
fn try_send_request(config: RequestConfig) -> Result<(), RequestConfig> {
    let msg = candid::Encode!(&vec![0_u8; config.payload_bytes as usize])
        .expect("failed to encode payload");

    // Record request stats including response payload bytes count on reply.
    let on_reply = move || {
        if let Ok(reply) = candid::Decode!(&api::arg_data()[..], Vec<u8>) {
            METRICS.with_borrow_mut(|metrics| {
                metrics.sent_requests_stats.push(RequestStats {
                    receiver: config.receiver,
                    payload_bytes_sent: config.payload_bytes,
                    response: Response::PayloadBytes(reply.len() as u32),
                });
            });
        } else {
            METRICS.with_borrow_mut(|metrics| {
                metrics.decode_error_count += 1;
            });
        }
    };

    // Record request stats including the reject message on reject.
    let on_reject = move || {
        let reject_msg = api::reject_message();
        METRICS.with_borrow_mut(|metrics| {
            metrics.sent_requests_stats.push(RequestStats {
                receiver: config.receiver,
                payload_bytes_sent: config.payload_bytes,
                response: Response::Rejected(reject_msg),
            });
        });
    };

    let error_code = api::call_with_callbacks(
        api::CanisterId::try_from(config.receiver).unwrap(),
        "handle_request",
        &msg[..],
        on_reply,
        on_reject,
    );

    match error_code {
        0 => {
            METRICS.with_borrow_mut(|metrics| {
                metrics.send_request_success_count += 1;
            });
            Ok(())
        }
        _ => {
            METRICS.with_borrow_mut(|metrics| {
                metrics.send_request_error_count += 1;
            });
            Err(config)
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
        if let Err(config) = match RETRY.take() {
            Some(config) => try_send_request(config),
            None => match next_request() {
                Some(config) => try_send_request(config),
                None => Ok(()),
            },
        } {
            RETRY.set(Some(config));
            return;
        }
    }
}
