use ic_types::{CanisterId, messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64};
use messaging_test::{Call, Message, Reply, Response, decode, encode};
use proptest::prelude::*;
use std::ops::RangeInclusive;

const MAX_PAYLOAD_SIZE: usize = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize;

/*
 * The proptest crate has dependencies that don't play nice with Wasm, therefore
 * proptest composers (and a few helper functions not used by the canister directly)
 * are defined here.
 */

/// Generates an arbitrary `Call` using reasonable default input ranges.
pub fn arb_call(receivers: Vec<CanisterId>) -> impl Strategy<Value = Call> {
    arb_call_with_config(
        receivers,
        0..=MAX_PAYLOAD_SIZE, // call_bytes_range
        0..=MAX_PAYLOAD_SIZE, // reply_bytes_range
        50,                   // best_effort_percentage
        1..=300,              // timeout_secs_range
        33,                   // make_calls_percentage
        50,                   // max_total_calls
        1..=3,                // calls_count_range
    )
}

/// Generates an arbitrary `Call` including downstream calls.
///
/// Starts with a list of `counts` and a correspondingly sized list of simple calls,
/// then recursively generates one call with nested downstream calls from them.
pub fn arb_call_with_config(
    receivers: Vec<CanisterId>,
    call_bytes_range: RangeInclusive<usize>,
    reply_bytes_range: RangeInclusive<usize>,
    best_effort_percentage: usize,
    timeout_secs_range: RangeInclusive<usize>,
    make_calls_percentage: usize,
    max_total_calls: usize,
    calls_count_range: RangeInclusive<usize>,
) -> impl Strategy<Value = Call> {
    proptest::collection::vec(
        arb_call_count(make_calls_percentage, calls_count_range.clone()),
        max_total_calls,
    )
    .prop_flat_map(move |counts| {
        let s: usize = counts.iter().sum();
        (
            proptest::collection::vec(
                arb_simple_call(
                    receivers.clone(),
                    call_bytes_range.clone(),
                    reply_bytes_range.clone(),
                    best_effort_percentage,
                    timeout_secs_range.clone(),
                ),
                s + 1, // + 1 to make sure there is at least one call we can return.
            ),
            Just(counts),
        )
    })
    .prop_map(|(mut simple_calls, mut counts)| {
        let mut call = simple_calls.pop().unwrap();
        to_nested_call(&mut call, &mut simple_calls, &mut counts);
        call
    })
}

/// Generates a count in `calls_count_range`, `make_calls_percentage` of the time, 0 otherwise.
fn arb_call_count(
    make_calls_percentage: usize,
    calls_count_range: RangeInclusive<usize>,
) -> impl Strategy<Value = usize> {
    (0..100_usize).prop_flat_map(move |p| {
        if p < make_calls_percentage {
            calls_count_range.clone()
        } else {
            0..=0_usize
        }
    })
}

prop_compose! {
    /// Generates an arbitrary `Call` without any downstream calls.
    fn arb_simple_call(
        receivers: Vec<CanisterId>,
        call_bytes_range: RangeInclusive<usize>,
        reply_bytes_range: RangeInclusive<usize>,
        best_effort_percentage: usize,
        timeout_secs_range: RangeInclusive<usize>,
    )(
        receiver in proptest::sample::select(receivers),
        call_bytes in call_bytes_range,
        reply_bytes in reply_bytes_range,
        best_effort_probe in 0..100_usize,
        timeout_secs in timeout_secs_range,
    ) -> Call {
        Call {
            receiver,
            call_bytes: call_bytes as u32,
            reply_bytes: reply_bytes as u32,
            timeout_secs: (best_effort_probe < best_effort_percentage).then_some(timeout_secs as u32),
            downstream_calls: Vec::new(),
        }
    }
}

/// Generates a `Call` from a number of simple calls (i.e. without downstream calls) using a vector of `counts`.
///
/// `counts` specifies how many downstream calls `call` should make. For a count > 0, count simple calls are popped
/// from the list and appended as downstream calls; then for each downstream call this function is called recursively.
///
/// Stops once all recursions have encountered a count of 0, or we run out of counts or simple calls.
fn to_nested_call(call: &mut Call, simple_calls: &mut Vec<Call>, counts: &mut Vec<usize>) {
    if let Some(downstream_calls_count) = counts.pop() {
        for _ in 0..downstream_calls_count {
            match simple_calls.pop() {
                Some(simple_call) => call.downstream_calls.push(simple_call),
                None => {
                    return;
                }
            }
        }
        for call in call.downstream_calls.iter_mut() {
            to_nested_call(call, simple_calls, counts)
        }
    }
}

/// Turns a `Call` into a receiver and an encoded payload ready to be enqueued in the ingress pool.
pub fn to_encoded_ingress(call: Call) -> (CanisterId, Vec<u8>) {
    let (payload, _) = encode(
        &Message {
            call_index: 0,
            reply_bytes: call.reply_bytes,
            downstream_calls: call.downstream_calls,
        },
        call.call_bytes as usize,
    );
    (call.receiver, payload)
}

/// Decodes a blob into a `Response`.
pub fn from_blob(blob: Vec<u8>) -> Response {
    let (reply, bytes_sent_on_reply, _) = decode::<Reply>(blob);
    Response::Success {
        bytes_received_on_call: reply.bytes_received_on_call,
        bytes_sent_on_reply,
        downstream_responses: reply.downstream_responses,
    }
}
