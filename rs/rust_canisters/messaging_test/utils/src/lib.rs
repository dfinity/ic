use ic_types::{
    CanisterId,
    messages::{EXPECTED_MESSAGE_ID_LENGTH, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64},
};
use messaging_test::{Call, CallMessage, Reply, ReplyMessage, decode, encode};
use proptest::prelude::*;
use std::ops::RangeInclusive;

const MAX_PAYLOAD_SIZE: usize = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize;

/*
 * The proptest crate has dependencies that don't play nice with Wasm, therefore
 * proptest composers (and a few helper functions not used by the canister directly)
 * are defined here.
 */

/// Parameters for generating arbitrary `Calls`.
#[derive(Clone, Debug)]
pub struct CallConfig {
    pub receivers: Vec<CanisterId>,
    pub call_bytes_range: RangeInclusive<usize>,
    pub reply_bytes_range: RangeInclusive<usize>,
    pub best_effort_percentage: usize,
    pub timeout_secs_range: RangeInclusive<usize>,
    pub downstream_calls_percentage: usize,
    pub downstream_calls_count_range: RangeInclusive<usize>,
    pub call_tree_size: usize,
}

impl Default for CallConfig {
    fn default() -> Self {
        Self {
            receivers: Vec::new(),
            call_bytes_range: 0..=MAX_PAYLOAD_SIZE,
            reply_bytes_range: 0..=MAX_PAYLOAD_SIZE,
            best_effort_percentage: 50,
            timeout_secs_range: 1..=300,
            downstream_calls_percentage: 33,
            downstream_calls_count_range: 1..=3,
            call_tree_size: 10,
        }
    }
}

/// Generates an arbitrary `Call` including downstream calls.
///
/// Starts with a list of `counts` and a correspondingly sized list of simple calls,
/// then recursively generates one call with nested downstream calls from that.
///
/// `receiver` is used such that an arbitrary `Call` can be generated aimed at a specific
/// canister, `config.receivers` is then used for downstream calls.
///
/// This is useful because the call is sent to `receiver` as a trigger via an ingress message
/// to then make downstream calls to other canisters.
pub fn arb_call(receiver: CanisterId, config: CallConfig) -> impl Strategy<Value = Call> {
    proptest::collection::vec(
        arb_call_count(
            config.downstream_calls_percentage,
            config.downstream_calls_count_range.clone(),
        ),
        config.call_tree_size,
    )
    .prop_flat_map(move |counts| {
        (
            arb_simple_call(CallConfig {
                receivers: vec![receiver],
                ..config.clone()
            }),
            proptest::collection::vec(arb_simple_call(config.clone()), config.call_tree_size),
            Just(counts),
        )
    })
    .prop_map(|(mut call, mut simple_calls, mut counts)| {
        to_nested_call(&mut call, &mut simple_calls, &mut counts);
        call
    })
}

/// Generates a count in `calls_count_range`, `make_calls_percentage` of the time, 0 otherwise.
fn arb_call_count(
    make_calls_percentage: usize,
    calls_count_range: RangeInclusive<usize>,
) -> impl Strategy<Value = usize> {
    (0..=100_usize).prop_flat_map(move |p| {
        if p <= make_calls_percentage {
            calls_count_range.clone()
        } else {
            0..=0_usize
        }
    })
}

/// Generates an arbitrary `Call` without any downstream calls.
fn arb_simple_call(config: CallConfig) -> impl Strategy<Value = Call> {
    (
        proptest::sample::select(config.receivers),
        config.call_bytes_range,
        config.reply_bytes_range,
        0..=u64::MAX,
        0..100_usize,
        config.timeout_secs_range,
    )
        .prop_map(
            move |(receiver, call_bytes, reply_bytes, cycles, best_effort_probe, timeout_secs)| {
                Call {
                    receiver: receiver.into(),
                    call_bytes: call_bytes as u32,
                    reply_bytes: reply_bytes as u32,
                    cycles: cycles as u128,
                    timeout_secs: (best_effort_probe < config.best_effort_percentage)
                        .then_some(timeout_secs as u32),
                    downstream_calls: Vec::new(),
                }
            },
        )
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
        &CallMessage {
            call_index: 0,
            reply_bytes: call.reply_bytes,
            downstream_calls: call.downstream_calls,
        },
        // Ingress message size is payload size + message ID length. Avoid exceeding
        // the limit.
        (call.call_bytes as usize)
            .min(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize - EXPECTED_MESSAGE_ID_LENGTH),
    );
    (into_canister_id(call.receiver), payload)
}

/// Decodes a blob into a `Response`.
pub fn from_blob(respondent: CanisterId, blob: Vec<u8>) -> Reply {
    let (reply, bytes_sent_on_reply, _) = decode::<ReplyMessage>(blob);
    Reply::Success {
        respondent: respondent.into(),
        bytes_received_on_call: reply.bytes_received_on_call,
        bytes_sent_on_reply,
        downstream_replies: reply.downstream_replies,
    }
}

/// Wraps the given principal within a `CanisterId`.
pub fn into_canister_id(principal: candid::Principal) -> CanisterId {
    CanisterId::unchecked_from_principal(principal.into())
}
