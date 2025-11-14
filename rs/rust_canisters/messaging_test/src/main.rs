use candid::Principal;
use messaging_test::{CallMessage, Reply, ReplyMessage, decode, encode};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

thread_local! {
    /// An index for each attempted call; starts at 0 and then increments with each call.
    static CALL_INDEX: Cell<u32> = Cell::default();
    /// A map of incoming call indices; this is updated with each call received for each
    /// originator; used to detect sequence errors.
    static INCOMING_CALL_INDICES: RefCell<BTreeMap<Principal, u32>> = RefCell::default();
}

/// No-op encoder used to prevent encoding with candid by default
/// (The canister manually encodes the reply with a target byte size).
fn no_op(bytes: Vec<u8>) -> Vec<u8> {
    bytes
}

/// Handles a `Call`; performing the downstream calls therein; and returning a
/// `ReplyMessage` summarizing the outcome of the call and all the downstream
/// calls (success / synchronous failure / asynchronous failure).
///
/// An increasing index is assigned to each call; and sequence errors are
/// detected by checking against out-of-order call indices from a given caller.
#[ic_cdk::update(decode_with = "decode", encode_with = "no_op")]
async fn handle_call((msg, bytes_received_on_call, _): (CallMessage, u32, u32)) -> Vec<u8> {
    // Canister principals have an (undocumented) tag byte of 1. This is good enough
    // for test code.
    const CANISTER_TAG: u8 = 1;

    // Check for sequence errors if this is an inter canister call.
    let caller = ic_cdk::api::msg_caller();
    if caller.as_slice().last() == Some(&CANISTER_TAG) {
        INCOMING_CALL_INDICES.with_borrow_mut(|incoming_call_indices| {
            let last_observed_call_index = incoming_call_indices.entry(caller).or_default();
            if *last_observed_call_index > 0 {
                assert!(
                    *last_observed_call_index < msg.call_index,
                    "sequence error from caller: {}",
                    caller
                );
            }
            *last_observed_call_index = msg.call_index;
        });
    }

    // Clone the calls for pairing them with the responses further down.
    let calls = msg.downstream_calls.clone();

    // Generate futures for all downstream calls.
    let futures = msg.downstream_calls.into_iter().map(|call| {
        let (payload, _) = encode(
            &CallMessage {
                call_index: CALL_INDEX.replace(CALL_INDEX.get() + 1),
                reply_bytes: call.reply_bytes,
                downstream_calls: call.downstream_calls,
            },
            call.call_bytes as usize,
        );
        match call.timeout_secs {
            Some(timeout_secs) => ic_cdk::call::Call::bounded_wait(call.receiver, "handle_call")
                .change_timeout(timeout_secs),
            None => ic_cdk::call::Call::unbounded_wait(call.receiver, "handle_call"),
        }
        .with_cycles(call.cycles)
        .take_raw_args(payload)
        .into_future()
    });

    // Perform and await the downstream calls; collect the responses.
    let downstream_replies = (futures::future::join_all(futures).await)
        .into_iter()
        .zip(calls.into_iter())
        .map(|(reply, call)| match reply {
            Ok(reply) => {
                let (reply, bytes_sent_on_reply, _) = decode::<ReplyMessage>(reply.into_bytes());
                Reply::Success {
                    respondent: call.receiver,
                    bytes_received_on_call: reply.bytes_received_on_call,
                    bytes_sent_on_reply,
                    downstream_replies: reply.downstream_replies,
                }
            }
            Err(ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)) => {
                unreachable!("not doing anything with cycles for now");
            }
            Err(ic_cdk::call::CallFailed::CallPerformFailed(_)) => Reply::SyncReject { call },
            Err(ic_cdk::call::CallFailed::CallRejected(rejection)) => Reply::AsyncReject {
                call,
                reject_code: rejection.raw_reject_code(),
                reject_message: rejection.reject_message().to_string(),
            },
        })
        .collect();

    // Collect the respondents together with the responses; encode them.
    let (payload, _) = encode(
        &ReplyMessage {
            bytes_received_on_call,
            downstream_replies,
        },
        msg.reply_bytes as usize,
    );
    payload
}

fn main() {}
