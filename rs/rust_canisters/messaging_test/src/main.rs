use ic_base_types::{CanisterId, PrincipalId};
use messaging_test::{Message, Reply, Response, decode, encode};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

thread_local! {
    /// An index for each attempted call; starts at 0 and then increments with each call.
    static CALL_INDEX: Cell<u32> = Cell::default();
    /// A map of incoming call indices; this is updated with each call received for each
    /// originator; used to detect sequence errors.
    static INCOMING_CALL_INDICES: RefCell<BTreeMap<CanisterId, u32>> = RefCell::default();
}

/// No-op encoder used to prevent encoding with candid by default
/// (The canister manually encodes the reply with a target byte size).
fn no_op(bytes: Vec<u8>) -> Vec<u8> {
    bytes
}

#[ic_cdk::update(decode_with = "decode", encode_with = "no_op")]
async fn pulse((msg, bytes_received, _): (Message, u32, u32)) -> Vec<u8> {
    // Check for sequence errors if this is an inter canister call.
    if let Ok(caller) = CanisterId::try_from_principal_id(PrincipalId(ic_cdk::api::msg_caller())) {
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

    // Keep the receivers to collect the responses after making all the calls.
    let respondents = msg
        .downstream_calls
        .iter()
        .map(|call| call.receiver)
        .collect::<Vec<_>>();

    // Generate futures for all downstream calls.
    let futures = msg.downstream_calls.into_iter().map(|call| {
        let (payload, _) = encode(
            &Message {
                call_index: CALL_INDEX.replace(CALL_INDEX.get() + 1),
                reply_bytes: call.reply_bytes,
                downstream_calls: call.downstream_calls,
            },
            call.call_bytes as usize,
        );
        match call.timeout_secs {
            Some(timeout_secs) => ic_cdk::call::Call::bounded_wait(call.receiver.into(), "pulse")
                .change_timeout(timeout_secs),
            None => ic_cdk::call::Call::unbounded_wait(call.receiver.into(), "pulse"),
        }
        .take_raw_args(payload)
        .into_future()
    });

    // Perform and await the downstream calls.
    let results = (futures::future::join_all(futures).await)
        .into_iter()
        .map(|reply| match reply {
            Ok(reply) => {
                let (reply, bytes_sent_on_reply, _) = decode::<Reply>(reply.into_bytes());
                Response::Success {
                    bytes_received_on_call: bytes_received,
                    bytes_sent_on_reply,
                    downstream_responses: reply.downstream_responses,
                }
            }
            Err(ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)) => {
                unreachable!("not doing anything with cycles for now");
            }
            Err(ic_cdk::call::CallFailed::CallPerformFailed(_)) => Response::SyncReject,
            Err(ic_cdk::call::CallFailed::CallRejected(rejection)) => Response::AsyncReject {
                reject_code: rejection.raw_reject_code(),
                reject_message: rejection.reject_message().to_string(),
            },
        });

    // Collect the respondents together with the responses; encode them.
    let (payload, _) = encode(
        &Reply {
            bytes_received_on_call: bytes_received,
            downstream_responses: respondents.into_iter().zip(results).collect::<Vec<_>>(),
        },
        msg.reply_bytes as usize,
    );
    payload
}

fn main() {}
