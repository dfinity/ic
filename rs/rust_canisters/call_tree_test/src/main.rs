//! This module contains a canister used for XNet integration test.
use dfn_core::api;
use dfn_macro::query;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str::FromStr;

/// Datastructure representing a call tree.
/// It's comprised of a canister_id representing where the canister originates
/// and a recurisve list of subtrees, which in turn are also of type CallTree.
#[derive(Deserialize, Serialize, Clone)]
struct CallTree {
    canister_id: String,
    subtrees: Vec<CallTree>,
}

/// Metrics observed by this canister.
///
/// This message is used as reply payload for "metrics" query.
#[derive(Default, Deserialize, Debug)]
pub struct Metrics {
    /// Number of requests rejected by the remote subnet (e,g, due to a full
    /// canister input queue).
    pub reject_responses: usize,
}

thread_local! {
    /// Various metrics observed by this canister, e.g. message latency distribution.
    static METRICS: RefCell<Metrics> = RefCell::new(Default::default());
}

#[derive(Serialize, Deserialize)]
struct Arguments {
    /// List of calltrees, each representing a call to another canister triggering running a call tree.
    calltrees: Vec<CallTree>,
    /// Enable debug mode. In which case the response is a list of all messages exchanged.
    debug: bool,
}

#[derive(Serialize, Deserialize)]
struct Message {
    sender: String,
    receiver: String,
}

/// Initializes network topology and instructs this canister to start sending
/// requests to other canisters.
#[query]
async fn start(arguments: Arguments) -> Vec<Message> {
    let calltrees = arguments.calltrees;

    let mut messages = vec![];
    let this_cid = api::id().to_string();

    let mut futures = vec![];
    for entry in &calltrees {
        let msg = serde_json::to_vec(&Arguments {
            calltrees: entry.subtrees.clone(),
            debug: arguments.debug,
        })
        .unwrap();

        if arguments.debug {
            messages.push(Message {
                sender: this_cid.clone(),
                receiver: entry.canister_id.clone(),
            });
        }
        futures.push(api::call_bytes(
            api::CanisterId::from_str(&entry.canister_id).unwrap(),
            "start",
            &msg[..],
            api::Funds::zero(),
        ));
    }

    for f in futures::future::join_all(futures).await {
        match f {
            Err(_e) => METRICS.with(|m| m.borrow_mut().reject_responses += 1),
            Ok(response) => {
                if arguments.debug {
                    let mut returned_messages: Vec<Message> =
                        serde_json::from_slice(&response).unwrap();
                    messages.append(&mut returned_messages);
                }
            }
        }
    }

    messages
}

#[export_name = "canister_init"]
fn main() {}
