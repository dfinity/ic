//! This module contains a canister used for XNet integration test.
use dfn_core::api;
use dfn_macro::query;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::min;
use std::mem;
use std::str::FromStr;

const ELEMENT_SIZE: usize = mem::size_of::<u64>();
const MEMORY_SIZE: usize = 1 << 30; // 1GiB, can't exceed 4GB.
const MEMORY_LEN: usize = MEMORY_SIZE / ELEMENT_SIZE;
const PAGE_SIZE: usize = 4096;
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

    /// Pages accessed by read/write methods.
    static MEMORY: RefCell<Vec<u64>> = RefCell::new(vec![]);
}

#[derive(Serialize, Deserialize)]
struct Arguments {
    /// List of calltrees, each representing a call to another canister triggering running a call tree.
    calltrees: Vec<CallTree>,
    /// Enable debug mode. In which case the response is a list of all messages exchanged.
    debug: bool,
    /// Number of pages to be touched by each canister
    num_pages: usize,
}

#[derive(Serialize, Deserialize)]
struct Message {
    sender: String,
    receiver: String,
}

/// Touch each page of the memory once
fn touch_memory(num_pages: usize) {
    let mut middle_of_page = PAGE_SIZE / ELEMENT_SIZE / 2;
    MEMORY.with(|memory| {
        let mut memory_ref = memory.borrow_mut();
        let memory = memory_ref.as_mut_slice();
        while (middle_of_page) < min(memory.len(), num_pages) {
            memory[middle_of_page] += 1;
            middle_of_page += PAGE_SIZE
        }
    });
}

/// Initializes network topology and instructs this canister to start sending
/// requests to other canisters.
#[query]
async fn start(arguments: Arguments) -> Vec<Message> {
    let calltrees = arguments.calltrees;

    let mut messages = vec![];
    let this_cid = api::id().to_string();

    touch_memory(arguments.num_pages);

    let mut futures = vec![];
    for entry in &calltrees {
        let msg = serde_json::to_vec(&Arguments {
            calltrees: entry.subtrees.clone(),
            debug: arguments.debug,
            num_pages: arguments.num_pages,
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
fn main() {
    let mut memory = vec![0; MEMORY_LEN];
    // Ensure that all pages are different.
    let mut middle_of_page = PAGE_SIZE / ELEMENT_SIZE / 2;
    while (middle_of_page) < memory.len() {
        memory[middle_of_page] = middle_of_page as u64;
        middle_of_page += PAGE_SIZE
    }
    MEMORY.with(|s| s.replace(memory));
    api::print(format!(
        "Successfully initialized canister with {} bytes",
        MEMORY_SIZE,
    ));
}
