//! This module contains a canister used for XNet integration test.
use candid::{CandidType, Principal};
use ic_cdk::api::{call::call_raw, id};
use ic_cdk_macros::query;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::min;
use std::str::FromStr;

const MB: usize = 1 << 20;
const MEMORY_SIZE: usize = 3800 * MB; // Cannot exceed 4 GiB
const MAX_VECTOR_SIZE: usize = 1 << 29; // 512 MiB
const PAGE_SIZE: usize = 4096;
/// Datastructure representing a call tree.
/// It's comprised of a canister_id representing where the canister originates
/// and a recurisve list of subtrees, which in turn are also of type CallTree.
#[derive(CandidType, Deserialize, Serialize, Clone)]
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
    /// Since each individual allocated object can only be up to 1 GiB of memory, we need
    /// multiple vectors to fill up the entire heap.
    static MEMORY: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

#[derive(CandidType, Serialize, Deserialize)]
struct Arguments {
    /// List of calltrees, each representing a call to another canister triggering running a call tree.
    calltrees: Vec<CallTree>,
    /// Enable debug mode. In which case the response is a list of all messages exchanged.
    debug: bool,
    /// Number of pages to be touched by each canister
    num_pages: usize,
}

#[derive(CandidType, Serialize, Deserialize)]
struct Message {
    sender: String,
    receiver: String,
}

/// Touch each page of the memory once
fn touch_memory(num_pages: usize) {
    MEMORY.with(|memory| {
        let mut middle_of_page: usize = PAGE_SIZE / 2;
        while (middle_of_page) < min(MEMORY_SIZE, PAGE_SIZE * num_pages) {
            // Find vector and offset within array to use.
            let vector_idx = middle_of_page / MAX_VECTOR_SIZE;
            let vector_offset: usize = middle_of_page % MAX_VECTOR_SIZE;

            let mut memory_ref = memory.borrow_mut();
            let memory = memory_ref[vector_idx].as_mut_slice();
            memory[vector_offset] += 1;

            middle_of_page += PAGE_SIZE
        }
    });
}

/// Initializes network topology and instructs this canister to start sending
/// requests to other canisters.
#[query(composite = true)]
async fn start(arguments: Arguments) -> Vec<Message> {
    let calltrees = arguments.calltrees;

    let mut messages = vec![];
    let this_cid = id().to_string();

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
        futures.push(call_raw(
            Principal::from_str(&entry.canister_id).unwrap(),
            "start",
            msg,
            0,
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
    let mut memory_size_left = MEMORY_SIZE;
    let mut memories: Vec<Vec<u8>> = vec![];
    while memory_size_left > 0 {
        let curr_memory_size = std::cmp::min(memory_size_left, MAX_VECTOR_SIZE);
        memories.push(vec![0; curr_memory_size]);
        memory_size_left -= curr_memory_size;
    }
    MEMORY.with(|s| s.replace(memories));
}
