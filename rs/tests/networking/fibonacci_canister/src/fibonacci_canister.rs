use candid::CandidType;
use ic_cdk::update;
use serde::{Deserialize, Serialize};
use std::cell::Cell;

thread_local! {
    static SUM_OF_ROOTS: Cell<u64> = Cell::new(0);
}

#[update]
async fn calculate_roots(args: FibonacciArgs) -> u64 {
    fibonacci(args.0)
}

fn fibonacci(i: u64) -> u64 {
    if i == 0 {
        return 0;
    } else if i == 1 {
        return 1;
    }

    fibonacci(i - 1) + fibonacci(i - 2)
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FibonacciArgs(u64);

// Needed since we build this file both as a canister and as a lib for `FibonacciArgs`
#[allow(dead_code)]
fn main() {}
