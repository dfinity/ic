use candid::CandidType;
use ic_cdk::{init, println, update};
use ic_nervous_system_long_message::break_message_if_over_instructions;
use serde::Deserialize;
use std::time::Duration;

#[init]
fn canister_init() {
    println!("long_message_canister init!");
}

#[derive(CandidType, Deserialize)]
struct BreakMessageParams {
    pub use_break: bool,
    pub message_threshold: u64,
    pub upper_bound: Option<u64>,
}

fn fib(n: u64) -> u64 {
    if n <= 1 {
        n
    } else {
        fib(n - 1) + fib(n - 2)
    }
}

#[update]
async fn test_next_message_if_over_instructions(params: BreakMessageParams) {
    // Just processing a message costs 30k instructions
    // each fib(17) costs about 80k instructions
    // so if we do that 10x, it's about 830k instructions.
    // The test setup for this canister allows for 500k instructions per message.

    let BreakMessageParams {
        use_break,
        message_threshold,
        upper_bound,
    } = params;

    // Doing anything costs about 30k instructions.
    for x in 0..10 {
        println!("Invocation number {}", x);
        println!(
            "Instruction_counter: {}",
            ic_cdk::api::instruction_counter()
        );
        // Fib(17) was benchmarked at about 80k instructions
        fib(17);
        if use_break {
            break_message_if_over_instructions(message_threshold, upper_bound).await;
        }
    }
}

#[update]
async fn test_2() {
    println!("Playground canister test_2 was called");
}

fn main() {}
