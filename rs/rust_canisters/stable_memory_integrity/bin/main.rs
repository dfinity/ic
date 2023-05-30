use ic_cdk::api::stable::{stable64_read, stable64_size};
use ic_cdk_macros::{query, update};

use ic_stable_memory_integrity::StableOperationResult;

#[update]
fn perform_and_check_ops(ops: Vec<StableOperationResult>) {
    for op in ops {
        op.perform_and_check()
    }
}

#[query]
fn final_size() -> u64 {
    stable64_size()
}

#[query]
fn read(start: u64, length: u64) -> Vec<u8> {
    let mut result = vec![0; length as usize];
    stable64_read(start, &mut result);
    result
}

fn main() {}
