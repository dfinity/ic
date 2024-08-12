//! This module contains a canister used for testing responses with variable payload size
use candid::{CandidType, Deserialize};
use ic_cdk_macros::query;
use serde::Serialize;

/// All methods get this struct as an argument encoded in a JSON string.
///
/// # Fields
///
/// * `response_size_bytes` - size of the response payload in bytes.
#[derive(CandidType, Serialize, Deserialize, Debug)]
struct Operation {
    response_size_bytes: usize,
}

#[query]
fn query(operation: Operation) -> Result<String, String> {
    Ok("a".repeat(operation.response_size_bytes))
}

fn main() {}
