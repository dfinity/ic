//! This module contains a canister used for testing responses with variable payload size

use dfn_macro::query;
use serde::{Deserialize, Serialize};

/// All methods get this struct as an argument encoded in a JSON string.
///
/// # Fields
///
/// * `response_size_bytes` - size of the response payload in bytes.
#[derive(Serialize, Deserialize, Debug)]
struct Operation {
    response_size_bytes: usize,
}

#[query]
fn query(operation: Operation) -> Result<Vec<u8>, String> {
    Ok(vec![0; operation.response_size_bytes])
}

fn main() {}
