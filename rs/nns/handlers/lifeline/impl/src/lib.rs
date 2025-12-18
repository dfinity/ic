//! Exposes the lifeline canister wasm as a constant.
//! This crate is NOT part of the lifeline canister itself: it only exposes it
//! into rust.

pub const LIFELINE_CANISTER_WASM: &[u8] = include_bytes!(env!("LIFELINE_CANISTER_WASM_PATH"));

#[cfg(test)]
mod tests;
