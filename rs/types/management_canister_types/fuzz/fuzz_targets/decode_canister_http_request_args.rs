#![no_main]
use ic_management_canister_types::CanisterHttpRequestArgs;
use ic_management_canister_types::Payload;
use libfuzzer_sys::fuzz_target;

// This fuzz test feeds binary data to Candid's `Decode!` macro for CanisterHttpRequestArgs with the goal of exposing panics
// e.g. caused by stack overflows during decoding.

fuzz_target!(|data: &[u8]| {
    let _ = CanisterHttpRequestArgs::decode(data);
});
