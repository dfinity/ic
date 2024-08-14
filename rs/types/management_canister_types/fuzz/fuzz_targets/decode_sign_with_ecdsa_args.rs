#![no_main]
use ic_management_canister_types::Payload;
use ic_management_canister_types::SignWithECDSAArgs;
use libfuzzer_sys::fuzz_target;

// This fuzz test feeds binary data to Candid's `Decode!` macro for SignWithECDSAArgs with the goal of exposing panics
// e.g. caused by stack overflows during decoding.

fuzz_target!(|data: &[u8]| {
    let _ = SignWithECDSAArgs::decode(data);
});
