#![no_main]
use candid::{Decode, Encode};
use ic_ic00_types::InstallCodeArgs;
use libfuzzer_sys::fuzz_target;

// This fuzz test feeds binary data to Candid's `Decode!` macro for InstallCodeArgs with the goal of exposing panics
// e.g. caused by stack overflows during decoding.

fuzz_target!(|data: &[u8]| {
    let payload = data.to_vec();
    match Decode!(payload.as_slice(), InstallCodeArgs) {
        Ok(install_code_args) => {
            let encoded = Encode!(&install_code_args).unwrap();
            assert_eq!(&encoded[..], data);
        }
        Err(_e) => (),
    };
});
