#![no_main]
use candid::{Decode, Encode};
use ic_ic00_types::ECDSAPublicKeyArgs;
use libfuzzer_sys::fuzz_target;

// This fuzz test feeds binary data to Candid's `Decode!` macro for ECDSAPublicKeyArgs with the goal of exposing panics
// e.g. caused by stack overflows during decoding.

fuzz_target!(|data: &[u8]| {
    let payload = data.to_vec();
    match Decode!(payload.as_slice(), ECDSAPublicKeyArgs) {
        Ok(ecdsa_public_key_args) => {
            let encoded = Encode!(&ecdsa_public_key_args).unwrap();
            assert_eq!(&encoded[..], data);
        }
        Err(_e) => (),
    };
});
