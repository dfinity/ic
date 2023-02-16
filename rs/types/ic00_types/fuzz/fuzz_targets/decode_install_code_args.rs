#![no_main]
use candid::Decode;
use ic_ic00_types::InstallCodeArgs;
use libfuzzer_sys::fuzz_target;

// This fuzz test feeds binary data to Candid's `Decode!` macro with the goal of exposing panics
// e.g. caused by stack overflows during decoding.
//
// The fuzz test is only compiled but not executed by CI. The test must be built e.g. using cargo
// fuzz (https://rust-fuzz.github.io/book/introduction.html) and then be executed e.g. on the
// ClusterFuzz platform.
fuzz_target!(|data: &[u8]| {
    let payload = data.to_vec();
    let _decoded = match Decode!(payload.as_slice(), InstallCodeArgs) {
        Ok(_v) => _v,
        Err(_e) => return,
    };
});
