#![no_main]
use candid::types::value::IDLArgs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = match IDLArgs::from_bytes(data) {
        Ok(_v) => _v,
        Err(_e) => return,
    };
    let _ = decoded.get_types();
    let _ = decoded.to_bytes();
    let _ = decoded.to_string();
});
