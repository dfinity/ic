#![no_main]
use candid::DecoderConfig;
use candid::types::value::IDLArgs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut config = DecoderConfig::new();
    config.set_decoding_quota(2_000_000_000); // already scaled by 50x due to untyped

    let decoded = match IDLArgs::from_bytes_with_config(data, &config) {
        Ok(_v) => _v,
        Err(_e) => return,
    };

    let _ = decoded.get_types();
    let _ = decoded.to_bytes();
    let _ = decoded.to_string();
});
