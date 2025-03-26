#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::compile::run_fuzzer;

fuzz_target!(|module: &[u8]| {
    run_fuzzer(module);
});
