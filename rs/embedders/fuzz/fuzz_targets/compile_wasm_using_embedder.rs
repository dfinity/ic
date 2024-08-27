#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::compile::run_fuzzer;
use wasm_fuzzers::compile::MaybeInvalidModule;

fuzz_target!(|module: MaybeInvalidModule| {
    run_fuzzer(module);
});
