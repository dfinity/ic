#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::differential::run_fuzzer;
use wasm_fuzzers::ic_wasm::ICWasmModule;

fuzz_target!(|module: ICWasmModule| {
    run_fuzzer(module);
});
