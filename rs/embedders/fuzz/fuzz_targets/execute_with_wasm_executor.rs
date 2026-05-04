#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::ic_wasm::ICWasmModule;
use wasm_fuzzers::wasm_executor::run_fuzzer;

fuzz_target!(|module: ICWasmModule| {
    run_fuzzer(module);
});
