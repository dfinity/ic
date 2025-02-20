#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::Corpus;
use wasm_fuzzers::ic_wasm::SystemApiModule;
use wasm_fuzzers::wasmtime::run_fuzzer;

fuzz_target!(|module: SystemApiModule| -> Corpus { run_fuzzer(module) });
