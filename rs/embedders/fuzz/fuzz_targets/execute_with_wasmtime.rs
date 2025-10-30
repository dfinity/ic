#![no_main]
use libfuzzer_sys::Corpus;
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::ic_wasm::ICWasmModule;
use wasm_fuzzers::wasmtime::run_fuzzer;

fuzz_target!(|module: ICWasmModule| -> Corpus { run_fuzzer(module) });
