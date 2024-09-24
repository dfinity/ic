#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_fuzzers::ic_wasm::ICWasmModule;
use execution_fuzzers::system_api::run_fuzzer;

// This fuzz tries to execute system API call.
//
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing //rs/execution_environment/fuzz:execute_system_api_call

fuzz_target!(|module: ICWasmModule| {
    run_fuzzer(module);
});
