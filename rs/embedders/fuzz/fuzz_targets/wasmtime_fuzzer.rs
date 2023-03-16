#![no_main]
use ic_test_utilities::wasmtime_instance::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use libfuzzer_sys::fuzz_target;
use wasm_smith::Module;

// The fuzzer creates valid wasms and tries to create a validate wasmtime instance.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// TODO (PSEC-1169)
// Adapt wasm-smith to produce IC valid wasm
//
// To execute the fuzzer run
// bazel run --@rules_rust//rust/toolchain/channel=nightly --build_tag_filters=fuzz_test //rs/embedders/fuzz:wasmtime_fuzzer -- corpus/

fuzz_target!(|module: Module| {
    let wasm = module.to_bytes();

    let instance_result = WasmtimeInstanceBuilder::new().with_wasm(wasm).try_build();
    let mut instance = match instance_result {
        Ok(instance) => instance,
        Err(_) => return,
    };
    let _ = instance.run(FuncRef::Method(WasmMethod::Query("test".to_string())));
});
