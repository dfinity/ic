#![no_main]
use ic_test_utilities::wasmtime_instance::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use libfuzzer_sys::{fuzz_target, Corpus};
mod ic_wasm;
use ic_wasm::ICWasmConfig;
use wasm_smith::ConfiguredModule;

// The fuzzer creates valid wasms and tries to create a validate wasmtime instance.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing //rs/embedders/fuzz:execute_with_wasmtime -- corpus/

fuzz_target!(|module: ConfiguredModule<ICWasmConfig>| -> Corpus {
    let wasm = module.module.to_bytes();

    let instance_result = WasmtimeInstanceBuilder::new().with_wasm(wasm).try_build();
    let mut instance = match instance_result {
        Ok(instance) => instance,
        Err((_, _)) => return Corpus::Reject,
    };
    let _ = instance.run(FuncRef::Method(WasmMethod::Query("test".to_string())));
    Corpus::Keep
});
