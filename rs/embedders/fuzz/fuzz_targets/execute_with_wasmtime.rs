#![no_main]
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use libfuzzer_sys::{fuzz_target, Corpus};
mod ic_wasm;
use ic_wasm::ICWasmModule;
use std::collections::BTreeSet;

// The fuzzer creates valid wasms and tries to create a validate wasmtime instance.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// libfuzzer: bazel run --config=fuzzing //rs/embedders/fuzz:execute_with_wasmtime_libfuzzer -- corpus/
// afl:  bazel run --config=afl //rs/embedders/fuzz:execute_with_wasmtime_afl -- corpus/

fuzz_target!(|module: ICWasmModule| -> Corpus {
    let wasm = module.module.to_bytes();
    let wasm_methods: BTreeSet<WasmMethod> = module.exported_functions;

    let instance_result = WasmtimeInstanceBuilder::new().with_wasm(wasm).try_build();
    let mut instance = match instance_result {
        Ok(instance) => instance,
        Err((_, _)) => {
            return Corpus::Reject;
        }
    };

    if wasm_methods.is_empty() {
        return Corpus::Reject;
    }

    // For determinism, all methods are executed
    for wasm_method in wasm_methods.iter() {
        let func_ref = FuncRef::Method(wasm_method.clone());
        let _ = instance.run(func_ref);
    }
    Corpus::Keep
});
