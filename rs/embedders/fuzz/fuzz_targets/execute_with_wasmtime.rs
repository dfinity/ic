#![no_main]
use ic_test_utilities::wasmtime_instance::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use libfuzzer_sys::{fuzz_target, Corpus};
mod ic_wasm;
use ic_wasm::ICWasmConfig;
use std::collections::BTreeSet;
use wasm_smith::ConfiguredModule;
mod transform;
use transform::transform_exports;

// The fuzzer creates valid wasms and tries to create a validate wasmtime instance.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// libfuzzer: bazel run --config=fuzzing //rs/embedders/fuzz:execute_with_wasmtime_libfuzzer -- corpus/
// afl:  bazel run --config=afl //rs/embedders/fuzz:execute_with_wasmtime_afl -- corpus/

fuzz_target!(|module: ConfiguredModule<ICWasmConfig>| -> Corpus {
    let wasm = module.module.to_bytes();
    let exports = module.module.exports();
    let wasm_methods: BTreeSet<WasmMethod> = transform_exports(exports);

    let instance_result = WasmtimeInstanceBuilder::new().with_wasm(wasm).try_build();
    let mut instance = match instance_result {
        Ok(instance) => instance,
        Err((_, _)) => return Corpus::Reject,
    };

    // return early if
    // 1. There are no exproted functions available to execute
    // 2. The total length of exports names is greater than 20_000

    if wasm_methods.is_empty() || module.module.export_length_total() > 20_000 {
        return Corpus::Reject;
    }

    // For determinism, all methods are executed
    for wasm_method in wasm_methods.iter() {
        let func_ref = FuncRef::Method(wasm_method.clone());
        let _ = instance.run(func_ref);
    }
    Corpus::Keep
});
