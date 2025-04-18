use crate::ic_wasm::{ic_embedders_config, ICWasmModule};
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use libfuzzer_sys::Corpus;
use std::collections::BTreeSet;

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) -> Corpus {
    let wasm = module.module.to_bytes();
    let wasm_methods: BTreeSet<WasmMethod> = module.exported_functions;

    let config = ic_embedders_config(module.config.memory64_enabled);

    let instance_result = WasmtimeInstanceBuilder::new()
        .with_wasm(wasm)
        .with_config(config)
        .try_build();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn test_execute_with_wasmtime_single_run() {
        let arbitrary_str: &str = "this is a test string";
        let unstrucutred = Unstructured::new(arbitrary_str.as_bytes());
        let module = <crate::ic_wasm::ICWasmModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
            .expect("Unable to extract wasm from Unstructured data");
        run_fuzzer(module);
    }
}
