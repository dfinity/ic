use crate::ic_wasm::ICWasmModule;
use ic_embedders::InstanceRunResult;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_interfaces::execution_environment::SystemApi;
use ic_replicated_state::Global;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::ingress::WasmResult;
use ic_types::methods::{FuncRef, WasmMethod};
use std::collections::BTreeSet;
use tokio::runtime::Runtime;

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) {
    let wasm = module.module.to_bytes();
    let wasm_methods: BTreeSet<WasmMethod> = module.exported_functions;

    if wasm_methods.is_empty() {
        return;
    }

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .max_blocking_threads(1)
        // thread stack overflows before wasmtime (2MiB vs 5MiB)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));

    let first_execution = rt.spawn({
        let wasm = wasm.clone();
        let wasm_methods = wasm_methods.clone();

        async move { execute_wasm(wasm, wasm_methods) }
    });

    let second_execution = rt.spawn(async move { execute_wasm(wasm, wasm_methods) });

    rt.block_on(async move {
        let first = first_execution.await.unwrap();
        let second = second_execution.await.unwrap();

        // same size
        assert_eq!(first.len(), second.len());

        for (x, y) in std::iter::zip(first, second) {
            // execution result must be same
            assert_eq!(x.0, y.0);

            // instructions used must be same
            assert_eq!(x.2, y.2);

            match (x.1, y.1) {
                (Ok(run_x), Ok(run_y)) => {
                    assert_eq!(run_x.wasm_dirty_pages, run_y.wasm_dirty_pages);
                    assert_eq!(
                        run_x.stable_memory_dirty_pages,
                        run_y.stable_memory_dirty_pages
                    );

                    // special treatment because of NaN
                    let globals_x = run_x.exported_globals;
                    let globals_y = run_y.exported_globals;
                    for (g_x, g_y) in std::iter::zip(globals_x, globals_y) {
                        match (g_x, g_y) {
                            (Global::F32(f_x), Global::F32(f_y)) => {
                                if !f_x.is_nan() && !f_y.is_nan() {
                                    assert_eq!(f_x, f_y);
                                } else {
                                    // should hold because of canonicalization
                                    assert_eq!(f_x.to_bits(), f_y.to_bits());
                                }
                            }
                            (Global::F64(f_x), Global::F64(f_y)) => {
                                if !f_x.is_nan() && !f_y.is_nan() {
                                    assert_eq!(f_x, f_y);
                                } else {
                                    // should hold because of canonicalization
                                    assert_eq!(f_x.to_bits(), f_y.to_bits());
                                }
                            }
                            (_, _) => {
                                assert_eq!(g_x, g_y);
                            }
                        }
                    }
                }
                (Err(e_x), Err(e_y)) => {
                    assert_eq!(e_x, e_y);
                }
                (_, _) => {
                    panic!("Instance results doesn't match");
                }
            }
        }
    });
}

#[inline(always)]
fn execute_wasm(
    wasm: Vec<u8>,
    wasm_methods: BTreeSet<WasmMethod>,
) -> Vec<(
    HypervisorResult<Option<WasmResult>>,
    HypervisorResult<InstanceRunResult>,
    u64,
)> {
    let mut result = vec![];
    let instance_result = WasmtimeInstanceBuilder::new().with_wasm(wasm).try_build();
    let mut instance = match instance_result {
        Ok(instance) => instance,
        Err((_, _)) => {
            return result;
        }
    };
    // For determinism, all methods are executed
    for wasm_method in wasm_methods.iter() {
        let func_ref = FuncRef::Method(wasm_method.clone());

        let run_result = instance.run(func_ref);
        let wasm_result = instance
            .store_data_mut()
            .system_api_mut()
            .unwrap()
            .take_execution_result(run_result.as_ref().err());
        let instruction_counter = instance.instruction_counter();
        let instruction_used = instance
            .store_data()
            .system_api()
            .unwrap()
            .slice_instructions_executed(instruction_counter)
            .get();
        result.push((wasm_result, run_result, instruction_used));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn test_differential_simd_execute_with_wasmtime_single_run() {
        let arbitrary_str: &str = "this is a test string";
        let unstrucutred = Unstructured::new(arbitrary_str.as_bytes());
        let module = <crate::ic_wasm::ICWasmModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
            .expect("Unable to extract wasm from Unstructured data");
        run_fuzzer(module);
    }
}
