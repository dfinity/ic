use crate::ic_wasm::ICWasmModule;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::WasmtimeEmbedder;
use ic_embedders::wasm_utils::validate_and_instrument_for_testing;
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use tokio::runtime::Runtime;

const MAX_PARALLEL_EXECUTIONS: usize = 4;

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) {
    let wasm = module.module.to_bytes();
    let config = EmbeddersConfig::default();
    let binary_wasm = BinaryEncodedWasm::new(wasm);

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .max_blocking_threads(1)
        // thread stack overflows before wasmtime (2MiB vs 5MiB)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));

    let futs = (0..MAX_PARALLEL_EXECUTIONS)
        .map(|_| {
            rt.spawn({
                let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());
                let wasm = binary_wasm.clone();
                async move { validate_and_instrument_for_testing(&embedder, &wasm) }
            })
        })
        .collect::<Vec<_>>();

    rt.block_on(async move {
        let result = futures::future::join_all(futs)
            .await
            .into_iter()
            .map(|r| r.expect("Failed to join tasks"))
            .collect::<Vec<_>>();

        let first = result.first();

        if let Some(first) = first {
            assert!(result.iter().all(|r| first == r));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn test_differential_instrumentation_single_run() {
        let arbitrary_str: &str = "this is a test string";
        let unstrucutred = Unstructured::new(arbitrary_str.as_bytes());
        let module = <crate::ic_wasm::ICWasmModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
            .expect("Unable to extract wasm from Unstructured data");
        run_fuzzer(module);
    }
}
