use crate::ic_wasm::{generate_exports, ic_embedders_config, ic_wasm_config};
use arbitrary::{Arbitrary, Result, Unstructured};
use ic_embedders::{wasm_utils::compile, WasmtimeEmbedder};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use std::time::Duration;
use tokio::runtime::Runtime;
use wasm_smith::{Config, MemoryOffsetChoices, Module};

#[derive(Debug)]
pub struct MaybeInvalidModule(pub Module);

impl<'a> Arbitrary<'a> for MaybeInvalidModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut config = if u.ratio(1, 2)? {
            let mut config = ic_wasm_config(ic_embedders_config());
            config.exports = generate_exports(ic_embedders_config(), u)?;
            config.min_data_segments = 2;
            config.max_data_segments = 10;
            config
        } else {
            Config::arbitrary(u)?
        };
        config.allow_invalid_funcs = true;
        config.memory_offset_choices = MemoryOffsetChoices(40, 20, 40);
        Ok(MaybeInvalidModule(Module::new(config, u)?))
    }
}

#[inline(always)]
pub fn run_fuzzer(module: &[u8]) {
    let config = ic_embedders_config();
    let mut u = Unstructured::new(module);

    // Arbitrary Wasm module generation probabilities
    // 33% - Random bytes
    // 33% - Wasm with arbitrary wasm-smith config + maybe invalid functions
    // 33% - IC complaint wasm + maybe invalid functions

    let wasm = if u.ratio(1, 3).unwrap() {
        let mut wasm: Vec<u8> = b"\x00asm".to_vec();
        wasm.extend_from_slice(module);
        wasm
    } else {
        let module = <MaybeInvalidModule as Arbitrary>::arbitrary_take_rest(u)
            .expect("Unable to extract wasm from Unstructured data");
        module.0.to_bytes()
    };

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));

    let first_execution = rt.spawn({
        let wasm = wasm.clone();
        let binary_wasm = BinaryEncodedWasm::new(wasm);
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        async move { compile(&embedder, &binary_wasm) }
    });

    let second_execution = rt.spawn({
        let binary_wasm = BinaryEncodedWasm::new(wasm);
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());

        async move { compile(&embedder, &binary_wasm) }
    });

    rt.block_on(async move {
        // The omitted field is EmbedderCache(Result<InstancePre<StoreData>, HypervisorError>)
        // 1. InstancePre<StoreData> doesn't implement PartialEq
        // 2. HypervisorError is the same in compilation_result which is checked for equality

        let (_, compilation_result_1) = first_execution.await.unwrap();
        let (_, compilation_result_2) = second_execution.await.unwrap();

        let time_removed_compilation_result_1 = compilation_result_1.map(|mut r| {
            r.0.compilation_time = Duration::from_millis(1);
            r
        });

        let time_removed_compilation_result_2 = compilation_result_2.map(|mut r| {
            r.0.compilation_time = Duration::from_millis(1);
            r
        });

        assert_eq!(
            time_removed_compilation_result_1,
            time_removed_compilation_result_2
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_wasm_using_embedder_single_run() {
        let arbitrary_str: &str = "this is a test string";
        run_fuzzer(arbitrary_str.as_bytes());
    }
}
