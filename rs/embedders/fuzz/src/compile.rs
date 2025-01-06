use crate::ic_wasm::{ic_embedders_config, ic_wasm_config};
use arbitrary::{Arbitrary, Result, Unstructured};
use ic_embedders::{wasm_utils::compile, WasmtimeEmbedder};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use std::time::Duration;
use tokio::runtime::Runtime;
use wasm_smith::{MemoryOffsetChoices, Module};

#[derive(Debug)]
pub struct MaybeInvalidModule(pub Module);

impl<'a> Arbitrary<'a> for MaybeInvalidModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut config = ic_wasm_config(ic_embedders_config());
        config.allow_invalid_funcs = true;
        config.memory_offset_choices = MemoryOffsetChoices(40, 20, 40);
        Ok(MaybeInvalidModule(Module::new(config, u)?))
    }
}

#[inline(always)]
pub fn run_fuzzer(module: MaybeInvalidModule) {
    let config = ic_embedders_config();
    let wasm = module.0.to_bytes();

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
        // The omitted field is Result<InstancePre<StoreData>, HypervisorError>
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
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn test_compile_wasm_using_embedder_single_run() {
        let arbitrary_str: &str = "this is a test string";
        let unstrucutred = Unstructured::new(arbitrary_str.as_bytes());
        let module = <MaybeInvalidModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
            .expect("Unable to extract wasm from Unstructured data");
        run_fuzzer(module);
    }
}
