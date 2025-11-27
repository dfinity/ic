use crate::ic_wasm::{generate_exports, ic_wasm_config};
use arbitrary::{Arbitrary, Result, Unstructured};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{WasmtimeEmbedder, wasm_utils::compile};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use std::time::Duration;
use tokio::runtime::Runtime;
use wasm_smith::{Config, MemoryOffsetChoices, Module};

#[derive(Debug)]
pub struct MaybeInvalidModule {
    pub module: Module,
}

const MAX_PARALLEL_EXECUTIONS: usize = 4;

impl<'a> Arbitrary<'a> for MaybeInvalidModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut config = if u.ratio(1, 2)? {
            let is_wasm64 = u.ratio(2, 3)?;
            let mut config = ic_wasm_config(EmbeddersConfig::default(), is_wasm64);
            config.exports = generate_exports(EmbeddersConfig::default(), u)?;
            config.min_data_segments = 2;
            config.max_data_segments = 10;
            config
        } else {
            Config::arbitrary(u)?
        };
        config.allow_invalid_funcs = true;
        config.memory_offset_choices = MemoryOffsetChoices(40, 20, 40);
        Ok(MaybeInvalidModule {
            module: Module::new(config.clone(), u)?,
        })
    }
}

#[inline(always)]
pub fn run_fuzzer(bytes: &[u8]) {
    let config;
    let mut u = Unstructured::new(bytes);

    // Arbitrary Wasm module generation probabilities
    // 33% - Random bytes
    // 33% - Wasm with arbitrary wasm-smith config + maybe invalid functions
    // 33% - IC compliant wasm + maybe invalid functions

    let wasm = if u.ratio(1, 3).unwrap_or(false)
        || bytes.len() < <MaybeInvalidModule as Arbitrary>::size_hint(0).0
    {
        config = EmbeddersConfig::default();
        raw_wasm_bytes(bytes)
    } else {
        let data = <MaybeInvalidModule as Arbitrary>::arbitrary_take_rest(u);

        match data {
            Ok(data) => {
                config = EmbeddersConfig::default();
                data.module.to_bytes()
            }
            Err(_) => {
                config = EmbeddersConfig::default();
                raw_wasm_bytes(bytes)
            }
        }
    };

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));

    let futs = (0..MAX_PARALLEL_EXECUTIONS)
        .map(|_| {
            rt.spawn({
                let wasm = wasm.clone();
                let binary_wasm = BinaryEncodedWasm::new(wasm);
                let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

                async move { compile(&embedder, &binary_wasm) }
            })
        })
        .collect::<Vec<_>>();

    rt.block_on(async move {
        // The omitted field is EmbedderCache(Result<InstancePre<StoreData>, HypervisorError>)
        // 1. InstancePre<StoreData> doesn't implement PartialEq
        // 2. HypervisorError is the same in compilation_result which is checked for equality

        let result = futures::future::join_all(futs)
            .await
            .into_iter()
            .map(|r| r.expect("Failed to join tasks"))
            .map(|(_, compilation_result)| {
                if let Ok(mut r) = compilation_result {
                    r.0.compilation_time = Duration::from_millis(1);
                    Ok(r)
                } else {
                    compilation_result
                }
            })
            .collect::<Vec<_>>();

        let first = result.first();

        if let Some(first) = first {
            assert!(result.iter().all(|r| r == first));
        }
    });
}

#[inline(always)]
fn raw_wasm_bytes(data: &[u8]) -> Vec<u8> {
    let mut wasm: Vec<u8> = b"\x00asm".to_vec();
    wasm.extend_from_slice(data);
    wasm
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
