use arbitrary::{Arbitrary, Result, Unstructured};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_config::flag_status::FlagStatus;
use ic_embedders::{wasm_utils::compile, WasmtimeEmbedder};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use wasm_smith::{Config, Module};

#[derive(Debug)]
pub struct MaybeInvalidModule(pub Module);

impl<'a> Arbitrary<'a> for MaybeInvalidModule {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut config = Config::arbitrary(u)?;
        config.allow_invalid_funcs = true;
        Ok(MaybeInvalidModule(Module::new(config, u)?))
    }
}

#[inline(always)]
pub fn run_fuzzer(module: MaybeInvalidModule) {
    let mut config = EmbeddersConfig::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let wasm = module.0.to_bytes();
    let binary_wasm = BinaryEncodedWasm::new(wasm);
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());

    let (_, _) = compile(&embedder, &binary_wasm);
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
