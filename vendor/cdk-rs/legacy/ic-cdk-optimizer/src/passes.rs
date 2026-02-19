use wabt::{wasm2wat, wat2wasm};

mod binaryen;

pub type PassResult = Result<Vec<u8>, Box<dyn std::error::Error>>;

pub trait OptimizationPass {
    fn short_name(&self) -> String;
    fn description(&self) -> String;
    fn opt(&self, wasm: &[u8]) -> PassResult;
}

struct RemoveDebugSymbolsPass;

impl OptimizationPass for RemoveDebugSymbolsPass {
    fn short_name(&self) -> String {
        String::from("strip_data")
    }

    fn description(&self) -> String {
        String::from("Stripping Unused Data Segments")
    }

    fn opt(&self, wasm: &[u8]) -> PassResult {
        let wat = wasm2wat(&wasm)?;
        Ok(wat2wasm(&wat)?)
    }
}

pub fn create() -> Vec<Box<dyn OptimizationPass>> {
    vec![
        Box::new(RemoveDebugSymbolsPass),
        Box::new(binaryen::BinaryenPass),
    ]
}
