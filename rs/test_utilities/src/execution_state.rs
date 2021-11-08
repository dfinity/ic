use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::wasmtime_embedder::WasmtimeEmbedder;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::ExecutionState;
use std::path::PathBuf;

pub struct ExecutionStateBuilder {
    wasm_binary: Vec<u8>,
    canister_root: PathBuf,
}

impl ExecutionStateBuilder {
    pub fn new(wasm_binary: Vec<u8>, canister_root: PathBuf) -> Self {
        Self {
            wasm_binary,
            canister_root,
        }
    }

    pub fn build(self) -> ExecutionState {
        let embedders_config = EmbeddersConfig::default();
        let wasm_embedder = WasmtimeEmbedder::new(embedders_config.clone(), no_op_logger());
        wasm_embedder
            .create_execution_state(self.wasm_binary, self.canister_root, &embedders_config)
            .expect("Failed to create execution state.")
    }
}
