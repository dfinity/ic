/// Keeps track of various utilization information that has to be
/// ephemerally kept at a canister abstraction layer and perhaps
/// survive across multiple restarts.
#[derive(Copy, Clone, Debug)]
pub struct CanisterDescriptorTable {
    /// In-memory monotonic index that tracks progression of current or
    /// upcoming wasm compilation object generation. This is used to
    /// ensure we 1) do not instruct the sandboxed process to
    /// re-compile needlessly and 2) that we are going to signal
    /// open_wasm() if we receive a closure (`ExecutionState`) that
    /// indicates wasm was compiled, yet in the meantime we have
    /// terminated the previous sandboxed process and thus discarded
    /// the compilation object.
    wasm_generation: WasmObjectGeneration,
}

impl CanisterDescriptorTable {
    pub fn new() -> Self {
        Self {
            wasm_generation: WasmObjectGeneration(0),
        }
    }

    pub fn increment_wasm_generation(&mut self) {
        self.wasm_generation.0 += 1;
    }

    pub fn wasm_generation_object(&self) -> WasmObjectGeneration {
        self.wasm_generation
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WasmObjectGeneration(u64);
