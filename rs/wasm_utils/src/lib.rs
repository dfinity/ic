use wasmtime::Config;

mod errors;
pub mod instrumentation;
pub mod validation;

/// Sets Wasmtime flags to ensure deterministic execution.
pub fn ensure_determinism(config: &mut Config) {
    config
        .wasm_threads(false)
        .wasm_simd(false)
        .cranelift_nan_canonicalization(true);
}
