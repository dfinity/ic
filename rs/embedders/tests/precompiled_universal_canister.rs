use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{SerializedModule, WasmtimeEmbedder};
use ic_universal_canister::UNIVERSAL_CANISTER_SERIALIZED_MODULE;

/// The precompiled universal canister is built once and then shared via the
/// remote cache with every machine that runs tests, so it must not be compiled
/// for the optional CPU features of the machine that built it. Otherwise it
/// fails to load on machines without them, e.g. with "compilation setting
/// "has_i8mm" is enabled, but not available on the host".
#[test]
fn precompiled_universal_canister_loads_without_optional_cpu_features() {
    let serialized_module: SerializedModule =
        bincode::deserialize(&UNIVERSAL_CANISTER_SERIALIZED_MODULE)
            .expect("Failed to deserialize universal canister module");

    // An engine for a host of the same architecture and OS without any
    // optional CPU features. The engine's own settings must not use the CPU
    // features of the actual host either, because Wasmtime also checks them
    // against `detect_host_feature` before loading a module.
    let mut config = WasmtimeEmbedder::wasmtime_execution_config(&EmbeddersConfig::default());
    WasmtimeEmbedder::disable_host_cpu_features(&mut config);
    // SAFETY: Reporting every CPU feature as unavailable can only make
    // Wasmtime reject code, never run code the host can't execute. Besides,
    // this engine never runs the module.
    unsafe {
        config.detect_host_feature(|_| Some(false));
    }
    let engine = wasmtime::Engine::new(&config).expect("Failed to create engine");

    // SAFETY: The bytes are a `wasmtime::Module` serialized by `instrument-wasm`.
    unsafe { wasmtime::Module::deserialize(&engine, serialized_module.bytes.as_slice()) }
        .unwrap_or_else(|err| {
            panic!(
                "The precompiled universal canister doesn't load on a host without optional CPU features: {err:?}"
            )
        });
}
