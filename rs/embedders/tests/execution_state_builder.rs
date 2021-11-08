use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::WasmtimeEmbedder;
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::ExportedFunctions;
use ic_types::methods::WasmMethod;
use ic_wasm_utils::validation::WasmValidationConfig;
use std::collections::BTreeSet;

#[test]
fn broken_wasm_results_in_compilation_error() {
    let wasm_embedder = WasmtimeEmbedder::new(EmbeddersConfig::new(), no_op_logger());
    let binary = vec![0xca, 0xfe, 0xba, 0xbe];

    assert_compile_error(wasm_embedder.create_execution_state(
        binary,
        std::path::PathBuf::from(r"/NOT_USED"),
        WasmValidationConfig::default(),
    ));
}

#[test]
fn can_extract_exported_functions() {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

    let wasm_embedder = WasmtimeEmbedder::new(EmbeddersConfig::new(), no_op_logger());
    let execution_state = wasm_embedder
        .create_execution_state(
            wabt::wat2wasm(
                r#"
                        (module
                          (func $write)
                          (func $read)
                          (export "canister_update write" (func $write))
                          (export "canister_query read" (func $read))
                          (memory (;0;) 2)
                          (export "memory" (memory 0))
                        )
                    "#,
            )
            .unwrap(),
            tmpdir.path().into(),
            WasmValidationConfig::default(),
        )
        .unwrap();
    let mut expected_exports = BTreeSet::new();
    expected_exports.insert(WasmMethod::Update("write".to_string()));
    expected_exports.insert(WasmMethod::Query("read".to_string()));
    assert_eq!(
        execution_state.exports,
        ExportedFunctions::new(expected_exports)
    );
}

fn assert_compile_error<T: std::fmt::Debug>(result: Result<T, HypervisorError>) {
    match result {
        Err(HypervisorError::InvalidWasm(_)) => (),
        val => panic!("Expected a compile error, got: {:?}", val),
    }
}
