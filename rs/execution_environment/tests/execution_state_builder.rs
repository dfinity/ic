use ic_interfaces::execution_environment::HypervisorError;
use ic_replicated_state::{ExecutionState, ExportedFunctions};
use ic_types::methods::WasmMethod;
use ic_wasm_utils::validation::WasmValidationLimits;
use std::collections::BTreeSet;

#[test]
fn broken_wasm_results_in_compilation_error() {
    let binary = vec![0xca, 0xfe, 0xba, 0xbe];
    assert_compile_error(ExecutionState::new(
        binary,
        std::path::PathBuf::from(r"/NOT_USED"),
        WasmValidationLimits::default(),
    ));
}

#[test]
fn can_extract_exported_functions() {
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

    let execution_state = ExecutionState::new(
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
        WasmValidationLimits::default(),
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
