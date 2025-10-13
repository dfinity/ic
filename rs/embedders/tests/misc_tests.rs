mod wasmtime_simple;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::{decoding::decode_wasm, validate_and_instrument_for_testing},
    wasmtime_embedder::system_api::ApiType,
};
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::{
    Cycles, NumBytes, PrincipalId,
    methods::{FuncRef, WasmMethod},
    time::UNIX_EPOCH,
};
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use std::sync::Arc;
use wirm::{Module, wasmparser::ExternalKind};

fn assert_memory_and_table_exports(module: &Module) {
    let export_section = &module.exports;
    let mut memory_exported = false;
    let mut table_exported = false;
    for e in export_section.iter() {
        if ExternalKind::Table == e.kind {
            assert_eq!(e.name, "table");
            table_exported = true;
        } else if ExternalKind::Memory == e.kind && e.name == "memory" {
            memory_exported = true;
        }
    }
    assert!(memory_exported && table_exported);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This tests
// checks that we rename "mem" to "memory" and "tab" to "table" during
// instrumentation.
fn test_instrument_module_rename_memory_table() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
                r#"
                        (module
                            (memory (export "mem") 1 2)
                            (table (export "tab") 2 2 funcref)
                            (func $run (export "run")
                                (drop (i32.const 123))
                            )
                        )
                    "#,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .1;

    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This test
// checks that we export them if they are not.
fn test_instrument_module_export_memory_table() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
                r#"
                        (module
                            (memory 1 2)
                            (table 2 2 funcref)
                            (func $run (export "run")
                                (drop (i32.const 123))
                            )
                        )
                    "#,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .1;

    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

#[test]
fn test_instrument_module_with_exported_global() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
                r#"
                (module
                  (func $run (export "run")
                    (drop (global.get $counter))
                  )
                  (global $counter
                    (export "my_global_counter")
                    (mut i32) (i32.const 123)
                  )
                )"#,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .1;

    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

fn compressed_test_contents(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/compressed/{}",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("couldn't open file {path}: {e}"))
}

fn default_max_size() -> NumBytes {
    EmbeddersConfig::default().wasm_max_size
}

#[test]
fn test_decode_large_compressed_module() {
    // Try decoding 101MB of zeros
    //
    // We also tested decoding with a much larger file.
    // To save space and CI time, we do not include the larger archive file and
    // do not generate it in the test. To reproduce the test, execute the following
    // command:
    //
    // dd if=/dev/zero bs=1024 count=$((500 * 1024)) | gzip -9 > zeroes.gz
    //
    // and replace the zeroes.gz file used in the test.
    let err = decode_wasm(
        default_max_size(),
        Arc::new(compressed_test_contents("zeros.gz")),
    )
    .unwrap_err();
    assert_matches::assert_matches!(err, WasmValidationError::ModuleTooLarge { .. });
}

#[test]
#[should_panic(expected = "specified uncompressed size 100 does not match extracted size 101")]
fn test_decode_large_compressed_module_with_tweaked_size() {
    let mut contents = compressed_test_contents("zeros.gz");
    let n = contents.len();
    contents[n - 4..n].copy_from_slice(&100u32.to_le_bytes());
    decode_wasm(default_max_size(), Arc::new(contents)).unwrap();
}

fn run_go_export(wat: &str) -> Result<(), HypervisorError> {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_api_type(ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::from(0_u128),
            PrincipalId::new_user_test_id(0),
            0.into(),
        ))
        .with_num_instructions(LARGE_INSTRUCTION_LIMIT.into())
        .try_build()
        .map_err(|(err, _)| err)?;

    instance
        .run(FuncRef::Method(WasmMethod::Update("go".to_string())))
        .unwrap();
    Ok(())
}

/// Test that we can handle a module that exports one of its imports.
#[test]
fn direct_export_of_import() {
    run_go_export(
        r#"
		(module
			(func $reply (export "canister_update go") (import "ic0" "msg_reply"))
		)
	"#,
    )
    .unwrap();
}

/// Test that we can handle a module that exports one of its imports when there
/// are other imports.
#[test]
fn direct_export_of_one_import_from_many() {
    run_go_export(
        r#"
		(module
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
            (import "ic0" "canister_cycle_balance" (func $ic0_canister_cycle_balance (result i64)))
			(func $reply (export "canister_update go") (import "ic0" "msg_reply"))
            (import "ic0" "msg_cycles_accept" (func $ic0_msg_cycles_accept (param $amount i64) (result i64)))
		)
	"#,
    ).unwrap();
}

#[test]
fn direct_export_of_import_fails_with_wrong_type() {
    let err = run_go_export(
        r#"
		(module
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
            (import "ic0" "msg_reply" (func $reply))
			(func (export "canister_update go") (import "ic0" "canister_cycle_balance") (result i64))
            (import "ic0" "msg_cycles_accept" (func $ic0_msg_cycles_accept (param $amount i64) (result i64)))
            (func $other (call $reply))
		)
	"#,
    ).unwrap_err();
    assert_eq!(
        err,
        HypervisorError::InvalidWasm(WasmValidationError::InvalidFunctionSignature(
            "Expected return type [] for 'canister_update go', got [I64].".to_string()
        ))
    );
}

/// A module should be allowed to export a direct import which doesn't have type
/// () -> () as long as it doesn't have a `canister_` prefix in the export name.
#[test]
fn direct_export_of_import_without_unit_type() {
    run_go_export(
        r#"
		(module
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
			(func (export "foo") (import "ic0" "canister_cycle_balance") (result i64))
            (import "ic0" "msg_cycles_accept" (func $ic0_msg_cycles_accept (param $amount i64) (result i64)))
            (func (export "canister_update go"))
		)
	"#,
    ).unwrap();
}

#[test]
fn nan_canonicalization_works() {
    /// Returns a typed NaN generated by the provided Wasm operator.
    fn get_nan<T: wasmtime::WasmTy>(canonicalize: bool, ty: &str, op: &str) -> T {
        let mut config =
            WasmtimeEmbedder::wasmtime_execution_config(&ic_config::embedders::Config::default());
        config.wasm_simd(true);
        config.cranelift_nan_canonicalization(canonicalize);

        let engine = wasmtime::Engine::new(&config).unwrap();
        let wasm = wat::parse_str(format!(
            r#"(module (func (export "get_nan") (result {ty}) {op}))"#,
        ))
        .unwrap();
        let module = wasmtime::Module::new(&engine, wasm).unwrap();
        let linker = wasmtime::Linker::new(&engine);
        let mut store: wasmtime::Store<()> = wasmtime::Store::new(&engine, ());

        let instance = linker.instantiate(&mut store, &module).unwrap();
        let get_nan = instance
            .get_typed_func::<(), T>(&mut store, "get_nan")
            .unwrap();
        get_nan.call(&mut store, ()).unwrap()
    }

    let non_canonical_nan = "nan:0x200000";

    let op = format!("(f32.sqrt (f32.const {non_canonical_nan}))");
    let res: f32 = get_nan(false, "f32", &op);
    // We can't compare the NaNs directly, but we can compare their bytes.
    assert_ne!(res.to_be_bytes(), f32::NAN.to_be_bytes());
    let res: f32 = get_nan(true, "f32", &op);
    // The NaN must be canonical when the canonicalization is enabled.
    assert_eq!(res.to_be_bytes(), f32::NAN.to_be_bytes());

    let op = format!("(f64.sqrt (f64.const {non_canonical_nan}))");
    let res: f64 = get_nan(false, "f64", &op);
    assert_ne!(res.to_be_bytes(), f64::NAN.to_be_bytes());
    let res: f64 = get_nan(true, "f64", &op);
    assert_eq!(res.to_be_bytes(), f64::NAN.to_be_bytes());

    let op = format!("(f64x2.sqrt (v128.const f64x2 {non_canonical_nan} {non_canonical_nan}))");
    let res: wasmtime::V128 = get_nan(false, "v128", &op);
    assert_ne!(
        res.as_u128().to_be_bytes().as_slice(),
        f64::NAN.to_be_bytes().repeat(2).as_slice()
    );
    let res: wasmtime::V128 = get_nan(true, "v128", &op);
    assert_eq!(
        res.as_u128().to_be_bytes().as_slice(),
        f64::NAN.to_be_bytes().repeat(2).as_slice()
    );
}
